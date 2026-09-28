"""Three abrupt native proxy deaths around a scoped durable host revocation."""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.proxy_migration.harness import REPO
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_policy_host_chaos import _converge
from tools.policy_chaos_recovery import (
    CHECKPOINTS,
    POLICY,
    TARGET,
    VM_INPUT_LIMIT,
    PolicyCheckpoint,
    assert_policy_document,
    native_proxy,
    observe_effects,
    policy_residue,
    policy_version,
    safe_vm_paths,
    success_audit,
    vm_fixture_manifest,
    vm_runtime_base,
    write_manifest,
)


@pytest.mark.parametrize("checkpoint", CHECKPOINTS)
def test_native_proxy_death_recovers_complete_scoped_revocation(tmp_path: Path, checkpoint: str):
    directory = tmp_path / checkpoint
    directory.mkdir()
    policy = directory / "policy.toml"
    policy.write_text(POLICY)
    binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", "proxy/target/debug/safeyolo-proxy")).resolve()
    manifest = vm_fixture_manifest(directory, tmp_path, binary, "process-death", checkpoint)
    old = policy.read_bytes()
    expected_new = base64.b64decode(manifest["new_b64"])
    expected_version = "old" if checkpoint == "before-rename" else "new"

    with PolicyCheckpoint(f"process-{checkpoint}", checkpoint) as controller, \
         patch.dict(os.environ, controller.environment()), origin_server() as origin:
        with native_proxy(directory, origin, initial=None) as (proxy, api):
            assert policy.read_bytes() == old
            observe_effects(proxy, origin, revoked=False)
            if checkpoint == "after-acknowledged-response":
                result = api.deny_host(TARGET, agent="alice")
                assert result["status"] == "denied" and result["agent"] == "alice"
                assert controller.transaction is not None
                assert policy.read_bytes() == expected_new
                marker = proxy.readiness_file.stat()
                _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
                observe_effects(proxy, origin, revoked=True)
                deadline = time.monotonic() + 3
                while not success_audit(directory) and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert len(success_audit(directory)) == 1
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(api.deny_host, TARGET, agent="alice")
                    assert controller.ready.wait(15), controller.events
                    assert controller.selected_event is not None
                    assert (controller.selected_event["phase"],
                            controller.selected_event["stage"]) == CHECKPOINTS[checkpoint]
                    assert not pending.done(), "Admin acknowledged before the selected checkpoint"
                    visible = policy.read_bytes()
                    assert policy_version(visible, old, expected_new) == expected_version
                    assert_policy_document(visible, revoked=expected_version == "new")
                    # The native policy read lock intentionally holds new traffic
                    # while this writer is paused; the pre-cut live probe above
                    # and the fresh-process probe below bracket the cut.
                    assert not success_audit(directory)
                    proxy.process.kill()  # Abrupt process death; never a VM-death substitute.
                    assert proxy.process.wait(timeout=5) < 0
                    with pytest.raises(Exception):
                        pending.result(timeout=5)
            if checkpoint == "after-acknowledged-response":
                proxy.process.kill()
                assert proxy.process.wait(timeout=5) < 0
            assert policy_version(policy.read_bytes(), old, expected_new) == expected_version

    residue = policy_residue(directory)
    if checkpoint == "before-rename":
        assert len(residue) == 1
        assert residue[0].read_bytes() == expected_new
    else:
        assert residue == []
    assert len(success_audit(directory)) == int(checkpoint == "after-acknowledged-response")
    surviving = policy.read_bytes()
    with origin_server() as origin, native_proxy(directory, origin, initial=None, admin=False) as (fresh, _):
        observe_effects(fresh, origin, revoked=expected_version == "new")
        assert policy.read_bytes() == surviving, "fresh Rust rewrote the recovered policy"
        assert_policy_document(surviving, revoked=expected_version == "new")


@pytest.fixture
def disk_tmp():
    with tempfile.TemporaryDirectory(prefix="sy-vm-guard-", dir=Path.home()) as directory:
        yield Path(directory)


@pytest.mark.skipif(sys.platform != "linux", reason="VM guard requires Linux mount information")
@pytest.mark.parametrize("checkpoint", CHECKPOINTS)
def test_vm_guard_requires_exact_external_ready_and_cut_record(
    tmp_path: Path, disk_tmp: Path, checkpoint: str,
):
    config = disk_tmp / "disposable"
    state = disk_tmp / "state"
    config.mkdir()
    state.mkdir()
    (config / "policy.toml").write_text(POLICY)
    (config / ".safeyolo-chaos-disposable").write_text("disposable fixture\n")
    binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", "proxy/target/debug/safeyolo-proxy")).resolve()
    run_id = "guard-" + checkpoint.replace("-", "")
    command = [sys.executable, "-m", "tools.policy_chaos", "fault", "prepare-power-cut",
               "--checkpoint", checkpoint, "--config-dir", str(config),
               "--state-dir", str(state), "--binary", str(binary), "--run-id", run_id,
               "--confirm-disposable-vm"]
    environment = {**os.environ, "SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"}
    # The child runs in this Linux environment only to inspect its guarded
    # protocol. No VM is stopped, and no recovery result is claimed.
    process = subprocess.Popen(command, cwd=REPO, env=environment, text=True,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    proxy_pid = None
    try:
        assert select.select([process.stdout], [], [], 30)[0], process.poll()
        prepared_line = process.stdout.readline()
        assert prepared_line, process.stderr.read() if process.poll() is not None else "empty prepared line"
        prepared = json.loads(prepared_line)
        assert prepared["status"] == "PREPARED"
        assert prepared["run_id"] == run_id
        assert (state / run_id / "recovery-manifest.json").is_file()
        observation = tmp_path / "external-observation.jsonl"
        observation.write_text(prepared_line)
        ready_command = [sys.executable, "-m", "tools.policy_chaos", "fault", "ready",
                         "--manifest", prepared["manifest"],
                         "--observation", str(observation)]
        missing = subprocess.run(ready_command, cwd=REPO, env=environment,
                                 text=True, capture_output=True, timeout=10)
        assert missing.returncode == 2 and "INCOMPLETE" in missing.stderr
        process.stdin.write(f"ARM {run_id} {checkpoint} {prepared['manifest_sha256']}\n")
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 30)[0], process.poll()
        ready_line = process.stdout.readline()
        assert ready_line, process.stderr.read() if process.poll() is not None else "empty ready line"
        ready = json.loads(ready_line)
        proxy_pid = ready["proxy_pid"]
        assert ready["transaction"] and ready["checkpoint"] == checkpoint
        with observation.open("a") as stream:
            stream.write(ready_line)
        valid = subprocess.run(ready_command, cwd=REPO, env=environment,
                               text=True, capture_output=True, timeout=10)
        assert valid.returncode == 0, valid.stderr
        stale = tmp_path / "stale-observation.jsonl"
        stale.write_text(prepared_line + ready_line.replace(checkpoint, "wrong-checkpoint"))
        rejected = subprocess.run([*ready_command[:-1], str(stale)], cwd=REPO,
                                  env=environment, text=True, capture_output=True, timeout=10)
        assert rejected.returncode == 2 and "INCOMPLETE" in rejected.stderr
        wrong_run = tmp_path / "wrong-run-observation.jsonl"
        wrong_run.write_text(prepared_line + ready_line.replace(run_id, "another-run"))
        rejected_run = subprocess.run([*ready_command[:-1], str(wrong_run)], cwd=REPO,
                                      env=environment, text=True, capture_output=True, timeout=10)
        assert rejected_run.returncode == 2 and "INCOMPLETE" in rejected_run.stderr
        recover = subprocess.run(
            [sys.executable, "-m", "tools.policy_chaos", "fault", "recover",
             "--run-id", run_id, "--config-dir", str(config), "--state-dir", str(state),
             "--observation", str(observation), "--cut-record", str(tmp_path / "missing-cut.json"),
             "--output", str(tmp_path / "report.json"), "--confirm-disposable-vm"],
            cwd=REPO, env=environment, text=True, capture_output=True, timeout=10,
        )
        assert recover.returncode == 2 and "INCOMPLETE" in recover.stderr
        assert not (tmp_path / "report.json").exists()
    finally:
        if proxy_pid is not None:
            try:
                os.kill(proxy_pid, signal.SIGKILL)  # Cleanup of guard-only probe, not a VM cut.
            except ProcessLookupError:
                pass
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="VM guard requires Linux mount information")
def test_vm_paths_require_opt_in_sentinel_and_separate_runtime(disk_tmp: Path):
    config = disk_tmp / "disposable-paths"
    state = disk_tmp / "state-paths"
    config.mkdir()
    state.mkdir()
    (config / "policy.toml").write_text(POLICY)
    with patch.dict(os.environ, {"SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"}):
        with pytest.raises(ValueError, match="confirm-disposable-vm"):
            safe_vm_paths(config, state, False)
        with pytest.raises(ValueError, match="sentinel"):
            safe_vm_paths(config, state, True)
        (config / ".safeyolo-chaos-disposable").write_text("disposable fixture\n")
        assert safe_vm_paths(config, state, True)[0] == config / "policy.toml"
        invalid_run = subprocess.run(
            [sys.executable, "-m", "tools.policy_chaos", "fault", "recover",
             "--run-id", "../escape", "--config-dir", str(config),
             "--state-dir", str(state), "--observation", str(disk_tmp / "missing-observation"),
             "--cut-record", str(disk_tmp / "missing-cut"),
             "--output", str(disk_tmp / "not-created-report"), "--confirm-disposable-vm"],
            cwd=REPO, env=os.environ, text=True, capture_output=True, timeout=10,
        )
        assert invalid_run.returncode == 2 and "run ID" in invalid_run.stderr
        (state / "linked-run").symlink_to(disk_tmp, target_is_directory=True)
        linked_run = subprocess.run(
            [sys.executable, "-m", "tools.policy_chaos", "fault", "recover",
             "--run-id", "linked-run", "--config-dir", str(config),
             "--state-dir", str(state), "--observation", str(disk_tmp / "missing-observation"),
             "--cut-record", str(disk_tmp / "missing-cut"),
             "--output", str(disk_tmp / "not-created-report"), "--confirm-disposable-vm"],
            cwd=REPO, env=os.environ, text=True, capture_output=True, timeout=10,
        )
        assert linked_run.returncode == 2 and "unsafe recovery run directory" in linked_run.stderr
        with pytest.raises(ValueError, match="tmpfs or ramfs"):
            vm_runtime_base(config, state)
        sentinel = config / ".safeyolo-chaos-disposable"
        outside = disk_tmp / "outside-policy.toml"
        outside.write_text(POLICY)
        sentinel.unlink()
        sentinel.symlink_to(outside)
        with pytest.raises(ValueError, match="sentinel"):
            safe_vm_paths(config, state, True)
        sentinel.unlink()
        sentinel.write_text("disposable fixture\n")
        policy = config / "policy.toml"
        policy.unlink()
        policy.symlink_to(outside)
        with pytest.raises(ValueError, match="unsafe policy path"):
            safe_vm_paths(config, state, True)
        linked_checkout = disk_tmp / "linked-checkout"
        linked_checkout.symlink_to(REPO, target_is_directory=True)
        with pytest.raises(ValueError, match="unsafe VM config/state root"):
            safe_vm_paths(linked_checkout, state, True)
    with patch.dict(os.environ, {"SAFEYOLO_CHAOS_DISPOSABLE_VM": ""}):
        with pytest.raises(ValueError, match="SAFEYOLO_CHAOS_DISPOSABLE_VM"):
            safe_vm_paths(config, state, True)


@pytest.mark.skipif(sys.platform != "linux", reason="VM guard requires Linux mount information")
def test_corrupt_survivor_is_finding_with_simulated_cut_record(tmp_path: Path, disk_tmp: Path):
    config = disk_tmp / "disposable-negative"
    state = disk_tmp / "state-negative"
    config.mkdir()
    state.mkdir()
    (config / "policy.toml").write_text(POLICY)
    (config / ".safeyolo-chaos-disposable").write_text("disposable fixture\n")
    binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", "proxy/target/debug/safeyolo-proxy")).resolve()
    run_id = "synthetic-negative-control"
    run_dir = state / run_id
    run_dir.mkdir()
    manifest = vm_fixture_manifest(config, state, binary, run_id, "before-rename")
    manifest_hash = write_manifest(run_dir / "recovery-manifest.json", manifest)
    prepared = {"status": "PREPARED", "run_id": run_id,
                "checkpoint": "before-rename", "manifest_sha256": manifest_hash}
    ready = {**prepared, "status": "READY_FOR_POWER_CUT", "proxy_pid": 123,
             "transaction": "synthetic-transaction", "phase": "commit", "stage": "rename",
             "success_audit_count": 0}
    observation = tmp_path / "synthetic-observation.jsonl"
    observation.write_text(json.dumps(prepared) + "\n" + json.dumps(ready) + "\n")
    cut_record = tmp_path / "synthetic-cut.json"
    cut_record.write_text(json.dumps({
        "run_id": run_id, "checkpoint": "before-rename",
        "manifest_sha256": manifest_hash, "transaction": "synthetic-transaction",
        "target": "vm", "abrupt_vm_stop": True, "vm_id": "synthetic-negative-control",
        "mechanism": "synthetic-negative-control", "filesystem": "synthetic",
        "storage": "synthetic", "stopped_at": "synthetic", "restarted_at": "synthetic",
    }))
    (config / "policy.toml").write_bytes(b"[invalid\n")
    report = tmp_path / "negative-report.json"
    result = subprocess.run(
        [sys.executable, "-m", "tools.policy_chaos", "fault", "recover",
         "--run-id", run_id, "--config-dir", str(config), "--state-dir", str(state),
         "--observation", str(observation), "--cut-record", str(cut_record),
         "--output", str(report), "--confirm-disposable-vm"],
        cwd=REPO, env={**os.environ, "SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"},
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 1, result.stderr
    outcome = json.loads(report.read_text())
    assert outcome["status"] == "FINDING" and outcome["visible_version"] is None
    assert "neither the complete old nor the complete new" in outcome["problems"][0]


@pytest.mark.skipif(sys.platform != "linux", reason="VM guard requires Linux mount information")
def test_recover_reads_complete_survivor_with_simulated_cut_record(tmp_path: Path, disk_tmp: Path):
    """Exercise recovery plumbing without claiming an actual VM stop."""
    config = disk_tmp / "disposable-complete"
    state = disk_tmp / "state-complete"
    config.mkdir()
    state.mkdir()
    (config / "policy.toml").write_text(POLICY)
    (config / ".safeyolo-chaos-disposable").write_text("disposable fixture\n")
    binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", "proxy/target/debug/safeyolo-proxy")).resolve()
    run_id = "synthetic-complete-control"
    run_dir = state / run_id
    run_dir.mkdir()
    manifest = vm_fixture_manifest(config, state, binary, run_id, "after-acknowledged-response")
    manifest_hash = write_manifest(run_dir / "recovery-manifest.json", manifest)
    (config / "policy.toml").write_bytes(base64.b64decode(manifest["new_b64"]))
    prepared = {"status": "PREPARED", "run_id": run_id,
                "checkpoint": "after-acknowledged-response", "manifest_sha256": manifest_hash}
    ready = {**prepared, "status": "READY_FOR_POWER_CUT", "proxy_pid": 123,
             "transaction": "synthetic-transaction", "phase": "response",
             "stage": "acknowledged", "operation_result": "denied", "success_audit_count": 1}
    observation = tmp_path / "complete-observation.jsonl"
    observation.write_text(json.dumps(prepared) + "\n" + json.dumps(ready) + "\n")
    cut_record = tmp_path / "complete-cut.json"
    cut_record.write_text(json.dumps({
        "run_id": run_id, "checkpoint": "after-acknowledged-response",
        "manifest_sha256": manifest_hash, "transaction": "synthetic-transaction",
        "target": "vm", "abrupt_vm_stop": True, "vm_id": "synthetic-complete-control",
        "mechanism": "synthetic-complete-control", "filesystem": "synthetic",
        "storage": "synthetic", "stopped_at": "synthetic", "restarted_at": "synthetic",
    }))
    report = tmp_path / "complete-report.json"
    result = subprocess.run(
        [sys.executable, "-m", "tools.policy_chaos", "fault", "recover",
         "--run-id", run_id, "--config-dir", str(config), "--state-dir", str(state),
         "--observation", str(observation), "--cut-record", str(cut_record),
         "--output", str(report), "--confirm-disposable-vm"],
        cwd=REPO, env={**os.environ, "SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"},
        text=True, capture_output=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    outcome = json.loads(report.read_text())
    assert outcome["status"] == "PASS" and outcome["visible_version"] == "new"
    assert outcome["fresh_effects"] == {
        "alice-target": 403, "bob-target": 403,
        "alice-control": 200, "alice-blocked": 403,
    }

    environment = {**os.environ, "SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"}
    ready_command = [sys.executable, "-m", "tools.policy_chaos", "fault", "ready",
                     "--manifest", str(run_dir / "recovery-manifest.json"),
                     "--observation", str(observation)]
    rejected_report = tmp_path / "rejected-report.json"
    recover_command = [sys.executable, "-m", "tools.policy_chaos", "fault", "recover",
                       "--run-id", run_id, "--config-dir", str(config),
                       "--state-dir", str(state), "--observation", str(observation),
                       "--cut-record", str(cut_record), "--output", str(rejected_report),
                       "--confirm-disposable-vm"]

    for checkpoint in ([], {}):
        invalid_manifest = tmp_path / f"invalid-checkpoint-{type(checkpoint).__name__}.json"
        invalid_manifest.write_text(json.dumps({"version": 1, "checkpoint": checkpoint}))
        command = ready_command.copy()
        command[command.index("--manifest") + 1] = str(invalid_manifest)
        rejected = subprocess.run(command, cwd=REPO, env=environment,
                                  text=True, capture_output=True, timeout=10)
        assert rejected.returncode == 2 and "INCOMPLETE" in rejected.stderr, rejected.stderr

    fifo = tmp_path / "unopened-fifo"
    os.mkfifo(fifo)
    oversized = tmp_path / "oversized-input"
    oversized.write_bytes(b"x" * (VM_INPUT_LIMIT + 1))
    deeply_nested = tmp_path / "deeply-nested-input"
    deeply_nested.write_bytes(b"[" * 20000 + b"0" + b"]" * 20000)
    linked = tmp_path / "linked-input"
    linked.symlink_to(observation)
    for unsafe, expected_error in ((Path("/dev/full"), "not a regular file"),
                                   (fifo, "not a regular file"),
                                   (oversized, "exceeds 1 MiB"),
                                   (deeply_nested, "too deeply nested"),
                                   (linked, "Too many levels of symbolic links")):
        for command, flag in ((ready_command, "--manifest"),
                              (ready_command, "--observation"),
                              (recover_command, "--observation"),
                              (recover_command, "--cut-record")):
            attempt = command.copy()
            attempt[attempt.index(flag) + 1] = str(unsafe)
            rejected = subprocess.run(attempt, cwd=REPO, env=environment,
                                      text=True, capture_output=True, timeout=10)
            assert rejected.returncode == 2 and "INCOMPLETE" in rejected.stderr and \
                   expected_error in rejected.stderr, (
                flag, unsafe, rejected.stderr,
            )
            assert not rejected_report.exists()
