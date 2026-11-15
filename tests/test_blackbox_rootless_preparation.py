"""Challenge retained Linux evidence selection without repeating native effects."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from tests.blackbox import rootless_preparation as rootless

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "a" * 40


@pytest.mark.parametrize("sudo_attempt", [False, True])
def test_executable_fixture_reuses_preparation_and_detects_unavailable_sudo(tmp_path, monkeypatch, sudo_attempt):
    from tests import test_guest_acquisition as acquisition

    prepared = tmp_path / "prepared"
    (prepared / "bin").mkdir(parents=True)
    cli = prepared / "bin/safeyolo"
    cli.touch()
    (prepared / "config.toml").write_text(
        f"[linux]\nhost_uid={os.getuid()}\nhost_gid={os.getgid()}\nuid_base=100000\ngid_base=100000\n")
    monkeypatch.setenv("SAFEYOLO_NATIVE_CLI", str(cli))
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_ROOTLESS", "1")
    monkeypatch.setenv("SAFEYOLO_ROOTLESS_PREPARED_CONFIG", str(prepared))
    assert acquisition.native_cli.__wrapped__() == cli
    fixture = acquisition.registry.__wrapped__(tmp_path, cli)
    *_unused, environment = next(fixture)
    assert environment["SAFEYOLO_TEST_NAMESPACE_ROOT"] == str(prepared)
    assert not (prepared / "host").exists()  # Preparation is reused, never created here.
    if sudo_attempt:
        result = subprocess.run(["sudo", "-n", "true"], env=environment, capture_output=True)
        assert result.returncode == 93
        with pytest.raises(AssertionError, match="candidate attempted unavailable sudo"):
            next(fixture)
    else:
        with pytest.raises(StopIteration):
            next(fixture)


@pytest.mark.parametrize("collect_only", [False, True])
def test_executable_shell_selector_cannot_pass_without_prepared_inputs(tmp_path, collect_only):
    output = tmp_path / "phase.json"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("SAFEYOLO_ROOTLESS_")}
    env.update(SAFEYOLO_NATIVE_CLI=str(tmp_path / "missing-cli"), SAFEYOLO_BLACKBOX_RUN_ID="rootless-missing")
    result = subprocess.run([str(ROOT / "tests/blackbox/run-controls.sh"), "rootless-preparation", "--execute",
                             "--output", str(output), "--", "-q", *(["--collect-only"] if collect_only else [])],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    report = json.loads(output.read_text())
    assert result.returncode != 0 and report["complete"] is False, result.stdout + result.stderr
    assert report["boundary"] == "installed-cli/native-kernel" and report["control_complete"] is False
    assert report["run_id"] == "rootless-missing" and len(report["selected"]) >= 29
    assert report["problems"]


@pytest.fixture
def source():
    """Match the fields produced by installed_storage and the execution owner."""
    selection = {
        "repository": "owned",
        "compatibility": "current",
        "platform": "linux/amd64",
        "index": {"digest": "sha256:" + "b" * 64},
        "manifest": {"digest": "sha256:" + "c" * 64},
        "archive": {"digest": "sha256:" + "d" * 64, "size": 42},
    }
    files = {
        name: {
            "uid": 100000 if name.endswith("root") else 1000,
            "gid": 100000 if name.endswith("root") else 1000,
            "mode": 0o644,
            "inode": index,
        }
        for index, name in enumerate(("home-agent", "home-root", "workspace-agent", "workspace-root"))
    }
    state = {
        "selection": selection,
        "guest_inputs": {"rootfs-tree": {"device": 1, "inode": 2}, "cache-paths.txt": {"device": 1, "inode": 3}},
    }
    result = {
        "controller_source": CANDIDATE,
        "package": {
            "source_commit": CANDIDATE,
            "platform": "linux-amd64",
            "profile": "production",
            "guest_repository": "owned",
            "guest_compatibility": "current",
        },
        "selection": selection,
        "archive": {"sha256": "d" * 64, "bytes": 42},
        "linux_settings": {
            "host_uid": 1000,
            "host_gid": 1000,
            "uid_base": 100000,
            "gid_base": 100000,
            "apparmor_profile": "prepared-entry",
        },
        "uid": 1000,
        "mapped_root": {"uid": 100000, "gid": 100000},
        "actions": [
            {"label": label, "command": ["recorded-command"], "exit": 0, "started": index, "ended": index + 0.5}
            for index, label in enumerate(rootless.STORAGE_ACTIONS)
        ],
        "guest_execution": {"exit_code": 0, "timed_out": False, "stdout_truncated": False, "stderr_truncated": False},
        "cache_operands": [
            {"phase": phase, "before": state, "after": state} for phase in ("repeat", "explicit-cached-upgrade")
        ],
        "initial-host-files": files,
        "restart-host-files": files,
        "operator_setup": {
            "post_prepare_sudo_attempts_successful_run": False,
            "original_attempt": 10,
            "first_failure": "retained original failure",
            "successful_resume": 12,
        },
        "result": "storage_passed",
        "cleanup_failures": [],
        "execution": {"execution": 12},
    }
    for phase in ("initial", "restart"):
        for user, uid in (("agent", 1000), ("root", 0)):
            result[phase + "-" + user] = {
                "uid": uid,
                "overlay_present": phase == "initial" and user == "root",
                "files": {
                    ("/home/agent/marker-" if name.startswith("home") else "/workspace/marker-") + owner: {
                        "uid": 0 if owner == "root" else 1000,
                        "gid": 0 if owner == "root" else 1000,
                        "mode": 0o644,
                    }
                    for name in files
                    for owner in [name.split("-", 1)[1]]
                    if phase == "restart" or owner == user
                },
            }
    # Independent decoded records prevent a mutation from editing before/after together.
    return json.loads(json.dumps(result))


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "revision",
        "profile",
        "execution-id",
        "platform",
        "archive",
        "prerequisite",
        "root-mapping",
        "missing-action",
        "duplicate-action",
        "failed-action",
        "boolean-exit",
        "unfinished-action",
        "timeout",
        "truncated",
        "missing-repeat",
        "changed-index",
        "wrong-cache-guest",
        "changed-inode",
        "missing-cache",
        "lost-host-file",
        "changed-host-file",
        "wrong-host-owner",
        "wrong-guest-owner",
        "lost-guest-file",
        "changed-guest-path",
        "malformed-guest-files",
        "wrong-guest-uid",
        "retained-overlay",
        "sudo",
        "sudo-unknown",
        "cleanup",
        "false-success",
        "malformed",
    ],
)
def test_retained_operands_cannot_hide_missing_or_failed_obligations(source, defect):
    if defect == "revision":
        source["package"]["source_commit"] = "e" * 40
    elif defect == "profile":
        del source["package"]["profile"]
    elif defect == "execution-id":
        del source["execution"]["execution"]
    elif defect == "platform":
        source["selection"]["platform"] = "darwin/arm64"
    elif defect == "archive":
        source["archive"]["bytes"] += 1
    elif defect == "prerequisite":
        del source["linux_settings"]["apparmor_profile"]
    elif defect == "root-mapping":
        source["mapped_root"]["gid"] += 1
    elif defect == "missing-action":
        source["actions"].pop()
    elif defect == "duplicate-action":
        source["actions"][1] = source["actions"][0]
    elif defect == "failed-action":
        source["actions"][6]["exit"] = 1
    elif defect == "boolean-exit":
        source["actions"][6]["exit"] = False
    elif defect == "unfinished-action":
        del source["actions"][6]["ended"]
    elif defect == "timeout":
        source["guest_execution"]["timed_out"] = True
    elif defect == "truncated":
        source["guest_execution"]["stdout_truncated"] = True
    elif defect == "missing-repeat":
        source["cache_operands"].pop(0)
    elif defect == "changed-index":
        source["cache_operands"][1]["after"]["selection"]["index"] = {}
    elif defect == "wrong-cache-guest":
        for position in ("before", "after"):
            source["cache_operands"][0][position]["selection"]["archive"] = {}
    elif defect == "changed-inode":
        source["cache_operands"][0]["after"]["guest_inputs"]["rootfs-tree"]["inode"] += 1
    elif defect == "missing-cache":
        del source["cache_operands"][0]["after"]["guest_inputs"]["cache-paths.txt"]
    elif defect == "lost-host-file":
        del source["initial-host-files"]["home-root"]
    elif defect == "changed-host-file":
        source["restart-host-files"]["home-root"]["inode"] += 1
    elif defect == "wrong-host-owner":
        for phase in ("initial", "restart"):
            source[phase + "-host-files"]["home-root"]["uid"] = 0
    elif defect == "wrong-guest-owner":
        next(iter(source["restart-root"]["files"].values()))["uid"] = 12
    elif defect == "lost-guest-file":
        source["initial-agent"]["files"].popitem()
    elif defect == "changed-guest-path":
        files = source["restart-agent"]["files"]
        path, value = next(iter(files.items()))
        del files[path]
        files[path.replace("marker", "another-marker")] = value
    elif defect == "malformed-guest-files":
        source["initial-agent"]["files"] = ["home", "workspace"]
    elif defect == "wrong-guest-uid":
        source["restart-root"]["uid"] = 1000
    elif defect == "retained-overlay":
        source["restart-root"]["overlay_present"] = True
    elif defect == "sudo":
        source["operator_setup"]["post_prepare_sudo_attempts_successful_run"] = True
    elif defect == "sudo-unknown":
        del source["operator_setup"]["post_prepare_sudo_attempts_successful_run"]
    elif defect == "cleanup":
        source["cleanup_failures"] = ["survivor"]
    elif defect == "false-success":
        source["result"] = "incomplete"
    elif defect == "malformed":
        source["actions"] = None
    observed = []
    if defect:
        with pytest.raises((ValueError, KeyError, TypeError)):
            rootless.observe(source, CANDIDATE, observed)
        assert observed != list(rootless.CASES)
    else:
        rootless.observe(source, CANDIDATE, observed)
        assert observed == list(rootless.CASES)


@pytest.mark.parametrize(
    "damage",
    [None, "digest", "candidate", "missing", "malformed", "cleanup", "overwrite", "overwrite-temp",
     "symlink-temp", "hardlink-temp"],
)
def test_shell_selector_reads_pinned_evidence_without_executing_it(tmp_path, source, damage):
    marker = tmp_path / "must-not-execute"
    source["actions"][0]["command"] = ["touch", str(marker)]
    if damage == "cleanup":
        source["cleanup_failures"] = ["survivor"]
    if damage == "malformed":
        source["linux_settings"] = None
    path = tmp_path / "source.json"
    path.write_text(json.dumps(source))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    original = path.read_bytes()
    output = path if damage == "overwrite" else tmp_path / "observed.json"
    if damage == "overwrite-temp":
        path = output.with_suffix(output.suffix + ".tmp")
        path.write_bytes(original)
    elif damage == "symlink-temp":
        output.with_suffix(output.suffix + ".tmp").symlink_to(path)
    elif damage == "hardlink-temp":
        output.with_suffix(output.suffix + ".tmp").hardlink_to(path)
    if damage == "missing":
        path.unlink()
    command = [
        str(ROOT / "tests/blackbox/run-controls.sh"),
        "rootless-preparation",
        "--source-report",
        str(path),
        "--source-sha256",
        "0" * 64 if damage == "digest" else digest,
        "--install-commit",
        "f" * 40 if damage == "candidate" else CANDIDATE,
        "--output",
        str(output),
    ]
    result = subprocess.run(
        command,
        env={**os.environ, "SAFEYOLO_BLACKBOX_RUN_ID": "observer-control"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert (result.returncode == 0) == (damage is None), result.stdout + result.stderr
    assert not marker.exists()
    if damage in {"overwrite", "overwrite-temp", "symlink-temp", "hardlink-temp"}:
        assert result.returncode == 2
        assert "output would overwrite source evidence" in result.stderr
        assert path.read_bytes() == original
        return
    report = json.loads(output.read_text())
    assert report["complete"] == (damage is None) and report["control_complete"] is False
    assert report["remaining"] == list(rootless.REMAINING) and report["run_id"] == "observer-control"
    if damage:
        assert report["observer_error"]
    else:
        assert report["selected"] == report["observed"] == list(rootless.CASES)
        assert report["source_observation"] == source and report["candidate"] == CANDIDATE
        assert report["source_sha256"] == digest and report["boundary"] == "retained-native-linux-storage"
