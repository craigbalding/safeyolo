"""Finite observer/input regressions; no managed guest or installed runtime."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HOST = REPO / "tests/blackbox/host"
spec = importlib.util.spec_from_file_location("guest_maintenance_probe", HOST / "guest_maintenance.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def run(*words, check=True):
    return subprocess.run(words, capture_output=True, text=True, check=check, timeout=30)


def tree(tmp_path):
    root = tmp_path / "rootfs-tree"
    for path in ("usr/bin", "usr/local/bin", "usr/local/lib/safeyolo", "usr/share/safeyolo/guest-base",
                 "etc/apt/sources.list.d", "var/lib/apt/lists/partial", "var/lib/dpkg", "var/log"):
        (root / path).mkdir(parents=True, exist_ok=True)
    for path in ("usr/bin/etckeeper", "usr/bin/git", "usr/bin/dpkg", "usr/bin/dpkg-deb",
                 "usr/local/bin/safeyolo-guest-state", "usr/local/lib/safeyolo/guest-state-hook"):
        (root / path).write_text("#!/bin/sh\n")
        (root / path).chmod(0o755)
    (root / "var/lib/dpkg/status").write_text("")
    (root / "usr/share/safeyolo/guest-base/packages.tsv").write_text("")
    return root


def package(tmp_path, version="2.0"):
    path = tmp_path / f"package-{version}"
    (path / "DEBIAN").mkdir(parents=True)
    (path / "DEBIAN/control").write_text(
        f"Package: sy-maintenance-fixture\nVersion: {version}\nArchitecture: all\n"
        "Maintainer: Probe <probe@invalid>\nDescription: disposable maintenance witness\n")
    payload = path / "usr/share/safeyolo-maintenance-fixture/version"
    payload.parent.mkdir(parents=True)
    payload.write_text(version)
    (path / "DEBIAN/md5sums").write_text(run("md5sum", str(payload)).stdout.replace(str(path) + "/", ""))
    archive = tmp_path / f"{version}.deb"
    run("dpkg-deb", "--root-owner-group", "--build", str(path), str(archive))
    return archive


@pytest.mark.parametrize("cache", [None, "directory", "symlink", "", "/var/cache/apt\n"])
def test_cache_list_is_required_before_copy(tmp_path, cache):
    tree(tmp_path)
    path = tmp_path / "cache-paths.txt"
    if cache == "directory":
        path.mkdir()
    elif cache == "symlink":
        (tmp_path / "real-cache").write_text("")
        path.symlink_to("real-cache")
    elif cache is not None:
        path.write_text(cache)
    output = tmp_path / "output"
    result = run("bash", str(HOST / "prepare_guest_maintenance_inputs.sh"),
                 str(tmp_path), str(output), check=False)
    if cache in (None, "directory", "symlink"):
        assert result.returncode and "regular cache-paths.txt" in result.stderr
        assert not output.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert (output / "cache-paths.txt").read_text() == cache


@pytest.mark.parametrize("fixed", [False, True])
def test_offline_apt_candidate_precedes_restore_and_fixed_base_is_real(tmp_path, fixed):
    root, archive = tree(tmp_path), package(tmp_path)
    options = ("--fixed-base",) if fixed else ()
    result = run("bash", str(HOST / "prepare_guest_maintenance_apt.sh"),
                 str(root), str(archive), *options)
    assert "Candidate: 2.0" in result.stdout
    # No apt-get update, external source, restore, or live guest is needed for
    # this policy lookup: the candidate already exists in the copied input.
    policy = run("apt-cache", "-o", f"Dir={root}", "-o",
                 f"Dir::State::status={root}/var/lib/dpkg/status", "policy", probe.PACKAGE).stdout
    assert "Candidate: 2.0" in policy
    inventory = (root / "usr/share/safeyolo/guest-base/packages.tsv").read_text()
    if fixed:
        assert "sy-maintenance-fixture\t2.0\tall\tii \n" in inventory
        assert (root / probe.PAYLOAD.lstrip("/")).read_text() == "2.0"
        assert run("dpkg-query", f"--admindir={root}/var/lib/dpkg", "-W", "-f=${Version}", probe.PACKAGE).stdout == "2.0"
    else:
        assert inventory == "" and not (root / probe.PAYLOAD.lstrip("/")).exists()
    before = (root / "var/lib/dpkg/status").read_bytes()
    repeated = run("bash", str(HOST / "prepare_guest_maintenance_apt.sh"),
                   str(root), str(archive), *options, check=False)
    assert repeated.returncode and "instead of replaying" in repeated.stderr
    assert (root / "var/lib/dpkg/status").read_bytes() == before


def test_fixed_base_preparation_does_not_downgrade_a_satisfactory_package(tmp_path):
    root = tree(tmp_path)
    archive, newer = package(tmp_path), package(tmp_path, "3.0")
    run("dpkg", f"--root={root}", "--force-not-root", "--install", str(newer))
    result = run("bash", str(HOST / "prepare_guest_maintenance_apt.sh"),
                 str(root), str(archive), "--fixed-base")
    assert "already supplies a satisfactory package: 3.0" in result.stdout
    assert (root / probe.PAYLOAD.lstrip("/")).read_text() == "3.0"
    assert "sy-maintenance-fixture\t3.0\tall\tii \n" in (
        root / "usr/share/safeyolo/guest-base/packages.tsv").read_text()


def test_prepared_apt_candidate_drives_real_native_restore_preview(tmp_path):
    helper = os.environ.get("SAFEYOLO_RETAINED_STATE_HELPER")
    if not helper or not shutil.which("etckeeper"):
        pytest.skip("existing candidate helper and etckeeper required")
    root, archive = tree(tmp_path), package(tmp_path)
    for path in ("usr/local/etc", "var/lib/apt", "var/cache/apt/archives/partial", "var/log/apt"):
        (root / path).mkdir(parents=True, exist_ok=True)
    (root / "etc/os-release").write_text("ID=debian\nVERSION_CODENAME=trixie\n")
    baseline = root / "usr/share/safeyolo/guest-base/configuration"
    shutil.copytree(root / "etc", baseline / "etc")
    (baseline / "usr/local/etc").mkdir(parents=True)
    directory = tmp_path / "retained"
    command = [helper, "retained-state", "--instance-dir", str(root), "--directory", str(directory)]
    run(*command, "start")
    state_path = directory / "state.json"
    state = json.loads(state_path.read_text())
    state["requirements"] = {probe.PACKAGE: {"distribution": "debian:trixie", "operator": "ge", "version": "2.0"}}
    state_path.write_text(json.dumps(state))
    assert run(*command, "restore", check=False).returncode != 0
    run("bash", str(HOST / "prepare_guest_maintenance_apt.sh"), str(root), str(archive))
    run(*command, "restore")
    restored = json.loads(state_path.read_text())["restore"]
    assert restored["package_blockers"] == [] and restored["installs"] == [probe.PACKAGE + "=2.0"]
    assert restored["applied"] is False


def m2_binding():
    # Actual operator readback schema and recorded identity. It intentionally
    # omits the native result's flat fields and full private retained state.
    root, agent, run_id, base = "/owned/m1611", "ag-m1611", "prior-run", "old-base"
    state = {"base_id": base, "actual_base_id": base, "status": "captured", "capture_error": None,
             "reconcile_required": False, "configuration_commit": "capture",
             "requirements": {probe.PACKAGE: {"distribution": "debian:trixie", "operator": "ge",
                              "version": "2.0", "advisory": "q1611/advisories.q1611-maintenance"}}}
    return {"results": {"retained_native_M2": {"binding": {"outcome": "passed"},
                    "advisory": {"source_id": "q1611", "id": "advisories.q1611-maintenance",
                                 "revision": 1, "observed_at": 10, "expires_at": 20}}},
            "native_report_identity_projection": {
                "raw_file_bytes": 44001, "raw_file_sha256": "0" * 64,
                "root_from_assessment_request": root,
                "runtime": {"agent_id": agent, "run_id": run_id},
                "context": {"agent_id": agent, "generation": run_id, "host_package": root},
                "retained_before": copy.deepcopy(state), "retained_after": state}}


@pytest.mark.parametrize("phase,base", [("restored", "old-base"), ("fixed", "later-base")])
def test_current_native_binding_receipt_can_continue_without_replaying_patch(phase, base):
    prior = m2_binding()
    original = copy.deepcopy(prior)
    advisory = probe.prior_binding(prior, Path("/owned/m1611"), "ag-m1611", "new-run", base, phase)
    current = probe.current_advisory(advisory, [], 100)
    assert current["revision"] == 2 and current["observed_at"] == 100
    assert current["evidence"]["subject"]["fixed_version"] == "2.0"
    assert prior == original and advisory["expires_at"] == 20


@pytest.mark.parametrize("fault", ["failed", "agent", "root", "same-run", "base", "reconcile", "requirement"])
def test_native_binding_refuses_failed_or_mismatched_prior(fault):
    prior = m2_binding()
    projection = prior["native_report_identity_projection"]
    if fault == "failed":
        prior["results"]["retained_native_M2"]["binding"]["outcome"] = "failed"
    elif fault == "agent":
        projection["runtime"]["agent_id"] = "other"
    elif fault == "root":
        projection["root_from_assessment_request"] = "/other"
    elif fault == "same-run":
        projection["runtime"]["run_id"] = projection["context"]["generation"] = "new-run"
    elif fault == "base":
        projection["retained_after"]["actual_base_id"] = "other"
    elif fault == "reconcile":
        projection["retained_after"]["reconcile_required"] = True
    else:
        projection["retained_after"]["requirements"][probe.PACKAGE]["version"] = "1.0"
    with pytest.raises(AssertionError):
        probe.prior_binding(prior, Path("/owned/m1611"), "ag-m1611", "new-run", "old-base", "restored")


def test_fresh_revision_preserves_constraint_and_uses_current_revision():
    previous = probe.current_advisory(None, [], 10)
    accepted = {**previous, "revision": 7}
    current = probe.current_advisory(previous, [{"evidence": accepted}], 10000)
    assert current["revision"] == 8 and current["evidence"] == previous["evidence"]
    assert previous["observed_at"] == 10 and previous["expires_at"] == 3610
    previous["evidence"]["subject"]["fixed_version"] = "3.0"
    with pytest.raises(AssertionError, match="adopted constraint"):
        probe.current_advisory(previous, [], 10000)


@pytest.mark.parametrize("version,expected", [("1.0", True), ("2.0", False), ("2.1", False), ("3.0", False)])
def test_restored_satisfactory_versions_do_not_require_another_patch(version, expected):
    assert probe.needs_patch(version) is expected


@pytest.mark.parametrize("phase,version,unavailable,provided", [
    ("restored", "1.0", False, True), ("restored", "2.0", False, True), ("restored", "3.0", False, True),
    ("fixed", "2.0", False, True), ("fixed", "3.0", False, True), ("restored", "2.0", True, True),
    ("fixed", "2.0", False, False)])
def test_complete_driver_consumes_current_run_and_stopped_prior_result(
        tmp_path, monkeypatch, phase, version, unavailable, provided):
    root, rootfs = tmp_path / "instance", tmp_path / "rootfs"
    agent = root / "agents/m"
    (agent / "config-share").mkdir(parents=True)
    rootfs.mkdir()
    (root / "q1611-inputs").mkdir()
    (agent / "runtime.json").write_text(json.dumps(
        {"agent_id": "ag-m1611", "run_id": "current-run", "state": "running"}))
    (agent / "config-share/host-launch-context.json").write_text(json.dumps(
        {"agent_id": "ag-m1611", "generation": "current-run"}))
    (agent / "config.json").write_text(json.dumps({"root": {"path": str(rootfs)}}))
    (root / "policy.toml").write_text("[agents.m]\nrootfs_overlay='file'\n")
    (root / "signals.toml").write_text(
        "[sources.advisories]\nsource_id='q1611'\nbucket='q1611'\n"
        "endpoint={mode='loopback',url='nats://127.0.0.1:1234'}\n"
        f"credential_file={json.dumps(str(root / 'data/coord/nats/creds'))}\n[rules.packages]\n")
    prior = m2_binding()
    projection = prior["native_report_identity_projection"]
    projection["root_from_assessment_request"] = projection["context"]["host_package"] = str(root)
    # The original operator readback records stopped state, while this boot's
    # runtime/status is current. File presence does not select the old run.
    prior["results"]["current_runtime"] = {"state": "stopped", "run_id": "prior-run"}
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(json.dumps(prior))
    base = "old-base" if phase == "restored" else "later-base"
    state = {"actual_base_id": base, "baseline_known": True, "last_completed_capture": 100,
             "configuration_commit": "captured", "capture_error": None,
             "requirements": projection["retained_after"]["requirements"]}
    observed = {"version": version, "count": 1, "assessed": False, "advisory": None}
    original_run = subprocess.run

    def fake_run(words, **kwargs):
        if words[0] == "dpkg":
            return original_run(words, **kwargs)
        action = words[3:]
        output = ""
        if action[:2] == ["agent", "status"]:
            output = json.dumps({"agent_id": "ag-m1611", "run_id": "current-run", "exec": True})
        elif action[:2] == ["agent", "shell"]:
            script = words[-1]
            if "safeyolo-guest-state status" in script:
                output = json.dumps(state)
            elif "--version" in script:
                output = "commit=fixture profile=debug"
            elif "sha256sum" in script:
                output = "hook  guest-state-hook"
            elif "dpkg-query" in script:
                output = observed["version"]
            elif "packages.tsv" in script:
                output = f"sy-maintenance-fixture\t{version}\tall\tii \n" if provided else ""
            elif "wc -l" in script:
                output = str(observed["count"])
            elif f"cat {probe.PAYLOAD}" in script:
                output = observed["version"]
            elif "cat " in script:
                output = "ag-m1611"
        elif action[:2] == ["coord", "status"]:
            output = json.dumps({"process": {"client_port": 1234}})
        elif action[:2] == ["signals", "publish"]:
            observed["advisory"] = json.loads(Path(words[-1]).read_text())
        elif action[:2] == ["signals", "assess"]:
            observed["assessed"] = True
            if probe.needs_patch(observed["version"]) and not unavailable:
                observed.update(version="2.0", count=2)
            output = json.dumps({"request": {"request_id": "current-request"}})
        elif action[:2] == ["signals", "status"]:
            responses = []
            if observed["assessed"]:
                responses.append({"rule": "packages", "agent": "m",
                    "response": {"status": "unavailable" if unavailable else "verified"},
                    "selection": {"run": {"run_id": "current-run"},
                        "inventory": {"request_id": "current-request"},
                        "applicability": "unknown_or_stale" if unavailable else "unaffected",
                        "next_action": "Resolve unavailable evidence."}})
            output = json.dumps({"sources": {"advisories": {"accepted":
                [{"evidence": observed["advisory"]}] if observed["advisory"] else []}},
                "responses": responses})
        return subprocess.CompletedProcess(words, 0, output, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: "commit=fixture profile=debug")
    output = tmp_path / "result.json"
    monkeypatch.setattr("sys.argv", [str(HOST / "guest_maintenance.py"), "--instance-dir", str(root),
        "--agent", "m", "--agent-id", "ag-m1611", "--run-id", "current-run", "--commit", "fixture",
        "--hook-sha256", "hook", "--root-kind", "stock", "--rootfs", str(rootfs),
        "--base-id", base, "--overlay", "file", "--phase", phase, "--prior-result", str(prior_path),
        "--output", str(output)])
    if not provided:
        with pytest.raises(AssertionError, match="later base inventory"):
            probe.main()
        assert json.loads(output.read_text())["outcome"] == "failed"
        assert observed["assessed"] is False
        return
    probe.main()
    result = json.loads(output.read_text())
    assert result["outcome"] == ("unavailable" if unavailable else "passed")
    assert result["prior_advisory"]["expires_at"] == 20
    assert result["advisory"]["expires_at"] > result["started_at"]
    if not unavailable:
        assert result["applied_after"] == (2 if version == "1.0" else 1)
    assert json.loads(prior_path.read_text()) == prior
