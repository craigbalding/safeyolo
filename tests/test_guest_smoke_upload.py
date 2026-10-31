"""Exercise retained report transfer and its separate Actions upload origin."""

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import guest_release as release
from tests.test_guest_promotion import INDEX, candidate, evidence, report_files

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
JOB = WORKFLOW["jobs"]["record-smoke"]
NAMES = ("selection.json", "retained-run.json", "installed-inputs.json", "guest/installed-sections.json")
GATE = "https://github.com/craigbalding/safeyolo/issues/1105#issuecomment-123"


def continuation_files(reports):
    """Use the producer shape in the retained AMD64 installed-9af-d0ee observation."""
    frozen = json.loads((reports / "selection.json").read_bytes())
    installed = json.loads((reports / "installed-inputs.json").read_bytes())
    frozen["platform"] = installed["platform"] = "linux-amd64"
    frozen["host"].update(platform="linux-amd64", profile="production", archive={"sha256": "c" * 64})
    frozen["controller_revision"] = "e" * 40
    prepared = "/b/package/prepared"
    original_sections = {"source_revision": frozen["host"]["source_revision"], "lane": "systrap",
                         "preparation": {"exit": 0, "config_dir": prepared, "reused_installation": True},
                         "sections": [{"section": section, "config_dir": f"/b/original/{section}",
                                       "prepared_config_dir": prepared, "exit": 0, "result": "passed",
                                       "cleanup": "stopped", "cleanup_failures": []}
                                      for section in ("isolation", "workloads", "access", "lifecycle", "continuity")]}
    resumed_sections = copy.deepcopy(original_sections)
    resumed_sections["sections"] = [resumed_sections["sections"][-1]]
    resumed_sections["sections"][0]["config_dir"] = "/b/resumed/continuity"
    original_sections["sections"][-1].update(exit=2, result="preparation_failure", error="Missing controller interpreter")
    observed = {"controller": {"revision": "e" * 40, "dirty": False},
                "original_execution": {"id": 1, "command": ["python", "/b/controller/tests/blackbox/retained_inputs.py",
                    "run", "--lane", "systrap", "--selection", "/b/inputs/selection.json"], "exit": 2,
                    "started_at": "2026-10-17T19:00:00Z", "ended_at": "2026-10-17T19:01:00Z"},
                "resume_execution": {"id": 2, "command": ["python", "/b/controller/tests/blackbox/installed_sections.py",
                    "systrap", "--section", "continuity", "--prepared-config", prepared,
                    "--install-commit", frozen["host"]["source_revision"]], "exit": 0, "controller_status": "",
                    "started_at": "2026-10-17T19:02:00Z", "ended_at": "2026-10-17T19:03:00Z"},
                "recorded_at": "2026-10-17T19:05:00Z",
                "verified_operands": {"host": "installed-amd64-host", "observed_at": "2026-10-17T19:04:00Z",
                    "installed_inputs": installed, "original_sections": original_sections, "resumed_sections": resumed_sections,
                    "owned_live_markers": [], "live_product_processes": [], "continuity_runtime_after": [{"pid_exists": False}],
                    "report_hashes": {name: hashlib.sha256(json.dumps(value).encode()).hexdigest() for name, value in (
                        ("reports/installed-inputs.json", installed), ("reports/guest/installed-sections.json", original_sections),
                        ("continuity-reports/installed-sections.json", resumed_sections))}}}
    (reports / "selection.json").write_text(json.dumps(frozen))
    for name in NAMES[1:]:
        (reports / name).unlink()
    (reports / "installed-continuation.json").write_text(json.dumps(observed))
    return observed


def restore(tmp_path, texts):
    step = next(step for step in JOB["steps"] if step.get("name") == "Restore retained report files")
    assert step["env"] == {"SMOKE_REPORTS": "${{ inputs.smoke_reports }}"}
    assert "${{" not in step["run"]
    return subprocess.run(["bash", "-e", "-c", step["run"]], cwd=ROOT,
                          env={**os.environ, "RUNNER_TEMP": str(tmp_path), "SMOKE_REPORTS": json.dumps(texts)},
                          capture_output=True, text=True, timeout=10)


def test_workflow_restores_original_bytes_without_executing_report_text(tmp_path):
    reports = tmp_path / "original"
    report_files(reports)
    original = {}
    for name in NAMES:
        # Valid JSON with shell metacharacters, Unicode, CRLF and extra space.
        value = json.loads((reports / name).read_bytes())
        value["note"] = "$(touch injected) `touch injected` ' \" café"
        original[name] = (json.dumps(value, ensure_ascii=False, indent=2) + "\r\n \n").encode()
    inputs = {name: raw.decode("utf-8") for name, raw in original.items()}
    # Exercise the same two nested JSON documents sent by gh --json.
    inputs = json.loads(json.loads(json.dumps({"smoke_reports": json.dumps(inputs)}))["smoke_reports"])
    result = restore(tmp_path, inputs)
    assert result.returncode == 0, result.stderr
    restored = tmp_path / "retained-reports"
    assert {name: (restored / name).read_bytes() for name in NAMES} == original
    assert release.smoke_result(restored, GATE) == release.smoke_result(reports, GATE)
    assert not (ROOT / "injected").exists() and not (tmp_path / "injected").exists()


def test_workflow_restores_continuation_without_rewriting_failed_execution(tmp_path):
    reports = tmp_path / "original"
    report_files(reports)
    observed = continuation_files(reports)
    texts = {name: (reports / name).read_bytes().decode() for name in release.CONTINUATION_REPORTS}
    result = restore(tmp_path, texts)
    assert result.returncode == 0, result.stderr
    restored = tmp_path / "retained-reports"
    assert {name: (restored / name).read_bytes().decode() for name in texts} == texts
    smoke = release.smoke_result(restored, GATE)
    assert smoke["result"] == "passed" and smoke["execution_mode"] == "same-installation-continuation"
    assert smoke["executions"] == {"original": observed["original_execution"], "resume": observed["resume_execution"]}
    assert smoke["executions"]["original"]["exit"] == 2
    assert smoke["finished_at"] == observed["resume_execution"]["ended_at"]
    assert not (restored / "retained-run.json").exists()


@pytest.mark.parametrize("texts", [None, [], {}, {name: {} for name in NAMES},
                                    {**dict.fromkeys(NAMES, "{}"), "../escape": "{}"},
                                    {**dict.fromkeys(release.CONTINUATION_REPORTS, "{}"), "../escape": "{}"},
                                    {**dict.fromkeys(NAMES, "{}"), "installed-continuation.json": "{}"}])
def test_workflow_refuses_incomplete_or_nontext_report_inputs(tmp_path, texts):
    assert restore(tmp_path, texts).returncode != 0
    assert not (tmp_path / "retained-reports").exists()


@pytest.mark.parametrize("event,ref,activity,expected", [
    ("workflow_dispatch", "refs/heads/master", "record-smoke", {"record-smoke"}),
    ("workflow_dispatch", "refs/heads/feature", "record-smoke", set()),
    ("pull_request", "refs/heads/master", "record-smoke", set()),
    ("workflow_dispatch", "refs/heads/master", "promote", {"promote"}),
    ("workflow_dispatch", "refs/heads/master", "build-stage", {"resolve"}),
    ("workflow_dispatch", "refs/heads/master", "inspect", {"inspect"}),
    ("workflow_dispatch", "refs/heads/feature", "inspect", set()),
    ("pull_request", "refs/heads/master", "inspect", set()),
    ("workflow_dispatch", "refs/heads/master", "custom-profile", {"custom-profile"}),
    ("workflow_dispatch", "refs/heads/feature", "custom-profile", set()),
    ("pull_request", "refs/heads/master", "custom-profile", set()),
])
def test_upload_activity_selects_only_the_upload_job(event, ref, activity, expected):
    github = SimpleNamespace(event_name=event, ref=ref, event=SimpleNamespace(
        schedule="", repository=SimpleNamespace(default_branch="master")))
    inputs = SimpleNamespace(activity=activity)
    selected = set()
    for name, job in WORKFLOW["jobs"].items():
        if "if" in job:
            # These guards use only string equality, format, AND and OR.
            expression = job["if"].removeprefix("${{").removesuffix("}}")
            expression = expression.replace("&&", " and ").replace("||", " or ")
            if eval(expression, {"__builtins__": {}, "format": str.format}, {"github": github, "inputs": inputs}):
                selected.add(name)
    assert selected == expected
    # Actions skips each dependent job when resolve is skipped.
    assert WORKFLOW["jobs"]["build"]["needs"] == "resolve"
    assert WORKFLOW["jobs"]["stage"]["needs"] == ["resolve", "build"]
    assert WORKFLOW["jobs"]["receipt"]["needs"] == "stage"
    assert "needs" not in JOB
    assert JOB["permissions"] == {"contents": "read", "actions": "read", "packages": "write"}
    commands = "\n".join(step.get("run", "") for step in JOB["steps"])
    assert "cargo" not in commands and "retained_inputs.py" not in commands and "--promote" not in commands


def test_inspection_activity_is_read_only_and_retains_its_result():
    job = WORKFLOW["jobs"]["inspect"]
    assert job["permissions"] == {"contents": "read", "actions": "read", "packages": "read"}
    assert "needs" not in job
    step = next(step for step in job["steps"] if step.get("name") == "Read the retained promotion decision")
    assert step["env"] == {"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}", "PROMOTION_JOB": "${{ inputs.promotion_job }}"}
    assert step["shell"] == "bash" and "${{" not in step["run"]
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "cargo" not in commands and "--promote" not in commands and "--record-smoke" not in commands
    retained = next(step for step in job["steps"] if step.get("with", {}).get("name") == "guest-promotion-inspection")
    assert retained["if"] == "always()" and retained["with"]["path"] == "${{ runner.temp }}/guest-inspection.json"


def test_custom_profile_activity_uses_only_the_selected_retained_layout():
    job = WORKFLOW["jobs"]["custom-profile"]
    assert "needs" not in job
    assert job["permissions"] == {"contents": "read", "actions": "read", "packages": "write"}
    assert WORKFLOW["concurrency"] == {"group": "default-guest-publication", "cancel-in-progress": False}
    download = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"] == {
        "artifact-ids": "${{ fromJSON(inputs.custom_profile).artifact_id }}",
        "run-id": "${{ fromJSON(inputs.custom_profile).run_id }}",
        "repository": "craigbalding/safeyolo", "github-token": "${{ secrets.GITHUB_TOKEN }}",
        "path": "${{ runner.temp }}/custom-profile-layout",
    }
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "prepare_guest_transport_fixture" not in commands and "build-all.sh" not in commands
    retained = next(step for step in job["steps"] if step.get("with", {}).get("name") == "guest-custom-profile-result")
    assert retained["if"] == "always()"
    assert "custom-profile-publication/result.json" in retained["with"]["path"]


@pytest.mark.parametrize("activity,step_name,input_name", [
    ("record-smoke", "Attach retained operator evidence", "SMOKE_GATE_URL"),
    ("inspect", "Read the retained promotion decision", "PROMOTION_JOB"),
])
def test_publication_step_stops_after_login_failure(tmp_path, activity, step_name, input_name):
    step = next(step for step in WORKFLOW["jobs"][activity]["steps"] if step.get("name") == step_name)
    assert step["shell"] == "bash"
    assert step["env"] == {"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}", input_name: "${{ inputs." + input_name.lower() + " }}"}
    assert "${{" not in step["run"]
    for name, body in (("oras", "exit 37"), ("python3", 'touch "$RUNNER_TEMP/unexpected-upload"')):
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
    result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                            env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path),
                                 "GH_TOKEN": "test-only", "GITHUB_ACTOR": "operator", "SMOKE_GATE_URL": GATE},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 37 and not (tmp_path / "unexpected-upload").exists()


@pytest.fixture
def upload(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    report_files(reports)
    for name, value in {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "record-smoke", "GITHUB_RUN_ID": "123",
                        "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": release.selection.REPOSITORY,
                        "GITHUB_WORKFLOW_REF": f"{release.selection.REPOSITORY}/{release.selection.GUEST_WORKFLOW}@refs/heads/master",
                        "GITHUB_REF": "refs/heads/master", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTOR": "operator"}.items():
        monkeypatch.setenv(name, value)
    run = {"head_sha": "a" * 40, "head_branch": "master", "path": release.selection.GUEST_WORKFLOW,
           "event": "workflow_dispatch", "run_attempt": 2, "actor": {"login": "operator"}}
    monkeypatch.setattr(release, "branch", lambda: "master")
    monkeypatch.setattr(release.selection, "pages", lambda *args: [{"name": "record-smoke", "id": 456}])
    state = {"permission": "write", "run": run, "writes": []}
    def gh(endpoint):
        if endpoint == "actions/runs/123/attempts/2":
            return state["run"]
        assert endpoint == "collaborators/operator/permission"
        return {"permission": state["permission"]}
    monkeypatch.setattr(release.selection, "gh", gh)
    monkeypatch.setattr(release.selection, "manifest", lambda *args: (INDEX, {}))
    monkeypatch.setattr(release, "referrers", lambda *args: [])
    monkeypatch.setattr(release, "attach", lambda index, kind, result, files: state["writes"].append(
        (index, kind, copy.deepcopy(result), [path.read_bytes() for path in files])))
    return SimpleNamespace(reports=reports, gate_url=GATE), state


def test_upload_preserves_execution_and_attributes_the_operator_separately(upload):
    args, state = upload
    original = release.smoke_result(args.reports, args.gate_url)
    result = release.record_smoke(args)
    assert {key: result[key] for key in original} == original
    assert result["controller_revision"] != result["upload"]["source_revision"]
    assert "producer" not in result and result["operator"] == "operator"
    assert result["upload"]["producer"]["job_id"] == 456
    assert result["upload"]["job_url"].endswith("/runs/123/job/456")
    assert state["writes"] == [(INDEX, release.SMOKE, result, [(args.reports / name).read_bytes() for name in NAMES])]


def test_upload_continuation_attaches_the_unchanged_operator_observation(upload):
    args, state = upload
    observed = continuation_files(args.reports)
    original = (args.reports / "installed-continuation.json").read_bytes()
    result = release.record_smoke(args)
    assert result["operator"] == "operator" and result["upload"]["producer"]["job_id"] == 456
    assert result["controller_revision"] == observed["controller"]["revision"]
    assert result["controller_revision"] != result["upload"]["source_revision"]
    assert result["executions"]["original"]["exit"] == 2 and result["executions"]["resume"]["exit"] == 0
    assert state["writes"] == [(INDEX, release.SMOKE, result,
                                [(args.reports / "selection.json").read_bytes(), original])]


def test_continuation_requires_the_maintained_lane_sections():
    from tests.blackbox.installed_sections import SECTIONS

    assert release.INSTALLED_SECTIONS == {lane: set(names) for lane, names in SECTIONS.items()}


def test_continuation_uses_normal_platform_gates_and_cannot_hide_a_newer_failure(upload, monkeypatch):
    args, _ = upload
    continuation_files(args.reports)
    result = release.record_smoke(args)
    value = candidate()
    monkeypatch.setattr(release, "verify_operator", lambda actor: None)
    other_platforms = [row for row in evidence(value) if row["platform"] != "linux-amd64"]
    proof = [result, *other_platforms]
    assert release.gates(value, proof, "master") == proof
    failed = {**result, "result": "failed", "finished_at": "2026-10-17T19:04:00Z"}
    with pytest.raises(ValueError, match="latest installed smoke failed: linux-amd64"):
        release.gates(value, [*proof, failed], "master")
    with pytest.raises(ValueError, match="missing successful installed guest smoke"):
        release.gates(value, [result], "master")


@pytest.mark.parametrize("path,value", [
    (("original_execution", "exit"), 0),
    (("original_execution", "command", 4), "kvm"),
    (("original_execution", "id"), 2),
    (("resume_execution", "exit"), 2),
    (("resume_execution", "command"), ["python", "installed_sections.py", "systrap", "--prepared-config"]),
    (("resume_execution", "controller_status"), " M tracked.py"),
    (("resume_execution", "started_at"), "2026-10-17T18:59:00Z"),
    (("resume_execution", "command", 2), "kvm"),
    (("resume_execution", "command", 6), "/different/prepared"),
    (("controller", "dirty"), True),
    (("controller", "revision"), "f" * 40),
    (("verified_operands", "installed_inputs", "guest", "archive", "size"), 999),
    (("verified_operands", "installed_inputs", "host_source_revision"), "f" * 40),
    (("verified_operands", "installed_inputs", "installed_files_sha256"), {"different-helper": "d" * 64}),
    (("verified_operands", "installed_inputs", "platform"), "linux-arm64"),
    (("verified_operands", "resumed_sections", "lane"), "kvm"),
    (("verified_operands", "resumed_sections", "source_revision"), "f" * 40),
    (("verified_operands", "resumed_sections", "preparation", "config_dir"), "/different/prepared"),
    (("verified_operands", "resumed_sections", "sections", 0, "prepared_config_dir"), "/different/prepared"),
    (("verified_operands", "original_sections", "sections", 4, "result"), "assertion_failure"),
    (("verified_operands", "original_sections", "sections", 4, "error"), ""),
    (("verified_operands", "original_sections", "sections", 0, "exit"), 1),
    (("verified_operands", "original_sections", "sections", 0, "cleanup"), "failed"),
    (("verified_operands", "resumed_sections", "sections", 0, "exit"), 1),
    (("verified_operands", "resumed_sections", "sections", 0, "cleanup_failures"), ["owned process still live"]),
    (("verified_operands", "owned_live_markers"), ["active"]),
    (("verified_operands", "live_product_processes"), [123]),
    (("verified_operands", "continuity_runtime_after", 0, "pid_exists"), True),
])
def test_upload_refuses_inconsistent_or_failed_continuation_before_write(upload, path, value):
    args, state = upload
    observed = continuation_files(args.reports)
    parent = observed
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = value
    (args.reports / "installed-continuation.json").write_text(json.dumps(observed))
    with pytest.raises(ValueError):
        release.record_smoke(args)
    assert not state["writes"]


@pytest.mark.parametrize("fault", ["missing-section", "duplicate-section", "replayed-section", "mixed-reports", "missing-observation"])
def test_upload_refuses_incomplete_or_ambiguous_continuation(upload, fault):
    args, state = upload
    observed = continuation_files(args.reports)
    operands = observed["verified_operands"]
    if fault == "missing-section":
        operands["original_sections"]["sections"].pop(0)
    elif fault == "duplicate-section":
        operands["resumed_sections"]["sections"] *= 2
    elif fault == "replayed-section":
        operands["resumed_sections"]["sections"].append(operands["original_sections"]["sections"][0])
    elif fault == "mixed-reports":
        (args.reports / "retained-run.json").write_text('{"exit": 0}')
    else:
        del operands["observed_at"]
    (args.reports / "installed-continuation.json").write_text(json.dumps(observed))
    with pytest.raises((ValueError, KeyError)):
        release.record_smoke(args)
    assert not state["writes"]


def test_continuation_cannot_claim_an_uninterrupted_actions_producer(upload, monkeypatch):
    args, state = upload
    continuation_files(args.reports)
    monkeypatch.setenv("GITHUB_JOB", "systrap")
    with pytest.raises(ValueError, match="operator attestation"):
        release.record_smoke(args)
    assert not state["writes"]


@pytest.mark.parametrize("failed", [False, True])
def test_installed_publication_keeps_its_execution_producer_and_failed_attempts(upload, monkeypatch, failed):
    args, state = upload
    monkeypatch.setenv("GITHUB_JOB", "systrap")
    monkeypatch.setenv("RUNNER_NAME", "installed-runner")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", f"{release.selection.REPOSITORY}/.github/workflows/blackbox.yml@refs/heads/master")
    monkeypatch.setattr(release.selection, "pages", lambda *args: [{"id": 789, "runner_name": "installed-runner", "status": "in_progress"}])
    if failed:
        frozen = json.loads((args.reports / "selection.json").read_bytes())
        frozen["controller_revision"] = "e" * 40
        (args.reports / "selection.json").write_text(json.dumps(frozen))
        (args.reports / "installed-inputs.json").unlink()
    result = release.record_smoke(args)
    assert result["result"] == ("failed" if failed else "passed")
    assert result["producer"]["job_id"] == 789
    assert result["producer"]["workflow"] == ".github/workflows/blackbox.yml"
    assert "operator" not in result and "upload" not in result
    assert len(state["writes"]) == 1


@pytest.mark.parametrize("field,value", [("GITHUB_REPOSITORY", "other/repo"), ("GITHUB_REF", "refs/heads/feature"),
    ("GITHUB_EVENT_NAME", "schedule"), ("GITHUB_WORKFLOW_REF", "other/workflow@refs/heads/master"), ("GITHUB_SHA", "f" * 40)])
def test_upload_refuses_invalid_environment_before_registry_write(upload, monkeypatch, field, value):
    args, state = upload
    monkeypatch.setenv(field, value)
    with pytest.raises(ValueError, match="upload"):
        release.record_smoke(args)
    assert not state["writes"]


@pytest.mark.parametrize("field,value", [("head_branch", "feature"), ("path", ".github/workflows/blackbox.yml"),
    ("event", "push"), ("run_attempt", 3), ("actor", {"login": "someone-else"})])
def test_upload_refuses_mismatched_api_origin(upload, field, value):
    args, state = upload
    state["run"][field] = value
    with pytest.raises(ValueError, match="origin"):
        release.record_smoke(args)
    assert not state["writes"]


@pytest.mark.parametrize("permission", ["read", "triage", "none"])
def test_upload_requires_existing_operator_permission(upload, permission):
    args, state = upload
    state["permission"] = permission
    with pytest.raises(ValueError, match="authorized repository operator"):
        release.record_smoke(args)
    assert not state["writes"]


@pytest.mark.parametrize("fault", [*NAMES, "failed-section", "failed-run", "missing-gate"])
def test_upload_refuses_missing_or_failed_evidence(upload, fault):
    args, state = upload
    if fault in NAMES:
        (args.reports / fault).unlink()
    elif fault == "missing-gate":
        args.gate_url = ""
    else:
        path = args.reports / ("guest/installed-sections.json" if fault == "failed-section" else "retained-run.json")
        value = json.loads(path.read_bytes())
        if fault == "failed-section":
            value["sections"][0]["exit"] = 1
        else:
            value["exit"] = 1
        path.write_text(json.dumps(value))
    with pytest.raises((ValueError, OSError)):
        release.record_smoke(args)
    assert not state["writes"]


@pytest.mark.parametrize("different", [None, "file-bytes", "gate", "failed", "subject"])
@pytest.mark.parametrize("continued", [False, True])
def test_upload_skips_only_an_exact_subject_bound_success(upload, monkeypatch, different, continued):
    args, state = upload
    if continued:
        continuation_files(args.reports)
    names = release.CONTINUATION_REPORTS if continued else NAMES
    prior = {**release.smoke_result(args.reports, args.gate_url), "operator": "operator"}
    if different == "gate":
        prior["gate_url"] += "-other"
    if different == "failed":
        prior["result"] = "failed"
    blobs = {}
    def layer(raw, media, title):
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return {"digest": digest, "size": len(raw), "mediaType": media,
                "annotations": {"org.opencontainers.image.title": title}}
    layers = [layer(json.dumps(prior).encode(), release.SMOKE, "receipt.json")]
    for number, name in enumerate(names):
        raw = (args.reports / name).read_bytes()
        if different == "file-bytes":
            raw += b"\n"
        layers.append(layer(raw, release.JSON, f"{number}-{Path(name).name}"))
    manifest = {"artifactType": release.SMOKE, "subject": {**INDEX}, "layers": layers}
    if different == "subject":
        manifest["subject"]["size"] += 1
    descriptor = {"digest": "sha256:" + "f" * 64}
    monkeypatch.setattr(release, "referrers", lambda *args: [descriptor])
    monkeypatch.setattr(release.selection, "manifest", lambda ref: (INDEX, {}) if ref.endswith(INDEX["digest"]) else (descriptor, manifest))
    monkeypatch.setattr(release.selection, "capture", lambda *args: blobs[args[-1].split("@")[-1]])
    if different == "subject":
        with pytest.raises(ValueError, match="not bound"):
            release.record_smoke(args)
        assert not state["writes"]
    else:
        result = release.record_smoke(args)
        if different is None:
            assert not state["writes"] and result["smoke"] == prior
            assert result["decision"] == "matching successful smoke retained"
        else:
            assert len(state["writes"]) == 1
    # No prior failed or different record is changed or deleted.
    assert json.loads(blobs[layers[0]["digest"]]) == prior


def test_installed_origin_keeps_workflow_branch_and_execution_time_guards(monkeypatch):
    origin = {"repository": release.selection.REPOSITORY, "workflow": ".github/workflows/blackbox.yml",
              "run_id": 123, "run_attempt": 1, "job_id": 456}
    result = {"producer": origin, "controller_revision": "b" * 40, "finished_at": "2026-10-17T19:18:00Z"}
    run = {"head_sha": "b" * 40, "head_branch": "master", "path": origin["workflow"], "event": "workflow_dispatch", "run_attempt": 1}
    monkeypatch.setattr(release.selection, "gh", lambda *args: run)
    monkeypatch.setattr(release.selection, "pages", lambda *args: [{"id": 456, "status": "completed", "conclusion": "success",
        "started_at": "2026-10-17T19:12:00Z", "completed_at": "2026-10-17T19:19:00Z"}])
    release.verify_smoke_origin(result, "master")
    run["head_branch"] = "forge/issue-1105-consumer-proof"
    with pytest.raises(ValueError, match="default-branch"):
        release.verify_smoke_origin(result, "master")
    run["head_branch"] = "master"
    result["finished_at"] = "2026-10-18T00:00:00Z"
    with pytest.raises(ValueError, match="outside"):
        release.verify_smoke_origin(result, "master")
    origin["workflow"] = release.selection.GUEST_WORKFLOW
    with pytest.raises(ValueError, match="maintained installed workflow"):
        release.verify_smoke_origin(result, "master")
