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
from tests.test_guest_promotion import INDEX, report_files

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
JOB = WORKFLOW["jobs"]["record-smoke"]
NAMES = ("selection.json", "retained-run.json", "installed-inputs.json", "guest/installed-sections.json")
GATE = "https://github.com/craigbalding/safeyolo/issues/1105#issuecomment-123"


def restore(tmp_path, texts):
    step = next(step for step in JOB["steps"] if step.get("name") == "Restore the four original report files")
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


@pytest.mark.parametrize("texts", [None, [], {}, {name: {} for name in NAMES},
                                    {**dict.fromkeys(NAMES, "{}"), "../escape": "{}"}])
def test_workflow_refuses_incomplete_or_nontext_report_inputs(tmp_path, texts):
    assert restore(tmp_path, texts).returncode != 0
    assert not (tmp_path / "retained-reports").exists()


@pytest.mark.parametrize("event,ref,activity,expected", [
    ("workflow_dispatch", "refs/heads/master", "record-smoke", {"record-smoke"}),
    ("workflow_dispatch", "refs/heads/feature", "record-smoke", set()),
    ("pull_request", "refs/heads/master", "record-smoke", set()),
    ("workflow_dispatch", "refs/heads/master", "promote", {"promote"}),
    ("workflow_dispatch", "refs/heads/master", "build-stage", {"resolve"}),
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


def test_publication_step_stops_after_login_failure(tmp_path):
    step = next(step for step in JOB["steps"] if step.get("name") == "Attach retained operator evidence")
    assert step["shell"] == "bash"
    assert step["env"] == {"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}", "SMOKE_GATE_URL": "${{ inputs.smoke_gate_url }}"}
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
def test_upload_skips_only_an_exact_subject_bound_success(upload, monkeypatch, different):
    args, state = upload
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
    for number, name in enumerate(NAMES):
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
