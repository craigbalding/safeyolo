"""Exercise the emitted event, literal SSH payload and report return offline."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import claude_blackbox_events as events
from tests import test_trusted_claude_blackbox as caller_tests

SOURCE = "a" * 40
ROOT = Path(__file__).resolve().parents[1]
invocation = caller_tests.invocation


@pytest.fixture
def transport(invocation, tmp_path, monkeypatch):
    args, controller = invocation
    shutil.copy2(ROOT / "scripts/run_claude_blackbox.py", controller / "scripts/run_claude_blackbox.py")
    for path in (controller / "scripts/select_blackbox_artifacts.py", controller / "tests/blackbox/retained_inputs.py"):
        path.write_text(path.read_text().replace("'d'*40", "__import__('subprocess').check_output(['git','rev-parse','HEAD'], text=True).strip()"))
    (controller / ".gitignore").write_text("__pycache__/\nevents\nprepared/\n")
    for command in (["git", "init", "-q"], ["git", "add", "."],
                    ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"]):
        subprocess.run(command, cwd=controller, check=True, capture_output=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=controller, text=True).strip()
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / "ssh_exec.sh").write_text(textwrap.dedent('''\
        set -eu
        test "$1" = owned-host
        test "$3" = 7200
        set +e
        printf '%s' "$2" | base64 -d | bash > "$HARNESS_PRIVATE" 2>&1
        status=$?
        set -e
        if [ "${LOST_RECEIPT:-0}" = 1 ]; then exit 19; fi
        printf 'HARNESS_JSON:{"exit_code":%s,"timed_out":%s}\\n' "${HARNESS_EXIT_OVERRIDE:-$status}" "${HARNESS_TIMEOUT:-false}"
        exit "${WRAPPER_EXIT:-0}"
    '''))
    fetch_python = textwrap.dedent('''\
        import base64, hashlib, json, os, pathlib, sys
        path = pathlib.Path(sys.argv[1])
        if os.environ.get('FETCH_FAULT') == 'missing':
            sys.exit(1)
        data = path.read_bytes()
        receipt = {'content_b64': base64.b64encode(data).decode(),
                   'sha256': hashlib.sha256(data).hexdigest(), 'truncated': False}
        fault = os.environ.get('FETCH_FAULT')
        if fault == 'truncated': receipt['truncated'] = True
        if fault == 'hash': receipt['sha256'] = '0'*64
        if fault == 'base64': receipt['content_b64'] = '!!!'
        print('HARNESS_JSON:' + json.dumps(receipt))
    ''')
    (jobs / "ssh_fetch.sh").write_text(f"set -eu\n{sys.executable} - \"$2\" <<'PY'\n{fetch_python}PY\n")
    binding = tmp_path / "private binding; literal.sh"
    binding.write_text(f"export CLAUDE_PROVISION={shlex.quote(str(args.provision))}\nexport CLAUDE_CREDENTIAL=host-access-only\n")
    config = {"controller": str(controller), "controller_revision": revision,
              "binding": str(binding), "jobs": str(jobs), "host": "owned-host",
              "remote_attempts": str(tmp_path / "remote attempts; literal"), "attempts": str(tmp_path / "attempts")}
    Path(config["attempts"]).mkdir()
    monkeypatch.setenv("HARNESS_PRIVATE", str(tmp_path / "harness-private.log"))
    request = {"trigger": "nightly", "ref": "refs/heads/master", "event_run": 42,
               "event_attempt": 1, "source_revision": None, "host_run": None, "guest_index": None}
    return config, request, controller


@pytest.mark.parametrize("code", [0, 17])
@pytest.mark.parametrize("trigger", ["nightly", "manual", "merge"])
def test_composed_payload_runs_real_caller_and_returns_original_report(transport, monkeypatch, code, trigger):
    config, request, controller = transport
    request["trigger"] = trigger
    if trigger == "merge":
        request.update(source_revision=SOURCE, host_run=123)
    monkeypatch.setenv("FAIL_SMOKE", str(code))
    attempt = Path(config["attempts"]) / "42-1"
    attempt.mkdir()
    result = events.execute(config, request, attempt)
    assert result["exit"] == code, result
    assert result["guest_exit"] == code and result["timed_out"] is False
    remote = Path(result["remote_output"]) / "result.json"
    assert (attempt / "result.json").read_bytes() == remote.read_bytes()
    report = json.loads(remote.read_bytes())
    assert report["exit"] == code
    assert report["controller_revision"] == config["controller_revision"] != SOURCE
    assert report["selection"]["host"]["source_revision"] == SOURCE
    assert "PRIVATE" not in json.dumps(result) + remote.read_text()
    assert "PRIVATE" in (remote.parent / "private.log").read_text()
    rows = [json.loads(line) for line in (controller / "events").read_text().splitlines()]
    assert [row["stage"] for row in rows] == ["selection", "readiness", "binding", "smoke"]
    if trigger == "merge":
        assert rows[0]["args"][-2:] == ["--host-run", "123"]


@pytest.mark.parametrize("fault", ["missing", "truncated", "hash", "base64"])
@pytest.mark.parametrize("code", [0, 17])
def test_report_transport_failures_cannot_pass_or_replace_guest_failure(transport, monkeypatch, fault, code):
    config, request, _ = transport
    monkeypatch.setenv("FETCH_FAULT", fault)
    monkeypatch.setenv("FAIL_SMOKE", str(code))
    attempt = Path(config["attempts"]) / "42-1"
    attempt.mkdir()
    result = events.execute(config, request, attempt)
    assert result["guest_exit"] == code and result["exit"] == (code or 2)
    assert result["report_failure"]
    assert not (attempt / "result.json").exists()


@pytest.mark.parametrize(("variable", "value", "expected"), [
    ("HARNESS_TIMEOUT", "true", 124), ("LOST_RECEIPT", "1", 2), ("WRAPPER_EXIT", "19", 19),
])
def test_timeout_and_uncertain_wrapper_results_retain_completed_report(transport, monkeypatch, variable, value, expected):
    config, request, _ = transport
    monkeypatch.setenv(variable, value)
    attempt = Path(config["attempts"]) / "42-1"
    attempt.mkdir()
    result = events.execute(config, request, attempt)
    assert result["exit"] == expected
    assert json.loads((attempt / "result.json").read_bytes())["exit"] == 0


def test_timeout_without_known_guest_exit_stays_a_timeout(transport, monkeypatch):
    config, request, _ = transport
    monkeypatch.setenv("HARNESS_TIMEOUT", "true")
    monkeypatch.setenv("HARNESS_EXIT_OVERRIDE", "null")
    attempt = Path(config["attempts"]) / "42-1"
    attempt.mkdir()
    result = events.execute(config, request, attempt)
    assert result["exit"] == 124 and result["timed_out"] is True
    assert result["guest_exit"] is None and (attempt / "result.json").is_file()


def test_wrong_deployed_controller_cannot_start_caller_or_provisioning(transport):
    config, request, controller = transport
    config["controller_revision"] = "b" * 40
    attempt = Path(config["attempts"]) / "42-1"
    attempt.mkdir()
    result = events.execute(config, request, attempt)
    assert result["exit"] == result["guest_exit"] == 1
    assert result["report_failure"] and not (controller / "events").exists()


class FakeGitHub:
    def __init__(self, request=None):
        self.posts = []
        self.head = SOURCE
        self.runs = []
        self.ready = False
        self.push = {"path": events.HOST_WORKFLOW, "event": "push", "head_branch": "master",
                     "head_sha": SOURCE, "head_repository": {"full_name": events.REPOSITORY},
                     "status": "completed", "conclusion": "success"}
        self.artifact = {"id": 99, "name": "claude-event-1", "expired": False}
        self.request = request
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("claude-event.json", json.dumps(request))
        self.data = stream.getvalue()
        self.artifact["digest"] = "sha256:" + hashlib.sha256(self.data).hexdigest()

    def api(self, endpoint, payload=None, *, raw=False):
        if payload is not None:
            self.posts.append((endpoint, payload))
            self.runs = [{"id": 123, "run_attempt": 1, "path": events.HOST_WORKFLOW,
                          "event": "workflow_dispatch", "head_branch": "master", "head_sha": SOURCE,
                          "status": "completed"}]
            self.ready = True
            return None
        if endpoint.startswith("commits/"):
            return {"sha": self.head}
        if endpoint == "actions/artifacts/99/zip":
            assert raw
            return self.data
        if endpoint == "actions/runs/15":
            return self.push
        raise AssertionError(endpoint)

    def pages(self, endpoint, field):
        if field == "workflow_runs":
            assert "head_sha=" + SOURCE in endpoint
            return self.runs
        if endpoint == "actions/runs/42/artifacts":
            return [self.artifact]
        if field == "jobs":
            return [{"name": "guest-inputs (amd64) / build", "status": "completed", "conclusion": "success"}]
        if field == "artifacts":
            return [{"name": events.HOST_ARTIFACT, "expired": not self.ready}]
        raise AssertionError(endpoint)


def trusted_run():
    return {"id": 42, "run_attempt": 1, "path": events.EVENT_WORKFLOW, "head_branch": "master",
            "event": "workflow_run", "repository": {"full_name": events.REPOSITORY}}


def merge_request():
    return {"trigger": "merge", "ref": "refs/heads/master", "event_run": 42, "event_attempt": 1,
            "source_revision": SOURCE, "push_run": 15, "host_run": None, "guest_index": None}


@pytest.mark.parametrize(("location", "field", "value"), [
    ("run", "head_branch", "feature"), ("run", "event", "pull_request"),
    ("run", "path", ".github/workflows/other.yml"), ("request", "ref", "refs/heads/feature"),
    ("request", "source_revision", "b" * 40), ("request", "event_run", 41),
    ("push", "event", "pull_request"), ("push", "path", ".github/workflows/ci.yml"),
    ("push", "head_sha", "b" * 40), ("push", "conclusion", "failure"),
])
def test_wrong_branch_source_or_producer_is_rejected_before_any_ssh(transport, monkeypatch, location, field, value):
    config, _, _ = transport
    request = merge_request()
    run = trusted_run()
    if location == "request":
        request[field] = value
    github = FakeGitHub(request)
    if location == "run":
        run[field] = value
    if location == "push":
        github.push[field] = value
    monkeypatch.setattr(events, "execute", lambda *_: pytest.fail("rejected event reached SSH"))
    result = events.consume(config, github, run, "master")
    assert result["exit"] == 2 and result["stage"] == "event-admission"
    assert not github.posts


def test_merge_dispatches_existing_exact_packages_path_once_and_binds_result(transport, monkeypatch):
    config, _, _ = transport
    github = FakeGitHub(merge_request())
    monkeypatch.setattr(events.time, "sleep", lambda _: None)
    seen = []
    monkeypatch.setattr(events, "execute", lambda _config, request, _attempt: seen.append(copy.deepcopy(request)) or {"exit": 0})
    result = events.consume(config, github, trusted_run(), "master")
    assert result["exit"] == 0
    assert github.posts == [("actions/workflows/proxy-rust.yml/dispatches", {
        "ref": "master", "inputs": {"packages_only": "true", "source_revision": SOURCE, "package_architecture": "amd64"}})]
    assert seen[0]["host_run"] == 123 and seen[0]["source_revision"] == SOURCE
    assert events.consume(config, github, trusted_run(), "master") is None
    assert len(seen) == len(github.posts) == 1


def test_missing_exact_artifact_for_old_head_fails_without_dispatch_or_ssh(transport, monkeypatch):
    config, _, _ = transport
    github = FakeGitHub(merge_request())
    github.head = "b" * 40
    monkeypatch.setattr(events, "execute", lambda *_: pytest.fail("missing artifact reached SSH"))
    result = events.consume(config, github, trusted_run(), "master")
    assert result["exit"] == 2 and result["stage"] == "exact-production"
    assert not github.posts


@pytest.mark.parametrize(("field", "value"), [
    ("path", ".github/workflows/ci.yml"), ("event", "push"),
    ("head_branch", "feature"), ("head_sha", "b" * 40),
])
def test_wrong_production_identity_cannot_supply_merge_input(transport, monkeypatch, field, value):
    config, _, _ = transport
    github = FakeGitHub(merge_request())
    github.runs = [{"id": 123, "run_attempt": 1, "path": events.HOST_WORKFLOW,
                    "event": "schedule", "head_branch": "master", "head_sha": SOURCE,
                    "status": "completed", field: value}]
    github.ready = True
    github.head = "b" * 40
    monkeypatch.setattr(events, "execute", lambda *_: pytest.fail("wrong production reached SSH"))
    result = events.consume(config, github, trusted_run(), "master")
    assert result["exit"] == 2 and result["stage"] == "exact-production"
    assert not github.posts


def test_ready_exact_production_is_reused_without_dispatch(transport, monkeypatch):
    config, _, _ = transport
    github = FakeGitHub(merge_request())
    github.runs = [{"id": 123, "run_attempt": 1, "path": events.HOST_WORKFLOW,
                    "event": "schedule", "head_branch": "master", "head_sha": SOURCE,
                    "status": "completed"}]
    github.ready = True
    attempt = Path(config["attempts"]) / "42-1"
    attempt.mkdir()
    assert events.production_run(github, "master", SOURCE, attempt, 0) == 123
    assert not github.posts


def test_cli_returns_completed_failing_report_without_private_logs(transport, monkeypatch, capsys):
    config, _, _ = transport
    config["enabled_since"] = "2026-11-04T00:00:00Z"
    request = merge_request()
    request.update(trigger="manual", source_revision=None, push_run=None)
    github = FakeGitHub(request)
    run = trusted_run()
    run["event"] = "workflow_dispatch"
    original = github.api

    def api(endpoint, *args, **kwargs):
        if endpoint == "":
            return {"default_branch": "master"}
        if endpoint == "actions/runs/42":
            return run
        return original(endpoint, *args, **kwargs)

    monkeypatch.setattr(github, "api", api)
    monkeypatch.setattr(events, "GitHub", lambda _log: github)
    monkeypatch.setenv("FAIL_SMOKE", "17")
    path = Path(config["attempts"]).parent / "config.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(sys, "argv", ["events", "--config", str(path), "--event-run", "42"])
    try:
        mask = os.umask(0o022)
        assert events.main() == 17
    finally:
        os.umask(mask)
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and lines[0].startswith("CLAUDE_RESULT:")
    assert json.loads(lines[0].removeprefix("CLAUDE_RESULT:"))["exit"] == 17
    assert json.loads(lines[1].removeprefix("CLAUDE_TRANSPORT:"))["guest_exit"] == 17
    assert "PRIVATE" not in "".join(lines)
    attempt = Path(config["attempts"]) / "42-1"
    assert attempt.stat().st_mode & 0o777 == 0o700
    for name in ("transport.json", "result.json", "ssh_exec-private.log", "ssh_fetch-private.log"):
        assert (attempt / name).stat().st_mode & 0o777 == 0o600


def test_unknown_dispatch_is_not_submitted_again(transport, monkeypatch):
    config, _, _ = transport
    github = FakeGitHub(merge_request())
    original = github.api

    def lose_response(endpoint, payload=None, **kwargs):
        value = original(endpoint, payload, **kwargs)
        if payload is not None:
            raise subprocess.TimeoutExpired("gh", 180)
        return value

    monkeypatch.setattr(github, "api", lose_response)
    assert events.consume(config, github, trusted_run(), "master")["exit"] == 2
    assert events.consume(config, github, trusted_run(), "master") is None
    assert len(github.posts) == 1


def test_skipped_merge_notification_does_not_become_a_claude_attempt(transport, monkeypatch):
    config, _, _ = transport
    github = FakeGitHub()
    monkeypatch.setattr(github, "pages", lambda *_: [{"name": "Record trusted Claude invocation", "conclusion": "skipped"}])
    assert events.consume(config, github, trusted_run(), "master") is None
    assert not list(Path(config["attempts"]).iterdir())


@pytest.mark.parametrize("kind", ["schedule", "workflow_dispatch", "workflow_run"])
def test_literal_workflow_event_emission(tmp_path, kind):
    workflow = yaml.safe_load((ROOT / ".github/workflows/blackbox.yml").read_text())
    job = workflow["jobs"]["claude-event"]
    script = job["steps"][0]["run"]
    payload = tmp_path / "event.json"
    payload.write_text(json.dumps({"workflow_run": {"id": 15, "head_sha": SOURCE}}))
    environment = dict(os.environ, GITHUB_EVENT_PATH=str(payload), GITHUB_EVENT_NAME=kind,
                       GITHUB_REF="refs/heads/master", GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1",
                       HOST_RUN="123" if kind == "workflow_dispatch" else "", GUEST_INDEX="")
    subprocess.run(["bash", "-eu", "-c", script], cwd=tmp_path, env=environment, check=True)
    request = json.loads((tmp_path / "claude-event.json").read_text())
    assert request["trigger"] == {"schedule": "nightly", "workflow_dispatch": "manual", "workflow_run": "merge"}[kind]
    assert request["source_revision"] == (SOURCE if kind == "workflow_run" else None)
    assert request["host_run"] == ("123" if kind == "workflow_dispatch" else None)
    assert workflow["jobs"]["systrap"]["if"] == "github.event_name != 'workflow_run'"
    assert workflow["jobs"]["macos-package"]["if"] == "github.event_name != 'workflow_run'"
    assert "pull_request" not in workflow[True]
