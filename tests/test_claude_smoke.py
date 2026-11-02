"""Offline controls for the installed native Claude smoke; no provider calls."""

from __future__ import annotations

import copy
import json
import os
import subprocess

import pytest

from tests.blackbox import claude_smoke as smoke
from tests.blackbox import installed_sections, retained_inputs

SOURCE = "a" * 40
RUNTIME = {"name": "bbtest", "agent_id": "agent-fixture", "run_id": "b" * 32}


def test_gateway_launch_finds_jq_in_the_guest_tool_path(tmp_path):
    guest_home = tmp_path / "guest"
    guest_tools = guest_home / ".local/bin"
    inherited_tools = tmp_path / "inherited"
    guest_tools.mkdir(parents=True)
    inherited_tools.mkdir()
    programs = {
        inherited_tools / "cat": "printf 'fixture-agent\\n'\n",
        inherited_tools / "curl": "IFS= read -r header\nprintf '{}\\n'\n",
        guest_tools / "jq": (
            "while IFS= read -r input; do :; done\n"
            "printf 'guest jq reached\\n' >&2\nexit 42\n"
        ),
    }
    for path, script in programs.items():
        path.write_text("#!/bin/sh\n" + script)
        path.chmod(0o700)

    result = subprocess.run(
        ["/bin/sh", "-c", smoke.GATEWAY_LAUNCH],
        env=dict(os.environ, HOME=str(guest_home), PATH=str(inherited_tools)),
        capture_output=True, text=True, timeout=10, check=False,
    )
    # Stop in the fixture jq before any staged client can run. All token and
    # gateway operations above are local fakes, with no credential access.
    assert result.returncode == 42, result.stderr
    assert "guest jq reached" in result.stderr


def events(tool="Bash"):
    return [
        {"type": "assistant", "session_id": "session-fixture", "message": {
            "model": "claude-fixture", "content": [{"type": "tool_use", "id": "tool-1", "name": tool,
                                                       "input": {"command": "private operands"}}]}},
        {"type": "user", "session_id": "session-fixture", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "tool-1", "content": "private result"}]}},
        {"type": "result", "session_id": "session-fixture", "subtype": "success", "is_error": False},
    ]


def gateway():
    return {"event": "gateway.allow", "request_id": "request-fixture", "host": "api.anthropic.com",
            "details": {"service": "claude", "capability": "inference", "path": "/v1/messages",
                        "sandbox_run": {"agent": "bbtest", "agent_id": RUNTIME["agent_id"],
                                        "run_id": RUNTIME["run_id"]}}}


@pytest.mark.parametrize("tool", ["Write", "Bash", "Read"])
def test_task_accepts_successful_tools_without_requiring_one_sequence(tool):
    observation = smoke.task_observation(events(tool), b"wanted", b"wanted")
    assert observation["successful_task"]
    assert observation["successful_tool_results"] == 1
    assert "private" not in json.dumps(observation)


@pytest.mark.parametrize("failure", ["text-only", "unpaired", "failed-tool", "missing-finish", "failed-finish",
                                     "mixed-session", "wrong-output", "absent-output", "result-before-call"])
def test_task_requires_tool_completion_client_completion_and_independent_output(failure):
    rows, actual = events(), b"wanted"
    if failure == "text-only":
        rows[0]["message"]["content"] = [{"type": "text", "text": "Done; wrote wanted"}]
    elif failure == "unpaired":
        rows[1]["message"]["content"][0]["tool_use_id"] = "other"
    elif failure == "failed-tool":
        rows[1]["message"]["content"][0]["is_error"] = True
    elif failure == "missing-finish":
        rows.pop()
    elif failure == "failed-finish":
        rows[-1]["is_error"] = True
    elif failure == "mixed-session":
        rows[1]["session_id"] = "other"
    elif failure == "wrong-output":
        actual = b"wrong"
    elif failure == "absent-output":
        actual = None
    elif failure == "result-before-call":
        rows = [rows[1], rows[0], rows[2]]
    assert not smoke.task_observation(rows, actual, b"wanted")["successful_task"]


@pytest.mark.parametrize("field", ["run_id", "agent_id", "agent", "service", "capability", "host", "path"])
def test_gateway_requires_the_actual_current_agent_run_and_provider(field):
    current = gateway()
    prior = copy.deepcopy(current)
    if field in {"run_id", "agent_id", "agent"}:
        prior["details"]["sandbox_run"][field] = "prior"
    elif field == "host":
        prior[field] = "other.example"
    else:
        prior["details"][field] = "other"
    # A retained prior run beside the live generation cannot create ambiguity
    # or substitute for this task's provider request.
    assert len(smoke.gateway_observation([prior, current], RUNTIME)) == 1
    assert smoke.gateway_observation([prior], RUNTIME) == []


@pytest.fixture
def installed_smoke(tmp_path, monkeypatch):
    root = tmp_path / "installed"
    root.mkdir()
    (root / "package-info").write_text(f"source_commit={SOURCE}\nprofile=production\nplatform=linux-amd64\n")
    (root / "config.toml").write_text("")
    monkeypatch.setattr(smoke, "_cli_identity", lambda _: {
        "profile": "production", "source_revision": SOURCE, "sha256": "c" * 64})
    monkeypatch.setattr(smoke, "check_sandbox", lambda _: {"backend": "gvisor", "platform": "systrap"})
    workspace = tmp_path / "workspace"
    output = tmp_path / "reports/claude.json"
    state = {"failure": None, "calls": [], "cleanup": []}

    def execute(arguments, **options):
        label = arguments[3:]
        state["calls"].append(label)
        stdout = b""
        if label[:2] == ["agent", "create"]:
            home = root / "agents/bbtest/home"
            (home / ".safeyolo").mkdir(parents=True)
            (home / ".claude/skills").mkdir(parents=True)
            (root / "assets/docs").mkdir(parents=True)
            (root / "assets/docs/AGENTS.md").write_text("baseline")
            (home / ".safeyolo/AGENTS.md").write_text("baseline")
            (home / ".safeyolo-command").write_text("unchanged staged command")
            (home / ".safeyolo-command").chmod(0o700)
            (home / ".claude/skills/safeyolo").symlink_to("/safeyolo/skills/safeyolo")
            (home / ".claude.json").write_text(json.dumps({"hasCompletedOnboarding": True,
                "projects": {"/workspace": {"hasTrustDialogAccepted": True}}}))
            if state["failure"] == "missing-skill":
                (home / ".claude/skills/safeyolo").unlink()
            elif state["failure"] == "wrong-baseline":
                (home / ".safeyolo/AGENTS.md").write_text("wrong")
            elif state["failure"] == "wrong-config":
                (home / ".claude.json").write_text("{}")
        elif label[:2] == ["agent", "start"]:
            (root / "agents/bbtest/runtime.json").write_text(json.dumps(RUNTIME))
        elif label[:2] == ["agent", "shell"]:
            script = label[-1]
            if script.endswith("--version"):
                stdout = b"2.1.306 (Claude Code)\n"
            elif "od -An" in script:
                if state["failure"] == "unreadable-skill":
                    return subprocess.CompletedProcess(arguments, 1, b"", b"private failure")
                stdout = (("d" * 64 + "  /native/claude\n")
                          + smoke.sha256(b"baseline") + "  /home/agent/.safeyolo/AGENTS.md\n"
                          + "e" * 64 + "  /home/agent/.claude/skills/safeyolo/SKILL.md\n"
                          + "# Operate inside SafeYolo\n").encode()
            else:
                assert script == smoke.GATEWAY_LAUNCH
                assert options["input"] == smoke.TASK.encode()
                if state["failure"] == "timeout":
                    raise subprocess.TimeoutExpired(arguments, options["timeout"], output=b"private timeout")
                if state["failure"] in {"auth", "client-exit"}:
                    return subprocess.CompletedProcess(arguments, 1, b"API Error: 401 private-provider-secret", b"")
                marker = (workspace / "claude-smoke-marker.txt").read_text()
                if state["failure"] != "absent-output":
                    (workspace / smoke.RESULT).write_text(
                        "wrong" if state["failure"] == "wrong-output" else marker + "# Operate inside SafeYolo\n")
                (root / "logs").mkdir()
                (root / "logs/audit.jsonl").write_text(json.dumps(gateway()) + "\n")
                stdout = "\n".join(json.dumps(row) for row in events()).encode()
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    monkeypatch.setattr(smoke.subprocess, "run", execute)
    monkeypatch.setattr(smoke, "cleanup_instance", lambda *_: state["cleanup"])
    return root, workspace, output, state


@pytest.mark.parametrize("failure", [None, "missing-skill", "wrong-baseline", "wrong-config", "unreadable-skill",
                                     "auth", "client-exit", "timeout", "wrong-output", "absent-output"])
def test_completed_instrument_cannot_turn_reached_failures_into_success(installed_smoke, failure):
    root, workspace, output, state = installed_smoke
    state["failure"] = failure
    code = smoke.run(root, workspace, "host-subscription", output, 1)
    report = json.loads(output.read_bytes())
    assert code == (0 if failure is None else 1)
    assert report["status"] == ("passed" if failure is None else "failed")
    assert report["cleanup"] == "stopped"
    assert report["model_attempts"] <= 1
    assert "private" not in output.read_text()
    if failure in {"missing-skill", "wrong-baseline", "wrong-config", "unreadable-skill"}:
        assert report["model_attempts"] == 0
    if failure == "timeout":
        assert report["steps"][-1]["timed_out"]
    if failure in {"auth", "client-exit"}:
        assert report["steps"][-1]["http_statuses"] == [401]


def test_cleanup_failure_keeps_completed_task_but_fails_the_run(installed_smoke):
    root, workspace, output, state = installed_smoke
    state["cleanup"] = ["owned process still live"]
    assert smoke.run(root, workspace, "host-subscription", output, 1) == 2
    report = json.loads(output.read_bytes())
    assert report["task"]["successful_task"]
    assert report["status"] == "failed"
    assert report["cleanup"] == "failed"


def test_existing_agent_home_is_rejected_before_mutation(installed_smoke):
    root, workspace, output, state = installed_smoke
    (root / "agents/operator/home").mkdir(parents=True)
    assert smoke.run(root, workspace, "host-subscription", output, 1) == 1
    assert not state["calls"]
    assert not workspace.exists()
    assert json.loads(output.read_bytes())["cleanup"] is None


def test_prepared_retained_claude_uses_selection_verification_before_execution(tmp_path, monkeypatch):
    selection = tmp_path / "selection.json"
    selection.write_text(json.dumps({"schema": "safeyolo.blackbox-inputs/v1", "status": "selected",
                                     "host": {"source_revision": SOURCE}}))
    seen = []
    monkeypatch.setattr(retained_inputs, "controller_identity", lambda: {})
    monkeypatch.setattr(retained_inputs, "verify_installed", lambda *args: seen.append("verified"))

    def execute(arguments, **_options):
        assert seen == ["verified"]
        assert "--prepared-config" in arguments
        assert arguments[arguments.index("--install-commit") + 1] == SOURCE
        seen.append("executed")
        return subprocess.CompletedProcess(arguments, 1)

    monkeypatch.setattr(retained_inputs.subprocess, "run", execute)
    assert retained_inputs.run(selection, "systrap", tmp_path / "reports", ["claude"], False,
                               prepared_config=tmp_path / "installed") == 1
    assert seen == ["verified", "executed"]
    report = json.loads((tmp_path / "reports/retained-run.json").read_bytes())
    assert report["reused_installation"] and report["exit"] == 1
    assert report["guest_input_mode"] == "prepared-installation"


def test_claude_is_explicit_and_does_not_change_credential_free_defaults():
    assert "claude" in installed_sections.OPTIONAL_SECTIONS["systrap"]
    assert all("claude" not in sections for sections in installed_sections.SECTIONS.values())


@pytest.mark.parametrize("cleanup_failed", [False, True])
def test_installed_section_uses_provisioned_root_and_preserves_cleanup_failure(tmp_path, monkeypatch, cleanup_failed):
    source = tmp_path / "prepared"
    calls = []

    def execute(arguments, **_options):
        calls.append(arguments)
        assert arguments[1].endswith("claude_smoke.py")
        assert arguments[arguments.index("--root") + 1] == str(source)
        assert arguments[arguments.index("--credential") + 1] == "host-subscription"
        report = tmp_path / "reports/claude/claude-smoke.json"
        report.write_text(json.dumps({"cleanup_failures": ["still live"] if cleanup_failed else [],
                                      "cleanup": "failed" if cleanup_failed else "stopped"}))
        return subprocess.CompletedProcess(arguments, 2 if cleanup_failed else 0)

    monkeypatch.setenv("SAFEYOLO_CLAUDE_SMOKE_CREDENTIAL", "host-subscription")
    monkeypatch.setattr(installed_sections.subprocess, "run", execute)
    sections = ("claude", "isolation") if cleanup_failed else ("claude",)
    result = installed_sections.run_sections("systrap", sections, tmp_path, SOURCE,
                                             tmp_path / "state", tmp_path / "reports", prepared_config=source)
    assert result == (2 if cleanup_failed else 0)
    assert len(calls) == 1
    row = json.loads((tmp_path / "reports/installed-sections.json").read_bytes())["sections"][0]
    assert row["result"] == ("cleanup_failure" if cleanup_failed else "passed")
