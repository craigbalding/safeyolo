"""Retained workflow callers delegate to the installed native lifecycle."""

import fcntl
import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from safeyolo import agent_lifecycle as lifecycle
from safeyolo.cli import app


def test_native_inventory_preserves_degraded_runtime_and_terminal_dimensions(monkeypatch):
    observed = {"agent_id": "ag-marker", "name": "marker", "runtime_state": "degraded",
                "control_state": "unavailable", "agent_state": "unknown", "terminal_state": "running"}
    monkeypatch.setattr(lifecycle, "_native_result", lambda _args: {"agents": [observed]})
    assert lifecycle.list_agent_runtimes() == [observed]


def test_missing_native_owner_cannot_start_a_python_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    with pytest.raises(lifecycle.AgentLifecycleError, match="Native CLI is missing"):
        lifecycle.start_native_agent("marker")


def test_workflow_child_uses_the_selected_lock_and_leaves_all_parent_locks_held(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    executable = tmp_path / "bin/safeyolo"
    executable.parent.mkdir()
    executable.write_text(
        f"#!{sys.executable}\n"
        "import fcntl,json,os,sys\n"
        "from pathlib import Path\n"
        "root=Path(sys.argv[2]); name=sys.argv[5]\n"
        "fd=int(os.environ['SAFEYOLO_HOST_SETUP_LOCK_FD'])\n"
        "assert os.fstat(fd).st_ino==(root/'agents'/name/'host-setup.lock').stat().st_ino\n"
        "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
        "(root/'arguments.json').write_text(json.dumps(sys.argv[3:]))\n"
    )
    executable.chmod(0o755)
    with lifecycle._agent_host_setup_lock("marker"), lifecycle._agent_host_setup_lock("other"):
        assert lifecycle.start_native_agent(
            "marker", launch_mode="background", agent_args=["--model", "fixture model", "--literal", "$(marker)"],
        ) == 0
        for name in ("marker", "other"):
            with (tmp_path / "agents" / name / "host-setup.lock").open("r+") as contender:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert json.loads((tmp_path / "arguments.json").read_text()) == [
        "agent", "start", "marker", "--", "--model", "fixture model", "--literal", "$(marker)",
    ]
    assert lifecycle._held_setup_locks() == {}
    for name in ("marker", "other"):
        with (tmp_path / "agents" / name / "host-setup.lock").open("r+") as contender:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize(("options", "expected"), [
    ({}, ["--foreground"]),
    ({"launch_mode": "sandbox", "dangerously_allow_unowned": True},
     ["--sandbox-only", "--dangerously-allow-unowned"]),
    ({"launch_mode": "background", "agent_args": []}, ["--"]),
])
def test_native_start_preserves_local_launch_selection_and_empty_argument_override(monkeypatch, options, expected):
    calls = []
    def invoke(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 19)
    monkeypatch.setattr(lifecycle, "_native_cli", invoke)
    assert lifecycle.start_native_agent("marker", **options) == 19
    assert calls == [(["agent", "start", "marker", *expected], {"setup_name": "marker"})]


def test_native_failure_does_not_become_stopped_or_trigger_python_cleanup(monkeypatch):
    monkeypatch.setattr(lifecycle, "_native_cli", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 1, "", "runtime identity is unknown"))
    with pytest.raises(lifecycle.AgentLifecycleError, match="runtime identity is unknown"):
        lifecycle.stop_agent_by_name("marker")


@pytest.mark.parametrize("output", ["{", "[]", "{}", '{"agents":false}', '{"agents":[false]}'])
def test_incomplete_native_inventory_is_an_error(monkeypatch, output):
    monkeypatch.setattr(lifecycle, "_native_cli", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, output, ""))
    with pytest.raises(lifecycle.AgentLifecycleError):
        lifecycle.list_agent_runtimes()


def test_retained_command_forwards_native_start_arguments_and_uses_start_verb(monkeypatch):
    calls = []
    def invoke(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 9)
    monkeypatch.setattr(lifecycle, "_native_cli", invoke)
    result = CliRunner().invoke(app, ["agent", "start", "marker", "--foreground", "--", "argument with spaces"])
    assert result.exit_code == 9, result.output
    assert calls == [(["agent", "start", "marker", "--foreground", "--", "argument with spaces"], {"setup_name": "marker"})]
    absent = CliRunner().invoke(app, ["agent", "run", "marker"])
    assert absent.exit_code != 0
    assert len(calls) == 1
