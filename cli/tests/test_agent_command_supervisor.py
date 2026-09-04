"""Acceptance boundaries for host-side detached-command supervision."""

from __future__ import annotations

import io
import json
from unittest.mock import create_autospec, patch

from typer.testing import CliRunner

from safeyolo import agent_command_supervisor as supervisor
from safeyolo.cli import app
from safeyolo.config import get_agent_command_supervisor_state_path
from safeyolo.platform import AgentPlatform


class _Process:
    def __init__(self, returncode: int, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdin = io.StringIO()
        self.stdout = io.StringIO("ordinary output\n")
        self.stderr = io.StringIO(stderr)
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


class _Platform:
    def __init__(self, processes: list[_Process]) -> None:
        self.processes = processes
        self.commands: list[tuple[str, str, str]] = []

    def popen_in_sandbox(self, name, command, user="agent"):
        self.commands.append((name, command, user))
        return self.processes.pop(0)


def _seed_state(tmp_config_dir, name: str, command: str) -> None:
    path = get_agent_command_supervisor_state_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    supervisor._write_json(path, supervisor._base_state(name, command))


def _state(tmp_config_dir, name: str) -> dict:
    return json.loads(get_agent_command_supervisor_state_path(name).read_text())


def test_unexpected_exit_restarts_same_command_without_restarting_sandbox(tmp_config_dir):
    _seed_state(tmp_config_dir, "demo", "exec codex --resume checkpoint")
    platform = _Platform([_Process(137, "killed while processing\n"), _Process(0)])
    sleeps: list[float] = []

    result = supervisor.CommandSupervisor(
        "demo",
        "exec codex --resume checkpoint",
        platform=platform,
        sleep=sleeps.append,
    ).run()

    assert result == 0
    assert platform.commands == [
        ("demo", "exec codex --resume checkpoint", "agent"),
        ("demo", "exec codex --resume checkpoint", "agent"),
    ]
    assert sleeps == [supervisor.INITIAL_BACKOFF_SECONDS]
    state = _state(tmp_config_dir, "demo")
    assert state["state"] == "exited"
    assert state["last_exit_code"] == 0
    assert state["restart_count"] == 1


def test_crash_loop_is_terminal_and_retains_exit_stderr(tmp_config_dir):
    _seed_state(tmp_config_dir, "demo", "exec worker")
    platform = _Platform([_Process(2, "configuration is invalid") for _ in range(3)])

    result = supervisor.CommandSupervisor(
        "demo",
        "exec worker",
        platform=platform,
        sleep=lambda _delay: None,
        max_failures=3,
    ).run()

    assert result == 2
    state = _state(tmp_config_dir, "demo")
    assert state["state"] == "failed"
    assert state["consecutive_failures"] == 3
    assert state["last_exit_code"] == 2
    assert state["last_stderr"] == "configuration is invalid"
    assert state["next_restart_at"] is None


def test_stop_intent_prevents_restart_after_command_crash(tmp_config_dir):
    _seed_state(tmp_config_dir, "demo", "exec worker")
    platform = _Platform([_Process(143, "terminated")])

    def request_stop(_delay: float) -> None:
        supervisor._write_json(
            get_agent_command_supervisor_state_path("demo").with_name(
                "command-supervisor.stop"
            ),
            {"name": "demo", "requested_at": "test"},
        )

    supervisor.CommandSupervisor(
        "demo",
        "exec worker",
        platform=platform,
        sleep=request_stop,
    ).run()

    assert len(platform.commands) == 1
    assert _state(tmp_config_dir, "demo")["state"] == "stopped"


def test_start_writes_command_and_launches_independent_host_process(
    tmp_config_dir, monkeypatch
):
    class _Launcher:
        returncode = None

        def poll(self):
            return self.returncode

    launches = []
    monkeypatch.setattr(
        supervisor.subprocess,
        "Popen",
        lambda *args, **kwargs: (launches.append((args, kwargs)) or _Launcher()),
    )

    supervisor.start_command_supervisor("demo", "exec worker")

    assert launches[0][0] == (
        [
            supervisor.sys.executable,
            "-m",
            "safeyolo.agent_command_supervisor",
            "--run",
            "demo",
        ],
    )
    assert launches[0][1]["start_new_session"] is True
    assert launches[0][1]["stdin"] is supervisor.subprocess.DEVNULL
    assert _state(tmp_config_dir, "demo")["command"] == "exec worker"


def test_agent_stop_records_intent_even_when_sandbox_is_already_gone(
    tmp_config_dir,
):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = False
    with (
        patch("safeyolo.platform.get_platform", return_value=platform),
        patch(
            "safeyolo.agent_command_supervisor.request_command_supervisor_stop",
            return_value=True,
        ) as request_stop,
    ):
        result = CliRunner().invoke(app, ["agent", "stop", "demo"])

    assert result.exit_code == 0, result.output
    request_stop.assert_called_once_with("demo")
    assert "command supervisor stopped" in result.output


def test_agent_diag_exposes_crash_loop_exit_and_stderr(tmp_config_dir):
    from safeyolo.agent_diag import _check_command_supervisor

    _seed_state(tmp_config_dir, "demo", "exec worker")
    state_path = get_agent_command_supervisor_state_path("demo")
    state = _state(tmp_config_dir, "demo")
    state.update(
        state="failed",
        last_exit_code=17,
        last_stderr="worker configuration failed",
        consecutive_failures=5,
    )
    supervisor._write_json(state_path, state)

    result = _check_command_supervisor("demo")

    assert result.status == "FAIL"
    assert "crash loop" in result.message
    assert "exit=17" in result.message
    assert "worker configuration failed" in result.message
    assert "safeyolo agent run demo --detach" in result.remediation
