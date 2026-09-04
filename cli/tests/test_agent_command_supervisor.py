"""Acceptance boundaries for host-side detached-command supervision."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import create_autospec, patch

from typer.testing import CliRunner

from safeyolo import agent_command_supervisor as supervisor
from safeyolo.cli import app
from safeyolo.config import get_agent_command_supervisor_state_path
from safeyolo.platform import AgentPlatform


class _Process:
    def __init__(self, returncode: int, stderr: str | bytes = "") -> None:
        self.returncode = returncode
        self.stdin = io.StringIO()
        self.stdout = io.StringIO("ordinary output\n")
        self.stderr = io.BytesIO(stderr) if isinstance(stderr, bytes) else io.StringIO(stderr)
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


class _TimedProcess(_Process):
    def __init__(self, returncode: int, clock: list[float], duration: float) -> None:
        super().__init__(returncode)
        self.clock = clock
        self.duration = duration

    def wait(self):
        self.clock[0] += self.duration
        return super().wait()


class _CallbackProcess(_Process):
    def __init__(self, returncode: int, callback) -> None:
        super().__init__(returncode)
        self.callback = callback

    def wait(self):
        self.callback()
        return super().wait()


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

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        if len(sleeps) == 2:
            # A clean exit is still unexpected and schedules another attempt;
            # the operator stop arrives before that attempt is launched.
            supervisor._write_json(
                get_agent_command_supervisor_state_path("demo").with_name(
                    "command-supervisor.stop"
                ),
                {"name": "demo", "requested_at": "test"},
            )

    result = supervisor.CommandSupervisor(
        "demo",
        "exec codex --resume checkpoint",
        platform=platform,
        sleep=sleep,
    ).run()

    assert result == 0
    assert platform.commands == [
        ("demo", "exec codex --resume checkpoint", "agent"),
        ("demo", "exec codex --resume checkpoint", "agent"),
    ]
    assert sleeps == [supervisor.INITIAL_BACKOFF_SECONDS, 0.5]
    state = _state(tmp_config_dir, "demo")
    assert state["state"] == "stopped"
    assert state["last_exit_code"] == 0
    assert state["last_exit_reason"] == "command-exit-clean"
    assert state["restart_count"] == 2


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


def test_stable_uptime_resets_persisted_failure_window(tmp_config_dir):
    _seed_state(tmp_config_dir, "demo", "exec worker")
    state = _state(tmp_config_dir, "demo")
    state.update(consecutive_failures=2, restart_count=7, failure_window_started_at=0.0)
    supervisor._write_json(get_agent_command_supervisor_state_path("demo"), state)
    clock = [0.0]
    platform = _Platform([
        _TimedProcess(2, clock, 61.0),
        _TimedProcess(2, clock, 0.0),
        _TimedProcess(2, clock, 0.0),
    ])

    result = supervisor.CommandSupervisor(
        "demo",
        "exec worker",
        platform=platform,
        now=lambda: clock[0],
        sleep=lambda _delay: None,
        max_failures=3,
    ).run()

    assert result == 2
    state = _state(tmp_config_dir, "demo")
    assert len(platform.commands) == 3
    assert state["state"] == "failed"
    assert state["consecutive_failures"] == 3
    assert state["restart_count"] == 10
    assert state["last_uptime_seconds"] == 0.0


def test_restart_restores_failure_budget_from_checkpoint(tmp_config_dir):
    _seed_state(tmp_config_dir, "demo", "exec worker")
    state = _state(tmp_config_dir, "demo")
    state.update(consecutive_failures=4, restart_count=12)
    supervisor._write_json(get_agent_command_supervisor_state_path("demo"), state)

    result = supervisor.CommandSupervisor(
        "demo",
        "exec worker",
        platform=_Platform([_Process(9, "still failing")]),
        sleep=lambda _delay: None,
        max_failures=5,
    ).run()

    assert result == 9
    state = _state(tmp_config_dir, "demo")
    assert state["state"] == "failed"
    assert state["consecutive_failures"] == 5
    assert state["restart_count"] == 13


def test_stderr_capture_is_bounded_and_sanitized(tmp_config_dir):
    payload = b"A" * (supervisor.MAX_STDERR_BYTES + 4096) + b"\x1b[31msecret\x1b[0m\x01"
    _seed_state(tmp_config_dir, "demo", "exec worker")

    result = supervisor.CommandSupervisor(
        "demo",
        "exec worker",
        platform=_Platform([_Process(9, payload)]),
        sleep=lambda _delay: None,
        max_failures=1,
    ).run()

    assert result == 9
    state = _state(tmp_config_dir, "demo")
    assert state["last_stderr_bytes"] == len(payload)
    assert state["last_stderr_truncated"] is True
    assert len(state["last_stderr"].encode()) <= supervisor.MAX_STDERR_BYTES
    assert "\x1b" not in state["last_stderr"]
    assert "\\x01" in state["last_stderr"]
    assert state["last_stderr_sha256"]


def test_restart_reconciles_checkpointed_terminal_without_duplicate_response(
    tmp_config_dir, tmp_path, monkeypatch
):
    """The outer runtime restart leaves Coord reconciliation exactly once."""
    coord_path = Path(__file__).resolve().parents[2] / "contrib/codex-coord-supervisor.py"
    spec = importlib.util.spec_from_file_location("coord_supervisor_for_runtime_test", coord_path)
    assert spec is not None and spec.loader is not None
    coord = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = coord
    spec.loader.exec_module(coord)

    target = "https://example.test/runtime/544"
    attention_id = "attn-" + "c" * 32
    coord_state = coord.empty_state()
    coord_state_path = tmp_path / "coord-checkpoint.json"
    factory_config = coord.Config(
        agent_name="forge",
        rooms=("backlog",),
        coordinators=frozenset({"relay"}),
        agent_room="forge-agent",
        factory_name="backlog",
        factory_role="owner",
        factory_roles=(("coordinator", "relay"), ("owner", "forge")),
        factory_handoffs=(
            coord.Handoff("TASK", "coordinator", "owner", ("DONE",), ("coordinator",)),
        ),
        factory_operator_role="coordinator",
        factory_operator_types=("DIRECTION",),
        contract_sha256="a" * 64,
    )
    task = {
        "edge": {
            "attention_id": attention_id,
            "room_id": "room-1",
            "kind": "message",
            "object_id": "message-1",
            "revision_or_sequence": 1,
        },
        "object": {
            "msg_id": "message-1",
            "sender_kind": "agent",
            "sender_agent_id": "agent-relay",
            "sender_agent_name": "relay",
            "content_type": "text/plain",
            "body": f"TASK target={target} assignee=forge",
            "sequence": 1,
        },
    }
    consumer = coord.EventConsumer(
        factory_config, coord_state, coord_state_path, {"room-1": "backlog"}
    )
    consumer.accept_attention_page([task], 1)
    coord.save_state(coord_state_path, coord_state)
    response = f"DONE target={target} attention_id={attention_id}"
    sent: list[str] = []

    def first_attempt():
        # The canonical send reached Coord, but the runtime died before its
        # local checkpoint cleanup. Reconciliation below is the recovery path.
        sent.append(response)

    def second_attempt():
        assert coord.load_state(coord_state_path)["in_flight"] == []
        supervisor._write_json(
            get_agent_command_supervisor_state_path("demo").with_name(
                "command-supervisor.stop"
            ),
            {"name": "demo", "requested_at": "test"},
        )

    platform = _Platform([
        _CallbackProcess(137, first_attempt),
        _CallbackProcess(0, second_attempt),
    ])

    def reconcile_before_restart(delay: float) -> None:
        assert delay == supervisor.INITIAL_BACKOFF_SECONDS
        monkeypatch.setattr(
            coord,
            "_history_page",
            lambda _room, _cursor: {
                "messages": [{
                    "sender_kind": "agent",
                    "sender_agent_id": "agent-forge",
                    "sender_agent_name": "forge",
                    "body": response,
                }],
                "has_more": False,
                "next_cursor": 2,
            },
        )
        assert coord.reconcile_terminals(factory_config, coord_state) is True
        coord.save_state(coord_state_path, coord_state)

    _seed_state(tmp_config_dir, "demo", "exec codex --resume checkpoint")
    result = supervisor.CommandSupervisor(
        "demo",
        "exec codex --resume checkpoint",
        platform=platform,
        sleep=reconcile_before_restart,
    ).run()

    assert result == 0
    assert sent == [response]
    assert coord.load_state(coord_state_path)["in_flight"] == []


def test_guest_owner_restarts_command_and_retains_bounded_evidence(tmp_path):
    state_path = tmp_path / "command-supervisor.json"
    stop_path = tmp_path / "command-supervisor.stop"
    count_path = tmp_path / "attempts"
    cwd_path = tmp_path / "cwd"
    command = (
        f"count={shlex.quote(str(count_path))}; "
        "n=0; test -f \"$count\" && n=$(cat \"$count\"); n=$((n + 1)); "
        "printf '%s' \"$n\" > \"$count\"; "
        f"pwd > {shlex.quote(str(cwd_path))}; "
        "if [ \"$n\" -eq 1 ]; then "
        "printf '\033[31mfirst crash\033[0m\\n' >&2; exit 137; "
        "fi; "
        f"touch {shlex.quote(str(stop_path))}; exit 0"
    )
    supervisor._write_json(
        state_path,
        {
            **supervisor._base_state("demo", command),
            "runtime_owner": "guest-pid1",
        },
    )
    script = Path(__file__).resolve().parents[1] / "src/safeyolo/guest-command-supervisor.py"
    artifact_dir = tmp_path / "isolated-config-share"
    artifact_dir.mkdir()
    artifact = artifact_dir / script.name
    shutil.copy2(script, artifact)
    artifact.chmod(artifact.stat().st_mode | 0o111)
    result = subprocess.run(
        [sys.executable, str(artifact)],
        env={
            **os.environ,
            "SAFEYOLO_COMMAND_SUPERVISOR_STATE": str(state_path),
            "SAFEYOLO_COMMAND_SUPERVISOR_STOP": str(stop_path),
        },
        check=False,
        timeout=10,
    )

    assert result.returncode == 0
    assert count_path.read_text() == "2"
    assert cwd_path.read_text() == "/workspace\n"
    state = json.loads(state_path.read_text())
    assert state["state"] == "stopped"
    assert state["restart_count"] == 1
    assert state["last_stderr_truncated"] is False
    assert "\\x1b" not in state["last_stderr"]


def test_guest_owner_stop_marker_interrupts_live_command(tmp_path):
    state_path = tmp_path / "command-supervisor.json"
    stop_path = tmp_path / "command-supervisor.stop"
    script = Path(__file__).resolve().parents[1] / "src/safeyolo/guest-command-supervisor.py"
    artifact_dir = tmp_path / "isolated-config-share"
    artifact_dir.mkdir()
    artifact = artifact_dir / script.name
    shutil.copy2(script, artifact)
    artifact.chmod(artifact.stat().st_mode | 0o111)
    supervisor._write_json(
        state_path,
        {
            **supervisor._base_state("demo", "exec sleep 60"),
            "runtime_owner": "guest-pid1",
        },
    )
    process = subprocess.Popen(
        [sys.executable, str(artifact)],
        env={
            **os.environ,
            "SAFEYOLO_COMMAND_SUPERVISOR_STATE": str(state_path),
            "SAFEYOLO_COMMAND_SUPERVISOR_STOP": str(stop_path),
        },
    )
    try:
        deadline = time.monotonic() + 5
        state = None
        while time.monotonic() < deadline:
            state = json.loads(state_path.read_text())
            if state.get("state") == "running":
                break
            time.sleep(0.05)
        else:
            raise AssertionError(f"guest supervisor did not start: {state}")
        stop_path.write_text('{"name":"demo","requested_at":"test"}\n')
        assert process.wait(timeout=5) == 0
        state = json.loads(state_path.read_text())
        assert state["state"] == "stopped"
        assert state["last_exit_reason"] == "intentional-stop"
        assert state["command_pid"] is None
    finally:
        if process.poll() is None:
            process.kill()


def test_guest_pid1_path_restarts_command_and_reconciles_checkpoint_once(tmp_path):
    state_path = tmp_path / "command-supervisor.json"
    stop_path = tmp_path / "command-supervisor.stop"
    attempts_path = tmp_path / "attempts"
    started_path = tmp_path / "started"
    output_path = tmp_path / "responses"
    checkpoint_path = tmp_path / "coord-checkpoint.json"
    worker_path = tmp_path / "worker.py"
    target = "https://github.com/example/safeyolo/issues/544"
    attention_id = "attn-" + "d" * 32
    checkpoint_path.write_text(
        json.dumps(
            {
                "in_flight": [
                    {
                        "edge": {"attention_id": attention_id},
                        "object": {
                            "body": f"TASK target={target} assignee=forge"
                        },
                    }
                ]
            }
        )
    )
    worker_path.write_text(
        """
import json
import sys
import time
from pathlib import Path

attempts, started, output, checkpoint, stop = map(Path, sys.argv[1:])
count = int(attempts.read_text()) if attempts.exists() else 0
count += 1
attempts.write_text(str(count))
started.write_text(str(count))
if count == 1:
    while True:
        time.sleep(0.1)
data = json.loads(checkpoint.read_text())
task = data["in_flight"][0]
body = task["object"]["body"]
target = body.split("target=", 1)[1].split()[0]
attention_id = task["edge"]["attention_id"]
response = f"DONE target={target} attention_id={attention_id}"
if count == 2:
    if not output.exists():
        output.write_text(response + "\\n")
    raise SystemExit(137)
data["in_flight"] = []
checkpoint.write_text(json.dumps(data))
stop.write_text(json.dumps({"name": "demo", "requested_at": "worker"}))
""".lstrip()
    )
    script = Path(__file__).resolve().parents[1] / "src/safeyolo/guest-command-supervisor.py"
    artifact_dir = tmp_path / "isolated-config-share"
    artifact_dir.mkdir()
    artifact = artifact_dir / script.name
    shutil.copy2(script, artifact)
    artifact.chmod(artifact.stat().st_mode | 0o111)
    supervisor._write_json(
        state_path,
        {
            **supervisor._base_state("demo", f"exec python3 {worker_path} {attempts_path} {started_path} {output_path} {checkpoint_path} {stop_path}"),
            "runtime_owner": "guest-pid1",
        },
    )
    source = (
        Path(__file__).resolve().parents[1] / "src/safeyolo/guest-init-per-run.sh"
    ).read_text()
    owner_fragment = source[
        source.index("COMMAND_SUPERVISOR_PID=") : source.index(
            "# All per-run setup is complete."
        )
    ]
    owner_fragment = owner_fragment.replace(
        "COMMAND_SUPERVISOR_STATE=/home/agent/.safeyolo-command-supervisor.json",
        f"COMMAND_SUPERVISOR_STATE={state_path}",
    ).replace(
        "COMMAND_SUPERVISOR_STOP=/home/agent/.safeyolo-command-supervisor.stop",
        f"COMMAND_SUPERVISOR_STOP={stop_path}",
    ).replace(
        "COMMAND_SUPERVISOR_SCRIPT=/run/safeyolo/guest-command-supervisor.py",
        f"COMMAND_SUPERVISOR_SCRIPT={artifact}",
    )
    owner_fragment = owner_fragment.replace(
        "exec python3 '$COMMAND_SUPERVISOR_SCRIPT'",
        "export SAFEYOLO_COMMAND_SUPERVISOR_STATE='$COMMAND_SUPERVISOR_STATE'; "
        "export SAFEYOLO_COMMAND_SUPERVISOR_STOP='$COMMAND_SUPERVISOR_STOP'; "
        "exec python3 '$COMMAND_SUPERVISOR_SCRIPT'",
    )
    # The test already runs as the guest agent uid; production PID 1 uses
    # `su agent` because it starts as root.
    owner_fragment = owner_fragment.replace(
        "setsid su agent -s /bin/bash -c \\",
        "setsid bash -c \\",
    )
    owner_fragment += (
        "\nexport SAFEYOLO_COMMAND_SUPERVISOR_STATE SAFEYOLO_COMMAND_SUPERVISOR_STOP\n"
        "SAFEYOLO_COMMAND_SUPERVISOR_STATE=\"$COMMAND_SUPERVISOR_STATE\"\n"
        "SAFEYOLO_COMMAND_SUPERVISOR_STOP=\"$COMMAND_SUPERVISOR_STOP\"\n"
        "keep_pid1_alive\n"
    )
    owner_script = tmp_path / "guest-pid1-owner.sh"
    owner_script.write_text(owner_fragment)
    owner = subprocess.Popen(
        ["/bin/bash", str(owner_script)],
        stderr=subprocess.PIPE,
        env={**os.environ, "SAFEYOLO_COMMAND_SUPERVISED": "1"},
    )
    try:
        deadline = time.monotonic() + 5
        state = None
        while time.monotonic() < deadline:
            state = json.loads(state_path.read_text())
            if state.get("state") == "running":
                break
            time.sleep(0.05)
        else:
            owner.terminate()
            error = owner.communicate(timeout=5)[1].decode()
            raise AssertionError(
                f"guest PID-1 owner did not start: {state}; "
                f"owner_rc={owner.returncode}; stderr={error!r}"
            )
        owner_pid = owner.pid
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if started_path.exists() and started_path.read_text() == "1":
                break
            time.sleep(0.05)
        else:
            raise AssertionError("guest command did not reach its first attempt")
        first_supervisor_pid = state["supervisor_pid"]
        first_command_pid = state["command_pid"]
        os.killpg(first_command_pid, signal.SIGKILL)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = json.loads(state_path.read_text())
            if state.get("state") == "stopped" and output_path.exists():
                break
            time.sleep(0.05)
        else:
            raise AssertionError(f"guest PID-1 recovery did not finish: {state}")

        assert owner.poll() is None
        assert owner.pid == owner_pid
        assert state["supervisor_pid"] == first_supervisor_pid
        assert state["command_pid"] is None
        assert attempts_path.read_text() == "3"
        assert output_path.read_text() == (
            f"DONE target={target} attention_id={attention_id}\n"
        )
        assert json.loads(checkpoint_path.read_text())["in_flight"] == []
    finally:
        if owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=5)


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


def test_start_publishes_command_for_guest_pid1_owner(tmp_config_dir):
    supervisor.start_command_supervisor("demo", "exec worker")

    assert _state(tmp_config_dir, "demo")["command"] == "exec worker"
    assert _state(tmp_config_dir, "demo")["runtime_owner"] == "guest-pid1"


def test_agent_stop_records_intent_even_when_sandbox_is_already_gone(
    tmp_config_dir,
):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = False
    with (
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch(
            "safeyolo.agent_command_supervisor.request_command_supervisor_stop",
            return_value=True,
            autospec=True,
        ) as request_stop,
    ):
        result = CliRunner().invoke(app, ["agent", "stop", "demo"])

    assert result.exit_code == 0, result.output
    request_stop.assert_called_once_with("demo")
    assert "command supervisor stopped" in result.output


def test_guest_owned_stop_fence_does_not_block_sandbox_cleanup(tmp_config_dir):
    _seed_state(tmp_config_dir, "demo", "exec worker")
    state = _state(tmp_config_dir, "demo")
    state.update(
        state="running",
        runtime_owner="guest-pid1",
        supervisor_pid=999999,
        heartbeat_at=time.time(),
    )
    supervisor._write_json(get_agent_command_supervisor_state_path("demo"), state)

    assert supervisor.request_command_supervisor_stop("demo") is True
    assert get_agent_command_supervisor_state_path("demo").with_name(
        "command-supervisor.stop"
    ).exists()


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
