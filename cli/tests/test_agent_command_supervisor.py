"""Native guest supervisor and intentional-stop boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from safeyolo.agent_token import _write_text


def _write_json(path: Path, value: dict) -> None:
    _write_text(path, json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _guest_state(name: str, command: str) -> dict:
    return {
        "schema_version": 1,
        "name": name,
        "command": command,
        "state": "starting",
        "supervisor_pid": None,
        "supervisor_start_token": None,
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "restart_count": 0,
        "consecutive_failures": 0,
        "last_exit_code": None,
        "last_exit_signal": None,
        "last_exit_reason": None,
        "last_stderr": "",
        "last_stderr_bytes": 0,
        "last_stderr_truncated": False,
        "last_stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "last_uptime_seconds": None,
        "attempt_started_at": None,
        "failure_window_started_at": None,
        "heartbeat_at": None,
        "runtime_owner": "guest-pid1",
        "command_pid": None,
        "command_start_token": None,
        "next_restart_at": None,
    }


def _stage_guest_supervisor_artifact(tmp_path: Path) -> tuple[Path, Path]:
    """Use the built native helper with explicit isolated fixture paths."""
    binary = Path(os.environ.get("SAFEYOLO_GUEST_HELPER", str(Path(__file__).resolve().parents[2] / "guest/command/target/debug/safeyolo-guest")))
    artifact_dir = tmp_path / "isolated-config-share"
    artifact_dir.mkdir()
    workspace = tmp_path / "guest-workspace"
    workspace.mkdir()
    context = artifact_dir / "context.json"
    context.write_text(json.dumps({"generation": "test-generation"}))
    artifact = artifact_dir / "safeyolo-guest"
    artifact.write_text(f"#!/bin/sh\nexec {shlex.quote(str(binary))} --context {shlex.quote(str(context))} --workspace {shlex.quote(str(workspace))} \"$@\"\n")
    artifact.chmod(artifact.stat().st_mode | 0o111)
    return artifact, workspace


@pytest.mark.skipif(sys.platform != "linux", reason="Native guest processes use Linux /proc")
def test_guest_owner_restarts_command_and_retains_bounded_evidence(tmp_path):
    state_path = tmp_path / "command-supervisor.json"
    stop_path = tmp_path / ".safeyolo-command-supervisor.stop"
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
    _write_json(
        state_path,
        {
            **_guest_state("demo", command),
            "runtime_owner": "guest-pid1",
            "generation": "test-generation",
            "supervision_id": "guest-fixture",
        },
    )
    artifact, workspace = _stage_guest_supervisor_artifact(tmp_path)
    result = subprocess.run(
        [str(artifact), "supervise"],
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
    assert cwd_path.read_text() == f"{workspace}\n"
    state = json.loads(state_path.read_text())
    assert state["state"] == "stopped"
    assert state["restart_count"] == 1
    assert state["last_stderr_truncated"] is False
    assert "\\x1b" not in state["last_stderr"]


@pytest.mark.skipif(sys.platform != "linux", reason="Native guest processes use Linux /proc")
def test_guest_owner_stop_marker_interrupts_live_command(tmp_path):
    state_path = tmp_path / "command-supervisor.json"
    stop_path = tmp_path / ".safeyolo-command-supervisor.stop"
    artifact, _ = _stage_guest_supervisor_artifact(tmp_path)
    _write_json(
        state_path,
        {
            **_guest_state("demo", "exec sleep 60"),
            "runtime_owner": "guest-pid1",
            "generation": "test-generation",
            "supervision_id": "guest-fixture",
        },
    )
    process = subprocess.Popen(
        [str(artifact), "supervise"],
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


@pytest.mark.skipif(sys.platform != "linux", reason="Native guest processes use Linux /proc")
def test_guest_pid1_path_restarts_command_and_reconciles_checkpoint_once(tmp_path):
    state_path = tmp_path / "command-supervisor.json"
    stop_path = tmp_path / ".safeyolo-command-supervisor.stop"
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
    artifact, _ = _stage_guest_supervisor_artifact(tmp_path)
    _write_json(
        state_path,
        {
            **_guest_state("demo", f"exec python3 {worker_path} {attempts_path} {started_path} {output_path} {checkpoint_path} {stop_path}"),
            "runtime_owner": "guest-pid1",
            "generation": "test-generation",
            "supervision_id": "guest-fixture",
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
        "COMMAND_SUPERVISOR_SCRIPT=/run/safeyolo/safeyolo-guest",
        f"COMMAND_SUPERVISOR_SCRIPT={artifact}",
    )
    owner_fragment = owner_fragment.replace(
        "exec '$COMMAND_SUPERVISOR_SCRIPT' supervise",
        "export SAFEYOLO_COMMAND_SUPERVISOR_STATE='$COMMAND_SUPERVISOR_STATE'; "
        "export SAFEYOLO_COMMAND_SUPERVISOR_STOP='$COMMAND_SUPERVISOR_STOP'; "
        "exec '$COMMAND_SUPERVISOR_SCRIPT' supervise",
    )
    # The test already runs as the guest agent uid; production PID 1 uses
    # `su agent` because it starts as root.
    owner_fragment = owner_fragment.replace(
        "setsid su agent -s /bin/bash -c \\",
        "setsid bash -c \\",
    )
    enabled = tmp_path / "command-supervisor-enabled"
    enabled.touch()
    owner_fragment = owner_fragment.replace("/safeyolo/command-supervisor-enabled", str(enabled))
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
        env=dict(os.environ),
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


def test_guest_supervisor_retains_root_transition_caps_only_on_gvisor():
    source = (
        Path(__file__).resolve().parents[1]
        / "src/safeyolo/guest-init-per-run.sh"
    ).read_text()
    gvisor_start = source.index("*-gvisor)")
    gvisor_end = source.index(";;", gvisor_start)
    hardware_start = source.index("*)", gvisor_end)
    hardware_end = source.index(";;", hardware_start)
    gvisor = source[gvisor_start:gvisor_end]
    hardware = source[hardware_start:hardware_end]

    assert "setpriv --reuid=agent --regid=agent --clear-groups" in gvisor
    assert (
        "--inh-caps=+setuid,+setgid --ambient-caps=+setuid,+setgid"
        in gvisor
    )
    assert "su agent -s /bin/bash" not in gvisor
    assert "su agent -s /bin/bash" in hardware
    assert "setpriv" not in hardware


def test_agent_stop_records_intent_even_when_sandbox_is_already_gone(
    native_agent,
):
    directory = native_agent["root"] / "agents/demo"
    home, share = directory / "home", directory / "config-share"
    home.mkdir(parents=True)
    share.mkdir()
    state_path = home / ".safeyolo-command-supervisor.json"
    state_path.write_text(json.dumps({
        "schema_version": 1, "name": "demo", "state": "exited",
        "supervision_id": "previous-command", "command": "exec true",
        "command_pid": None, "command_start_token": None,
    }))
    original_state = state_path.read_bytes()
    enabled = share / "command-supervisor-enabled"
    enabled.touch()
    result = subprocess.run(
        [str(native_agent["cli"]), "--root", str(native_agent["root"]), "agent", "stop", "demo"],
        capture_output=True, text=True, timeout=5,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["runtime_state"] == "stopped"
    assert json.loads((home / ".safeyolo-command-supervisor.stop").read_text()) == {
        "supervision_id": "previous-command",
    }
    assert not enabled.exists()
    assert state_path.read_bytes() == original_state
