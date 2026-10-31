"""Focused host-wrapper and oracle controls; these never run a model or sandbox."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from scripts.accept_herdr_native import (
    Journey,
    JourneyError,
    check_continuity,
    check_initial,
    prepared_agents,
    prompt_for,
    rollout_turn,
    turn_proof,
)

ROOT = Path(__file__).resolve().parents[1]
STATUS = {"name": "first", "agent_id": "ag-first", "run_id": "run-first", "launch_id": None,
          "runtime_state": "running", "control_state": "ready", "agent_state": "stopped",
          "terminal_state": "absent", "harness": "codex"}


def wait_for(check):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.02)
    pytest.fail("fixture observation timed out")


@pytest.fixture
def herdr_socket(tmp_path):
    calls = []
    stop = threading.Event()
    path = tmp_path / "herdr.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen()
        listener.settimeout(0.05)

        def serve():
            while not stop.is_set():
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                with connection, connection.makefile("rb") as stream:
                    request = json.loads(stream.readline())
                    calls.append(request)
                    connection.sendall(b'{"id":"safeyolo","result":{}}\n')

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield path, calls
        finally:
            stop.set()
            thread.join(timeout=2)
            assert not thread.is_alive()


@pytest.fixture
def native_cli(tmp_path):
    path = tmp_path / "native"
    path.write_text(f"#!{sys.executable}\n" + '''
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[2])
operation = sys.argv[4]
if operation == "status":
    marker = root / "status-called"
    if os.environ.get("FAIL_LATER_STATUS") and marker.exists():
        raise SystemExit(9)
    marker.touch()
    status = ''' + repr(STATUS) + '''
    if (root / "stopped").exists():
        status.update(runtime_state="stopped", agent_state="stopped", terminal_state="absent")
    print(json.dumps(status))
elif operation == "stop":
    (root / "stop-called").touch()
    if not os.environ.get("STOP_INCOMPLETE"):
        (root / "stopped").touch()
    print("{}")
else:
    (root / "command.json").write_text(json.dumps({
        "args": sys.argv[3:],
        "herdr_controls_absent": not any(k.startswith("HERDR_") for k in os.environ),
        "outer_tmux_absent": "TMUX_PANE" not in os.environ and "TMUX" not in os.environ,
        "ca_preserved": os.environ.get("SSL_CERT_FILE") == os.environ.get("EXPECTED_CA"),
    }))
    print("NATIVE_TERMINAL_READY", flush=True)
    input()
    print("NATIVE_TERMINAL_EXIT", flush=True)
    raise SystemExit(7)
''')
    path.chmod(0o755)
    return path


@pytest.mark.parametrize("attach", [False, True])
def test_wrapper_delegates_real_stdio_and_exit_without_claiming_idle(tmp_path, native_cli, herdr_socket, attach):
    socket_path, calls = herdr_socket
    environment = dict(os.environ, HERDR_SOCKET_PATH=str(socket_path), HERDR_PANE_ID="w1:p1",
                       HERDR_ENV="1", EXPECTED_CA=os.environ.get("SSL_CERT_FILE", ""),
                       TMUX="unrelated", TMUX_PANE="%99")
    args = [sys.executable, str(ROOT / "scripts/safeyolo_herdr.py"), "first",
            "--safeyolo", str(native_cli), "--root", str(tmp_path)]
    if attach:
        args.append("--attach")
    process = subprocess.Popen(args, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        wait_for(lambda: (tmp_path / "command.json").exists())
        os.kill(process.pid, signal.SIGINT)
        time.sleep(0.1)
        assert process.poll() is None
        stdout, stderr = process.communicate("finish\n", timeout=10)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    assert process.returncode == 7
    assert "NATIVE_TERMINAL_READY" in stdout and "NATIVE_TERMINAL_EXIT" in stdout
    assert not stderr
    invocation = json.loads((tmp_path / "command.json").read_text())
    expected = ["agent", "attach", "first"] if attach else ["agent", "start", "first", "--foreground"]
    assert invocation["args"] == expected
    assert invocation["herdr_controls_absent"] and invocation["outer_tmux_absent"] and invocation["ca_preserved"]
    reports = [call["params"] for call in calls if call["method"] == "pane.report_agent"]
    assert reports and all(report["state"] == "unknown" for report in reports)
    metadata = [call["params"] for call in calls if call["method"] == "pane.report_metadata"]
    assert metadata[0]["tokens"]["agent_id"] == "ag-first"
    assert metadata[-1]["tokens"]["agent_id"] is None
    assert any(call["method"] == "pane.release_agent" for call in calls)


def test_failed_status_clears_metadata_and_preserves_terminal(tmp_path, native_cli, herdr_socket):
    socket_path, calls = herdr_socket
    environment = dict(os.environ, HERDR_SOCKET_PATH=str(socket_path), HERDR_PANE_ID="w1:p1",
                       FAIL_LATER_STATUS="1")
    process = subprocess.Popen([sys.executable, str(ROOT / "scripts/safeyolo_herdr.py"), "first",
                                "--safeyolo", str(native_cli), "--root", str(tmp_path)], env=environment,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_for(lambda: any(call["method"] == "pane.report_metadata"
                             and call["params"]["tokens"]["agent_id"] is None for call in calls))
        assert process.poll() is None
        _stdout, stderr = process.communicate("finish\n", timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode == 7
    assert "native status unavailable" in stderr


def write_rollout(path: Path, items: list[dict]) -> None:
    path.write_text("".join(json.dumps(item) + "\n" for item in items))


def message(role: str, text: str) -> dict:
    return {"type": "response_item", "payload": {"type": "message", "role": role,
            "content": [{"type": "input_text" if role == "user" else "output_text", "text": text}]}}


def test_oracle_requires_received_prompt_tool_assistant_and_workspace_receipt(tmp_path):
    prompt, answer = prompt_for("unpredictable-token", "receipt", False)
    assert answer not in prompt
    continuation, next_answer = prompt_for("unpredictable-token", "different-receipt", True)
    assert "unpredictable-token" not in continuation and next_answer not in continuation
    rollout, receipt = tmp_path / "rollout.jsonl", tmp_path / "receipt"
    meta = {"type": "session_meta", "payload": {"id": "thread-first", "cli_version": "0.164.0"}}
    tool = {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec"}}
    items = [meta, message("user", prompt), tool, message("assistant", answer)]
    write_rollout(rollout, items)
    assert turn_proof([rollout], prompt, answer, receipt) is None
    receipt.write_text(answer + "\n")
    proof = turn_proof([rollout], prompt, answer, receipt)
    assert proof["session_id"] == "thread-first" and proof["assistant_answer_observed"]
    for rejected in (
        [meta, message("user", prompt), message("assistant", answer)],
        [meta, tool, message("assistant", answer)],
        [meta, message("user", prompt), tool, message("user", answer)],
        [meta, message("user", prompt), tool,
         {"type": "response_item", "payload": {"type": "function_call_output", "output": answer}}],
        [meta, message("user", prompt), tool, message("assistant", prompt)],
    ):
        write_rollout(rollout, rejected)
        assert rollout_turn(rollout, prompt, answer) is None


def test_rollout_reader_waits_for_complete_line_and_rejects_other_version(tmp_path):
    path = tmp_path / "rollout.jsonl"
    path.write_text('{"type":')
    assert rollout_turn(path, "prompt", "answer") is None
    write_rollout(path, [{"type": "session_meta", "payload": {"id": "thread", "cli_version": "other"}}])
    with pytest.raises(JourneyError, match="version"):
        rollout_turn(path, "prompt", "answer")


def test_initial_running_sandbox_is_not_a_coding_command_and_continuity_catches_restarts():
    check_initial(STATUS, STATUS)
    live = dict(STATUS, launch_id="launch-first", agent_state="running", terminal_state="running")
    check_continuity(live, live)
    with pytest.raises(JourneyError, match="coding command"):
        check_continuity(live, dict(live, agent_state="stopped"))
    for field in ("agent_id", "run_id", "launch_id"):
        with pytest.raises(JourneyError, match="identity"):
            check_continuity(live, dict(live, **{field: "replacement"}))
    with pytest.raises(JourneyError, match="do not replay"):
        check_initial(STATUS, live)
    with pytest.raises(JourneyError, match="no coding command"):
        check_initial(dict(STATUS, agent_state="running"), dict(STATUS, agent_state="running"))


def test_preparation_uses_native_status_and_keeps_distinct_sandboxes():
    second = dict(STATUS, name="second", agent_id="ag-second", run_id="run-second")
    preparation = {"preflight": [
        {"command": ["safeyolo", "agent", "status", item["name"]], "exit": 0, "stdout": json.dumps(item)}
        for item in (STATUS, second)
    ]}
    assert list(prepared_agents(preparation)) == ["first", "second"]
    preparation["preflight"][1]["stdout"] = json.dumps(dict(second, agent_id=STATUS["agent_id"]))
    with pytest.raises(JourneyError, match="identities must differ"):
        prepared_agents(preparation)


def test_cleanup_preserves_a_changed_generation(tmp_path, native_cli):
    expected = dict(STATUS, run_id="previous-run")
    preparation = {"route": {"cli": str(native_cli), "root": str(tmp_path), "native_source": "source"},
                   "herdr": {"path": "unused"}, "preflight": [
                       {"command": ["safeyolo", "agent", "status", "first"], "exit": 0,
                        "stdout": json.dumps(expected)},
                       {"command": ["safeyolo", "agent", "status", "second"], "exit": 0,
                        "stdout": json.dumps(dict(STATUS, name="second", agent_id="ag-second", run_id="run-second"))},
                   ]}
    journey = Journey(preparation, tmp_path, 1)
    journey.owned = ["first"]
    assert journey.cleanup() is False
    assert "changed native generation" in journey.result["cleanup"]["first"]["error"]
    assert not (tmp_path / "command.json").exists()  # No stop was sent to the replacement.


@pytest.mark.parametrize("incomplete", [False, True])
def test_cleanup_checks_stopped_state_after_successful_stop(tmp_path, native_cli, monkeypatch, incomplete):
    if incomplete:
        monkeypatch.setenv("STOP_INCOMPLETE", "1")
    preparation = {"route": {"cli": str(native_cli), "root": str(tmp_path), "native_source": "source"},
                   "herdr": {"path": "unused"}, "preflight": [
                       {"command": ["safeyolo", "agent", "status", item["name"]], "exit": 0,
                        "stdout": json.dumps(item)} for item in (
                            STATUS, dict(STATUS, name="second", agent_id="ag-second", run_id="run-second"))]}
    journey = Journey(preparation, tmp_path, 1)
    journey.owned = ["first"]
    assert journey.cleanup() is not incomplete
    assert (tmp_path / "stop-called").exists()
    if incomplete:
        assert "stop is incomplete" in journey.result["cleanup"]["first"]["error"]
    else:
        assert journey.result["cleanup"]["first"]["runtime_state"] == "stopped"
