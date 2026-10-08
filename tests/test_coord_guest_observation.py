"""Challenge the witness reader; these controlled events are not a model run."""

import copy
import json
import os
import runpy
import shlex
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

witness = runpy.run_path(str(Path(__file__).parent / "nested-linux/operator_coord_acceptance.py"))
observe = witness["mcp_observation"]


def events():
    message = {"msg_id": "msg-one", "body": "exact marker", "sender_kind": "agent",
               "sender_agent_name": "bbtest", "sender_agent_id": "ag-primary"}
    results = ({"room_id": "room-one"}, {"envelope": message},
               {"messages": [message]}, {"messages": [message]})
    arguments = {"room_name": "owned-room", "body": "exact marker"}
    calls = [{"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "safeyolo-coord",
             "tool": tool, "status": "completed", "arguments": arguments.copy(),
             "result": {"structured_content": copy.deepcopy(result)}}}
            for tool, result in zip(("join_room", "send", "read_room", "wait_for_message"), results, strict=True)]
    return [{"type": "thread.started", "thread_id": "fixture-only"}, *calls, {"type": "turn.completed"}]


def read(rows):
    return observe("\n".join(json.dumps(row) for row in rows), "owned-room", "exact marker", "bbtest")


def test_mcp_results_require_matching_retained_caller_and_payload():
    result = read(events())
    assert result["message_id"] == "msg-one" and result["sender_agent_id"] == "ag-primary"
    rows = events()
    rows[3]["item"]["result"] = {"content": [{"type": "text", "text": json.dumps({"messages": [
        rows[2]["item"]["result"]["structured_content"]["envelope"]]})}]}
    assert read(rows)["message_id"] == "msg-one"


@pytest.mark.parametrize("fault", ("narration", "missing_wait", "failed", "server", "caller", "read", "duplicate_send", "order", "unfinished"))
def test_mcp_narration_incomplete_or_mismatched_calls_cannot_supply_observation(fault):
    rows = events()
    match fault:
        case "narration":
            rows = [{"type": "item.completed", "item": {"type": "agent_message", "text": "All calls succeeded"}}]
        case "missing_wait":
            rows.pop(-2)
        case "failed":
            rows[2]["item"]["result"]["isError"] = True
        case "server":
            rows[2]["item"]["server"] = "another-server"
        case "caller":
            rows[2]["item"]["result"]["structured_content"]["envelope"]["sender_agent_name"] = "bbpeer"
        case "read":
            rows[3]["item"]["result"]["structured_content"]["messages"][0]["body"] = "another marker"
        case "duplicate_send":
            rows.insert(3, copy.deepcopy(rows[2]))
        case "order":
            rows[2], rows[3] = rows[3], rows[2]
        case "unfinished":
            rows.pop()
    with pytest.raises(AssertionError):
        read(rows)


@pytest.mark.parametrize("fault", (None, "body", "msg_id", "caller", "order", "send_body"))
def test_guest_initial_reads_are_bound_to_both_send_envelopes(tmp_path, monkeypatch, fault):
    """Drive the actual journey with controlled identities; stop before any API send."""
    from tests.blackbox import installed_host_smoke, installed_ingress

    commit = "a" * 40
    version = f"safeyolo commit={commit} profile=debug"
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin/safeyolo-proxy").symlink_to(Path(f"/proc/{os.getpid()}/exe").resolve())
    (tmp_path / "data").mkdir()
    (tmp_path / "data/proxy-process.json").write_text(json.dumps({
        "pid": os.getpid(), "token": installed_host_smoke._process_start_token(os.getpid())}))
    monkeypatch.setattr(installed_host_smoke, "_agent_map", lambda root: [
        {"agent_id": name, "path": str(root / name / "proxy.sock")} for name in ("primary", "peer")])
    monkeypatch.setattr(installed_ingress, "runsc_identity", lambda root, name, listener, **kwargs: {
        "pid": 1 if name == "primary" else 2})
    monkeypatch.setattr(witness["subprocess"], "check_output", lambda *args, **kwargs: version)
    envelopes = []

    def command(*arguments, **kwargs):
        if arguments[:2] == ("agent", "status"):
            return json.dumps({"runtime_state": "running", "control_state": "ready"})
        if arguments[:2] == ("coord", "room"):
            return ""
        if arguments[:2] == ("coord", "grant"):
            return json.dumps({"agent_id": "ag-" + arguments[-1]})
        assert arguments[:2] == ("agent", "shell"), arguments
        name, script = arguments[2], arguments[-1]
        if script.endswith(" --version"):
            return version
        if "python3 -c " in script:
            raise RuntimeError("initial history accepted")
        words = shlex.split(script)
        payload = json.loads(words[words.index("|") - 1])
        match words[-1]:
            case "join_room" | "get_room_state":
                return json.dumps({"room_id": "room-one"})
            case "send":
                envelope = {"msg_id": f"msg-{len(envelopes)}", "body": payload["body"],
                            "sender_kind": "agent", "sender_agent_name": name, "sender_agent_id": "ag-" + name}
                if fault == "send_body":
                    envelope["body"] = "changed send body"
                envelopes.append(envelope)
                return json.dumps({"envelope": envelope})
            case "read_room":
                messages = copy.deepcopy(envelopes)
                for row in messages:
                    if fault in ("body", "msg_id"):
                        row[fault] = "changed " + row[fault]
                    elif fault == "caller":
                        row["sender_agent_id"] = "ag-foreign"
                if fault == "order":
                    messages.reverse()
                return json.dumps({"messages": messages})
        raise AssertionError(words)

    if fault is None:
        with pytest.raises(RuntimeError, match="initial history accepted"):
            witness["coordination_journey"](tmp_path, "primary", "peer", commit, command)
    else:
        with pytest.raises(AssertionError):
            witness["coordination_journey"](tmp_path, "primary", "peer", commit, command)


def session_cli(root, rows, exit_code=0, delay=0):
    """Use an actual child process for output and failure retention, without a model."""
    binary = root / "bin/safeyolo"
    binary.parent.mkdir()
    output = "\n".join(json.dumps(row) for row in rows) + "\n"
    binary.write_text(f"#!{sys.executable}\nimport os,sys,time\n"
                      f"print({output!r},end='',flush=True)\n"
                      "print('private stderr sentinel',file=sys.stderr,flush=True)\n"
                      f"time.sleep({delay})\nsys.exit({exit_code})\n")
    binary.chmod(0o700)


def retained_session(root, stderr="private stderr sentinel\n", diagnostic_error=False):
    directory, = (root / "logs").iterdir()
    assert directory.stat().st_mode & 0o777 == 0o700
    expected = {"prompt.txt", "stdout.jsonl", "stderr.txt", "exit.json"}
    if not diagnostic_error:
        expected.add("completed-mcp.json")
    assert {path.name for path in directory.iterdir()} == expected
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())
    assert all((path.stat().st_uid, path.stat().st_gid) == (os.getuid(), os.getgid())
               for path in directory.iterdir())
    assert directory.joinpath("stderr.txt").read_text() == stderr
    return directory


@pytest.mark.parametrize("extra_room", (False, True))
def test_codex_prompt_and_completed_operands_are_retained_before_observation(tmp_path, extra_room):
    rows = events()
    # Raw model narration and other tools stay outside the selected projection.
    rows.insert(1, {"type": "item.completed", "item": {"type": "agent_message", "text": "private model sentinel"}})
    if extra_room:
        unrelated = copy.deepcopy(rows[2])
        unrelated["item"]["arguments"]["room_name"] = "another-room"
        rows.insert(2, unrelated)
    session_cli(tmp_path, rows)
    output, directory = witness["codex_mcp_session"](tmp_path, "bbtest", "owned-room", "exact marker", 5)
    assert directory == retained_session(tmp_path)
    prompt = (directory / "prompt.txt").read_text()
    assert 'notify=["bbtest"]' in prompt and "notify=none" not in prompt
    assert prompt.count("since_sequence=5") == 2 and "include_self=true" in prompt
    assert "do not advance it to a returned next_cursor" in prompt
    assert json.loads((directory / "exit.json").read_text()) == {
        "exit_code": 0, "timed_out": False, "output_complete": True}
    projected = json.loads((directory / "completed-mcp.json").read_text())["calls"]
    assert [row["tool"] for row in projected] == ["join_room", "send", "read_room", "wait_for_message"]
    assert projected[1]["arguments"] == events()[2]["item"]["arguments"]
    assert projected[-1]["result"] == rows[-2]["item"]["result"]
    assert "private model sentinel" in output and "private model sentinel" not in (directory / "completed-mcp.json").read_text()
    if extra_room:
        # The invalid extra room still fails the original observer; projection is diagnostic.
        with pytest.raises(AssertionError):
            observe(output, "owned-room", "exact marker", "bbtest")
    else:
        assert observe(output, "owned-room", "exact marker", "bbtest")["message_id"] == "msg-one"


def test_codex_capture_keeps_files_in_parent_and_drains_both_pipes_before_exit(tmp_path, monkeypatch):
    """A real child checks donated descriptors and blocks before its final output."""
    rows = events()
    rows.insert(1, {"type": "item.completed", "item": {
        "type": "agent_message", "text": "private large output" * 32768}})
    stdout = ("\r\n".join(json.dumps(row) for row in rows) + "\r\n").encode()
    stderr = b"private stderr\r\n\x00\xff" * 32768
    tail = b'{"type":"fixture.after_barrier"}\r\n'
    binary = tmp_path / "bin/safeyolo"
    binary.parent.mkdir()
    capture = witness["stream_codex_output"]
    monkeypatch.setitem(witness["codex_mcp_session"].__globals__, "stream_codex_output",
                        lambda *args: capture(*args, timeout=5))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        binary.write_text(f"#!{sys.executable}\nimport os,socket,stat,sys\n"
                          "assert all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (1,2)), 'regular file donated'\n"
                          f"sys.stdout.buffer.write({stdout!r});sys.stdout.buffer.flush()\n"
                          f"sys.stderr.buffer.write({stderr!r});sys.stderr.buffer.flush()\n"
                          f"with socket.create_connection({listener.getsockname()!r},timeout=5) as barrier:\n"
                          "    assert barrier.recv(1) == b'x'\n"
                          f"sys.stdout.buffer.write({tail!r});sys.stdout.buffer.flush()\n")
        binary.chmod(0o700)
        with ThreadPoolExecutor(max_workers=1) as executor:
            session = executor.submit(witness["codex_mcp_session"], tmp_path,
                                      "bbtest", "owned-room", "exact marker", 5)
            connection, _ = listener.accept()
            with connection:
                try:
                    directory, = (tmp_path / "logs").iterdir()
                    deadline = time.monotonic() + 3
                    while ((directory / "stdout.jsonl").read_bytes() != stdout
                           or (directory / "stderr.txt").read_bytes() != stderr):
                        assert time.monotonic() < deadline, "private output was not flushed before exit"
                        time.sleep(0.01)
                    assert not session.done() and not (directory / "exit.json").exists()
                    assert directory.stat().st_mode & 0o777 == 0o700
                    for path in directory.iterdir():
                        state = path.stat()
                        assert state.st_mode & 0o777 == 0o600
                        assert (state.st_uid, state.st_gid) == (os.getuid(), os.getgid())
                finally:
                    connection.sendall(b"x")
            output, saved = session.result(timeout=5)
    assert saved == directory
    assert (directory / "stdout.jsonl").read_bytes() == stdout + tail
    assert (directory / "stderr.txt").read_bytes() == stderr
    assert json.loads((directory / "exit.json").read_text()) == {
        "exit_code": 0, "timed_out": False, "output_complete": True}
    assert observe(output, "owned-room", "exact marker", "bbtest")["message_id"] == "msg-one"


@pytest.mark.parametrize("failure,diagnostic_error", (
    ("nonzero", False), ("parse", False), ("observer", False), ("timeout", False),
    ("closed_timeout", False), ("launch", False), ("lingering_timeout", False),
    ("nonzero", True), ("timeout", True), ("launch", True), ("success", True),
    ("interrupt", True), ("shutdown", True)))
def test_failed_codex_session_keeps_private_operands_and_original_failure(tmp_path, monkeypatch, failure, diagnostic_error):
    from tests.blackbox import installed_sections

    rows = events()
    if failure == "observer":
        rows[-2]["item"]["result"]["structured_content"]["messages"] = []
    timed_out = failure in ("timeout", "closed_timeout", "lingering_timeout")
    if failure != "launch":
        session_cli(tmp_path, rows, exit_code=7 if failure == "nonzero" else 0,
                    delay=5 if failure in ("timeout", "closed_timeout") else 0)
    if failure == "parse":
        # Keep completed calls before a later malformed event.
        source = (tmp_path / "bin/safeyolo").read_text().replace("sys.exit(0)", "print('{invalid-json',flush=True)")
        (tmp_path / "bin/safeyolo").write_text(source)
    if failure == "closed_timeout":
        source = (tmp_path / "bin/safeyolo").read_text().replace("time.sleep(5)", "os.close(1);os.close(2);time.sleep(5)")
        (tmp_path / "bin/safeyolo").write_text(source)
    if timed_out:
        capture = witness["stream_codex_output"]
        monkeypatch.setitem(witness["codex_mcp_session"].__globals__, "stream_codex_output",
                            lambda *args: capture(*args, timeout=0.3))
    if failure in ("interrupt", "shutdown"):
        def interrupted_capture(*args):
            raise KeyboardInterrupt() if failure == "interrupt" else SystemExit(9)
        monkeypatch.setitem(witness["codex_mcp_session"].__globals__, "stream_codex_output", interrupted_capture)
    if diagnostic_error:
        read_text = Path.read_text

        def diagnostic_read(path, *args, **kwargs):
            if path.name == "stdout.jsonl" and kwargs.get("errors") == "replace":
                raise PermissionError("controlled private diagnostic read failure")
            return read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", diagnostic_read)
    popen = subprocess.Popen
    children = []
    lingering_writers = []
    writers_live_at_cleanup = []
    stops = []
    survivor_checks = []

    def selected_run(command, **kwargs):
        arguments = tuple(command[3:])
        if arguments == ("--version",):
            output = "safeyolo commit=" + "a" * 40 + " profile=debug"
        elif arguments[:2] == ("agent", "status"):
            output = json.dumps({"runtime_state": "stopped" if stops else "running", "control_state": "ready"})
        elif arguments == ("coord", "status"):
            output = json.dumps({"state": "stopped" if stops else "running"})
        else:
            assert arguments in (("agent", "stop", "bbtest"), ("agent", "stop", "bbpeer"), ("stop",), ("coord", "stop"))
            stops.append(arguments)
            if arguments == ("agent", "stop", "bbtest"):
                for writer in lingering_writers:
                    writers_live_at_cleanup.append(writer.poll() is None)
                    writer.terminate()
                    writer.wait(timeout=3)
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    def selected_popen(*args, **kwargs):
        if failure == "lingering_timeout":
            # Another owned child holds both write ends after transport exit.
            # Only main's guest cleanup ends this writer's lifetime.
            stdout_read, stdout_write = os.pipe()
            stderr_read, stderr_write = os.pipe()
            kwargs.update(stdout=stdout_write, stderr=stderr_write)
            try:
                process = popen(*args, **kwargs)
                process.stdout = os.fdopen(stdout_read, "rb", buffering=0)
                process.stderr = os.fdopen(stderr_read, "rb", buffering=0)
                lingering_writers.append(popen([sys.executable, "-c", "import time;time.sleep(10)"],
                                               stdout=stdout_write, stderr=stderr_write))
            finally:
                os.close(stdout_write)
                os.close(stderr_write)
        else:
            process = popen(*args, **kwargs)
        children.append(process)
        return process

    def journey(root, primary, peer, commit, command):
        output, _ = witness["codex_mcp_session"](root, primary, "owned-room", "exact marker", 5)
        return observe(output, "owned-room", "exact marker", primary)

    monkeypatch.setattr(witness["subprocess"], "run", selected_run)
    monkeypatch.setattr(witness["subprocess"], "Popen", selected_popen)
    monkeypatch.setitem(witness["main"].__globals__, "coordination_journey", journey)
    monkeypatch.setattr(installed_sections, "owned_processes", lambda root: [])
    monkeypatch.setattr(installed_sections, "surviving_processes", lambda owners: survivor_checks.append(owners.copy()) or [])
    monkeypatch.setattr(sys, "argv", ["operator_coord_acceptance.py", "--root", str(tmp_path),
                                      "--agent", "bbtest", "--peer", "bbpeer", "--commit", "a" * 40])
    expected = {"nonzero": AssertionError, "parse": json.JSONDecodeError,
                "observer": AssertionError, "timeout": subprocess.TimeoutExpired,
                "closed_timeout": subprocess.TimeoutExpired, "lingering_timeout": subprocess.TimeoutExpired,
                "launch": FileNotFoundError, "success": PermissionError,
                "interrupt": KeyboardInterrupt, "shutdown": SystemExit}[failure]
    with pytest.raises(expected) as raised:
        witness["main"]()
    if failure == "nonzero":
        assert "Codex exited 7" in str(raised.value)
    if failure == "launch":
        assert raised.value.filename == str(tmp_path / "bin/safeyolo")
    if diagnostic_error and failure != "success":
        assert len(raised.value.__notes__) == 1
        assert "controlled private diagnostic read failure" in raised.value.__notes__[0]
    assert all(child.poll() is not None for child in children)
    if failure == "lingering_timeout":
        assert children[0].returncode == 0 and writers_live_at_cleanup == [True]
        assert all(writer.poll() is not None for writer in lingering_writers)
    assert stops == [("agent", "stop", "bbtest"), ("agent", "stop", "bbpeer"), ("stop",), ("coord", "stop")]
    assert survivor_checks == [[]]
    unknown = timed_out or failure in ("launch", "interrupt", "shutdown")
    directory = retained_session(tmp_path, stderr="" if failure in ("launch", "interrupt", "shutdown")
                                 else "private stderr sentinel\n", diagnostic_error=diagnostic_error)
    if failure in ("launch", "interrupt", "shutdown"):
        assert (directory / "stdout.jsonl").read_bytes() == b""
    else:
        assert "thread.started" in (directory / "stdout.jsonl").read_text()
    assert json.loads((directory / "exit.json").read_text()) == {
        "exit_code": None if unknown else 7 if failure == "nonzero" else 0,
        "timed_out": timed_out, "output_complete": not unknown}
    if diagnostic_error:
        return  # Raw output and the primary failure survive the failed projection.
    projected = json.loads((directory / "completed-mcp.json").read_text())["calls"]
    assert len(projected) == (0 if failure == "launch" else 4)
    if failure == "observer":
        assert projected[-1]["result"]["structured_content"]["messages"] == []


def test_native_quiet_self_notification_and_advanced_cursor_controls(tmp_path):
    """Challenge the prompt's relationship through native tools and real owned NATS."""
    if not os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
        pytest.skip("select the existing pinned NATS executable for this boundary check")
    from tests.proxy_contracts.native_proposal_fixture import ROOM, proposal_instance

    with contextmanager(proposal_instance)(tmp_path) as instance:
        def call(tool, arguments):
            return instance.command("call", tool, agent=True, input=json.dumps({"room_name": ROOM, **arguments}))

        joined = call("join_room", {})
        for notify in ("none", "room", ["relay"]):
            cursor = call("read_room", {"since_sequence": 0})["next_cursor"]
            marker = "G4:" + json.dumps(notify)
            sent = call("send", {"body": marker, "notify": notify, "declared_content_type": "text/plain"})
            read_result = call("read_room", {"since_sequence": cursor})
            waited = call("wait_for_message", {"since_sequence": cursor, "include_self": True, "timeout_seconds": 1})
            assert read_result["messages"][0]["msg_id"] == sent["envelope"]["msg_id"]
            completed = events()
            operands = ({}, {"body": marker, "notify": notify, "declared_content_type": "text/plain"},
                        {"since_sequence": cursor}, {"since_sequence": cursor, "include_self": True, "timeout_seconds": 1})
            for event, result, arguments in zip(completed[1:-1], (joined, sent, read_result, waited), operands, strict=True):
                event["item"]["arguments"] = {"room_name": ROOM, **arguments}
                event["item"]["result"]["structured_content"] = result

            def observation():
                return observe("\n".join(json.dumps(row) for row in completed), ROOM, marker, "relay")

            if notify != ["relay"]:
                assert waited["messages"] == [] and waited["next_cursor"] == cursor
                with pytest.raises(AssertionError):
                    observation()
                continue
            assert waited["messages"] == read_result["messages"]
            assert observation()["message_id"] == sent["envelope"]["msg_id"]
            peer = instance.agent_api("lens", f"/api/coord/rooms/{ROOM}/messages?since={cursor}")["messages"]
            assert peer == read_result["messages"]
            advanced = call("wait_for_message", {"since_sequence": read_result["next_cursor"],
                                                  "include_self": True, "timeout_seconds": 1})
            assert advanced["messages"] == []
            completed[-2]["item"]["arguments"]["since_sequence"] = read_result["next_cursor"]
            completed[-2]["item"]["result"]["structured_content"] = advanced
            with pytest.raises(AssertionError):
                observation()
