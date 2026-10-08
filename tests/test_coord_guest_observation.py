"""Challenge the witness reader; these controlled events are not a model run."""

import copy
import json
import os
import runpy
import shlex
import subprocess
import sys
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
    binary.write_text(f"#!{sys.executable}\nimport sys,time\n"
                      f"print({output!r},end='',flush=True)\n"
                      "print('private stderr sentinel',file=sys.stderr,flush=True)\n"
                      f"time.sleep({delay})\nsys.exit({exit_code})\n")
    binary.chmod(0o700)


def retained_session(root):
    directory, = (root / "logs").iterdir()
    assert directory.stat().st_mode & 0o777 == 0o700
    assert {path.name for path in directory.iterdir()} == {
        "prompt.txt", "stdout.jsonl", "stderr.txt", "exit.json", "completed-mcp.json"}
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())
    assert directory.joinpath("stderr.txt").read_text() == "private stderr sentinel\n"
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
    assert json.loads((directory / "exit.json").read_text()) == {"exit_code": 0, "timed_out": False}
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


@pytest.mark.parametrize("failure", ("nonzero", "parse", "observer", "timeout"))
def test_failed_codex_session_keeps_private_operands_and_original_failure(tmp_path, monkeypatch, failure):
    from tests.blackbox import installed_sections

    rows = events()
    if failure == "observer":
        rows[-2]["item"]["result"]["structured_content"]["messages"] = []
    session_cli(tmp_path, rows, exit_code=7 if failure == "nonzero" else 0,
                delay=5 if failure == "timeout" else 0)
    if failure == "parse":
        # Keep completed calls before a later malformed event.
        source = (tmp_path / "bin/safeyolo").read_text().replace("sys.exit(0)", "print('{invalid-json',flush=True)")
        (tmp_path / "bin/safeyolo").write_text(source)
    run = subprocess.run
    stops = []
    survivor_checks = []

    def selected_run(command, **kwargs):
        if "stdout" in kwargs:
            if failure == "timeout":
                kwargs["timeout"] = 0.3
            return run(command, **kwargs)
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
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    def journey(root, primary, peer, commit, command):
        output, _ = witness["codex_mcp_session"](root, primary, "owned-room", "exact marker", 5)
        return observe(output, "owned-room", "exact marker", primary)

    monkeypatch.setattr(witness["subprocess"], "run", selected_run)
    monkeypatch.setitem(witness["main"].__globals__, "coordination_journey", journey)
    monkeypatch.setattr(installed_sections, "owned_processes", lambda root: [])
    monkeypatch.setattr(installed_sections, "surviving_processes", lambda owners: survivor_checks.append(owners.copy()) or [])
    monkeypatch.setattr(sys, "argv", ["operator_coord_acceptance.py", "--root", str(tmp_path),
                                      "--agent", "bbtest", "--peer", "bbpeer", "--commit", "a" * 40])
    expected = {"nonzero": AssertionError, "parse": json.JSONDecodeError,
                "observer": AssertionError, "timeout": subprocess.TimeoutExpired}[failure]
    with pytest.raises(expected) as raised:
        witness["main"]()
    if failure == "nonzero":
        assert "Codex exited 7" in str(raised.value)
    assert stops == [("agent", "stop", "bbtest"), ("agent", "stop", "bbpeer"), ("stop",), ("coord", "stop")]
    assert survivor_checks == [[]]
    directory = retained_session(tmp_path)
    assert "thread.started" in (directory / "stdout.jsonl").read_text()
    assert json.loads((directory / "exit.json").read_text()) == {
        "exit_code": None if failure == "timeout" else 7 if failure == "nonzero" else 0,
        "timed_out": failure == "timeout"}
    projected = json.loads((directory / "completed-mcp.json").read_text())["calls"]
    assert len(projected) == 4
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
