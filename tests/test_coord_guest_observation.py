"""Challenge the witness reader; these controlled events are not a model run."""

import copy
import json
import os
import runpy
import shlex
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
