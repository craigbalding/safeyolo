"""Challenge the witness reader; these controlled events are not a model run."""

import copy
import json
import runpy
from pathlib import Path

import pytest

observe = runpy.run_path(str(Path(__file__).parent / "nested-linux/operator_coord_acceptance.py"))["mcp_observation"]


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
