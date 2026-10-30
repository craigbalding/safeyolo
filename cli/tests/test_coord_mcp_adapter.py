"""Native MCP stdio boundary: canonical results, validation and uncertain writes."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[2]
IDS = ["attn-" + digit * 32 for digit in "ab"]


@pytest.fixture
def adapter(tmp_path):
    binary = Path(os.environ.get("SAFEYOLO_COORD_TEST_BINARY", ROOT / "proxy/target/release/safeyolo-coord"))
    assert binary.is_file(), "Build safeyolo-coord first"
    token = tmp_path / "token"
    token.write_text("fixture-token")
    calls = []
    replies = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.reply(None)

        def do_POST(self):
            self.reply(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

        def reply(self, payload):
            path = urlsplit(self.path).path
            calls.append((self.command, self.path, payload, self.headers.get("Authorization")))
            status, value = replies.get(path, (200, {"envelope": {"msg_id": "msg-fixture"}, "sequence": 41}))
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = {**os.environ, "HTTP_PROXY": f"http://127.0.0.1:{server.server_port}", "SAFEYOLO_COORD_TOKEN_PATH": str(token)}
    env.pop("SAFEYOLO_COORD_SOCKET", None)

    def rpc(requests):
        result = subprocess.run([str(binary), "mcp"], input="".join(json.dumps(item) + "\n" for item in requests), capture_output=True, text=True, env=env, timeout=8)
        assert result.returncode == 0, result.stderr
        return {item["id"]: item for item in map(json.loads, result.stdout.splitlines())}

    def call(name, args):
        return rpc([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}])[1]["result"]

    yield call, rpc, calls, replies, token
    server.shutdown()
    server.server_close()
    thread.join()


def test_discovery_and_rpc_errors(adapter):
    _, rpc, calls, _, _ = adapter
    results = rpc([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        [], {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 3, "method": "missing"},
    ])
    assert results[1]["result"]["protocolVersion"] == "2025-03-26"
    tools = results[2]["result"]["tools"]
    by_name = {tool["name"]: tool for tool in tools}
    assert len(tools) == len(by_name)
    assert set(by_name) == {
        "join_room", "read_brief", "get_room_state", "declare_capabilities",
        "send", "send_task", "read_room", "wait_for_coord", "wait_for_attention",
        "read_attention", "wait_for_message",
        "list_approvals", "read_approval", "resolve_approval",
        "create_work", "list_work", "read_work", "claim_work", "release_work", "complete_work",
        "create_signal", "read_signal", "list_signals",
        "change_work_target", "attest_work", "list_work_attestations",
        "import_github_work", "read_github_work",
    }
    for name, required in {
        "list_approvals": [],
        "read_approval": ["approval_id"],
        "resolve_approval": ["approval_id", "decision", "delegation", "option"],
    }.items():
        schema = by_name[name]["inputSchema"]
        assert schema["type"] == "object" and schema["additionalProperties"] is False
        assert schema["required"] == required
        assert set(schema["properties"]) == set(required)
    assert by_name["resolve_approval"]["inputSchema"]["properties"]["decision"]["enum"] == ["approve", "reject", "defer"]
    assert results[None]["error"]["code"] == -32600
    assert results[3]["error"]["code"] == -32601
    assert calls == []


def test_native_exact_work_target_requests(adapter):
    call, _, calls, _, _ = adapter
    target = {"work_id": "work-example", "expected_version": 3, "expected_target_generation": 2,
              "target_ref": "opaque:branch?candidate=π", "operation_id": "target-change"}
    call("change_work_target", {"room_name": "backlog", **target})
    assert calls[-1][0:2] == ("POST", "http://_safeyolo.proxy.internal/api/coord/rooms/backlog/work")
    assert calls[-1][2] == {"action": "change_target", **target}
    evidence = {"work_id": "work-example", "target_generation": 3, "kind": "acceptance",
                "verdict": "reject", "summary": "Check this exact candidate", "evidence_refs": ["https://untrusted.invalid/ref"],
                "operation_id": "attestation"}
    call("attest_work", {"room_name": "backlog", **evidence})
    assert calls[-1][2] == {"action": "attest", **evidence}
    call("list_work_attestations", {"room_name": "backlog", "work_id": "work-example", "after": "att-previous", "limit": 2})
    assert calls[-1][0] == "GET"
    request = urlsplit(calls[-1][1])
    assert request.path == "/api/coord/rooms/backlog/work"
    assert parse_qs(request.query) == {"work_id": ["work-example"], "attestations": ["true"], "limit": ["2"], "after": ["att-previous"]}


def test_github_import_uses_local_create_replay_without_remote_access(adapter):
    call, _, calls, _, _ = adapter
    call("import_github_work", {"room_name": "backlog", "url": "https://github.com/owner/repo/issues/42#comment", "operation_id": "seed42"})
    assert len(calls) == 1
    assert calls[0][2] == {"action": "create", "title": "GitHub owner/repo#42", "external_ref": "https://github.com/owner/repo/issues/42", "operation_id": "seed42"}
    call("import_github_work", {"room_name": "backlog", "url": "https://evil.test/o/r/issues/42"})
    assert len(calls) == 1


def test_github_read_without_service_returns_local_work_and_no_secret(adapter):
    call, _, calls, replies, _ = adapter
    work = {"work_id": "work-42", "external_ref": "https://github.com/owner/repo/pull/42", "state": "claimed", "claim_agent_id": "alice", "version": 3, "target_generation": 2}
    replies["/api/coord/rooms/backlog/work"] = (200, work)
    replies["/gateway/services"] = (200, {"authorized": {"other": {"token": "sgw_PRIVATE"}}})
    result = call("read_github_work", {"room_name": "backlog", "work_id": "work-42"})
    assert result["structuredContent"]["work"] == work
    assert result["structuredContent"]["external"]["status"] == "unavailable"
    assert "PRIVATE" not in json.dumps(result)
    assert all(method == "GET" for method, *_ in calls)
    assert [urlsplit(path).path for _, path, *_ in calls] == ["/api/coord/rooms/backlog/work", "/gateway/services", "/api/coord/rooms/backlog/work"]


def test_github_read_requires_current_room_access_even_when_service_is_unavailable(adapter):
    call, _, calls, replies, _ = adapter
    replies["/api/coord/rooms/backlog/work"] = (403, {"error": "room revoked"})
    result = call("read_github_work", {"room_name": "backlog", "work_id": "work-42"})
    assert result["isError"] is True
    assert len(calls) == 1


def test_native_send_defaults_and_exact_task_producer(adapter):
    call, _, calls, _, token = adapter
    result = call("send", {"room_name": "backlog", "body": "marker"})
    assert result["structuredContent"]["sequence"] == 41
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    assert calls[-1][2] == {"body": "marker", "declared_content_type": "text/markdown", "notify": "none"}
    token.write_text("rotated-fixture-token")
    result = call("send_task", {"room_name": "backlog", "assignee": "forge", "target": "https://example.test/818", "body": "Keep assignee=forge in explanatory text."})
    assert result["isError"] is False
    assert calls[-1][2]["body"] == "TASK target=https://example.test/818 assignee=forge\n\nKeep assignee=forge in explanatory text."
    assert calls[-1][2]["notify"] == ["forge"]
    assert calls[-1][3] == "Bearer rotated-fixture-token"


@pytest.mark.parametrize("change", [{"target": "https://[bad"}, {"target": "issue-818"}, {"assignee": "forge extra"}, {"room_name": ""}, {"body": "TASK target=https://example.test/other assignee=forge"}])
def test_malformed_task_never_sends(adapter, change):
    call, _, calls, _, _ = adapter
    result = call("send_task", {"room_name": "backlog", "assignee": "forge", "target": "https://example.test/818", "body": "work", **change})
    assert result["isError"] is True
    assert calls == []


@given(st.one_of(st.none(), st.booleans(), st.integers(), st.lists(st.integers()), st.dictionaries(st.text(max_size=10), st.integers(), max_size=3)))
@settings(max_examples=30, deadline=None)
def test_untrusted_field_types_do_not_reach_transport(value):
    binary = Path(os.environ.get("SAFEYOLO_COORD_TEST_BINARY", ROOT / "proxy/target/release/safeyolo-coord"))
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "send", "arguments": {"room_name": "backlog", "body": value}}}
    result = subprocess.run([str(binary), "mcp"], input=json.dumps(request) + "\n", capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    assert response["result"]["isError"] is True
    assert "invalid type for body" in response["result"]["content"][0]["text"]


def test_whole_page_resolution_and_failure_hide_cursor(adapter):
    call, _, calls, replies, _ = adapter
    edges = [{"attention_id": id, "object_id": f"msg-{i}"} for i, id in enumerate(IDS)]
    replies["/api/coord/attention/wait"] = (200, {"edges": edges, "next_cursor": 9})
    for edge in edges:
        replies[f'/api/coord/attention/{edge["attention_id"]}/object'] = (200, {"edge": edge, "object": {"msg_id": edge["object_id"]}})
    result = call("wait_for_coord", {"since_sequence": 7, "limit": 2, "timeout_seconds": 0})
    assert result["structuredContent"]["next_cursor"] == 9
    assert len(result["structuredContent"]["objects"]) == 2
    assert len(calls) == 3
    replies[f"/api/coord/attention/{IDS[1]}/object"] = (403, {"error": "membership revoked"})
    result = call("wait_for_coord", {"since_sequence": 7, "limit": 2, "timeout_seconds": 0})
    assert result["isError"] is True
    assert "structuredContent" not in result
    assert "next_cursor" not in result["content"][0]["text"]


@pytest.mark.parametrize("status,value", [(403, {"error": "unauthorized room"}), (503, {"error": "NATS unavailable"}), (503, {"error": "receipt unavailable", "send_outcome": "unknown"})])
def test_refused_unavailable_and_uncertain_sends_are_not_retried(adapter, status, value):
    call, _, calls, replies, _ = adapter
    replies["/api/coord/rooms/backlog/send"] = status, value
    result = call("send", {"room_name": "backlog", "body": "marker"})
    assert result["isError"] is True
    assert "structuredContent" not in result
    assert len(calls) == 1
    if value.get("send_outcome") == "unknown":
        assert "outcome unknown" in result["content"][0]["text"]
