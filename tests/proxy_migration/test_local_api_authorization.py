"""Local control-plane failures through both real proxy listeners."""

import base64
import http.client
import json
import time

import pytest

from tests.proxy_migration.harness import ReadinessError, launch_proxy, read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, origin_server
from tests.proxy_migration.test_agent_api_contract import HOST, TOKEN, api_request
from tests.proxy_migration.test_native_network_policy import ALLOW, policy_proxy, replace_policy


@pytest.mark.parametrize("handler_state", ["disabled", "unusable-token-file"])
def test_reserved_routes_stay_local_when_agent_api_unavailable(
    proxy_backend, tmp_path, handler_state,
):
    """A missing or unusable handler cannot hand local requests to the parent."""
    with origin_server(capture_heads=True) as parent:
        with policy_proxy(
            proxy_backend, tmp_path / proxy_backend, ALLOW,
            agent_api=handler_state == "unusable-token-file",
            agent_api_token=b"\xff" if handler_state == "unusable-token-file" else None,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        ) as proxy:
            for authority in (HOST, HOST.upper(), HOST + ".", HOST.upper() + ".", HOST + ":8123"):
                result = send_request(
                    proxy.paths["bob"], f"http://{authority}/health?secret=query-canary-621",
                    headers={
                        "Authorization": "Bearer bearer-canary-621",
                        "X-Agent-Id": "alice", "X-SafeYolo-Agent": "alice",
                        "X-Forwarded-For": "10.0.0.2", "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                    },
                )
                status, headers, body = result
                assert status == 503, body
                assert json.loads(body)["reason_code"] == "agent_api_unavailable"
                assert {key.lower(): value for key, value in headers.items()}["x-safeyolo-agent-api"] == "true"
                assert parent.accepts == 0 and parent.request_heads == []
                assert proxy.events("proxy.egress") == []

            for authority in ("_safeyolo.probe.internal", "_SAFEYOLO.PROBE.INTERNAL."):
                status, _, body = send_request(
                    proxy.paths["bob"], f"http://{authority}/__pipeline_probe?secret=query-canary-621",
                    headers={"Authorization": "Bearer bearer-canary-621", "X-Agent-Id": "alice"},
                )
                assert status == 200 and json.loads(body)["probe_ok"] is True
                assert parent.accepts == 0 and parent.request_heads == []
                assert proxy.events("proxy.egress") == []

            status, _, body = send_request(
                proxy.paths["bob"], "http://ordinary.invalid/health?secret=query-canary-621",
                headers={"Authorization": "Bearer bearer-canary-621"},
            )
            assert status == 200 and body == b"hello"
            assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1
            assert b"query-canary-621" in parent.request_heads[0]
            assert b"bearer-canary-621" in parent.request_heads[0]


def test_agent_cannot_reach_operator_listener_through_proxy(proxy_backend, tmp_path):
    token_file = tmp_path / "operator-token"
    token_file.write_text("synthetic-operator-token-621\n")
    with origin_server(capture_heads=True) as parent:
        with policy_proxy(
            proxy_backend, tmp_path / proxy_backend, ALLOW,
            admin_port=0, admin_api_token_file=token_file,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        ) as proxy:
            marker = json.loads(proxy.readiness_file.read_text())
            port = marker["admin_port"]
            for agent, method, target, auth in (
                ("alice", "GET", f"http://127.0.0.1:{port}/stats", "synthetic-operator-token-621"),
                ("bob", "POST", f"http://LOCALHOST.:{port}/admin/budgets/reset", "wrong"),
                ("bob", "GET", f"http://localhost.:{port}/stats", None),
                ("alice", "GET", f"http://127.1:{port}/stats", "wrong"),
                ("alice", "GET", f"http://127.1.:{port}/stats?secret=query-canary-621", "wrong"),
                ("alice", "GET", f"http://2130706433:{port}/stats", "wrong"),
                ("alice", "GET", f"http://2130706433.:{port}/stats?secret=query-canary-621", "wrong"),
                ("alice", "GET", f"http://0x7f000001.:{port}/stats?secret=query-canary-621", "wrong"),
                ("alice", "GET", f"http://0177.0.0.1.:{port}/stats?secret=query-canary-621", "wrong"),
                ("bob", "GET", f"http://[::ffff:127.0.0.1]:{port}/stats", "wrong"),
                ("bob", "CONNECT", f"127.0.0.1:{port}", "synthetic-operator-token-621"),
            ):
                headers = {"X-Agent-Id": "alice", "X-Forwarded-For": "127.0.0.1"}
                if auth is not None:
                    headers["Authorization"] = f"Bearer {auth}"
                status, headers, body = send_request(
                    proxy.paths[agent], target, method=method,
                    headers=headers,
                )
                assert status == 403, body
                assert {key.lower(): value for key, value in headers.items()}["x-blocked-by"] == "admin-shield"
                assert parent.accepts == 0 and parent.request_heads == []
                assert proxy.events("proxy.egress") == []

            # The operator's direct listener retains public health and token-gated reads.
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                client.request("GET", "/health")
                response = client.getresponse()
                assert response.status == 200, response.read()
                response.read()
                client.request("GET", "/stats", headers={"Authorization": "Bearer wrong"})
                response = client.getresponse()
                assert response.status == 401, response.read()
                response.read()
                client.request("GET", "/stats", headers={"Authorization": "Bearer synthetic-operator-token-621"})
                response = client.getresponse()
                assert response.status == 200, response.read()
                response.read()
            finally:
                client.close()
            assert parent.accepts == 0 and proxy.events("proxy.egress") == []

            # The same port at another address is not an operator listener.
            status, _, body = send_request(proxy.paths["alice"], f"http://127.0.0.2:{port}/ordinary")
            assert status == 200 and body == b"hello"
            status, _, body = send_request(proxy.paths["alice"], f"http://127.0.0.2.:{port}/ordinary")
            assert status == 200 and body == b"hello"
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2


def test_shared_bearer_does_not_grant_other_agents_state(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with origin_server() as parent:
        with policy_proxy(
            proxy_backend, directory, ALLOW, agent_api=True, flow_store_enabled=True,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        ) as proxy:
            def call(agent, path, *, method="GET", body=None, status=200):
                forged = "alice" if agent == "bob" else "bob"
                result = send_request(
                    proxy.paths[agent], f"http://{HOST}{path}", method=method, body=body,
                    headers={
                        "Authorization": f"Bearer {TOKEN}",
                        "Content-Type": "application/json", "X-Agent-Id": forged,
                        "X-SafeYolo-Agent": forged, "X-Forwarded-For": "10.0.0.2",
                        "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                    },
                )
                assert result[0] == status, result
                assert {key.lower(): value for key, value in result[1].items()}["x-safeyolo-agent-api"] == "true"
                assert parent.accepts == origin_accepts
                assert len(proxy.events("proxy.egress")) == origin_accepts
                return json.loads(result[2])

            origin_accepts = 0
            context = "run=control-plane-621;agent=alice;test=scope"
            assert call("alice", "/api/test-context/current?agent=bob", method="POST",
                        body=json.dumps({"context": context}).encode())["agent"] == "alice"
            assert call("bob", "/api/test-context/current?agent=alice") == {"agent": "bob", "context": None}
            assert call("bob", "/api/test-context/current?agent=alice", method="DELETE") == {"status": "cleared"}
            assert call("alice", "/api/test-context/current")["context"]["run"] == "control-plane-621"
            assert call("bob", "/api/test-context/current?agent=alice", method="POST",
                        body=b"{", status=400)["error"] == "Invalid JSON body"
            assert call("alice", "/api/test-context/current")["context"]["run"] == "control-plane-621"

            status, headers, body = send_request(
                proxy.paths["alice"], "http://ordinary.invalid/owned",
                headers={"X-SafeYolo-Test-Context": context, "X-SafeYolo-Trace": "1"},
            )
            assert status == 200 and body == b"hello"
            origin_accepts = 1
            identifier = {key.lower(): value for key, value in headers.items()}["x-safeyolo-request-id"]
            assert call("alice", f"/trace?request_id={identifier}")["agent_id"] == "alice"
            assert call("bob", f"/trace?request_id={identifier}&agent=alice", status=404)["request_id"] == identifier

            deadline = time.monotonic() + 2
            while True:
                flows = call("alice", "/api/flows/search?run=control-plane-621&test=scope")["flows"]
                owned = [flow for flow in flows if flow["request_id"] == identifier]
                if owned or time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            assert len(owned) == 1, flows
            flow_id = owned[0]["id"]
            assert call("bob", f"/api/flows/{flow_id}?agent=alice", status=404) == {"error": "Flow not found"}
            tag = json.dumps({"tag": "scope-proof", "value": "owned"}).encode()
            assert call("bob", f"/api/flows/{flow_id}/tag?agent=alice", method="POST", body=tag,
                        status=404) == {"error": "Flow not found"}
            call("alice", f"/api/flows/{flow_id}/tag", method="POST", body=tag)
            assert call("bob", f"/api/flows/{flow_id}/tag/scope-proof?agent=alice", method="DELETE",
                        status=404) == {"error": "Flow not found"}
            assert call("alice", f"/api/flows/{flow_id}")["tags"][0]["value"] == "owned"
            assert base64.b64decode(call("alice", f"/api/flows/{flow_id}/response-body")["body_base64"]) == b"hello"
            assert call("bob", f"/api/flows/{flow_id}/response-body?agent=alice", status=404) == {
                "error": "Flow not found",
            }
            bob_context = "run=control-plane-621;agent=bob;test=scope"
            assert call("bob", "/api/test-context/current?agent=alice", method="POST",
                        body=json.dumps({"context": bob_context}).encode())["agent"] == "bob"
            status, headers, body = send_request(
                proxy.paths["bob"], "http://ordinary.invalid/bob-owned",
                headers={"X-SafeYolo-Test-Context": bob_context, "X-SafeYolo-Trace": "1"},
            )
            assert status == 200 and body == b"hello"
            origin_accepts = 2
            bob_id = {key.lower(): value for key, value in headers.items()}["x-safeyolo-request-id"]
            assert call("bob", f"/trace?request_id={bob_id}")["agent_id"] == "bob"
            assert call("alice", f"/trace?request_id={bob_id}&agent=bob", status=404)["request_id"] == bob_id
            deadline = time.monotonic() + 2
            while True:
                bob_flows = call("bob", "/api/flows/search?run=control-plane-621&test=scope")["flows"]
                bob_owned = [flow for flow in bob_flows if flow["request_id"] == bob_id]
                if bob_owned or time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            assert len(bob_owned) == 1, bob_flows
            assert not any(flow["request_id"] == bob_id for flow in
                           call("alice", "/api/flows/search?run=control-plane-621&test=scope")["flows"])
            bob_flow_id = bob_owned[0]["id"]
            assert call("alice", f"/api/flows/{bob_flow_id}/tag?agent=bob", method="POST", body=tag,
                        status=404) == {"error": "Flow not found"}
            assert call("bob", f"/api/flows/{bob_flow_id}")["tags"] == []
            assert base64.b64decode(call("bob", f"/api/flows/{bob_flow_id}/response-body")["body_base64"]) == b"hello"
            assert call("alice", f"/api/flows/{bob_flow_id}/response-body?agent=bob", status=404) == {
                "error": "Flow not found",
            }
            assert parent.accepts == 2 and len(parent.requests) == 2
            local = [row for row in proxy.events("proxy.request") if row["host"].lower().rstrip(".") == HOST]
            assert local and all(row["decision"] == "local" for row in local)
            deadline = time.monotonic() + 2
            while True:
                mutations = [row for row in read_events(directory / "audit.jsonl")
                             if row["event"] in {"security.test_context_declared", "security.test_context_cleared"}]
                if len(mutations) >= 3 or time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            assert [(row["event"], row["agent"], row["details"]["source_id"])
                    for row in mutations] == [
                ("security.test_context_declared", "alice", "10.0.0.2"),
                ("security.test_context_cleared", "bob", "10.0.0.3"),
                ("security.test_context_declared", "bob", "10.0.0.3"),
            ]


def test_flow_post_rejects_non_object_json_without_effect(proxy_backend, tmp_path):
    """All four flow POST routes validate the shape at the real agent listener."""
    with origin_server() as parent:
        with policy_proxy(
            proxy_backend, tmp_path / proxy_backend, ALLOW,
            agent_api=True, flow_store_enabled=True,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        ) as proxy:
            status, headers, raw = send_request(
                proxy.paths["alice"], "http://ordinary.invalid/body-shape",
                body=b"needle", headers={
                    "Content-Type": "text/plain",
                    "X-SafeYolo-Test-Context": "run=body-shape;agent=alice;test=flow-api",
                },
            )
            assert status == 200 and raw == b"hello"
            request_id = {key.lower(): value for key, value in headers.items()}["x-safeyolo-request-id"]
            assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1

            def call(agent, path, body=None, *, method="POST"):
                status, response_headers, raw = send_request(
                    proxy.paths[agent], f"http://{HOST}{path}", method=method, body=body,
                    headers={
                        "Authorization": f"Bearer {TOKEN}",
                        "Content-Type": "application/json",
                        "X-Agent-Id": "bob" if agent == "alice" else "alice",
                    },
                )
                assert {key.lower(): value for key, value in response_headers.items()}[
                    "x-safeyolo-agent-api"
                ] == "true"
                assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1
                return status, json.loads(raw)

            deadline = time.monotonic() + 2
            while True:
                status, result = call("alice", "/api/flows/search", b"{}")
                assert status == 200
                owned = [flow for flow in result["flows"] if flow["request_id"] == request_id]
                if owned or time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            assert len(owned) == 1, result
            flow_id = owned[0]["id"]

            paths = (
                "/api/flows/endpoints", "/api/flows/body-search",
                "/api/flows/request-body-search", f"/api/flows/{flow_id}/tag",
            )
            for path in paths:
                for body in (b'""', b"[]", b'"x"'):
                    assert call("alice", path, body) == (400, {"error": "Invalid JSON body"})
            assert call("alice", f"/api/flows/{flow_id}", method="GET")[1]["tags"] == []

            status, endpoints = call("alice", "/api/flows/endpoints", b"{}")
            assert status == 200 and endpoints["count"] >= 1
            assert any(row["host"] == "ordinary.invalid" for row in endpoints["endpoints"])
            status, result = call(
                "alice", "/api/flows/body-search",
                b'{"engagement_id":"alice","query":"hello","evidence_owner":"bob"}',
            )
            assert status == 200 and result == {"flows": [], "count": 0}
            status, result = call(
                "alice", "/api/flows/request-body-search",
                b'{"engagement_id":"alice","query":"needle","evidence_owner":"bob"}',
            )
            assert status == 200 and any(row["id"] == flow_id for row in result["flows"])

            tag_path = f"/api/flows/{flow_id}/tag"
            tag = b'{"tag":"shape-proof","value":"owned"}'
            assert call("bob", tag_path, tag) == (404, {"error": "Flow not found"})
            assert call("alice", tag_path, tag)[1]["value"] == "owned"
            assert call("alice", f"/api/flows/{flow_id}", method="GET")[1]["tags"][0][
                "value"
            ] == "owned"
            assert parent.requests == [
                {"method": "GET", "target": "http://ordinary.invalid/body-shape"}
            ]


def test_invalid_policy_startup_refuses_and_reload_keeps_denial(proxy_backend, tmp_path):
    bad_directory = tmp_path / "invalid-startup"
    with pytest.raises(ReadinessError) as failure:
        with launch_proxy(proxy_backend, bad_directory, "hosts = 7", native_policy=True):
            pytest.fail("Invalid initial policy reached readiness")
    cause = (bad_directory / "process.log").read_text()
    expected = ("Expected dict for 'hosts', got int" if proxy_backend == "python"
                else "hosts must be a table")
    assert expected in cause, (failure.value, cause)
    assert not (bad_directory / "ready").exists()

    directory = tmp_path / "valid-startup"
    policy = '''[hosts]
"*" = { egress = "allow" }
"blocked.invalid" = { egress = "deny" }
'''
    with origin_server() as parent:
        with policy_proxy(
            proxy_backend, directory, policy, agent_api=True,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        ) as proxy:
            denied = "http://blocked.invalid/denied"
            allowed = "http://open.invalid/allowed"
            assert send_request(proxy.paths["alice"], denied)[0] == 403
            assert parent.accepts == 0 and proxy.events("proxy.egress") == []
            status, _, body = send_request(proxy.paths["alice"], allowed)
            assert status == 200 and body == b"hello"
            assert parent.accepts == 1
            before = api_request(proxy, "/policy")[2]
            replace_policy(proxy, proxy_backend, directory, "hosts = 7", valid=False)
            assert api_request(proxy, "/policy")[2] == before
            assert send_request(proxy.paths["alice"], denied)[0] == 403
            assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1
            assert send_request(proxy.paths["bob"], allowed)[0] == 200
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2
            assert any(row["event"] == "ops.policy_error" for row in read_events(directory / "audit.jsonl"))
