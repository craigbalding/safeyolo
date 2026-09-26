"""Trusted UDS identity and network-rule precedence at the real proxy boundary."""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import threading
from urllib.parse import urlsplit

from tests.proxy_migration.harness import connection, read_events
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, POLICY, origin_server
from tests.proxy_migration.test_http_test_context import parent_server
from tests.proxy_migration.test_native_network_policy import policy_proxy

PRECEDENCE_POLICY = '''budget = 12000
[hosts]
"*" = { egress = "prompt" }
"exact.invalid" = { egress = "deny" }
"*.scope.invalid" = { egress = "allow" }
"special.scope.invalid" = { egress = "deny" }
"endpoint.invalid" = { egress = "allow" }
"endpoint.invalid:8124" = { egress = "deny" }
"default.invalid" = { egress = "deny" }
"default.invalid:80" = { egress = "allow" }
[agents.alice.hosts]
"exact.invalid" = { egress = "allow" }
"*.scope.invalid" = { egress = "deny" }
"endpoint.invalid" = { egress = "deny" }
"endpoint.invalid:8123" = { egress = "allow" }
"default.invalid:80" = { egress = "deny" }
[agents.bob.hosts]
"exact.invalid" = { egress = "prompt" }
"special.scope.invalid" = { egress = "allow" }
"endpoint.invalid:8124" = { egress = "allow" }
'''


# Every row has a conflicting less-specific rule or a different agent result.
# Explicit port 80 and an omitted HTTP port must select the same endpoint rule.
CASES = {
    "alice": (
        ("exact.invalid:8123", 200),
        ("ordinary.scope.invalid:8123", 403),
        ("special.scope.invalid:8123", 403),
        ("endpoint.invalid:8123", 200),
        ("endpoint.invalid:8124", 403),
        ("default.invalid", 403),
        ("default.invalid:80", 403),
        ("unlisted.invalid:8123", 428),
    ),
    "bob": (
        ("exact.invalid:8123", 428),
        ("ordinary.scope.invalid:8123", 200),
        ("special.scope.invalid:8123", 200),
        ("endpoint.invalid:8123", 200),
        ("endpoint.invalid:8124", 200),
        ("default.invalid", 200),
        ("default.invalid:80", 200),
        ("unlisted.invalid:8123", 428),
    ),
}


def _send(client, url, claimed_agent, *, body=None):
    client.request("POST" if body is not None else "GET", url, body=body, headers={
        "X-Agent-Id": claimed_agent,
        "X-SafeYolo-Agent": claimed_agent,
        "X-Forwarded-For": "10.0.0.2" if claimed_agent == "alice" else "10.0.0.3",
        "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
        "Connection": "keep-alive",
    })
    response = client.getresponse()
    try:
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        response.close()


def test_agent_and_destination_precedence_on_concurrent_reused_connections(proxy_backend, tmp_path):
    """Policy and evidence follow each host-owned listener despite forged claims."""
    directory = tmp_path / proxy_backend
    with origin_server(keep_alive=True) as parent:
        with policy_proxy(
            proxy_backend, directory, PRECEDENCE_POLICY,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        ) as proxy:
            gate = threading.Barrier(2)

            def run_agent(agent):
                client = connection(proxy.paths[agent])
                first_socket = client.sock
                results = []
                try:
                    for index, (authority, expected) in enumerate(CASES[agent]):
                        url = f"http://{authority}/{agent}-{index}"
                        gate.wait(timeout=10)
                        status, headers, body = _send(
                            client, url, "bob" if agent == "alice" else "alice",
                        )
                        assert status == expected, (agent, authority, status, body)
                        if status == 200:
                            assert body == b"hello"
                        else:
                            assert headers.get("x-blocked-by") == "network-guard"
                        identifier = headers["x-safeyolo-request-id"]
                        assert identifier != FORGED_REQUEST_ID
                        results.append((url, expected, identifier))
                    assert client.sock is first_socket, f"{agent} listener was not reused"
                finally:
                    client.close()
                return results

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                alice = workers.submit(run_agent, "alice")
                bob = workers.submit(run_agent, "bob")
                results = {"alice": alice.result(), "bob": bob.result()}

            expected_deliveries = {
                f"http://{authority}/{agent}-{index}"
                for agent, cases in CASES.items()
                for index, (authority, status) in enumerate(cases) if status == 200
            }
            delivered = {row["target"] for row in parent.requests}
            assert len(parent.requests) == len(expected_deliveries)
            assert delivered == expected_deliveries
            assert 1 <= parent.accepts <= len(expected_deliveries)

            runtime = {row["request_id"]: row for row in proxy.events("proxy.request")}
            guards = {row["request_id"]: row for row in read_events(directory / "audit.jsonl")
                      if row["event"] == "security.network_guard"}
            all_ids = [identifier for cases in results.values() for _, _, identifier in cases]
            assert len(set(all_ids)) == len(all_ids)
            for agent, cases in results.items():
                connection_ids = set()
                for url, status, identifier in cases:
                    row = runtime[identifier]
                    assert (row["agent"], row["status"], row["host"], row["port"]) == (
                        agent, status, urlsplit(url).hostname, urlsplit(url).port or 80,
                    )
                    connection_ids.add(row["connection_id"])
                    if status != 200:
                        guard = guards[identifier]
                        assert guard["agent"] == agent
                        assert guard["decision"] == ("deny" if status == 403 else "require_approval")
                assert len(connection_ids) == 1
            assert runtime[results["alice"][0][2]]["connection_id"] != (
                runtime[results["bob"][0][2]]["connection_id"]
            )


def test_permitted_local_endpoint_overrides_host_prompt(proxy_backend, tmp_path):
    """A configured loopback endpoint is reachable without a private-IP ban."""
    with parent_server() as origin, parent_server() as other_origin:
        port = origin.server_address[1]
        other_port = other_origin.server_address[1]
        direct = http.client.HTTPConnection("127.0.0.1", other_port, timeout=5)
        try:
            direct.request("POST", "/direct-control", body=b"live")
            response = direct.getresponse()
            assert response.status == 200 and response.read() == b"reply"
        finally:
            direct.close()
        assert other_origin.accepts == 1
        policy = f'''budget = 12000
[hosts]
"*" = {{ egress = "deny" }}
"127.0.0.1" = {{ egress = "prompt" }}
"127.0.0.1:{port}" = {{ egress = "allow" }}
'''
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, policy) as proxy:
            for agent in ("alice", "bob"):
                client = connection(proxy.paths[agent])
                try:
                    claim = json.dumps({"agent": "forged", "agent_id": "forged"}).encode()
                    status, _, body = _send(client, f"http://127.0.0.1:{port}/{agent}", "forged", body=claim)
                    assert (status, body) == (200, b"reply")
                finally:
                    client.close()
                client = connection(proxy.paths[agent])
                try:
                    status, headers, _ = _send(
                        client,
                        f"http://127.0.0.1:{other_port}/blocked", "forged",
                        body=claim,
                    )
                    assert status == 428
                    assert headers["x-blocked-by"] == "network-guard"
                finally:
                    client.close()
            assert [row["target"] for row in origin.requests] == ["/alice", "/bob"]
            assert other_origin.accepts == 1
            assert [row["target"] for row in other_origin.requests] == ["/direct-control"]


def test_agent_default_deny_overrides_global_exact_allow(proxy_backend, tmp_path):
    """An agent-wide decision has priority over a global named host."""
    with origin_server() as origin:
        port = origin.server_address[1]
        policy = f'''budget = 12000
[hosts]
"127.0.0.1:{port}" = {{ egress = "allow" }}
[agents.alice]
egress = "deny"
'''
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, policy) as proxy:
            target = f"http://127.0.0.1:{port}/agent-default"
            alice = connection(proxy.paths["alice"])
            bob = connection(proxy.paths["bob"])
            try:
                status, _, body = _send(bob, target, "alice")
                assert (status, body) == (200, b"hello")
                assert _send(alice, target, "bob")[0] == 403
                assert len(origin.requests) == 1
            finally:
                alice.close()
                bob.close()
            assert origin.requests == [{"method": "GET", "target": "/agent-default"}]


def test_forged_body_agent_cannot_cross_uds_listener(proxy_backend, tmp_path):
    """A JSON identity claim is application data, not network authority."""
    directory = tmp_path / proxy_backend
    with parent_server() as parent:
        with policy_proxy(proxy_backend, directory, POLICY,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            observed = []
            for agent, claim, expected in (("alice", "bob", 200), ("bob", "alice", 403)):
                client = connection(proxy.paths[agent])
                try:
                    body = json.dumps({"agent": claim, "agent_id": claim}).encode()
                    status, headers, reply = _send(
                        client, f"http://body.invalid:8123/{agent}", claim, body=body,
                    )
                finally:
                    client.close()
                assert status == expected, reply
                observed.append((agent, headers["x-safeyolo-request-id"], status))
            assert parent.accepts == len(parent.requests) == 1
            assert parent.requests[0]["body"] == json.dumps({"agent": "bob", "agent_id": "bob"}).encode()
            runtime = {row["request_id"]: row for row in proxy.events("proxy.request")}
            for agent, identifier, status in observed:
                assert (runtime[identifier]["agent"], runtime[identifier]["status"]) == (agent, status)
