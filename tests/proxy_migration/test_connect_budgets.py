"""CONNECT admission budgets through the shared real Python/Rust proxy lane."""

import http.client
import json
import socket
import time

import pytest

from safeyolo.api import AdminAPI
from tests.proxy_migration.harness import read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, origin_server
from tests.proxy_migration.test_agent_api_contract import api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import assert_rejection, policy_proxy
from tests.proxy_migration.test_operator_budgets import RESET_EVENTS, TOKEN, operator_wire, reset_audits

PER_HOST_POLICY = '''[[permissions]]
action = "network:request"
resource = "*"
effect = "budget"
budget = 1
'''
GLOBAL_POLICY = '''[budgets]
"network:request" = 1
[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
'''


def connect(path, authority, agent):
    """Make one fresh tunnel attempt without sending an inner HTTP request."""
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(path)
        forged_agent = "bob" if agent == "alice" else "alice"
        stream.sendall((
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            f"X-SafeYolo-Agent: {forged_agent}\r\n"
            f"X-SafeYolo-Request-Id: {FORGED_REQUEST_ID}\r\n"
            "Connection: close\r\n\r\n"
        ).encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        status = response.status
        headers = dict(response.getheaders())
        body = response.read() if status != 200 else b""
        response.close()
    return status, headers, body


def wait_for_accepts(origin, expected):
    deadline = time.monotonic() + 3
    while origin.accepts < expected and time.monotonic() < deadline:
        time.sleep(0.01)
    assert origin.accepts == expected


@pytest.mark.parametrize("scope", ["per-host", "global"])
def test_network_connect_limit_scope_and_request_separation(proxy_backend, tmp_path, monkeypatch, scope):
    """Count admitted dials, local 429s and an independent HTTP request."""
    def no_operator_defaults():
        raise AssertionError("Use only the fixture-owned operator endpoint and token")

    monkeypatch.setattr("safeyolo.api.get_admin_token", no_operator_defaults)
    monkeypatch.setattr("safeyolo.api.load_config", no_operator_defaults)
    directory = tmp_path / proxy_backend
    directory.mkdir()
    token_file = tmp_path / "operator-token"
    token_file.touch(mode=0o600)
    token_file.write_text(TOKEN + "\n")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        admin_port = reservation.getsockname()[1]
    assert admin_port != 9090
    policy = PER_HOST_POLICY if scope == "per-host" else GLOBAL_POLICY
    with origin_server() as target, origin_server() as neighbor:
        with policy_proxy(
            proxy_backend,
            directory,
            policy,
            eager_connect=True,
            agent_api=True,
            admin_port=admin_port,
            admin_api_token_file=token_file,
        ) as proxy:
            started = time.monotonic()
            client = AdminAPI(base_url=f"http://127.0.0.1:{admin_port}", token=TOKEN, timeout=5)
            attempts = []

            def attempt(agent, host, origin):
                before = (origin.accepts, len(origin.requests), len(proxy.events("proxy.egress")))
                status, headers, body = connect(
                    proxy.paths[agent], f"{host}:{origin.server_address[1]}", agent
                )
                if status == 200:
                    wait_for_accepts(origin, before[0] + 1)
                    assert len(proxy.events("proxy.egress")) == before[2] + 1
                else:
                    assert_rejection(status, headers, body, 429, host)
                    assert json.loads(body)["reason"] == f"Request budget exceeded for {host}"
                    assert (origin.accepts, len(proxy.events("proxy.egress"))) == (before[0], before[2])
                assert len(origin.requests) == before[1]
                request_id = {name.lower(): value for name, value in headers.items()}[
                    "x-safeyolo-request-id"
                ]
                assert request_id and request_id != FORGED_REQUEST_ID
                attempts.append({
                    "agent": agent, "host": host, "port": origin.server_address[1],
                    "status": status, "request_id": request_id,
                    "headers": headers, "body_hex": body.hex(),
                    "origin_accepts_before": before[0], "origin_accepts_after": origin.accepts,
                    "origin_requests_before": before[1], "origin_requests_after": len(origin.requests),
                })
                (directory / "connect-limit-wire.json").write_text(json.dumps(attempts, indent=2) + "\n")
                return status

            # Rate one permits a small GCRA burst. Observe exhaustion well
            # before refill, without asserting a token-bucket window edge.
            for index in range(4):
                status = attempt(("alice", "bob")[index % 2], "127.0.0.1", target)
                if status == 429:
                    break
            else:
                pytest.fail("The configured CONNECT budget did not exhaust within four attempts")
            assert any(row["status"] == 200 for row in attempts)

            neighbor_status = attempt("bob", "localhost", neighbor)
            assert neighbor_status == (200 if scope == "per-host" else 429)

            # A direct HTTP request to the exhausted host has its own counter.
            before = (target.accepts, len(target.requests))
            status, headers, body = send_request(
                proxy.paths["alice"], f"http://127.0.0.1:{target.server_address[1]}/connect-control"
            )
            assert (status, body) == (200, b"hello")
            wait_for_accepts(target, before[0] + 1)
            assert len(target.requests) == before[1] + 1
            assert target.requests[-1] == {"method": "GET", "target": "/connect-control"}
            report = assert_api_response(api_request(proxy, "/budgets"), 200)
            suffix = "127.0.0.1" if scope == "per-host" else "__global__"
            assert {f"network:connect:{suffix}", f"network:request:{suffix}"} <= set(report["budgets"])

            unauthorized = operator_wire(
                proxy, admin_port, "POST", "/admin/budgets/reset", body=b"{}", token=None
            )
            assert len(unauthorized) == 1 and unauthorized[0]["status"] == 401
            assert attempt("alice", "127.0.0.1", target) == 429
            resource = "network:connect:127.0.0.1" if scope == "per-host" else None
            reset_result = client.reset_budget(resource)
            assert reset_result == {"status": "ok", "resource": resource or "all", "reset_count": 0}
            assert attempt("alice", "127.0.0.1", target) == 200
            assert reset_audits(proxy, proxy_backend) == RESET_EVENTS

            requests = proxy.events("proxy.request")
            connect_ids = {row["request_id"] for row in attempts}
            connect_requests = [row for row in requests if row["request_id"] in connect_ids]
            if proxy_backend == "rust":
                assert [
                    (row["agent"], row["host"], row["port"], row["status"], row["request_id"])
                    for row in connect_requests
                ] == [
                    (row["agent"], row["host"], row["port"], row["status"], row["request_id"])
                    for row in attempts
                ]
            else:
                assert connect_requests == []  # Python records CONNECT in the security audit.
            assert len(requests) == len(connect_requests) + 2
            request_id = {name.lower(): value for name, value in headers.items()}[
                "x-safeyolo-request-id"
            ]
            request_event = next(row for row in requests if row["request_id"] == request_id)
            budget_read_event = next(row for row in requests if row["host"] == "_safeyolo.proxy.internal")
            assert (budget_read_event["host"], budget_read_event["status"], budget_read_event["decision"]) == (
                "_safeyolo.proxy.internal", 200, "local"
            )
            assert (request_event["agent"], request_event["host"], request_event["port"],
                    request_event["status"], request_event["request_id"]) == (
                "alice", "127.0.0.1", target.server_address[1], 200, request_id,
            )
            assert len({row["request_id"] for row in attempts}) == len(attempts)

            audits = [
                row for row in read_events(directory / "audit.jsonl")
                if row.get("event") == "security.network_guard" and row.get("details", {}).get("method") == "CONNECT"
            ]
            assert [
                (row["agent"], row["host"], row["request_id"], row["decision"])
                for row in audits
            ] == [
                (row["agent"], row["host"], row["request_id"],
                 "budget_exceeded" if row["status"] == 429 else "allow")
                for row in attempts
            ]
            assert all(row["details"]["port"] == attempt["port"] for row, attempt in zip(audits, attempts, strict=True))
            assert all(row["details"]["connection_id"] for row in audits)
            if proxy_backend == "rust":
                assert [row["connection_id"] for row in connect_requests] == [
                    row["details"]["connection_id"] for row in audits
                ]
            assert target.accepts == sum(row["status"] == 200 and row["host"] == "127.0.0.1" for row in attempts) + 1
            assert neighbor.accepts == int(neighbor_status == 200)
            assert len(target.requests) == 1 and neighbor.requests == []
            assert len(proxy.events("proxy.egress")) == target.accepts + neighbor.accepts
            assert time.monotonic() - started < 30, "Scenario crossed the rate-one no-refill interval"
            (directory / "connect-limit-origin.json").write_text(json.dumps({
                "target_accepts": target.accepts, "target_requests": target.requests,
                "neighbor_accepts": neighbor.accepts, "neighbor_requests": neighbor.requests,
            }, indent=2) + "\n")
