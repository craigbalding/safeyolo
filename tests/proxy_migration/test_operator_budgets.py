"""Real operator reset workflow over the same budget state agents consume.

All endpoints, tokens and peers are owned by the fixture. Source malformed-body
mutation is captured before a strict historical xfail; it is not accepted as
native behavior. The existing rate=1, thirty-second no-refill bound is reused.
"""

import json
import socket
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from safeyolo.api import AdminAPI
from tests.proxy_migration.harness import read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_agent_api_budgets import assert_no_refill, read_budgets
from tests.proxy_migration.test_agent_api_contract import api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import assert_rejection, policy_proxy, replace_policy

TOKEN = "synthetic-operator-budget-token"
ALPHA = "network:request:alpha.invalid"
BETA = "network:request:beta.invalid"
GLOBAL = "network:request:__global__"
RESET_EVENTS = ["admin.budget_reset", "admin.budgets_reset"]
POLICY = """[[permissions]]
action = "network:request"
resource = "*.invalid/*"
effect = "budget"
budget = 1
"""
GLOBAL_POLICY = '[budgets]\n"network:request" = 1\n' + POLICY
GLOBAL_REQUEST_LIMIT = """[budgets]
"network:request" = 1
[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
"""


def report(keys=(), *, global_limit=False):
    return {
        "tracked_keys": len(keys),
        "budgets": {
            key: {"budget_per_minute": 1, "remaining": 0, "resource": key.removeprefix("network:request:")}
            for key in keys
        },
        "global_budgets": {"network:request": 1} if global_limit else {},
    }


@contextmanager
def budget_proxy(backend, tmp_path, policy, monkeypatch):
    def no_operator_defaults():
        raise AssertionError("Use only the explicitly owned operator endpoint and synthetic token")

    monkeypatch.setattr("safeyolo.api.get_admin_token", no_operator_defaults)
    monkeypatch.setattr("safeyolo.api.load_config", no_operator_defaults)
    token_file = tmp_path / "operator-token"
    token_file.touch(mode=0o600)
    token_file.write_text(TOKEN + "\n")
    # Source shield owns the configured port, so use the actual selected port
    # instead of configured zero. The close-before-child-bind race is bounded:
    # failed bind prevents fixture readiness; no request uses an unready server.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    assert port != 9090
    directory = tmp_path / backend
    with origin_server() as parent:
        proxy = None
        try:
            with policy_proxy(
                backend,
                directory,
                policy,
                agent_api=True,
                parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                admin_port=port,
                admin_api_token_file=token_file,
            ) as proxy:
                marker = json.loads(proxy.readiness_file.read_text())
                assert marker["pid"] == proxy.process.pid and marker["admin_port"] == port
                client = AdminAPI(base_url=f"http://127.0.0.1:{port}", token=TOKEN, timeout=5)
                yield proxy, parent, client, port
        finally:
            if proxy is not None:
                assert proxy.process.poll() is not None
                assert not proxy.readiness_file.exists()
                assert all(not Path(path).exists() for path in proxy.paths.values())
                with socket.socket() as closed:
                    closed.settimeout(1)
                    assert closed.connect_ex(("127.0.0.1", port)) != 0
                for path in (directory / "events.jsonl", directory / "audit.jsonl", directory / "process.log"):
                    if path.exists():
                        data = path.read_bytes()
                        assert TOKEN.encode() not in data and TOKEN.encode().hex().encode() not in data
                (directory / "operator-budget-lifecycle.json").write_text(
                    json.dumps(
                        {
                            "pid": proxy.process.pid,
                            "admin_port": port,
                            "returncode": proxy.process.returncode,
                            "readiness_gone": True,
                            "agent_sockets_gone": True,
                            "admin_port_closed": True,
                            "token_absent_from_diagnostics": True,
                            "origin_accepts": parent.accepts,
                        },
                        indent=2,
                    )
                    + "\n"
                )


def operator_wire(proxy, port, method, path, *, body=b"", token=TOKEN):
    """Read complete response bytes, including the source's second error reply."""
    head = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n".encode()
    if token is not None:
        head += f"Authorization: Bearer {token}\r\n".encode()
    head += f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode()
    chunks = []
    with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
        stream.sendall(head + body)
        while chunk := stream.recv(65536):
            chunks.append(chunk)
    wire = b"".join(chunks)
    remaining = wire
    responses = []
    while remaining:
        response_head, separator, remainder = remaining.partition(b"\r\n\r\n")
        assert separator, "Incomplete operator response head"
        lines = response_head.split(b"\r\n")
        headers = [line.split(b":", 1) for line in lines[1:]]
        length = next(int(value.strip()) for name, value in headers if name.lower() == b"content-length")
        response_body, remaining = remainder[:length], remainder[length:]
        assert len(response_body) == length
        responses.append(
            {"status": int(lines[0].split()[1]), "body": json.loads(response_body), "body_hex": response_body.hex()}
        )
    with (proxy.event_log.parent / "operator-budget-wire.jsonl").open("a") as output:
        output.write(
            json.dumps(
                {
                    "method": method,
                    "path": path,
                    "authorization_present": token is not None,
                    "response_hex": wire.hex(),
                    "responses": responses,
                }
            )
            + "\n"
        )
    return responses


def read_shared(proxy, parent, port, expected):
    before = parent.accepts, len(proxy.events("proxy.egress"))
    for agent in ("alice", "bob"):
        read_budgets(proxy, parent, expected, agent=agent)
    responses = operator_wire(proxy, port, "GET", "/admin/budgets")
    assert len(responses) == 1 and responses[0]["status"] == 200
    assert responses[0]["body"] == expected
    assert bytes.fromhex(responses[0]["body_hex"]) == json.dumps(expected, indent=2).encode()
    assert (parent.accepts, len(proxy.events("proxy.egress"))) == before


def hit(proxy, parent, host, status, *, agent="alice"):
    before = parent.accepts, len(proxy.events("proxy.egress"))
    result = send_request(proxy.paths[agent], f"http://{host}/operator-budget")
    if status == 200:
        assert result[0] == 200 and result[2] == b"hello"
        assert (parent.accepts, len(proxy.events("proxy.egress"))) == (before[0] + 1, before[1] + 1)
    else:
        assert_rejection(*result, status, host)
        assert (parent.accepts, len(proxy.events("proxy.egress"))) == before


def reset(client, resource=None):
    result = client.reset_budget(resource)
    assert list(result) == ["status", "resource", "reset_count"]
    assert result == {"status": "ok", "resource": resource or "all", "reset_count": 0}


def reset_audits(proxy, backend):
    if backend == "python":
        return [
            event["event"]
            for event in read_events(proxy.event_log.parent / "audit.jsonl")
            if event["event"] in RESET_EVENTS
        ]
    return [
        event["audit_intent"] for event in proxy.events("proxy.admin_api") if event.get("audit_intent") in RESET_EVENTS
    ]


@pytest.mark.parametrize("scope", ["per-host", "global"])
def test_network_request_limit_scope_and_recovery(proxy_backend, tmp_path, monkeypatch, scope):
    """Observe request-budget denial at the wire and origin, then reset it."""
    policy = POLICY if scope == "per-host" else GLOBAL_REQUEST_LIMIT
    directory = tmp_path / proxy_backend
    with budget_proxy(proxy_backend, tmp_path, policy, monkeypatch) as (proxy, parent, client, _port):
        started = time.monotonic()
        attempts = []
        forwarded = []

        def send(agent, host):
            target = f"http://{host}/request-limit"
            before = (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress")))
            status, headers, body = send_request(proxy.paths[agent], target)
            after = (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress")))
            if status == 200:
                assert body == b"hello"
                forwarded.append({"method": "GET", "target": target})
                assert after == tuple(value + 1 for value in before)
            else:
                assert_rejection(status, headers, body, 429, host)
                assert json.loads(body)["reason"] == f"Request budget exceeded for {host}"
                assert after == before
            assert parent.requests == forwarded
            (directory / "request-limit-origin.json").write_text(
                json.dumps({"accepts": parent.accepts, "requests": parent.requests}, indent=2) + "\n"
            )
            attempts.append(
                {
                    "agent": agent,
                    "host": host,
                    "target": target,
                    "status": status,
                    "headers": headers,
                    "body_hex": body.hex(),
                    "origin_accepts_before": before[0],
                    "origin_accepts_after": after[0],
                    "origin_requests_before": before[1],
                    "origin_requests_after": after[1],
                }
            )
            (directory / "request-limit-wire.json").write_text(json.dumps(attempts, indent=2) + "\n")
            return status

        # A rate of one has a small GCRA burst. Bound attempts and stay well
        # before refill rather than assuming a token-bucket window boundary.
        for index in range(4):
            status = send(("alice", "bob")[index % 2], "alpha.invalid")
            if status == 429:
                break
        else:
            pytest.fail("The configured request budget did not exhaust within four attempts")
        assert any(attempt["status"] == 200 for attempt in attempts)

        neighbor_status = send("bob", "beta.invalid")
        assert neighbor_status == (200 if scope == "per-host" else 429)
        resource = ALPHA if scope == "per-host" else None
        reset(client, resource)
        assert send("alice", "alpha.invalid") == 200

        assert parent.accepts == len(parent.requests) == len(forwarded)
        requests = proxy.events("proxy.request")
        assert [(event["agent"], event["host"], event["port"], event["status"]) for event in requests] == [
            (attempt["agent"], attempt["host"], 80, attempt["status"]) for attempt in attempts
        ]
        assert [event["request_id"] for event in requests] == [
            next(value for name, value in attempt["headers"].items() if name.lower() == "x-safeyolo-request-id")
            for attempt in attempts
        ]
        denials = [
            event
            for event in read_events(directory / "audit.jsonl")
            if event.get("event") == "security.network_guard" and event.get("decision") == "budget_exceeded"
        ]
        assert [(event["agent"], event["host"], event["request_id"]) for event in denials] == [
            (event["agent"], event["host"], event["request_id"]) for event in requests if event["status"] == 429
        ]
        assert_no_refill(started)


def test_operator_exact_budget_reset_shares_state_and_retains_order(proxy_backend, tmp_path, monkeypatch):
    with budget_proxy(proxy_backend, tmp_path, POLICY, monkeypatch) as (proxy, parent, client, port):
        started = time.monotonic()
        read_shared(proxy, parent, port, report())
        for agent in ("alice", "bob"):
            preview = assert_api_response(api_request(proxy, "/lookup?host=alpha.invalid", agent=agent), 200)
            assert preview["effect"] == "allow"
        read_shared(proxy, parent, port, report())
        hit(proxy, parent, "beta.invalid", 200, agent="bob")
        hit(proxy, parent, "alpha.invalid", 200)
        hit(proxy, parent, "alpha.invalid", 200)
        hit(proxy, parent, "alpha.invalid", 429)
        read_shared(proxy, parent, port, report([BETA, ALPHA]))
        reset(client, "network:request:*")
        read_shared(proxy, parent, port, report([BETA, ALPHA]))
        hit(proxy, parent, "alpha.invalid", 429)
        reset(client, ALPHA)
        read_shared(proxy, parent, port, report([BETA]))
        hit(proxy, parent, "alpha.invalid", 200)
        read_shared(proxy, parent, port, report([BETA, ALPHA]))
        reset(client, BETA)
        read_shared(proxy, parent, port, report([ALPHA]))
        hit(proxy, parent, "beta.invalid", 200, agent="bob")
        read_shared(proxy, parent, port, report([ALPHA, BETA]))
        directory = tmp_path / proxy_backend
        replace_policy(proxy, proxy_backend, directory, POLICY + "\n# valid same-state reload\n")
        read_shared(proxy, parent, port, report([ALPHA, BETA]))
        replace_policy(proxy, proxy_backend, directory, "[[permissions]\n", valid=False)
        read_shared(proxy, parent, port, report([ALPHA, BETA]))
        reset(client)
        read_shared(proxy, parent, port, report())
        assert reset_audits(proxy, proxy_backend) == RESET_EVENTS * 4
        hit(proxy, parent, "alpha.invalid", 200)
        assert parent.accepts == 6
        assert_no_refill(started)


def test_operator_all_reset_clears_global_limit_with_auth_and_shield_boundaries(
    proxy_backend,
    tmp_path,
    monkeypatch,
):
    with budget_proxy(proxy_backend, tmp_path, GLOBAL_POLICY, monkeypatch) as (proxy, parent, client, port):
        started = time.monotonic()
        hit(proxy, parent, "beta.invalid", 200, agent="bob")
        hit(proxy, parent, "alpha.invalid", 200)
        hit(proxy, parent, "alpha.invalid", 429)
        exhausted = report([BETA, GLOBAL, ALPHA], global_limit=True)
        read_shared(proxy, parent, port, exhausted)
        for method, path, token in (
            ("GET", "/admin/budgets", None),
            ("POST", "/admin/budgets/reset", "synthetic-wrong"),
        ):
            responses = operator_wire(proxy, port, method, path, body=b"{}", token=token)
            assert len(responses) == 1 and responses[0]["status"] == 401
            read_shared(proxy, parent, port, exhausted)
        before = parent.accepts, len(proxy.events("proxy.egress"))
        for agent, method, target in (
            ("alice", "POST", client.base_url + "/admin/budgets/reset"),
            ("bob", "CONNECT", f"127.0.0.1:{port}"),
        ):
            status, headers, body = send_request(
                proxy.paths[agent],
                target,
                method=method,
                headers={"Authorization": f"Bearer {TOKEN}"},
                body=b"{}" if method == "POST" else None,
            )
            assert status == 403
            assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "admin-shield"
            assert json.loads(body)["message"] == "Admin API not accessible through proxy"
        assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
        read_shared(proxy, parent, port, exhausted)
        assert reset_audits(proxy, proxy_backend) == []
        reset(client, ALPHA)
        retained = report([BETA, GLOBAL], global_limit=True)
        read_shared(proxy, parent, port, retained)
        hit(proxy, parent, "alpha.invalid", 429)
        read_shared(proxy, parent, port, retained)
        reset(client)
        read_shared(proxy, parent, port, report(global_limit=True))
        assert reset_audits(proxy, proxy_backend) == RESET_EVENTS * 2
        hit(proxy, parent, "alpha.invalid", 200)
        read_shared(proxy, parent, port, report([ALPHA, GLOBAL], global_limit=True))
        assert parent.accepts == 3
        assert_no_refill(started)


@pytest.mark.parametrize("payload", [b"{", b"\xff"], ids=["malformed-json", "invalid-utf8"])
def test_operator_malformed_budget_reset_is_terminal_without_mutation(
    proxy_backend,
    tmp_path,
    monkeypatch,
    request,
    payload,
):
    with budget_proxy(proxy_backend, tmp_path, POLICY, monkeypatch) as (proxy, parent, _client, port):
        started = time.monotonic()
        hit(proxy, parent, "alpha.invalid", 200)
        hit(proxy, parent, "alpha.invalid", 200)
        hit(proxy, parent, "alpha.invalid", 429)
        exhausted = report([ALPHA])
        read_shared(proxy, parent, port, exhausted)
        assert reset_audits(proxy, proxy_backend) == []
        before = parent.accepts, len(proxy.events("proxy.egress"))
        responses = operator_wire(proxy, port, "POST", "/admin/budgets/reset", body=payload)
        assert responses[0]["status"] == 400
        assert responses[0]["body"]["error"] == "Malformed JSON in request body"
        assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
        if proxy_backend == "python":
            # Establish the actual source defect before marking its final
            # terminal-response assertion as a historical expected failure.
            assert [row["status"] for row in responses] == [400, 200]
            assert responses[1]["body"] == {"status": "ok", "resource": "all", "reset_count": 0}
            after = report()
            read_shared(proxy, parent, port, after)
            audits = reset_audits(proxy, proxy_backend)
            assert audits == RESET_EVENTS
            retry_status = 200
        else:
            assert len(responses) == 1
            after = exhausted
            read_shared(proxy, parent, port, after)
            audits = reset_audits(proxy, proxy_backend)
            assert audits == []
            retry_status = 429
        hit(proxy, parent, "alpha.invalid", retry_status)
        (proxy.event_log.parent / "operator-budget-malformed.json").write_text(
            json.dumps(
                {
                    "input_hex": payload.hex(),
                    "responses": responses,
                    "before": exhausted,
                    "after": after,
                    "reset_audits": audits,
                    "retry_status": retry_status,
                    "origin_accepts": parent.accepts,
                },
                indent=2,
            )
            + "\n"
        )
        assert_no_refill(started)
    # All source state/audit/teardown evidence has passed before this marker.
    if proxy_backend == "python":
        request.node.add_marker(
            pytest.mark.xfail(
                strict=True, reason=("Source malformed reset sends 400 then resets all budgets and sends 200")
            )
        )
    assert len(responses) == 1
