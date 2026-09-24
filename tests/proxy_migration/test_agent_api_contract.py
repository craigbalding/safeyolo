"""Finite live Agent API health/lookup contracts with synthetic token files.

Ordinary migration fixtures leave the handler disabled. These cases explicitly
enable the actual handler, with a policy and token isolated to each proxy child.
They do not cover the API's other operational routes or production audit stores.
"""

import http.client
import json
import socket
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, POLICY, origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy, replace_policy

HOST = "_safeyolo.proxy.internal"
TOKEN = "fixture-agent-api-token-one"
NEXT_TOKEN = "fixture-agent-api-token-two"
HEALTH = {"agent_api": "ok", "pdp": "ok"}
AUTH_REQUIRED = {"error": "Authorization required", "hint": "Bearer <token>"}


@contextmanager
def api_proxy(backend, directory, **options):
    with origin_server() as parent:
        with policy_proxy(backend, directory, POLICY, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}", **options) as proxy:
            try:
                yield proxy
            finally:
                assert parent.accepts == 0 and parent.requests == []
                assert proxy.events("proxy.egress") == []


def api_request(proxy, path="/health", *, agent="alice", method="GET", auth=f"Bearer {TOKEN}",
                host=HOST, headers=None):
    fields = {"X-SafeYolo-Request-Id": FORGED_REQUEST_ID, **(headers or {})}
    if auth is not None:
        fields["Authorization"] = auth
    result = send_request(proxy.paths[agent], f"http://{host}{path}", headers=fields, method=method)
    status, response_headers, body = result
    # Exact response bytes and attribution are evidence; synthetic bearer bytes
    # stay in the fixture token file and request, outside the observation log.
    with (proxy.event_log.parent / "agent-api-wire.jsonl").open("a") as output:
        output.write(json.dumps({
            "method": method, "path": path, "host": host, "trusted_agent": agent,
            "authorization_present": auth is not None, "status": status,
            "headers": response_headers, "body_hex": body.hex(),
        }) + "\n")
    return result


def assert_api_response(result, expected_status, expected_body=None, *, head=False):
    status, headers, body = result
    assert status == expected_status, body
    headers = {name.lower(): value for name, value in headers.items()}
    assert headers["content-type"] == "application/json"
    assert headers["x-safeyolo-agent-api"] == "true"
    assert headers["x-safeyolo-request-id"] != FORGED_REQUEST_ID
    if head:
        assert body == b""
        return None
    decoded = json.loads(body)
    assert body == json.dumps(decoded).encode()
    if expected_body is not None:
        assert decoded == expected_body
    return decoded


@pytest.mark.parametrize("auth,status,body", [
    (None, 401, AUTH_REQUIRED),
    ("Basic fixture", 401, AUTH_REQUIRED),
    (f"bearer {TOKEN}", 401, AUTH_REQUIRED),
    ("Bearer fixture-wrong-token", 401, {"error": "Invalid agent token"}),
    (f"Bearer {TOKEN}", 200, HEALTH),
], ids=["missing", "basic", "case-sensitive-prefix", "wrong", "valid"])
def test_agent_api_authentication(proxy_backend, tmp_path, auth, status, body):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        assert_api_response(api_request(proxy, auth=auth), status, body)


@pytest.mark.parametrize("method", ["POST", "DELETE", "OPTIONS", "HEAD"])
def test_agent_api_method_checks_precede_authentication(proxy_backend, tmp_path, method):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        allowed = ["GET"] if method in ("POST", "DELETE") else ["GET", "POST", "DELETE"]
        assert_api_response(api_request(proxy, method=method, auth=None), 405,
                            {"error": "Method Not Allowed", "allowed": allowed}, head=method == "HEAD")


@pytest.mark.parametrize("host,path,auth,status", [
    (HOST.upper(), "/health", f"Bearer {TOKEN}", 200),
    (HOST, "/health///?owned=yes", f"Bearer {TOKEN}", 200),
    (HOST, "/Health", f"Bearer {TOKEN}", 404),
    (HOST, "/fixture-unknown", f"Bearer {TOKEN}", 404),
    (HOST, "/fixture-unknown", None, 401),
], ids=["uppercase-host", "trailing-slashes-query", "case-sensitive-path", "unknown", "unknown-unauthenticated"])
def test_agent_api_path_and_host_routing(proxy_backend, tmp_path, host, path, auth, status):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        body = assert_api_response(api_request(proxy, path, host=host, auth=auth), status)
        if status == 200:
            assert body == HEALTH
        elif status == 401:
            assert body == AUTH_REQUIRED
        else:
            assert body["error"] == "Not Found"
            assert {"/health", "/lookup"} <= set(body["endpoints"])


def test_agent_api_trailing_dot_alias_remains_local(proxy_backend, tmp_path):
    """D9: the reserved hostname's root-dot alias uses authenticated local API."""
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, POLICY, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            result = api_request(proxy, host=HOST + ".", agent="bob")
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []
            assert_api_response(result, 200, HEALTH)


def test_agent_api_token_file_rotation_is_immediate(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with api_proxy(proxy_backend, directory, agent_api_token=b" \t" + TOKEN.encode() + b"\n") as proxy:
        token_file = directory / "api-data/agent_token"
        assert_api_response(api_request(proxy), 200, HEALTH)
        replacement = token_file.with_suffix(".next")
        replacement.write_text(NEXT_TOKEN + "\n")
        replacement.replace(token_file)
        assert_api_response(api_request(proxy), 401, {"error": "Invalid agent token"})
        assert_api_response(api_request(proxy, auth=f"Bearer {NEXT_TOKEN}"), 200, HEALTH)
        token_file.write_text(" \t\n")
        assert_api_response(api_request(proxy, auth=f"Bearer {NEXT_TOKEN}"), 503,
                            {"error": "Agent token not configured"})
        token_file.unlink()
        assert_api_response(api_request(proxy, auth=f"Bearer {NEXT_TOKEN}"), 503,
                            {"error": "Agent token not configured"})
        token_file.write_text(TOKEN + "\n")
        assert_api_response(api_request(proxy), 200, HEALTH)


@pytest.mark.parametrize("query,status,body", [
    ("", 400, {"error": "Missing 'host' parameter", "usage": "/lookup?host=example.com"}),
    ("host=target.invalid&scheme=HTTP&method=post&path=%2Fowned%3Fpart%3Done", 200,
     {"host": "target.invalid", "port": 80, "method": "POST", "path": "/owned?part=one",
      "agent": "alice", "effect": "allow", "reason": ""}),
    ("host=target.invalid&scheme=ws&method=CONNECT", 200,
     {"host": "target.invalid", "port": 80, "method": "CONNECT", "path": "",
      "agent": "alice", "effect": "allow", "reason": ""}),
    ("host=target.invalid&scheme=ftp", 400, {"error": "scheme must be http, https, ws or wss"}),
    ("host=target.invalid&port=0", 400, {"error": "port must be an integer from 1 to 65535"}),
], ids=["missing-host", "http-method-path", "ws-connect", "bad-scheme", "bad-port"])
def test_agent_api_lookup_parameters(proxy_backend, tmp_path, query, status, body):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        assert_api_response(api_request(proxy, "/lookup?" + query), status, body)


def test_agent_api_lookup_uses_trusted_identity_without_spending_budget(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, POLICY.replace("12000", "1"), agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            started = time.monotonic()
            for agent in ("alice", "bob"):
                forged = "bob" if agent == "alice" else "alice"
                for _ in range(3):
                    result = api_request(proxy, f"/lookup?host=target.invalid&agent={forged}&agent_id={forged}",
                                         agent=agent, headers={"X-SafeYolo-Agent": forged})
                    assert_api_response(result, 200, {
                        "host": "target.invalid", "port": 443, "method": "GET", "path": "/",
                        "agent": agent, "effect": "allow" if agent == "alice" else "deny", "reason": "",
                    })
            assert parent.accepts == 0 and proxy.events("proxy.egress") == []
            # The rate=1 policy admits two requests using its existing burst
            # allowance. Read-only lookups above must not consume that allowance.
            for expected in (200, 200, 429):
                status, _, body = send_request(proxy.paths["alice"], "http://target.invalid:8123/budget")
                assert status == expected, body
            assert parent.accepts == 2
            assert_api_response(api_request(proxy, "/lookup?host=target.invalid"), 200, {
                "host": "target.invalid", "port": 443, "method": "GET", "path": "/", "agent": "alice",
                "effect": "budget_exceeded", "reason": "Request budget exceeded for target.invalid",
            })
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2
            assert time.monotonic() - started < 30, "Scenario crossed the intended no-refill window"


def raw_api_request(proxy, *, method="GET", auth_headers=()):
    """Preserve repeated Authorization fields and ordinary CONNECT authority."""
    authority = f"{HOST}:443" if method == "CONNECT" else HOST
    target = authority if method == "CONNECT" else f"http://{HOST}/health?owned=synthetic"
    head = (f"{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
            f"X-SafeYolo-Request-Id: {FORGED_REQUEST_ID}\r\n").encode()
    head += b"".join(b"Authorization: " + value + b"\r\n" for value in auth_headers) + b"\r\n"
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(proxy.paths["alice"])
        stream.sendall(head)
        response = http.client.HTTPResponse(stream, method=method)
        response.begin()
        # A faulty accepted CONNECT must fail the assertion, without waiting
        # for a tunnel body that has no HTTP message framing.
        body = b"" if method == "CONNECT" and response.status == 200 else response.read()
        result = response.status, dict(response.getheaders()), body
    with (proxy.event_log.parent / "agent-api-raw-wire.jsonl").open("a") as output:
        output.write(json.dumps({
            "method": method, "target": target, "authorization_fields": len(auth_headers),
            "status": result[0], "headers": result[1], "body_hex": body.hex(),
        }) + "\n")
    return result


def assert_unavailable_api_response(result):
    body = assert_api_response(result, 503)
    headers = {name.lower(): value for name, value in result[1].items()}
    assert body == {
        "error": "SafeYolo Agent API handler unavailable", "reason_code": "agent_api_unavailable",
        "handler": "agent-api", "host": HOST, "path": "/health",
        "request_id": headers["x-safeyolo-request-id"],
    }


@pytest.mark.parametrize("auth_headers", [(), (f"Bearer {TOKEN}".encode(),)], ids=["missing-auth", "valid-auth"])
def test_agent_api_reserved_connect_cannot_open_a_tunnel(proxy_backend, tmp_path, auth_headers):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        status, headers, body = raw_api_request(proxy, method="CONNECT", auth_headers=auth_headers)
        headers = {name.lower(): value for name, value in headers.items()}
        assert status == 403, body
        assert body == b'{"error":"Reserved virtual host cannot accept CONNECT"}'
        assert headers["content-type"] == "application/json"
        assert headers["x-blocked-by"] == "transport-guard"
        assert headers["x-safeyolo-request-id"] != FORGED_REQUEST_ID
        assert "x-safeyolo-agent-api" not in headers


@pytest.mark.parametrize("mode,token", [
    ("missing", None), ("invalid-utf8", b"\xff"),
    ("non-ascii", "fixture-\u03bb".encode()), ("directory", None),
])
def test_agent_api_token_file_errors_remain_local(proxy_backend, tmp_path, mode, token):
    directory = tmp_path / proxy_backend
    with api_proxy(proxy_backend, directory, agent_api_token=token) as proxy:
        if mode == "directory":
            (directory / "api-data/agent_token").mkdir()
        result = api_request(proxy, "/health?owned=synthetic")
        if mode in ("invalid-utf8", "non-ascii"):
            assert_unavailable_api_response(result)
        else:
            assert_api_response(result, 503, {"error": "Agent token not configured"})


@pytest.mark.parametrize("auth_headers,body", [
    ((f"Bearer {TOKEN}".encode(), f"Bearer {TOKEN}".encode()), {"error": "Invalid agent token"}),
    ((f"Bearer {TOKEN}".encode(), b"Bearer fixture-wrong"), {"error": "Invalid agent token"}),
    ((b"Bearer fixture-wrong", f"Bearer {TOKEN}".encode()), {"error": "Invalid agent token"}),
    ((b"Basic fixture", f"Bearer {TOKEN}".encode()), AUTH_REQUIRED),
], ids=["valid-valid", "valid-wrong", "wrong-valid", "basic-valid"])
def test_agent_api_duplicate_authorization_uses_combined_value(proxy_backend, tmp_path, auth_headers, body):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        assert_api_response(raw_api_request(proxy, auth_headers=auth_headers), 401, body)


def test_agent_api_lookup_uses_last_valid_policy_reload(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with api_proxy(proxy_backend, directory) as proxy:
        lookup = "/lookup?host=target.invalid"
        body = assert_api_response(api_request(proxy, lookup), 200)
        assert body["agent"] == "alice" and body["effect"] == "allow"
        replace_policy(proxy, proxy_backend, directory, POLICY.replace("agents.alice", "agents.bob"))
        body = assert_api_response(api_request(proxy, lookup), 200)
        assert body["agent"] == "alice" and body["effect"] == "deny"
        replace_policy(proxy, proxy_backend, directory, "[hosts\n", valid=False)
        body = assert_api_response(api_request(proxy, lookup), 200)
        assert body["agent"] == "alice" and body["effect"] == "deny"


@pytest.mark.parametrize("case", ["health", "handler-backstop", "wrong-token"])
def test_agent_api_response_survives_development_evidence_failure(proxy_backend, tmp_path, case):
    """Fail actual sink writes while preserving the already-local API response.

    This exercises the development evidence writer. The source production
    audit writer has separate retained ENOSPC specimens; native production
    audit persistence is outside this fixture's contract.
    """
    full = Path("/dev/full")
    if not full.exists():
        pytest.skip("Requires /dev/full to inject a real write failure")
    directory = tmp_path / proxy_backend
    directory.mkdir()
    sink = directory / "events.jsonl"
    # Native keeps an open descriptor, so select the failing sink before
    # launch. Never read /dev/full through RunningProxy.events or read_events.
    sink.symlink_to(full)
    try:
        with origin_server() as parent:
            with policy_proxy(proxy_backend, directory, POLICY, agent_api=True,
                              agent_api_token=b"\xff" if case == "handler-backstop" else TOKEN.encode(),
                              parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
                auth = "Bearer fixture-wrong" if case == "wrong-token" else f"Bearer {TOKEN}"
                result = api_request(proxy, "/health?owned=synthetic", auth=auth)
                if case == "handler-backstop":
                    assert_unavailable_api_response(result)
                elif case == "wrong-token":
                    assert_api_response(result, 401, {"error": "Invalid agent token"})
                else:
                    assert_api_response(result, 200, HEALTH)
                headers = {name.lower(): value for name, value in result[1].items()}
                if proxy_backend == "rust":
                    assert headers["x-safeyolo-evidence-error"] == "true"
                    assert "request evidence write failed:" in (directory / "process.log").read_text()
                assert proxy.process.poll() is None
                assert parent.accepts == 0 and parent.requests == []
                (directory / "evidence-write-failure.json").write_text(json.dumps({
                    "case": case, "sink": str(full),
                    "native_evidence_marker": headers.get("x-safeyolo-evidence-error"),
                    "status": result[0], "origin_accepts": parent.accepts,
                    "event_log_read": False, "source_production_audit_failure_claim": False,
                }, indent=2) + "\n")
    finally:
        # Retained artifacts must never lead a reader into this endless device.
        sink.unlink()
