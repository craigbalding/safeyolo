"""Native declaration API wire regression; HTTP context injection is separate.

The existing Python migration launcher leaves TestContext unloaded, so this
fixture selects the native backend explicitly. The source handler and Unix-slot
contracts are retained in the declaration core and source API oracles.
"""

import gzip
import json
import math
import signal
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.proxy_migration.harness import connection
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, origin_server
from tests.proxy_migration.test_agent_api_contract import AUTH_REQUIRED, HOST, TOKEN, assert_api_response
from tests.proxy_migration.test_native_network_policy import policy_proxy, replace_policy

CURRENT = "/api/test-context/current"


def declaration_policy(maximum=900):
    return json.dumps({"hosts": {"*": {"egress": "allow"}}, "addons": {"test_context": {
        "declared_ttl_max": maximum, "inject_declared": False, "target_hosts": [],
    }}})


@pytest.fixture
def native_declaration_api(proxy_backend, tmp_path):
    if proxy_backend != "rust":
        pytest.skip("Native declaration API contract; source migration launcher leaves TestContext unloaded")
    with origin_server() as parent:
        with policy_proxy("rust", tmp_path / "rust", declaration_policy(), policy_format="json", agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                          circuit_breaker_enabled=False, circuit_state_file="") as proxy:
            try:
                yield proxy
            finally:
                assert parent.accepts == 0 and parent.requests == []
                assert proxy.events("proxy.egress") == []
        assert proxy.process.returncode == 0
        assert not proxy.readiness_file.exists()
        assert all(not Path(path).exists() for path in proxy.paths.values())


@dataclass
class DeclarationResponse:
    body: dict
    started: float
    finished: float


def exchange(proxy, *, listener="alice", trusted_agent="alice", source="10.0.0.2", method="GET", body=b"",
             auth=f"Bearer {TOKEN}", path=CURRENT, encoding=None, withheld=False, before_body=None,
             status=200, expected=None):
    """Send owned UDS HTTP with optional body suspension before the real handler."""
    mutations = {"security.test_context_declared", "security.test_context_cleared"}
    before = sum((row.get("audit") or {}).get("event") in mutations for row in proxy.events("proxy.agent_api"))
    client = connection(proxy.paths[listener])
    started = time.monotonic()
    try:
        client.putrequest(method, f"http://{HOST}{path}")
        client.putheader("X-SafeYolo-Request-Id", FORGED_REQUEST_ID)
        client.putheader("X-Agent-Id", "forged")
        client.putheader("X-Forwarded-For", "203.0.113.77")
        client.putheader("Connection", "close")
        client.putheader("Content-Length", str(max(32, len(body)) if withheld else len(body)))
        if auth is not None:
            client.putheader("Authorization", auth)
        if encoding:
            client.putheader("Content-Encoding", encoding)
        client.endheaders()
        if before_body is not None:
            assert not withheld and method == "POST"
            before_body()
        if not withheld:
            client.send(body)
        response = client.getresponse()
        headers = dict(response.getheaders())
        raw = response.read()
        finished = time.monotonic()
        result = response.status, headers, raw
    finally:
        client.close()
    decoded = assert_api_response(result, status, expected)
    request_id = {key.lower(): value for key, value in headers.items()}["x-safeyolo-request-id"]
    events = [row for row in proxy.events("proxy.agent_api") if row["request_id"] == request_id]
    assert len(events) == 1
    event = events[0]
    assert event["agent"] == trusted_agent and event["status"] == status and event["handler_owned"] is True
    audit = event.get("audit")
    mutation = status == 200 and method in {"POST", "DELETE"} and path.split("?")[0].rstrip("/") == CURRENT
    after = sum((row.get("audit") or {}).get("event") in mutations for row in proxy.events("proxy.agent_api"))
    assert after == before + int(mutation)
    if mutation:
        declared = method == "POST"
        assert audit["event"] == ("security.test_context_declared" if declared else "security.test_context_cleared")
        assert audit["kind"] == "security" and audit["severity"] == "low"
        assert audit["addon"] == "agent-api" and audit["host"] == HOST
        assert audit["agent"] == trusted_agent and audit["request_id"] == request_id
        assert "decision" not in audit
        if declared:
            payload = json.loads(gzip.decompress(body) if encoding == "gzip" else body)
            assert audit["summary"] == f"Declared test context for agent {trusted_agent}"
            assert audit["details"] == {
                "source_id": source, "trusted_agent": trusted_agent, "declared_agent": decoded["context"]["agent"],
                "test_agent_match": decoded["context"]["agent"] == trusted_agent, "context": decoded["context"],
                "requested_ttl": payload.get("ttl"), "granted_ttl": decoded["expires_in"],
            }
        else:
            assert audit["summary"] == f"Cleared test context for agent {trusted_agent}"
            assert audit["details"] == {"source_id": source, "trusted_agent": trusted_agent, "had_declaration": True}
    elif auth == f"Bearer {TOKEN}":
        assert audit is None
    return DeclarationResponse(decoded, started, finished)


def declare(proxy, *, listener="alice", source="10.0.0.2", trusted_agent="alice", run="retained", ttl=90):
    body = {"context": f"run={run};agent=claimed"}
    if ttl is not None:
        body["ttl"] = ttl
    return exchange(proxy, listener=listener, source=source, trusted_agent=trusted_agent,
                    method="POST", body=json.dumps(body).encode())


def current(proxy, original, *, listener="alice", trusted_agent="alice", source="10.0.0.2"):
    result = exchange(proxy, listener=listener, trusted_agent=trusted_agent, source=source)
    assert result.body["agent"] == trusted_agent and result.body["context"] == original.body["context"]
    assert list(result.body) == ["agent", "context", "expires_in"]
    granted = original.body["expires_in"]
    lower = max(1, math.ceil(granted + original.started - result.finished))
    upper = max(1, math.ceil(granted + original.finished - result.started))
    assert lower <= result.body["expires_in"] <= upper
    return result


def reload_listeners(proxy, update):
    path = proxy.event_log.parent / "proxy.json"
    config = json.loads(path.read_text())
    update(config["listeners"])
    before = proxy.readiness_file.stat()
    replacement = path.with_suffix(".next.json")
    replacement.write_text(json.dumps(config))
    replacement.replace(path)
    proxy.process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 6
    while True:
        assert proxy.process.poll() is None
        try:
            after = proxy.readiness_file.stat()
        except FileNotFoundError:
            observed = False
        else:
            observed = (before.st_ino, before.st_mtime_ns) != (after.st_ino, after.st_mtime_ns)
        if observed:
            marker = json.loads(proxy.readiness_file.read_text())
            assert marker["ready"] is True and marker["pid"] == proxy.process.pid
            assert marker["listeners"] == len(config["listeners"])
            return
        assert time.monotonic() < deadline, "Listener reload was not published"
        time.sleep(0.025)


def test_native_declaration_api_identity_lifecycle_and_early_body_checks(native_declaration_api):
    proxy = native_declaration_api
    root = Path(proxy.paths["alice"]).parents[1]
    extra = [("alias", "alice", root / "alternate/10.0.0.2_alice/proxy.sock", None),
             ("no-source", "alice", root / "development.sock", None),
             ("non-agent", "default", root / "non-agent.sock", "10.0.0.9")]

    def add(entries):
        for label, agent, path, source in extra:
            entries.append({"agent_id": agent, "socket_path": str(path), "source_id": source})
            proxy.paths[label] = str(path)
    reload_listeners(proxy, add)
    for method, path, auth, listener, agent, status, expected in [
        ("PATCH", CURRENT, None, "alice", "alice", 405, {"error": "Method Not Allowed", "allowed": ["GET", "POST", "DELETE"]}),
        ("POST", "/policy", None, "alice", "alice", 405, {"error": "Method Not Allowed", "allowed": ["GET"]}),
        ("POST", CURRENT, None, "alice", "alice", 401, AUTH_REQUIRED),
        ("POST", CURRENT, "Bearer owned-wrong-token", "alice", "alice", 401, {"error": "Invalid agent token"}),
        ("POST", CURRENT, f"Bearer {TOKEN}", "no-source", "alice", 403, {"error": "Could not identify source"}),
        ("POST", CURRENT, f"Bearer {TOKEN}", "non-agent", "default", 403, {"error": "Could not identify agent"}),
        ("GET", CURRENT, f"Bearer {TOKEN}", "alice", "alice", 200, {"agent": "alice", "context": None}),
    ]:
        exchange(proxy, method=method, path=path, auth=auth, listener=listener, trusted_agent=agent,
                 body=b"{", withheld=True, status=status, expected=expected)
    one = declare(proxy, run="one")
    current(proxy, one)
    current(proxy, one, listener="alias")
    exchange(proxy, listener="bob", trusted_agent="bob", source="10.0.0.3", expected={"agent": "bob", "context": None})

    def reassign(agent="alice", source=None):
        def update(entries):
            next(entry for entry in entries if entry["socket_path"] == proxy.paths["alice"]).update(
                agent_id=agent, source_id=source)
        reload_listeners(proxy, update)
    reassign(source="10.0.0.4")
    exchange(proxy, source="10.0.0.4", expected={"agent": "alice", "context": None})
    current(proxy, one, listener="alias")
    reassign(agent="bob")
    exchange(proxy, trusted_agent="bob", expected={"agent": "bob", "context": None})
    exchange(proxy, listener="alias", expected={"agent": "alice", "context": None})
    declare(proxy, listener="alias", run="two")
    exchange(proxy, trusted_agent="bob", method="DELETE", body=b"{", withheld=True, expected={"status": "cleared"})
    reassign()
    exchange(proxy, expected={"agent": "alice", "context": None})


def test_native_declaration_api_byte_bodies_and_failed_mutation_retention(native_declaration_api):
    proxy = native_declaration_api
    valid = b'{"context":"run=R;agent=claimed"}'
    bodies = [(valid.decode().encode(codec), None, "R") for codec in ("utf-16", "utf-32", "utf-16-be", "utf-32-le")]
    bodies.extend([
        (gzip.compress(valid, mtime=0), "gzip", "R"),
        (b'{"context":"run=R;agent=claimed","unused":[NaN,Infinity,-Infinity,1e999]}', None, "R"),
        (b'{"context":"run=first;agent=wrong","context":"run=last;agent=claimed"}', None, "last"),
        (b'{"context":"run=deep;agent=claimed","unused":' + b"[" * 256 + b"0" + b"]" * 256 + b"}", None, "deep"),
    ])
    for body, encoding, run in bodies:
        exchange(proxy, method="POST", body=body, encoding=encoding, path=CURRENT + "///?agent=forged&source_id=forged",
                 expected={"status": "set", "agent": "alice", "expires_in": 900, "context": {"run": run, "agent": "claimed"}})
    retained = declare(proxy, run="stable")
    for body, encoding, status, expected in [
        (b"{", None, 400, {"error": "Invalid JSON body"}),
        (b"\xff", None, 400, {"error": "Invalid JSON body"}),
        (b"not-a-gzip-stream", "gzip", 500, {"error": "Internal error: ValueError"}),
        (b'{"context":[],"ttl":NaN}', None, 400, {
            "error": "context must be a string", "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
        }),
        (b'{"context":"invalid","ttl":NaN}', None, 400, {
            "error": "Invalid test context", "detail": "context field has no '=' separator: 'invalid'",
            "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
            "example": "run=sec1;agent=idor;test=IDOR-003;intent=probe;expect=blocked",
        }),
    ]:
        exchange(proxy, method="POST", body=body, encoding=encoding, status=status, expected=expected)
        current(proxy, retained)


def test_native_declaration_api_reload_uses_current_ttl_and_retains_old_records(native_declaration_api):
    proxy = native_declaration_api
    directory = proxy.event_log.parent
    retained = declare(proxy, run="stable")

    def reload_while_body_is_pending():
        replace_policy(proxy, "rust", directory, declaration_policy(3))
        assert current(proxy, retained).body["expires_in"] > 3
    changed = exchange(proxy, listener="bob", trusted_agent="bob", source="10.0.0.3", method="POST",
                       body=b'{"context":"run=newmax;agent=claimed"}', before_body=reload_while_body_is_pending)
    assert changed.body["expires_in"] == 3
    replace_policy(proxy, "rust", directory, '{"addons":', valid=False)
    current(proxy, retained)
    assert declare(proxy, listener="bob", trusted_agent="bob", source="10.0.0.3", ttl=None).body["expires_in"] == 3
    replace_policy(proxy, "rust", directory, declaration_policy(10**400))
    exchange(proxy, method="POST", body=b'{"context":"run=overflow;agent=claimed"}', status=500,
             expected={"error": "Internal error: OverflowError"})
    current(proxy, retained)
    assert declare(proxy, listener="bob", trusted_agent="bob", source="10.0.0.3", ttl=1).body["expires_in"] == 1
    replace_policy(proxy, "rust", directory, declaration_policy())
    assert declare(proxy, ttl=10**400).body["expires_in"] == 900
    exchange(proxy, method="DELETE", body=b"{", expected={"status": "cleared"})
    exchange(proxy, expected={"agent": "alice", "context": None})
