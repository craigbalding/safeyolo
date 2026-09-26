"""First shared HTTP contracts; transport/TLS/WS coverage remains explicit."""

import concurrent.futures
import http.client
import json
import socket
import socketserver
import ssl
import threading
import time
from contextlib import contextmanager
from urllib.parse import urlsplit

import pytest
from mitmproxy.certs import CertStore

from tests.proxy_migration import scenarios
from tests.proxy_migration.harness import connection, launch_proxy, read_events, request
from tests.proxy_migration.run import (
    cancelled_sse_workload,
    concurrent_short_admin_workload,
    short_https_connections,
    streamed_control_workload,
    streamed_slow_admin_workload,
)
from tests.proxy_migration.scenarios import (
    FORGED_REQUEST_ID,
    POLICY,
    network_scenario,
    origin_server,
    request_evidence,
    reserved_scenario,
    scoped_api,
    wait_for_reserved_audit,
)
from tests.proxy_migration.test_http2_contract import origin_certificate
from tests.proxy_migration.test_http2_contract import origin_server as tls_origin_server
from tests.proxy_migration.test_websocket_contract import read_head


@pytest.mark.parametrize("parent", [False, True], ids=["direct", "parent"])
def test_two_agent_http_policy_and_attribution(proxy_backend, tmp_path, parent):
    network_scenario(proxy_backend, tmp_path / proxy_backend, parent=parent)


def test_enforced_context_and_scoped_request_evidence(proxy_backend, tmp_path):
    """A source-owned declaration admits its target without widening another listener."""
    directory = tmp_path / proxy_backend
    policy = json.dumps({
        "hosts": {"*": {"egress": "allow"}},
        "addons": {"test_context": {
            "target_hosts": ["context.invalid"], "inject_declared": True,
        }},
    })
    run = "context-request-ids"
    context = f"run={run};agent=bob;test=request-ids"
    target = "http://context.invalid:8123"
    forged = {
        "X-Agent-Id": "alice", "X-SafeYolo-Agent": "alice",
        "X-Forwarded-For": "10.0.0.2", "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
        "X-SafeYolo-Trace": "1",
    }
    with origin_server(keep_alive=True, capture_heads=True) as parent:
        with launch_proxy(
            proxy_backend, directory, policy, policy_format="json", native_policy=True,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
            agent_api=True, flow_store_enabled=True, test_context_block=True,
        ) as proxy:
            denials = []
            for agent in ("alice", "bob"):
                status, headers, body = request(proxy.paths[agent], target + "/missing",
                                                headers=forged)
                identifier = {key.lower(): value for key, value in headers.items()}[
                    "x-safeyolo-request-id"]
                assert status == 428 and parent.accepts == 0 and parent.requests == []
                assert json.loads(body)["type"] == "missing_context"
                assert {key.lower(): value for key, value in headers.items()}[
                    "x-blocked-by"] == "test-context"
                scoped = request_evidence(
                    proxy, agent, identifier, host="context.invalid", port=8123,
                    method="GET", status=428, decision="deny", blocker="test-context",
                    run=run, path="/missing",
                )
                denials.append((agent, identifier, scoped))

            status, _, body = request(proxy.paths["alice"], "http://ordinary.invalid:8123/unrelated")
            assert status == 200 and body == b"hello"
            assert len(parent.requests) == 1
            assert parent.requests[0]["target"] == "http://ordinary.invalid:8123/unrelated"

            declared = scoped_api(
                proxy, "alice", "/api/test-context/current", method="POST",
                body=json.dumps({"context": context, "ttl": 60}).encode(),
                headers=forged,
            )
            assert declared["agent"] == "alice" and declared["context"] == {
                "run": run, "agent": "bob", "test": "request-ids",
            }
            assert 0 < declared["expires_in"] <= 60
            current = scoped_api(proxy, "alice", "/api/test-context/current")
            assert current["agent"] == "alice" and current["context"] == declared["context"]
            assert 0 < current["expires_in"] <= declared["expires_in"]
            assert scoped_api(proxy, "bob", "/api/test-context/current") == {
                "agent": "bob", "context": None,
            }

            before = (parent.accepts, len(parent.requests))
            status, headers, _ = request(proxy.paths["bob"], target + "/bob",
                                         headers=forged)
            identifier = {key.lower(): value for key, value in headers.items()}[
                "x-safeyolo-request-id"]
            assert status == 428 and (parent.accepts, len(parent.requests)) == before
            scoped = request_evidence(
                proxy, "bob", identifier, host="context.invalid", port=8123,
                method="GET", status=428, decision="deny", blocker="test-context",
                run=run, path="/bob",
            )
            denials.append(("bob", identifier, scoped))

            # Agent and source claims on Bob's listener cannot replace Alice's
            # declaration. Bob may create and use only his own context.
            bob_run = "context-bob-owned"
            bob_context = f"run={bob_run};agent=alice;test=request-ids"
            before = (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress")))
            bob_declared = scoped_api(
                proxy, "bob", "/api/test-context/current?agent=alice&source_id=10.0.0.2",
                method="POST", body=json.dumps({"context": bob_context, "ttl": 60}).encode(),
                headers=forged,
            )
            assert bob_declared["agent"] == "bob" and bob_declared["context"] == {
                "run": bob_run, "agent": "alice", "test": "request-ids",
            }
            assert scoped_api(proxy, "bob", "/api/test-context/current?agent=alice")["context"] == bob_declared["context"]
            assert scoped_api(proxy, "alice", "/api/test-context/current")["context"] == declared["context"]
            assert (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress"))) == before

            status, headers, body = request(proxy.paths["bob"], target + "/bob-declared", headers=forged)
            assert status == 200 and body == b"hello"
            assert len(parent.requests) == before[1] + 1
            assert parent.requests[-1]["target"] == target + "/bob-declared"
            assert b"x-safeyolo-test-context:" not in parent.request_heads[-1].lower()
            bob_owned_id = {key.lower(): value for key, value in headers.items()}["x-safeyolo-request-id"]
            bob_owned = request_evidence(
                proxy, "bob", bob_owned_id, host="context.invalid", port=8123,
                method="GET", status=200, decision="allow", run=bob_run,
                path="/bob-declared", flow_expected=True, context_source="declared",
            )
            assert json.loads(bob_owned["flow"]["context_json"]) == bob_declared["context"]
            assert bob_owned["flow"]["source_id"] == "10.0.0.3"
            assert bob_owned["flow"]["test_agent"] == "alice"
            assert bob_owned["flow"]["evidence_owner"] == "bob"

            before = (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress")))
            assert scoped_api(proxy, "bob", "/api/test-context/current?agent=alice", method="DELETE") == {
                "status": "cleared",
            }
            assert scoped_api(proxy, "bob", "/api/test-context/current?agent=alice") == {
                "agent": "bob", "context": None,
            }
            assert scoped_api(proxy, "alice", "/api/test-context/current")["context"] == declared["context"]
            assert (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress"))) == before
            status, headers, body = request(proxy.paths["bob"], target + "/bob-cleared", headers=forged)
            assert status == 428 and json.loads(body)["type"] == "missing_context"
            assert (parent.accepts, len(parent.requests), len(proxy.events("proxy.egress"))) == before
            identifier = {key.lower(): value for key, value in headers.items()}["x-safeyolo-request-id"]
            scoped = request_evidence(
                proxy, "bob", identifier, host="context.invalid", port=8123,
                method="GET", status=428, decision="deny", blocker="test-context",
                run=bob_run, path="/bob-cleared",
            )
            denials.append(("bob", identifier, scoped))

            before = (parent.accepts, len(parent.requests))
            status, headers, _ = request(
                proxy.paths["alice"], target + "/malformed",
                headers={**forged, "X-SafeYolo-Test-Context": "malformed"},
            )
            identifier = {key.lower(): value for key, value in headers.items()}[
                "x-safeyolo-request-id"]
            assert status == 428 and (parent.accepts, len(parent.requests)) == before
            scoped = request_evidence(
                proxy, "alice", identifier, host="context.invalid", port=8123,
                method="GET", status=428, decision="deny", blocker="test-context",
                block_reason="malformed_context", run=run, path="/malformed",
            )
            denials.append(("alice", identifier, scoped))

            client = connection(proxy.paths["alice"])
            owned = []
            try:
                for path, source, extra in (
                    ("/declared?part=one&part=two%2Fthree", "declared", {}),
                    ("/explicit?part=one&part=two%2Fthree", "header",
                     {"X-SafeYolo-Test-Context": context}),
                ):
                    before = len(parent.requests)
                    client.request("GET", target + path, headers={**forged, **extra})
                    response = client.getresponse()
                    headers = {key.lower(): value for key, value in response.getheaders()}
                    assert response.status == 200 and response.read() == b"hello"
                    identifier = headers["x-safeyolo-request-id"]
                    assert len(parent.requests) == before + 1
                    assert parent.requests[-1]["target"] == target + path
                    assert b"x-safeyolo-test-context:" not in parent.request_heads[-1].lower()
                    assert FORGED_REQUEST_ID.encode() not in parent.request_heads[-1]
                    owned.append((identifier, request_evidence(
                        proxy, "alice", identifier, host="context.invalid", port=8123,
                        method="GET", status=200, decision="allow", run=run,
                        path=path, flow_expected=True, context_source=source,
                    )))
            finally:
                client.close()
            assert owned[0][0] != owned[1][0]
            assert owned[0][1]["connection_id"] == owned[1][1]["connection_id"]
            for _, evidence in owned:
                flow = evidence["flow"]
                assert json.loads(flow["context_json"]) == declared["context"]
                assert flow["source_id"] == "10.0.0.2" and flow["test_agent"] == "bob"
                assert flow["evidence_owner"] == "alice"

            search = f"/api/flows/search?run={run}&test=request-ids"
            assert {flow["request_id"] for flow in scoped_api(proxy, "alice", search)["flows"]} == {
                identifier for identifier, _ in owned
            }
            assert scoped_api(proxy, "bob", search)["flows"] == []

            observed_ids = ({identifier for _, identifier, _ in denials} |
                            {identifier for identifier, _ in owned} | {bob_owned_id})
            runtime = {event["request_id"]: event for event in proxy.events("proxy.request")
                       if event["request_id"] in observed_ids}
            assert len(runtime) == len(denials) + len(owned) + 1
            assert all(event["host"] == "context.invalid" and event["port"] == 8123
                       for event in runtime.values())
            for agent, identifier, evidence in denials:
                assert runtime[identifier]["agent"] == agent
                assert runtime[identifier]["status"] == 428
                assert runtime[identifier]["decision"] == "deny"
                assert runtime[identifier]["connection_id"] == evidence["connection_id"]
            for identifier, evidence in owned:
                assert runtime[identifier]["agent"] == "alice"
                assert runtime[identifier]["status"] == 200
                assert runtime[identifier]["decision"] == "allow"
                assert runtime[identifier]["connection_id"] == evidence["connection_id"]
            assert runtime[bob_owned_id]["agent"] == "bob"
            assert runtime[bob_owned_id]["status"] == 200
            assert runtime[bob_owned_id]["decision"] == "allow"
            assert runtime[bob_owned_id]["connection_id"] == bob_owned["connection_id"]

            deadline = time.monotonic() + 2
            while True:
                context_mutations = [event for event in read_events(directory / "audit.jsonl")
                                     if event["event"] in {
                                         "security.test_context_declared", "security.test_context_cleared",
                                     }]
                if len(context_mutations) >= 3 or time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            assert [(event["event"], event["agent"], event["details"]["source_id"])
                    for event in context_mutations] == [
                ("security.test_context_declared", "alice", "10.0.0.2"),
                ("security.test_context_declared", "bob", "10.0.0.3"),
                ("security.test_context_cleared", "bob", "10.0.0.3"),
            ]
            assert context_mutations[0]["details"]["trusted_agent"] == "alice"
            assert context_mutations[0]["details"]["declared_agent"] == "bob"
            assert context_mutations[1]["details"]["trusted_agent"] == "bob"
            assert context_mutations[1]["details"]["declared_agent"] == "alice"
            local_runtime = {event["request_id"]: event for event in proxy.events("proxy.request")
                             if event["host"].lower().rstrip(".") == "_safeyolo.proxy.internal"}
            for event in context_mutations:
                runtime_event = local_runtime[event["request_id"]]
                assert runtime_event["agent"] == event["agent"]
                assert runtime_event["status"] == 200 and runtime_event["decision"] == "local"
            assert len(parent.requests) == 4


def test_connect_and_inner_request_ids_keep_scoped_connection_evidence(proxy_backend, tmp_path):
    """An admitted tunnel and its inner decision have distinct owned IDs."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    pem, public = origin_certificate(directory)
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    policy = '''[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { agent = "alice", method = "GET" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
'''
    observations = []
    run = "request-ids-connect"
    with tls_origin_server(pem, ("http/1.1",)) as origin:
        with launch_proxy(proxy_backend, directory, policy, native_policy=True, tls=True,
                          upstream_ca=public, eager_connect=True, agent_api=True,
                          flow_store_enabled=True) as proxy:
            for agent, expected in (("bob", 403), ("alice", 200)):
                before = (origin.accepts, len(origin.requests))
                raw = socket.socket(socket.AF_UNIX)
                raw.settimeout(5)
                try:
                    raw.connect(proxy.paths[agent])
                    connect_request = (f"CONNECT {origin.authority} HTTP/1.1\r\n"
                                       f"Host: {origin.authority}\r\n"
                                       f"X-SafeYolo-Request-Id: {FORGED_REQUEST_ID}\r\n"
                                       "X-SafeYolo-Trace: 1\r\n\r\n").encode()
                    raw.sendall(connect_request)
                    connect_status, connect_headers = read_head(raw)
                    assert connect_status.startswith("HTTP/1.1 200 "), connect_status
                    assert len(connect_headers["x-safeyolo-request-id"]) == 1
                    connect_id = connect_headers["x-safeyolo-request-id"][0]
                    outer = request_evidence(
                        proxy, agent, connect_id, host="127.0.0.1", port=origin.server_address[1],
                        method="CONNECT", status=200, decision="allow", run=run,
                    )
                    assert origin.accepts == before[0] + 1
                    context = ssl.create_default_context(cafile=directory / "ca/mitmproxy-ca-cert.pem")
                    stream = context.wrap_socket(raw, server_hostname="127.0.0.1")
                    client = http.client.HTTPConnection("127.0.0.1", origin.server_address[1], timeout=5)
                    client.sock = stream
                    try:
                        client.request("GET", "/inner", headers={
                            "X-SafeYolo-Agent": "alice" if agent == "bob" else "bob",
                            "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                            "X-SafeYolo-Trace": "1",
                            "X-SafeYolo-Test-Context": f"run={run};agent={agent};test=request-ids",
                        })
                        response = client.getresponse()
                        inner_headers = dict(response.getheaders())
                        body = response.read()
                        assert response.status == expected, body
                        inner_id = {name.lower(): value for name, value in inner_headers.items()}[
                            "x-safeyolo-request-id"]
                        assert inner_id != connect_id
                        inner = request_evidence(
                            proxy, agent, inner_id, host="127.0.0.1", port=origin.server_address[1],
                            method="GET", status=expected,
                            decision="allow" if expected == 200 else "deny", run=run,
                            path="/inner", flow_expected=expected == 200,
                        )
                        assert inner["connection_id"] == outer["connection_id"]
                        assert origin.accepts == before[0] + 1
                        assert len(origin.requests) == before[1] + int(expected == 200)
                        if expected == 200:
                            assert body == b"hello"
                            assert origin.requests[-1]["head"].startswith("GET /inner HTTP/1.1\r\n")
                        observations.append({
                            "agent": agent, "connect_request_hex": connect_request.hex(),
                            "connect_status": connect_status, "connect_headers": connect_headers,
                            "connect_id": connect_id, "outer": outer,
                            "inner_status": expected, "inner_headers": inner_headers,
                            "inner_body_hex": body.hex(), "inner_id": inner_id, "inner": inner,
                            "origin_accepts_before": before[0], "origin_accepts_after": origin.accepts,
                            "origin_requests_before": before[1],
                            "origin_requests_after": list(origin.requests),
                        })
                    finally:
                        client.close()
                finally:
                    raw.close()
            assert observations[0]["outer"]["connection_id"] != observations[1]["outer"]["connection_id"]
            for observation in observations:
                events = [event for event in proxy.events("proxy.request")
                          if event.get("request_id") == observation["inner_id"]]
                assert len(events) == 1 and events[0]["status"] == observation["inner_status"]
                assert events[0]["connection_id"] == observation["inner"]["connection_id"]
                assert events[0]["agent"] == observation["agent"]
        (directory / "connect-request-id-observations.json").write_text(
            json.dumps(observations, indent=2) + "\n"
        )


def test_reserved_hosts_stay_local_and_do_not_contact_parent(proxy_backend, tmp_path):
    reserved_scenario(proxy_backend, tmp_path / proxy_backend)


@pytest.mark.parametrize(
    ("expected_event", "request_id", "before_count"),
    [
        ("security.agent_api_unavailable", "req-" + "1" * 32, 0),
        ("security.agent_auth_failed", None, 1),
    ],
    ids=["request-id", "new-row-delta"],
)
def test_reserved_audit_wait_accepts_a_late_matching_row(
    tmp_path, monkeypatch, expected_event, request_id, before_count
):
    audit_path = tmp_path / "audit.jsonl"
    old = {"event": expected_event}
    late = {"event": expected_event}
    if request_id is not None:
        old["request_id"] = "req-" + "2" * 32
        late["request_id"] = request_id
    audit_path.write_text(json.dumps(old) + "\n")
    first_read = threading.Event()
    original_read = scenarios.read_events

    def read_then_signal(path):
        rows = original_read(path)
        first_read.set()
        return rows

    monkeypatch.setattr(scenarios, "read_events", read_then_signal)

    def append_late_row():
        if first_read.wait(1):
            with audit_path.open("a") as output:
                output.write(json.dumps(late) + "\n")

    writer = threading.Thread(target=append_late_row)
    writer.start()
    try:
        rows = wait_for_reserved_audit(
            audit_path, before_count, expected_event, request_id=request_id,
            timeout_seconds=0.5,
        )
    finally:
        writer.join(timeout=1)
    assert not writer.is_alive()
    assert rows == [late]


@pytest.mark.parametrize(
    ("rows", "before_count", "request_id"),
    [
        ([], 0, "req-" + "1" * 32),
        ([{"event": "security.agent_api_unavailable", "request_id": "req-" + "2" * 32},
          {"event": "traffic.response", "request_id": "req-" + "1" * 32}], 0, "req-" + "1" * 32),
        ([{"event": "security.agent_auth_failed"}, {"event": "traffic.response"}], 1, None),
    ],
    ids=["absent", "wrong-request-and-event", "no-new-auth-row"],
)
def test_reserved_audit_wait_rejects_absent_or_wrong_rows(
    tmp_path, rows, before_count, request_id
):
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    expected_event = (
        "security.agent_auth_failed" if request_id is None else "security.agent_api_unavailable"
    )
    with pytest.raises(AssertionError, match=expected_event):
        wait_for_reserved_audit(
            audit_path, before_count, expected_event, request_id=request_id,
            timeout_seconds=0.03,
        )


class ViaRelay(socketserver.ThreadingTCPServer):
    """Record an HTTP parent request, then deliver it to an owned proxy socket."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.accepts = 0
        self.request_heads = []
        self.response_statuses = []
        self.paths = {}
        self.errors = []
        super().__init__(("127.0.0.1", 0), ViaRelayHandler)

    def get_request(self):
        accepted = super().get_request()
        self.accepts += 1
        return accepted


class ViaRelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                chunk = self.request.recv(1)
                assert chunk and len(head) < 65536, "incomplete parent request head"
                head.extend(chunk)
            head = bytes(head)
            self.server.request_heads.append(head)
            target = head.split(b"\r\n", 1)[0].split(b" ", 2)[1].decode("ascii")
            route = "loop" if urlsplit(target).path == "/loop" else "peer"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as downstream:
                downstream.settimeout(5)
                downstream.connect(self.server.paths[route])
                downstream.sendall(head)
                response = http.client.HTTPResponse(downstream)
                response.begin()
                body = response.read()
                self.server.response_statuses.append(response.status)
                headers = [(name, value) for name, value in response.getheaders()
                           if name.lower() not in {"connection", "content-length", "transfer-encoding"}]
                status_line = f"HTTP/1.1 {response.status} {response.reason}\r\n"
                header_lines = "".join(f"{name}: {value}\r\n" for name, value in headers)
                self.request.sendall((status_line + header_lines +
                                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
                                     + body)
        except Exception as error:
            self.server.errors.append(error)


@contextmanager
def via_relay():
    relay = ViaRelay()
    thread = threading.Thread(target=relay.serve_forever)
    thread.start()
    try:
        yield relay
    finally:
        relay.shutdown()
        relay.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "owned Via relay did not stop"
        if relay.errors:
            raise relay.errors[0]


def test_via_self_loop_stays_local_and_distinct_instance_reaches_parent(proxy_backend, tmp_path):
    """A forwarded request loops into one real instance and crosses another."""
    own_token = "fixture-via-instance"
    other_token = own_token + "-peer"
    policy = 'budget = 12000\n[hosts]\n"*" = { egress = "allow" }\n'
    loop_target = "http://target.invalid:8123/loop?canary=fixture-via-canary"
    distinct_target = "http://target.invalid:8123/distinct?canary=fixture-via-canary"
    control_target = "http://control.invalid:8123/control"
    with origin_server(capture_heads=True) as origin, via_relay() as relay:
        origin_url = f"http://127.0.0.1:{origin.server_address[1]}"
        relay_url = f"http://127.0.0.1:{relay.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / "peer", policy, parent_proxy=origin_url,
                          native_policy=True, via_token=other_token) as peer:
            with launch_proxy(proxy_backend, tmp_path / "first", policy, parent_proxy=relay_url,
                              native_policy=True, via_token=own_token) as first:
                relay.paths = {"loop": first.paths["alice"], "peer": peer.paths["alice"]}
                client_ids = []
                for target, status, relay_accepts, origin_accepts in (
                    (loop_target, 508, 1, 0),
                    (distinct_target, 200, 2, 1),
                    (control_target, 200, 3, 2),
                ):
                    actual, headers, body = request(first.paths["alice"], target,
                                                    headers={"X-Fixture-Canary": "fixture-via-canary"})
                    assert actual == status, (target, actual, body)
                    assert relay.accepts == len(relay.request_heads) == relay_accepts
                    assert origin.accepts == len(origin.requests) == origin_accepts
                    assert len(first.events("proxy.egress")) == relay_accepts
                    assert len(peer.events("proxy.egress")) == origin_accepts
                    identifier = {key.lower(): value for key, value in headers.items()}[
                        "x-safeyolo-request-id"]
                    assert identifier.startswith("req-")
                    client_ids.append(identifier)
                    if status == 508:
                        assert b"proxy loop" in body.lower()
                        assert relay.response_statuses == [508]
                    else:
                        assert body == b"hello"

                assert relay.response_statuses == [508, 200, 200]
                assert [head.split(b"\r\n", 1)[0] for head in relay.request_heads] == [
                    f"GET {target} HTTP/1.1".encode()
                    for target in (loop_target, distinct_target, control_target)
                ]
                assert all(b"X-Fixture-Canary: fixture-via-canary\r\n" in head
                           for head in relay.request_heads)
                assert all(f"1.1 {own_token}".encode() in head for head in relay.request_heads)
                assert all(f"1.1 {other_token}".encode() not in head for head in relay.request_heads)
                assert [item["target"] for item in origin.requests] == [
                    distinct_target, control_target,
                ]
                assert origin.canary_headers == ["fixture-via-canary"] * 2
                assert all(f"1.1 {own_token}" in ", ".join(headers)
                           and f"1.1 {other_token}" in ", ".join(headers)
                           for headers in origin.via_headers)
                assert all(b"fixture-via-canary" in head for head in origin.request_heads)
                assert len(set(client_ids)) == 3
                first_requests = first.events("proxy.request")
                assert len(first_requests) == 4
                by_id = {row["request_id"]: row for row in first_requests}
                assert len(by_id) == 4
                assert [(by_id[identifier]["status"], by_id[identifier]["decision"])
                        for identifier in client_ids] == [(508, "allow"), (200, "allow"), (200, "allow")]
                blocked = next(row for row in first_requests if row["request_id"] not in client_ids)
                assert (blocked["status"], blocked["decision"], blocked["agent"],
                        blocked["host"], blocked["port"]) == (
                    508, "deny", "alice", "target.invalid", 8123,
                )
                peer_requests = peer.events("proxy.request")
                assert [(row["host"], row["status"], row["decision"], row["agent"])
                        for row in peer_requests] == [
                    ("target.invalid", 200, "allow", "alice"),
                    ("control.invalid", 200, "allow", "alice"),
                ]
                audit = read_events((tmp_path / "first") / "audit.jsonl")
                if proxy_backend == "python":
                    assert any(row["event"] == "security.loop_guard" and row["agent"] == "alice"
                               and row["decision"] == "deny"
                               and row["request_id"] == blocked["request_id"] for row in audit)
                else:
                    assert any(row["event"] == "traffic.response" and row["agent"] == "alice"
                               and row["details"].get("blocked_by") == "loop-guard"
                               and row["details"].get("block_reason") == "proxy_loop"
                               and row["request_id"] == blocked["request_id"]
                               for row in audit)

                # Preserve the received-by spelling controls alongside the routed loop.
                case_status, case_headers, _ = request(
                    first.paths["alice"], "http://control.invalid:8123/case",
                    headers={"Via": f"1.0 earlier-instance, 1.1 {own_token.upper()}"},
                )
                assert case_status == 508
                assert {key.lower(): value for key, value in case_headers.items()}[
                    "x-blocked-by"] == "loop-guard"
                assert relay.accepts == 3 and origin.accepts == 2
                near_token = own_token + "-near"
                near_status, _, near_body = request(
                    first.paths["alice"], "http://control.invalid:8123/near",
                    headers={"Via": f"1.1 {near_token}"},
                )
                assert near_status == 200 and near_body == b"hello"
                assert relay.accepts == 4 and origin.accepts == 3
                assert origin.requests[-1]["target"] == "http://control.invalid:8123/near"
                assert all(f"1.1 {token}" in ", ".join(origin.via_headers[-1])
                           for token in (near_token, own_token, other_token))


def test_streamed_response_delivers_before_release_and_keeps_control_live(proxy_backend, tmp_path):
    result = streamed_control_workload(proxy_backend, tmp_path / proxy_backend)
    assert result["first_event_before_release"] is True
    assert result["control_completed_before_stream_release"] is True
    assert result["control_elapsed_seconds"] < 5
    assert result["stream_released_after_control"] is True
    timing = result["origin_observation"]
    assert timing["first_flush_at"] <= timing["first_received_at"] < timing["released_at"]
    assert timing["control_completed_at"] < timing["released_at"]
    assert timing["released_at"] <= timing["release_seen_at"] <= timing["finished_at"]
    assert timing["accepted_connections"] == 2
    assert timing["stream_finished_after_read"] is True


def test_slow_consumer_keeps_allowed_request_and_authenticated_admin_live(proxy_backend, tmp_path):
    result = streamed_slow_admin_workload(proxy_backend, tmp_path / proxy_backend)
    assert result["first_event_before_release"] is True
    assert result["origin_bytes_sent_before_controls"] > 0
    assert result["control_completed_before_release"] is True
    assert result["control_elapsed_seconds"] < 5
    assert result["request_counts"] == {
        "origin_requests": 2,
        "origin_error_responses": 0,
        "proxy_request_events": 2,
        "proxy_error_responses": 0,
        "allowed_control_requests": 1,
        "authenticated_admin_operations": 1,
        "authenticated_admin_errors": 0,
    }
    assert result["admin"]["authenticated"] is True
    assert result["admin"]["status"] == 200
    assert result["admin"]["completed_before_release"] is True
    assert result["admin"]["elapsed_seconds"] < 5
    timing = result["origin_observation"]
    assert timing["first_flush_at"] <= timing["first_received_at"]
    assert timing["control_completed_at"] < timing["released_at"]
    assert timing["admin_completed_at"] < timing["released_at"]
    assert timing["released_at"] <= timing["release_seen_at"] <= timing["finished_at"]
    assert timing["accepted_connections"] == 2
    assert result["origin_observation"]["stream_finished_after_read"] is True


def test_repeated_concurrent_short_requests_keep_authenticated_admin_live(proxy_backend, tmp_path):
    result = concurrent_short_admin_workload(proxy_backend, tmp_path / proxy_backend, 24, 8, 3)
    assert result["completed"] == 72
    assert result["failed_or_incomplete"] == 0
    assert result["origin_observation"]["accepted_connections"] == 72
    assert result["proxy_observation"] == {"request_events": 72, "error_responses": 0}
    assert all(batch["admin"]["started_while_batch_active"] for batch in result["batches_result"])
    assert all(batch["admin"]["completed_while_batch_active"] for batch in result["batches_result"])
    assert all(batch["admin"]["unauthenticated_status"] == 401 for batch in result["batches_result"])
    assert all(batch["admin"]["authenticated_status"] == 200 for batch in result["batches_result"])


def test_short_https_requests_record_counts_latency_resources_and_control(proxy_backend, tmp_path):
    result = short_https_connections(proxy_backend, tmp_path / proxy_backend, 8)
    assert result["workload"] == "sequential_short_https_connections"
    assert result["requests"] == 8
    assert result["completed"] == 8
    assert result["failed_or_incomplete"] == 0
    counts = result["request_counts"]
    assert counts["measured"] == {"expected": 8, "completed": 8, "failed_or_incomplete": 0}
    assert counts["control"] == {"expected": 1, "completed": 1, "failed_or_incomplete": 0}
    assert counts["total"]["expected"] == counts["total"]["origin_requests"] == 9
    assert counts["total"]["proxy_request_events"] == 9
    assert counts["total"]["proxy_events_total"] == 9 + (9 if proxy_backend == "rust" else 0)
    assert counts["total"]["connect_events"] == (9 if proxy_backend == "rust" else 0)
    assert counts["total"]["error_responses"] == 0
    assert len(result["latency_samples_ms"]) == 8
    assert result["control_observation"]["status"] == 200
    assert result["control_observation"]["body_bytes"] == 5
    assert len(result["resource_samples"]) >= 5
    assert len(result["origin_observation"]["requests"]) == 9
    assert result["proxy_observation"]["request_events"] == 9
    if proxy_backend == "rust":
        provenance = result["proxy_identity"]["native_policy_provenance"]["payload"]
        assert provenance["policy_mode"] == "native"
        assert provenance["temporary_policy_adapter"] is False


def test_short_requests_report_warmup_quiet_and_repeated_resource_phases(proxy_backend, tmp_path):
    result = concurrent_short_admin_workload(
        proxy_backend,
        tmp_path / proxy_backend,
        8,
        4,
        3,
        warmup=4,
        quiet_seconds=0.25,
    )
    assert result["warmup"]["requests"] == 4
    assert result["warmup"]["completed"] == 4
    assert result["warmup"]["failed_or_incomplete"] == 0
    assert result["quiet"]["elapsed_seconds"] >= 0.25
    assert result["quiet"]["origin_connections_before"] == 4
    assert result["quiet"]["origin_connections_after"] == 4
    assert result["quiet"]["proxy_request_events_before"] == 4
    assert result["quiet"]["proxy_request_events_after"] == 4
    assert result["origin_observation"]["expected_requests"] == 28
    assert result["request_counts"] == {
        "warmup": {"expected": 4, "completed": 4, "failed_or_incomplete": 0},
        "measured": {"expected": 24, "completed": 24, "failed_or_incomplete": 0},
        "total": {
            "expected": 28,
            "origin_connections": 28,
            "proxy_request_events": 28,
            "error_responses": 0,
        },
    }
    assert len(result["warmup"]["latency_samples_ms"]) == 4
    assert len(result["batches_result"]) == 3
    assert all(batch["completed"] == 8 for batch in result["batches_result"])
    assert all(batch["failed_or_incomplete"] == 0 for batch in result["batches_result"])
    assert all(batch["runtime_resources"]["before_batch"] for batch in result["batches_result"])
    assert all(batch["runtime_resources"]["during_batch"] for batch in result["batches_result"])
    assert all(batch["runtime_resources"]["after_batch"] for batch in result["batches_result"])
    if proxy_backend == "rust":
        provenance = result["proxy_identity"]["native_policy_provenance"]["payload"]
        assert provenance["policy_mode"] == "native"
        assert provenance["temporary_policy_adapter"] is False


def test_cancelled_sse_releases_upstream_and_keeps_other_request_live(proxy_backend, tmp_path):
    result = cancelled_sse_workload(proxy_backend, tmp_path / proxy_backend)
    assert result["first_event_before_release"] is True
    assert result["downstream_closed_before_release"] is True
    assert result["control_status"] == 200
    assert result["control_completed_while_stream_held"] is True
    assert result["origin_observation"]["stream_cancelled"] is True
    assert result["origin_observation"]["write_error"] in {
        "BrokenPipeError",
        "ConnectionResetError",
        "OSError",
    }
    assert result["origin_observation"]["stream_bytes_sent_after_release"] < (
        result["origin_observation"]["stream_chunks_available"] * 16384
    )
    assert result["origin_observation"]["stream_finished_after_cancel"] is True
    events = [event for event in read_events(tmp_path / proxy_backend / "events.jsonl")
              if event.get("event") == "proxy.request"]
    assert len(events) == (2 if proxy_backend == "rust" else 1)
    assert all(int(event.get("status", 500)) == 200 for event in events)
    assert sum(event.get("request_id") == result["control_request_id"] for event in events) == 1


def test_concurrent_policy_decisions_keep_agent_scope(proxy_backend, tmp_path):
    """Exercise the real policy process beyond its Unix accept queue depth."""
    with origin_server() as origin:
        url = f"http://127.0.0.1:{origin.server_address[1]}/concurrent"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            def send(index):
                agent = "alice" if index % 2 == 0 else "bob"
                status, headers, body = request(proxy.paths[agent], url)
                expected = 200 if agent == "alice" else 403
                assert status == expected, (agent, status, body)
                if expected == 200:
                    assert body == b"hello"
                response_headers = {key.lower(): value for key, value in headers.items()}
                return agent, status, response_headers["x-safeyolo-request-id"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                outcomes = list(workers.map(send, range(160)))

        by_request = {identifier: (agent, status) for agent, status, identifier in outcomes}
        assert len(by_request) == 160
        events = proxy.events("proxy.request")
        assert len(events) == 160
        for event in events:
            assert by_request[event["request_id"]] == (event["agent"], event["status"])
            assert event["decision"] == ("allow" if event["agent"] == "alice" else "deny")
        egress = proxy.events("proxy.egress")
        assert len(egress) == 80
        assert all(event["agent"] == "alice" for event in egress)
        assert len(origin.requests) == origin.accepts == 80


def _persistent_request(client, url, *, forged_agent):
    client.request(
        "GET",
        url,
        headers={
            "Connection": "keep-alive",
            "X-SafeYolo-Agent": forged_agent,
        },
    )
    response = client.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()


def test_persistent_http1_requests_keep_routing_and_identity_isolated(proxy_backend, tmp_path):
    """Each trusted UDS identity keeps its scope across persistent HTTP/1.1."""
    with origin_server(keep_alive=True) as origin:
        target = f"http://127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            alice = connection(proxy.paths["alice"])
            bob = connection(proxy.paths["bob"])
            try:
                alice_socket = alice.sock
                bob_socket = bob.sock
                alice_results = [
                    _persistent_request(alice, f"{target}/first?part=one", forged_agent="bob"),
                    _persistent_request(alice, f"{target}/second?part=two%2Fthree", forged_agent="bob"),
                ]
                bob_results = [
                    _persistent_request(bob, f"{target}/denied-one", forged_agent="alice"),
                    _persistent_request(bob, f"{target}/denied-two", forged_agent="alice"),
                ]
                assert alice.sock is alice_socket
                assert bob.sock is bob_socket
            finally:
                alice.close()
                bob.close()

        assert alice_results == [(200, b"hello"), (200, b"hello")]
        assert all(status == 403 for status, _ in bob_results)
        assert [request["target"] for request in origin.requests] == [
            "/first?part=one",
            "/second?part=two%2Fthree",
        ]
        assert origin.accepts >= 1
        assert all(request["connection_id"] for request in origin.requests)

    events = proxy.events("proxy.request")
    assert len(events) == 4
    assert [event["agent"] for event in events] == ["alice", "alice", "bob", "bob"]
    assert [event["status"] for event in events] == [200, 200, 403, 403]
    alice_event_ids = {event["connection_id"] for event in events[:2]}
    bob_event_ids = {event["connection_id"] for event in events[2:]}
    assert len(alice_event_ids) == len(bob_event_ids) == 1
    assert alice_event_ids.isdisjoint(bob_event_ids)
    egress = proxy.events("proxy.egress")
    assert egress
    assert all(event["agent"] == "alice" for event in egress)
