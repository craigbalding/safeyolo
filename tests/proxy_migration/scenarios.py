"""Product observations independent of proxy framework or implementation."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests.proxy_migration.harness import launch_proxy, request

POLICY = '''budget = 12000
[hosts]
"*" = { egress = "deny" }
[agents.alice]
egress = "allow"
'''
FORGED_REQUEST_ID = "req-" + "f" * 32
REQUEST_ID = re.compile(r"req-[0-9a-f]{32}\Z")
AGENT_API = "http://_safeyolo.proxy.internal"
AGENT_TOKEN = "fixture-agent-api-token-one"


def scoped_api(proxy, agent, path, *, expected=200):
    status, _, body = request(
        proxy.paths[agent], AGENT_API + path,
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert status == expected, (path, status, body)
    return json.loads(body)


def request_evidence(proxy, agent, identifier, *, host, port, method, status, decision,
                     run, path=None, flow_expected=False):
    """Join one response ID to owned trace, audit and eligible persisted flow."""
    assert REQUEST_ID.fullmatch(identifier) and identifier != FORGED_REQUEST_ID
    other = "bob" if agent == "alice" else "alice"
    trace = scoped_api(proxy, agent, f"/trace?request_id={identifier}")
    assert trace["request_id"] == identifier and trace["agent_id"] == agent
    assert trace["truncated"] is False, trace
    guard = [step for step in trace["steps"] if step["addon"] == "network-guard"
             and step["hook"] == ("http_connect" if method == "CONNECT" else "request")]
    assert len(guard) == 1, trace
    guard = guard[0]
    assert {key: guard[key] for key in ("state", "outcome", "host", "port", "method")} == {
        "state": "evaluated", "outcome": "allowed" if decision == "allow" else "blocked",
        "host": host, "port": port, "method": method,
    }
    connection_id = guard["connection_id"]
    assert connection_id and all(step.get("connection_id") == connection_id for step in trace["steps"])
    if decision == "deny":
        assert guard["details"]["status"] == status
    assert scoped_api(proxy, other, f"/trace?request_id={identifier}", expected=404)["request_id"] == identifier

    explained = scoped_api(proxy, agent, f"/explain?request_id={identifier}")
    assert explained["request_id"] == identifier and explained["status"] == "complete", explained
    events = explained["events"]
    assert events and all(event["request_id"] == identifier and event["agent"] == agent
                          and event["host"] == host for event in events), events
    if method == "CONNECT" or decision == "deny":
        policy = [event for event in events if event["event"] == "security.network_guard"]
        assert len(policy) == 1 and policy[0]["decision"] == decision, events
        details = policy[0]["details"]
        assert details["method"] == method and details["port"] == port
        assert details["connection_id"] == connection_id
    else:
        context = [event for event in events if event["event"] == "security.test_context"]
        assert [event["details"]["phase"] for event in context] == ["request", "response"], events
        assert all(event["details"]["method"] == method and event["details"]["path"] == path
                   for event in context)
        assert context[1]["details"]["status_code"] == status
    foreign = scoped_api(proxy, other, f"/explain?request_id={identifier}")
    assert foreign == {"request_id": identifier, "status": "complete", "events": []}, foreign

    # The API scopes first, then searches. It does not accept a request-ID
    # filter, so match returned IDs only after the owned search has completed.
    search = f"/api/flows/search?run={run}&test=request-ids"
    deadline = time.monotonic() + 2
    while True:
        flows = scoped_api(proxy, agent, search)["flows"]
        matching = [flow for flow in flows if flow["request_id"] == identifier]
        if matching or not flow_expected or time.monotonic() >= deadline:
            break
        time.sleep(0.025)
    foreign_flows = scoped_api(proxy, other, search)["flows"]
    assert not any(flow["request_id"] == identifier for flow in foreign_flows)
    if flow_expected:
        assert len(matching) == 1, (identifier, flows)
        flow = matching[0]
        assert {key: flow[key] for key in ("request_id", "agent_id", "evidence_owner", "method",
                                            "host", "status_code", "flow_state")} == {
            "request_id": identifier, "agent_id": agent, "evidence_owner": agent,
            "method": method, "host": host, "status_code": status, "flow_state": "completed",
        }
        assert flow["path"] == path.split("?", 1)[0] and flow["request_body_truncated"] == 0
        assert flow["response_body_truncated"] == 0
        detail = scoped_api(proxy, agent, f"/api/flows/{flow['id']}")
        assert detail["request_id"] == identifier and detail["port"] == port
        scoped_api(proxy, other, f"/api/flows/{flow['id']}", expected=404)
    else:
        # FlowRecorder requires applied test context. Early NetworkGuard
        # denials and CONNECT admission never reach that capture boundary.
        assert matching == [], (identifier, matching)
        detail = None
    return {"trace": trace, "explain": explained, "flow": detail,
            "foreign_trace_status": 404, "foreign_explain": foreign,
            "foreign_flow_ids": [flow["request_id"] for flow in foreign_flows],
            "connection_id": connection_id}


class Origin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0, *, stream_seconds=2.0, response_delay=0.0):
        self.accepts = 0
        self.requests = []
        self.websocket_frames = []
        self.keep_alive = False
        self.connection_ids = {}
        self.stream_finished = threading.Event()
        self.stream_initial_sent = threading.Event()
        self.stream_release = threading.Event()
        self.stream_cancelled = threading.Event()
        self.stream_write_error = None
        self.response_delay = response_delay
        self.stream_bytes_sent = 0
        self.stream_chunks = max(1, math.ceil(stream_seconds / 0.02))
        super().__init__(("127.0.0.1", port), OriginHandler)

    def get_request(self):
        request, address = super().get_request()
        self.accepts += 1
        if getattr(self, "keep_alive", False):
            self.connection_ids[id(request)] = f"origin-{uuid.uuid4().hex}"
        return request, address


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        observation = {"method": self.command, "target": self.path}
        if self.server.keep_alive:
            observation["connection_id"] = self.server.connection_ids[id(self.connection)]
        self.server.requests.append(observation)
        if self.path in {"/stream", "/stream-control", "/stream-cancel"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "keep-alive" if self.server.keep_alive else "close")
            self.end_headers()
            chunk = b"data: " + b"x" * (16384 - 8) + b"\n\n"
            if self.path in {"/stream-control", "/stream-cancel"}:
                first = b"data: first-event\n\n"
                self.wfile.write(first)
                self.wfile.flush()
                self.server.stream_initial_sent.set()
                self.server.stream_release.wait(timeout=30)
                remaining = self.server.stream_chunks
                if self.path == "/stream-control":
                    remaining = max(0, remaining - 1)
            else:
                remaining = self.server.stream_chunks
            for _ in range(remaining):
                try:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    self.server.stream_bytes_sent += len(chunk)
                except (BrokenPipeError, ConnectionResetError, OSError) as error:
                    self.server.stream_write_error = type(error).__name__
                    self.server.stream_cancelled.set()
                    break
                time.sleep(0.02)
            self.server.stream_finished.set()
            return
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.websocket()
            return
        if self.server.response_delay:
            time.sleep(self.server.response_delay)
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.send_header("Connection", "keep-alive" if self.server.keep_alive else "close")
        self.end_headers()
        self.wfile.write(b"hello")

    def websocket(self):
        # Deliberately small synthetic workload: complete five-byte text
        # messages. Compression, fragments and inspection need separate tests.
        key = self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(hashlib.sha1(key.encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        while prefix := self.rfile.read(2):
            if prefix[0] == 0x88:
                return
            assert prefix == b"\x81\x85", prefix
            mask = self.rfile.read(4)
            payload = self.rfile.read(5)
            plain = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            self.server.websocket_frames.append({
                "index": len(self.server.websocket_frames),
                "opcode": prefix[0] & 0x0F,
                "payload_bytes": len(plain),
                "payload_sha256": hashlib.sha256(plain).hexdigest(),
            })
            self.wfile.write(b"\x81\x05" + plain)
            self.wfile.flush()


@contextmanager
def origin_server(port=0, *, stream_seconds=2.0, keep_alive=False, response_delay=0.0):
    server = Origin(port, stream_seconds=stream_seconds, response_delay=response_delay)
    server.keep_alive = keep_alive
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def network_scenario(backend, directory, *, parent=False, origin_port=0):
    """Allow alice and deny bob despite forged headers, with no denied egress."""
    with origin_server(origin_port) as origin:
        origin_port = origin.server_address[1]
        # A configured parent answers itself. A made-up target ensures the child
        # must hand authority to that parent, without resolving the target.
        host, port = ("target.invalid", 8123) if parent else ("127.0.0.1", origin_port)
        url = f"http://{host}:{port}/signed?part=one&part=two%2Fthree"
        parent_url = f"http://127.0.0.1:{origin_port}" if parent else None
        observations = []
        evidence = []
        run = "request-ids-parent" if parent else "request-ids-direct"
        with launch_proxy(backend, directory, POLICY, parent_proxy=parent_url,
                          native_policy=True, agent_api=True, flow_store_enabled=True) as proxy:
            identifiers = []
            for agent, expected in (("bob", 403), ("alice", 200), ("bob", 403), ("alice", 200)):
                before = origin.accepts
                egress_before = len(proxy.events("proxy.egress"))
                status, headers, body = request(proxy.paths[agent], url, headers={
                    "X-SafeYolo-Agent": "alice" if agent == "bob" else "bob",
                    "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                    "X-SafeYolo-Trace": "1",
                    "X-SafeYolo-Test-Context": f"run={run};agent={agent};test=request-ids",
                })
                response_headers = {key.lower(): value for key, value in headers.items()}
                assert status == expected, (status, body)
                identifier = response_headers.get("x-safeyolo-request-id")
                assert identifier and identifier != FORGED_REQUEST_ID
                assert identifier not in identifiers
                identifiers.append(identifier)
                assert origin.accepts - before == int(expected == 200)
                if expected == 403:
                    assert response_headers["x-blocked-by"] == "network-guard"
                    assert len(proxy.events("proxy.egress")) == egress_before
                else:
                    assert body == b"hello"
                scoped = request_evidence(
                    proxy, agent, identifier, host=host, port=port, method="GET", status=status,
                    decision="allow" if status == 200 else "deny", run=run,
                    path="/signed?part=one&part=two%2Fthree",
                    flow_expected=status == 200,
                )
                evidence.append({"agent": agent, "status": status, "request_id": identifier,
                                 "response_headers": headers, "response_body_hex": body.hex(),
                                 "origin_accepts_before": before, "origin_accepts_after": origin.accepts,
                                 "origin_requests": list(origin.requests), **scoped})
                observations.append({"agent": agent, "status": status,
                                     "delivered_body": body.decode() if expected == 200 else None,
                                     "denial_body": json.loads(body) if expected == 403 else None,
                                     "blocked_by": response_headers.get("x-blocked-by"),
                                     "origin_connections": origin.accepts - before})
        (Path(directory) / "request-id-observations.json").write_text(
            json.dumps(evidence, indent=2) + "\n"
        )
        events = [event for event in proxy.events("proxy.request")
                  if event.get("host") == host and event.get("port") == port]
        assert len(events) == len(observations), events
        for event, observation, identifier, record in zip(
            events, observations, identifiers, evidence, strict=True
        ):
            assert event["agent"] == observation["agent"]
            assert event["request_id"] == identifier
            assert event["host"] == host and event["port"] == port
            assert event["status"] == observation["status"]
            assert event["decision"] == ("allow" if observation["status"] == 200 else "deny")
            assert event["connection_id"]
            assert event["connection_id"] == record["connection_id"]
        assert len({event["connection_id"] for event in events}) == len(events)
        assert len(proxy.events("proxy.egress")) == 2
        target = url if parent else "/signed?part=one&part=two%2Fthree"
        assert origin.requests == [{"method": "GET", "target": target}] * 2
        assert not proxy.readiness_file.exists(), "Graceful shutdown left readiness behind"
        # Only generated request IDs are substituted. Their one-to-one client,
        # response and event relationships were asserted above. Error fields,
        # reflections, destinations, ports and delivered bytes remain intact.
        serialized = json.dumps(observations)
        for index, identifier in enumerate(identifiers):
            serialized = serialized.replace(identifier, f"request-{index}")
        observations = json.loads(serialized)
        return {"fixture_origin_port": origin_port,
                "requests": observations, "origin_targets": [item["target"] for item in origin.requests],
                "policy_events": [{key: event[key] for key in ("agent", "host", "port", "status", "decision")}
                                  for event in events]}


def reserved_scenario(backend, directory):
    """Invalid/missing local handlers cannot send even a DNS/connect attempt."""
    with origin_server() as parent:
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        with launch_proxy(backend, directory, POLICY, parent_proxy=parent_url) as proxy:
            responses = []
            for host in ("_safeyolo.proxy.internal", "_SAFEYOLO.PROXY.INTERNAL", "_safeyolo.probe.internal"):
                status, headers, body = request(
                    proxy.paths["alice"], f"http://{host}/missing?secret=synthetic",
                    headers={"Authorization": "Bearer synthetic-local-token"},
                )
                assert status in {200, 503}, (status, body)
                assert parent.accepts == 0
                assert proxy.events("proxy.egress") == []
                responses.append({"host": host, "status": status})
        assert parent.requests == []
        return {"responses": responses, "origin_connections": parent.accepts, "egress_attempts": 0}
