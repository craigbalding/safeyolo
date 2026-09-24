"""Product observations independent of proxy framework or implementation."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.proxy_migration.harness import launch_proxy, read_events, request

POLICY = '''budget = 12000
[hosts]
"*" = { egress = "deny" }
[agents.alice]
egress = "allow"
'''
FORGED_REQUEST_ID = "req-" + "f" * 32


class Origin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0, *, stream_seconds=2.0, response_delay=0.0,
                 capture_heads=False):
        self.accepts = 0
        self.requests = []
        self.capture_heads = capture_heads
        self.request_heads = []
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
        if self.server.capture_heads:
            self.server.request_heads.append(self.raw_requestline + self.headers.as_bytes())
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
def origin_server(port=0, *, stream_seconds=2.0, keep_alive=False, response_delay=0.0,
                  capture_heads=False):
    server = Origin(port, stream_seconds=stream_seconds, response_delay=response_delay,
                    capture_heads=capture_heads)
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
        with launch_proxy(backend, directory, POLICY, parent_proxy=parent_url) as proxy:
            identifiers = []
            for agent, expected in (("bob", 403), ("alice", 200), ("bob", 403), ("alice", 200)):
                before = origin.accepts
                egress_before = len(proxy.events("proxy.egress"))
                status, headers, body = request(proxy.paths[agent], url, headers={
                    "X-SafeYolo-Agent": "alice" if agent == "bob" else "bob",
                    "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                    "X-SafeYolo-Trace": "1",
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
                observations.append({"agent": agent, "status": status,
                                     "delivered_body": body.decode() if expected == 200 else None,
                                     "denial_body": json.loads(body) if expected == 403 else None,
                                     "blocked_by": response_headers.get("x-blocked-by"),
                                     "origin_connections": origin.accepts - before})
        events = proxy.events("proxy.request")
        assert len(events) == len(observations), events
        for event, observation, identifier in zip(events, observations, identifiers, strict=True):
            assert event["agent"] == observation["agent"]
            assert event["request_id"] == identifier
            assert event["host"] == host and event["port"] == port
            assert event["status"] == observation["status"]
            assert event["decision"] == ("allow" if observation["status"] == 200 else "deny")
            assert event["connection_id"]
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
    """Reserved names stay local while the configured parent serves ordinary hosts."""
    api_hosts = ("_safeyolo.proxy.internal", "_SAFEYOLO.PROXY.INTERNAL", "_safeyolo.proxy.internal.")
    probe_hosts = ("_safeyolo.probe.internal", "_SAFEYOLO.PROBE.INTERNAL", "_safeyolo.probe.internal.")
    responses = []
    with origin_server(capture_heads=True) as parent:
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        for enabled in (False, True):
            state = "wrong-token" if enabled else "unavailable"
            run_dir = directory / state
            with launch_proxy(backend, run_dir, POLICY, parent_proxy=parent_url,
                              agent_api=enabled, native_policy=True) as proxy:
                rows = [(host, "api", "/lookup" if enabled else "/health") for host in api_hosts]
                rows += [(host, "probe", "/__pipeline_probe") for host in probe_hosts]
                rows += [("_safeyolo.proxy.internal..", "invalid", "/health"),
                         ("_safeyolo.probe.internal..", "invalid", "/__pipeline_probe"),
                         ("control.invalid", "control", "/ordinary")]
                for host, kind, path in rows:
                    bearer = f"synthetic-bearer-{uuid.uuid4().hex}"
                    query = f"synthetic-query-{uuid.uuid4().hex}"
                    before_accepts = parent.accepts
                    before_egress = len(proxy.events("proxy.egress"))
                    before_audit = len(read_events(run_dir / "audit.jsonl"))
                    status, _headers, body = request(
                        proxy.paths["alice"], f"http://{host}{path}?secret={query}",
                        headers={"Authorization": f"Bearer {bearer}"},
                    )
                    heads = parent.request_heads
                    audit = read_events(run_dir / "audit.jsonl")[before_audit:]
                    row = {"state": state, "host": host, "kind": kind, "status": status,
                           "body": body.decode("utf-8", errors="replace"),
                           "parent_accepts": parent.accepts - before_accepts,
                           "egress_attempts": len(proxy.events("proxy.egress")) - before_egress,
                           "audit_events": [event["event"] for event in audit],
                           "parent_heads_hex": [head.hex() for head in heads],
                           "bearer": bearer, "query": query}
                    with (run_dir / "reserved-wire.jsonl").open("a") as output:
                        output.write(json.dumps(row) + "\n")
                    responses.append(row)
                    if kind == "control":
                        assert status == 200 and body == b"hello", row
                        assert row["parent_accepts"] == row["egress_attempts"] == 1, row
                        assert bearer.encode() in heads[-1] and query.encode() in heads[-1], row
                        continue
                    assert row["parent_accepts"] == row["egress_attempts"] == 0, row
                    assert all(bearer.encode() not in head and query.encode() not in head
                               for head in heads), row
                    if kind == "api":
                        assert status == (401 if enabled else 503), row
                        if enabled:
                            assert json.loads(body) == {"error": "Invalid agent token"}, row
                            assert "security.agent_auth_failed" in row["audit_events"], row
                        else:
                            assert json.loads(body)["reason_code"] == "agent_api_unavailable", row
                            assert "security.agent_api_unavailable" in row["audit_events"], row
                    elif kind == "probe":
                        native_root_dot = backend == "rust" and host.endswith(".")
                        assert status == (503 if native_root_dot else 200), row
                        if native_root_dot:
                            assert json.loads(body)["error"] == "Local endpoint is not implemented in the development proxy", row
                        else:
                            assert json.loads(body)["probe_ok"] is True, row
                    else:
                        assert status == 400, row
    return {"responses": responses, "origin_connections": parent.accepts,
            "egress_attempts": sum(row["egress_attempts"] for row in responses)}
