"""Request inspection and retained evidence at the real streaming boundary."""

import hashlib
import http.client
import json
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.proxy_migration.harness import launch_proxy, read_events
from tests.proxy_migration.scenarios import scoped_api

STREAM_LIMIT = 10 * 1024 * 1024
CAPTURE_LIMIT = 16
BLOCK_MARKER = b"STREAM-BLOCK-CANARY"
LOG_MARKER = b"ZCAPTURE"
CONTEXT = "run=stream-inspection;agent=alice;test=request-body"


class ObservedOrigin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.accepts = 0
        self.requests = {}
        self.condition = threading.Condition()
        super().__init__(("127.0.0.1", 0), OriginHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        with self.condition:
            self.accepts += 1
            self.condition.notify_all()
        return connection, address

    def wait_for(self, path, predicate):
        with self.condition:
            assert self.condition.wait_for(
                lambda: path in self.requests and predicate(self.requests[path]), timeout=8
            ), (path, self.accepts, self.requests)
            return dict(self.requests[path])


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        row = {"bytes": 0, "complete": False, "digest": None, "authorization": self.headers.get("Authorization")}
        digest = hashlib.sha256()
        with self.server.condition:
            self.server.requests[self.path] = row
            self.server.condition.notify_all()

        def observe(part):
            digest.update(part)
            with self.server.condition:
                row["bytes"] += len(part)
                self.server.condition.notify_all()

        try:
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                while True:
                    size = int(self.rfile.readline().split(b";", 1)[0], 16)
                    if size == 0:
                        assert self.rfile.readline() == b"\r\n"
                        break
                    part = self.rfile.read(size)
                    assert len(part) == size
                    observe(part)
                    assert self.rfile.read(2) == b"\r\n"
            else:
                remaining = int(self.headers["Content-Length"])
                while remaining:
                    part = self.rfile.read(min(remaining, 65536))
                    assert part
                    observe(part)
                    remaining -= len(part)
            with self.server.condition:
                row.update(complete=True, digest=digest.hexdigest())
                self.server.condition.notify_all()
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"ok")
        except (AssertionError, OSError, ValueError) as error:
            with self.server.condition:
                row["error"] = f"{type(error).__name__}: {error}"
                self.server.condition.notify_all()
        finally:
            self.close_connection = True


@contextmanager
def observed_origin():
    server = ObservedOrigin()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def policy():
    return json.dumps(
        {
            "hosts": {"*": {"egress": "allow"}},
            "permissions": [
                {"action": "network:request", "resource": "*", "effect": "allow"},
                {"action": "credential:use", "resource": "*", "effect": "deny"},
            ],
            "credential_rules": [
                {
                    "name": "stream-fixture",
                    "patterns": ["key-forbidden"],
                    "allowed_hosts": ["example.invalid"],
                    "header_names": ["authorization"],
                }
            ],
            "scan_patterns": [
                {
                    "name": "body-block",
                    "pattern": BLOCK_MARKER.decode(),
                    "target": "request",
                    "scope": ["body"],
                    "action": "block",
                },
                {
                    "name": "url-block",
                    "pattern": "blocked-url",
                    "target": "request",
                    "scope": ["url"],
                    "action": "block",
                },
                {
                    "name": "header-block",
                    "pattern": "STREAM-FORBIDDEN",
                    "target": "request",
                    "scope": ["headers"],
                    "action": "block",
                },
                {"name": "url-log", "pattern": "warn-url", "target": "request", "scope": ["url"], "action": "log"},
                {
                    "name": "body-log",
                    "pattern": LOG_MARKER.decode(),
                    "target": "request",
                    "scope": ["body"],
                    "action": "log",
                },
            ],
            "addons": {
                "credential_guard": {"enabled": True, "settings": {"use_default_credential_rules": False}},
                "test_context": {"target_hosts": ["127.0.0.1"]},
                "flow_store": {"max_request_body_bytes": CAPTURE_LIMIT, "compress_bodies": False},
            },
        }
    )


@contextmanager
def inspected_proxy(backend, directory):
    with launch_proxy(
        backend,
        directory,
        policy(),
        policy_format="json",
        native_policy=True,
        inspection={"block_request": True},
        credential_head_decision=True,
        stream_large_bodies="10m",
        flow_store_enabled=True,
        agent_api=True,
    ) as proxy:
        if backend == "rust":
            config = json.loads((directory / "proxy.json").read_text())
            assert config["policy_file"] == str(directory / "policy.json")
            assert "temporary_policy_socket" not in config
            assert proxy.policy_process is None
        yield proxy


def head(proxy, origin, path, *, length=None, credential=False, chunked=False, first=b"", extra_headers=()):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(15)
    client.connect(proxy.paths["alice"])
    framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {length}"
    headers = [
        f"POST http://127.0.0.1:{origin.server_address[1]}{path} HTTP/1.1",
        f"Host: 127.0.0.1:{origin.server_address[1]}",
        framing,
        "Content-Type: text/plain",
        f"X-SafeYolo-Test-Context: {CONTEXT}",
        "Connection: close",
    ]
    if credential:
        headers.append("Authorization: Bearer key-forbidden")
    headers.extend(extra_headers)
    client.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + first)
    return client


def response(client):
    reply = http.client.HTTPResponse(client)
    reply.begin()
    return reply.status, {name.lower(): value for name, value in reply.getheaders()}, reply.read()


def send_chunk(client, body):
    client.sendall(f"{len(body):x}\r\n".encode() + body + b"\r\n")


def scanner_rows(directory, request_id):
    return [
        row
        for row in read_events(directory / "audit.jsonl")
        if row.get("request_id") == request_id and row.get("event") == "security.pattern_scanner"
    ]


def scanner_finding(row):
    return row["details"].get("finding") or row["details"]


def wait_audit(directory, request_id, event):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = [
            row
            for row in read_events(directory / "audit.jsonl")
            if row.get("request_id") == request_id and row.get("event") == event
        ]
        if rows:
            return rows
        time.sleep(0.02)
    raise AssertionError(f"no {event} decision for {request_id}")


def wait_scanner(directory, request_id):
    return wait_audit(directory, request_id, "security.pattern_scanner")


def assert_streamed_body_unscanned(backend, proxy, directory, request_id):
    rows = scanner_rows(directory, request_id)
    if backend == "python":
        assert rows == []
        trace = scoped_api(proxy, "alice", f"/trace?request_id={request_id}")
        steps = [step for step in trace["steps"] if step["addon"] == "pattern-scanner"
                 and step["hook"] == "request"]
        assert len(steps) == 1 and steps[0]["outcome"] == "no_match", steps
    else:
        assert len(rows) == 1 and rows[0]["decision"] == "allow", rows
        assert rows[0]["details"]["outcome"] == "no_match", rows


def flow_row(directory, path):
    database = directory / "flows.sqlite3"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT request_body_size, request_body_stored, request_body_truncated, "
                "request_body_blob, request_body_text_preview FROM flows WHERE path = ?",
                (path,),
            ).fetchone()
        if row is not None:
            return dict(row)
        time.sleep(0.02)
    raise AssertionError(f"no captured flow for {path}")


def test_request_inspection_before_and_after_streaming_boundary(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with observed_origin() as origin, inspected_proxy(proxy_backend, directory) as proxy:
        # An announced large body can be denied from its head plus a partial
        # prefix; neither a dial nor the rest of the body is needed.
        with head(
            proxy, origin, "/credential", length=STREAM_LIMIT + 1, credential=True, first=b"only-a-prefix"
        ) as client:
            status, headers, _ = response(client)
        assert status == 428 and headers["x-blocked-by"] == "credential-guard"
        assert origin.accepts == 0
        credential = wait_audit(directory, headers["x-safeyolo-request-id"], "security.credential_guard")
        assert len(credential) == 1 and credential[0]["decision"] == "require_approval", credential

        # URL scope remains actionable even though the body would stream.
        with head(proxy, origin, "/blocked-url", length=STREAM_LIMIT + 1) as client:
            status, headers, _ = response(client)
        assert status == 403 and headers["x-blocked-by"] == "pattern-scanner"
        assert origin.accepts == 0
        assert len(wait_scanner(directory, headers["x-safeyolo-request-id"])) == 1

        with head(
            proxy, origin, "/blocked-header", length=STREAM_LIMIT + 1, extra_headers=("X-Probe: STREAM-FORBIDDEN",)
        ) as client:
            status, headers, _ = response(client)
        assert status == 403 and headers["x-blocked-by"] == "pattern-scanner"
        assert origin.accepts == 0
        rows = wait_scanner(directory, headers["x-safeyolo-request-id"])
        assert len(rows) == 1 and scanner_finding(rows[0])["location"] == "header:X-Probe", rows

        for size in (STREAM_LIMIT - 1, STREAM_LIMIT):
            path = f"/buffered-{size}"
            body = b"x" * (size - len(BLOCK_MARKER)) + BLOCK_MARKER
            with head(proxy, origin, path, length=size) as client:
                client.sendall(body)
                status, headers, _ = response(client)
            assert status == 403 and headers["x-blocked-by"] == "pattern-scanner"
            assert origin.accepts == 0
            rows = wait_scanner(directory, headers["x-safeyolo-request-id"])
            assert len(rows) == 1 and rows[0]["decision"] == "deny", rows
            assert scanner_finding(rows[0])["rule_name"] == "body-block", rows
            assert scanner_finding(rows[0])["location"] == "body", rows
            stored = flow_row(directory, path)
            assert stored["request_body_size"] == size
            assert stored["request_body_stored"] == 1
            assert stored["request_body_truncated"] == 1
            assert stored["request_body_blob"] == body[:CAPTURE_LIMIT]

        # Keep the upload open after the first chunk. The origin must see
        # actual body bytes while the client has not completed this request.
        size = STREAM_LIMIT + 1
        body = b"x" * (size - len(BLOCK_MARKER)) + BLOCK_MARKER
        with head(
            proxy, origin, "/streamed-known", length=size, extra_headers=("X-SafeYolo-Trace: 1",)
        ) as client:
            client.sendall(body[:65536])
            partial = origin.wait_for("/streamed-known", lambda row: row["bytes"] > 0)
            assert not partial["complete"] and partial["bytes"] < size
            client.sendall(body[65536:])
            status, headers, reply = response(client)
        assert status == 200 and reply == b"ok" and "x-blocked-by" not in headers
        observed = origin.wait_for("/streamed-known", lambda row: row["complete"])
        assert observed["bytes"] == size and observed["digest"] == hashlib.sha256(body).hexdigest()
        assert observed["authorization"] is None
        assert_streamed_body_unscanned(proxy_backend, proxy, directory, headers["x-safeyolo-request-id"])
        stored = flow_row(directory, "/streamed-known")
        assert (
            stored["request_body_size"],
            stored["request_body_stored"],
            stored["request_body_truncated"],
            stored["request_body_blob"],
            stored["request_body_text_preview"],
        ) == (0, 0, 0, None, "")
        with head(proxy, origin, "/warn-url", length=size) as client:
            client.sendall(body[:65536])
            partial = origin.wait_for("/warn-url", lambda row: row["bytes"] > 0)
            assert not partial["complete"]
            client.sendall(body[65536:])
            status, headers, reply = response(client)
        assert status == 200 and reply == b"ok"
        observed = origin.wait_for("/warn-url", lambda row: row["complete"])
        assert observed["bytes"] == size and observed["digest"] == hashlib.sha256(body).hexdigest()
        rows = wait_scanner(directory, headers["x-safeyolo-request-id"])
        assert len(rows) == 1 and rows[0]["decision"] == "log", rows
        assert scanner_finding(rows[0])["location"] == "url", rows
        assert scanner_finding(rows[0])["rule_name"] == "url-log", rows
        stored = flow_row(directory, "/warn-url")
        assert (
            stored["request_body_size"],
            stored["request_body_stored"],
            stored["request_body_truncated"],
            stored["request_body_blob"],
        ) == (0, 0, 0, None)

        # Unknown length switches to streaming only after crossing the same
        # threshold. Hold the terminator while the origin reads partial data.
        with head(
            proxy, origin, "/streamed-chunked", chunked=True,
            extra_headers=("X-SafeYolo-Trace: 1",),
        ) as client:
            for start in range(0, len(body), 65536):
                send_chunk(client, body[start : start + 65536])
            partial = origin.wait_for("/streamed-chunked", lambda row: row["bytes"] > 0)
            assert not partial["complete"] and partial["bytes"] <= size
            send_chunk(client, b"")
            status, headers, reply = response(client)
        assert status == 200 and reply == b"ok"
        observed = origin.wait_for("/streamed-chunked", lambda row: row["complete"])
        assert observed["bytes"] == size and observed["digest"] == hashlib.sha256(body).hexdigest()
        assert observed["authorization"] is None
        assert_streamed_body_unscanned(proxy_backend, proxy, directory, headers["x-safeyolo-request-id"])
        stored = flow_row(directory, "/streamed-chunked")
        assert (
            stored["request_body_size"],
            stored["request_body_stored"],
            stored["request_body_truncated"],
            stored["request_body_blob"],
            stored["request_body_text_preview"],
        ) == (0, 0, 0, None, "")
        assert origin.accepts == 3


def test_python_chunked_url_rule_blocks_at_head(tmp_path, proxy_backend):
    if proxy_backend != "python":
        pytest.skip("Rust selects unknown-length streaming after its buffer fills")
    directory = tmp_path / proxy_backend
    with observed_origin() as origin, inspected_proxy(proxy_backend, directory) as proxy:
        with head(proxy, origin, "/blocked-url-chunked", chunked=True) as client:
            status, headers, _ = response(client)
        assert status == 403 and headers["x-blocked-by"] == "pattern-scanner"
        assert origin.accepts == 0
        assert len(wait_scanner(directory, headers["x-safeyolo-request-id"])) == 1


@pytest.mark.parametrize("block", [True, False], ids=["block", "warn"])
def test_streamed_network_policy_decision_precedes_origin_bytes(proxy_backend, tmp_path, block):
    directory = tmp_path / proxy_backend
    denied = json.dumps(
        {
            "hosts": {"*": {"egress": "deny"}},
            "permissions": [{"action": "network:request", "resource": "*", "effect": "deny"}],
        }
    )
    with (
        observed_origin() as origin,
        launch_proxy(
            proxy_backend,
            directory,
            denied,
            policy_format="json",
            native_policy=True,
            stream_large_bodies="10m",
            network_guard_block=block,
        ) as proxy,
    ):
        size = STREAM_LIMIT + 1
        body = b"x" * size
        with head(proxy, origin, "/network-deny", length=size, first=body[:65536]) as client:
            if not block:
                partial = origin.wait_for("/network-deny", lambda row: row["bytes"] > 0)
                assert not partial["complete"] and partial["bytes"] < size
                client.sendall(body[65536:])
            status, headers, reply = response(client)
        if block:
            assert status == 403 and headers["x-blocked-by"] == "network-guard"
            assert origin.accepts == 0 and origin.requests == {}
        else:
            assert status == 200 and reply == b"ok" and "x-blocked-by" not in headers
            observed = origin.wait_for("/network-deny", lambda row: row["complete"])
            assert observed["bytes"] == size and observed["digest"] == hashlib.sha256(body).hexdigest()
        identifier = headers["x-safeyolo-request-id"]
        rows = wait_audit(directory, identifier, "security.network_guard")
        assert len(rows) == 1 and rows[0]["decision"] == ("deny" if block else "warn"), rows


def test_capture_limit_does_not_limit_buffered_inspection(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with observed_origin() as origin, inspected_proxy(proxy_backend, directory) as proxy:
        for size in (CAPTURE_LIMIT - 1, CAPTURE_LIMIT, CAPTURE_LIMIT + 1):
            path = f"/capture-{size}"
            body = b"a" * (size - len(LOG_MARKER)) + LOG_MARKER
            with head(proxy, origin, path, length=size) as client:
                client.sendall(body)
                status, headers, reply = response(client)
            assert status == 200 and reply == b"ok" and "x-blocked-by" not in headers
            observed = origin.wait_for(path, lambda row: row["complete"])
            assert observed["bytes"] == size and observed["digest"] == hashlib.sha256(body).hexdigest()
            rows = wait_scanner(directory, headers["x-safeyolo-request-id"])
            assert len(rows) == 1 and rows[0]["decision"] == "log", rows
            assert scanner_finding(rows[0])["rule_name"] == "body-log", rows
            assert scanner_finding(rows[0])["location"] == "body", rows
            stored = flow_row(directory, path)
            assert stored["request_body_size"] == size
            assert stored["request_body_stored"] == 1
            assert stored["request_body_truncated"] == int(size > CAPTURE_LIMIT)
            assert stored["request_body_blob"] == body[:CAPTURE_LIMIT]
            assert stored["request_body_text_preview"] == body[:CAPTURE_LIMIT].decode()
        assert origin.accepts == 3
