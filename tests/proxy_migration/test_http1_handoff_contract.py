"""Exercise HTTP/1.1 framing handoffs at the real proxy boundaries.

The fixture keeps one client UDS connection open while it sends a request that
uses ``Expect: 100-continue``, a chunked request with trailers, and bodyless
responses followed by another request.  The origin is a raw HTTP/1.1 peer so
the assertions retain the bytes and trailer fields that a high-level client
would normalize away.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer

import pytest

from tests.proxy_migration.harness import launch_proxy
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.run import proxy_identity
from tests.proxy_migration.scenarios import POLICY

_LIMIT = 5.0


class _RawHttp:
    """Small bounded HTTP/1.1 reader used only to retain fixture wire data."""

    def __init__(self, stream):
        self.stream = stream
        self.buffer = bytearray()

    def _fill(self, length):
        deadline = time.monotonic() + _LIMIT
        while len(self.buffer) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"timed out waiting for {length} bytes")
            self.stream.settimeout(remaining)
            chunk = self.stream.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise AssertionError("peer closed before the complete HTTP message")
            self.buffer.extend(chunk)

    def _until(self, marker):
        deadline = time.monotonic() + _LIMIT
        while True:
            position = self.buffer.find(marker)
            if position >= 0:
                end = position + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"timed out waiting for {marker!r}")
            self.stream.settimeout(remaining)
            chunk = self.stream.recv(4096)
            if not chunk:
                raise AssertionError("peer closed before HTTP headers")
            self.buffer.extend(chunk)

    def _exact(self, length):
        self._fill(length)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    @staticmethod
    def _headers(raw):
        lines = raw[:-4].split(b"\r\n")
        first = lines.pop(0)
        headers = []
        for line in lines:
            name, separator, value = line.partition(b":")
            if not separator:
                raise AssertionError(f"invalid header line: {line!r}")
            headers.append((name.decode("latin-1").lower(), value.lstrip().decode("latin-1")))
        return first, headers

    def message(self, *, method=None):
        first, headers = self._headers(self._until(b"\r\n\r\n"))
        fields = {}
        for name, value in headers:
            fields.setdefault(name, []).append(value)
        transfer = ",".join(fields.get("transfer-encoding", [])).lower()
        status = int(first.split()[1]) if first.startswith(b"HTTP/") else None
        body = bytearray()
        trailers = []
        no_body = method == "HEAD" or (status is not None and (
            100 <= status < 200 or status in (204, 304)
        ))
        if not no_body and "chunked" in transfer:
            while True:
                size_line = self._until(b"\r\n")[:-2]
                size = int(size_line.split(b";", 1)[0], 16)
                if size:
                    body.extend(self._exact(size))
                    assert self._exact(2) == b"\r\n"
                else:
                    trailer_block = self._until(b"\r\n\r\n")
                    _, trailers = self._headers(b"HTTP/1.1 200 OK\r\n" + trailer_block)
                    break
        elif not no_body and fields.get("content-length"):
            body.extend(self._exact(int(fields["content-length"][-1])))
        return {
            "first": first,
            "status": status,
            "headers": headers,
            "body": bytes(body),
            "trailers": trailers,
        }


class _HandoffOrigin(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.records = []
        self.headers_received = []
        self.body_bytes_received = []
        self.response_started = threading.Event()
        self.cancel_observed = threading.Event()
        self.cancel_result = None
        self.cancel_observed_at = None
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _HandoffHandler)


class _HandoffHandler(BaseRequestHandler):
    def handle(self):
        raw = _RawHttp(self.request)
        while True:
            try:
                first, headers = raw._headers(raw._until(b"\r\n\r\n"))
            except (AssertionError, ConnectionError, OSError):
                return
            method, target, _version = first.decode("latin-1").split(" ", 2)
            fields = {}
            for name, value in headers:
                fields.setdefault(name, []).append(value)
            with self.server.lock:
                self.server.headers_received.append((method, target, headers))
                self.server.body_bytes_received.append(0)
                body_index = len(self.server.body_bytes_received) - 1

            if fields.get("expect", [""])[-1].lower() == "100-continue":
                self.request.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

            body = bytearray()
            trailers = []
            transfer = ",".join(fields.get("transfer-encoding", [])).lower()
            if "chunked" in transfer:
                while True:
                    line = raw._until(b"\r\n")[:-2]
                    size = int(line.split(b";", 1)[0], 16)
                    if not size:
                        trailer_block = raw._until(b"\r\n\r\n")
                        _, trailers = raw._headers(b"HTTP/1.1 200 OK\r\n" + trailer_block)
                        break
                    body.extend(raw._exact(size))
                    assert raw._exact(2) == b"\r\n"
                    with self.server.lock:
                        self.server.body_bytes_received[body_index] = len(body)
            elif fields.get("content-length"):
                remaining = int(fields["content-length"][-1])
                while remaining:
                    chunk = raw._exact(min(remaining, 4096))
                    body.extend(chunk)
                    remaining -= len(chunk)
                    with self.server.lock:
                        self.server.body_bytes_received[body_index] = len(body)

            with self.server.lock:
                self.server.records.append({
                    "method": method,
                    "target": target,
                    "headers": headers,
                    "body": bytes(body),
                    "trailers": trailers,
                })

            if target == "/cancel-response":
                # The missing terminating chunk holds the response open until
                # the downstream closes. Observe the origin socket separately
                # from the client's received prefix.
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                    b"Content-Type: text/event-stream\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                    b"D\r\ndata: first\n\n\r\n"
                )
                self.server.response_started.set()
                self.request.settimeout(_LIMIT)
                try:
                    remaining = self.request.recv(1)
                except ConnectionResetError:
                    result = "reset"
                except TimeoutError:
                    result = "timeout"
                else:
                    result = "eof" if not remaining else f"unexpected:{remaining.hex()}"
                with self.server.lock:
                    self.server.cancel_result = result
                    self.server.cancel_observed_at = time.monotonic()
                self.server.cancel_observed.set()
                return
            if method == "HEAD":
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                )
            elif target == "/empty":
                response = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n"
            else:
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                    b"Connection: keep-alive\r\n\r\nhello"
                )
            self.request.sendall(response)


@contextmanager
def _origin():
    origin = _HandoffOrigin()
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        yield origin
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)


def _wait_until(predicate):
    deadline = time.monotonic() + _LIMIT
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("timed out waiting for origin observation")
        time.sleep(0.01)


def _retain_evidence(name, proxy, origin, **details):
    destination = os.environ.get("SAFEYOLO_H1_HANDOFF_EVIDENCE")
    if not destination:
        return
    config = proxy.event_log.parent / "proxy.json"
    payload = {
        "schema": 1,
        "test_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "backend": details.pop("backend"),
        "proxy_identity": proxy_identity(proxy),
        "origin": {
            "headers_received": origin.headers_received,
            "body_bytes_received": origin.body_bytes_received,
            "records": origin.records,
            "cancel_result": origin.cancel_result,
        },
        "proxy_events": {
            "request": proxy.events("proxy.request"),
            "egress": proxy.events("proxy.egress"),
        },
        "details": details,
        "fixture_config": json.loads(config.read_text()),
    }

    def json_default(value):
        if isinstance(value, bytes):
            return {"encoding": "hex", "value": value.hex()}
        raise TypeError(f"cannot serialize evidence value {type(value).__name__}")

    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    (output / f"{name}-{payload['backend']}.json").write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=json_default,
        ) + "\n"
    )


def test_http1_handoff_preserves_expect_and_bodyless_followups(proxy_backend, tmp_path):
    """One UDS connection survives Expect, HEAD, 204, and a follow-up."""
    with _origin() as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(_LIMIT)
            client.connect(proxy.paths["alice"])
            try:
                parser = _RawHttp(client)
                client.sendall((
                    f"POST http://{authority}/expect HTTP/1.1\r\n"
                    f"Host: {authority}\r\nExpect: 100-continue\r\n"
                    "Content-Length: 12\r\nConnection: keep-alive\r\n\r\n"
                ).encode())
                interim = parser.message()
                assert interim["status"] == 100
                with origin.lock:
                    # A proxy may acknowledge Expect locally before it opens
                    # the origin connection. Either way, no body byte may
                    # cross the boundary before the client sends its payload.
                    assert all(count == 0 for count in origin.body_bytes_received)
                client.sendall(b"hello expect")
                assert parser.message()["status"] == 200

                client.sendall((
                    f"HEAD http://{authority}/head HTTP/1.1\r\n"
                    f"Host: {authority}\r\nConnection: keep-alive\r\n\r\n"
                ).encode())
                head = parser.message(method="HEAD")
                assert head["status"] == 200
                assert head["body"] == b""

                client.sendall((
                    f"GET http://{authority}/empty HTTP/1.1\r\n"
                    f"Host: {authority}\r\nConnection: keep-alive\r\n\r\n"
                ).encode())
                assert parser.message()["status"] == 204

                client.sendall((
                    f"GET http://{authority}/after HTTP/1.1\r\n"
                    f"Host: {authority}\r\nConnection: close\r\n\r\n"
                ).encode())
                after = parser.message()
                assert after["status"] == 200
                assert after["body"] == b"hello"
            finally:
                client.close()
            _retain_evidence(
                "expect-bodyless", proxy, origin, backend=proxy_backend,
                outcome="Expect acknowledgement, HEAD/204 framing, then follow-up",
            )

        _wait_until(lambda: len(origin.records) == 4)
        assert [record["method"] for record in origin.records] == [
            "POST", "HEAD", "GET", "GET"
        ]
        assert origin.records[0]["body"] == b"hello expect"
        assert origin.records[1]["method"] == "HEAD"
        assert origin.records[2]["target"] == "/empty"
        assert origin.records[3]["target"] == "/after"


def test_http1_response_cancel_keeps_next_request_and_agent_decision_clean(
    proxy_backend, tmp_path
):
    """A canceled, unterminated response cannot contaminate later traffic."""
    with _origin() as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(
            proxy_backend, tmp_path / proxy_backend, POLICY, native_policy=True
        ) as proxy:
            status, _, body = send_request(
                proxy.paths["alice"], f"http://{authority}/before"
            )
            assert status == 200 and body == b"hello"

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(_LIMIT)
            client.connect(proxy.paths["alice"])
            try:
                client.sendall((
                    f"GET http://{authority}/cancel-response HTTP/1.1\r\n"
                    f"Host: {authority}\r\nConnection: keep-alive\r\n\r\n"
                ).encode())
                parser = _RawHttp(client)
                response_head = parser._until(b"\r\n\r\n")
                first, _ = parser._headers(response_head)
                assert first.startswith(b"HTTP/1.1 200 "), response_head
                response_prefix = parser._until(b"data: first\n\n")
                assert origin.response_started.is_set()
                assert not origin.cancel_observed.is_set(), "origin closed before client cancel"
            finally:
                # This is the deliberate cancellation, after the first body
                # bytes reached the client and before the terminal zero chunk.
                client_close_started_at = time.monotonic()
                client.close()

            denied_status, _, denied_body = send_request(
                proxy.paths["bob"], f"http://{authority}/denied"
            )
            assert denied_status == 403
            assert b"data: first" not in denied_body

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as followup:
                followup.settimeout(_LIMIT)
                followup.connect(proxy.paths["alice"])
                followup.sendall((
                    f"GET http://{authority}/after-cancel HTTP/1.1\r\n"
                    f"Host: {authority}\r\nConnection: keep-alive\r\n\r\n"
                ).encode())
                after = _RawHttp(followup)
                response = after.message()
                assert response["status"] == 200 and response["body"] == b"hello"
                assert not after.buffer, "later response contained extra bytes"
                followup.sendall((
                    f"GET http://{authority}/after-cancel-again HTTP/1.1\r\n"
                    f"Host: {authority}\r\nConnection: close\r\n\r\n"
                ).encode())
                response_again = after.message()
                assert response_again["status"] == 200
                assert response_again["body"] == b"hello"
                assert not after.buffer, "reused client received stale response bytes"

            _wait_until(origin.cancel_observed.is_set)
            _retain_evidence(
                "response-cancel", proxy, origin, backend=proxy_backend,
                outcome="client closed after first response bytes; fresh denied and allowed requests",
                response_head_hex=response_head.hex(),
                response_prefix_hex=response_prefix.hex(),
                denied_status=denied_status,
                denied_body_hex=denied_body.hex(),
                followup_response=response,
                followup_again_response=response_again,
                followup_extra_bytes=0,
                origin_close_after_client_ms=round(
                    (origin.cancel_observed_at - client_close_started_at) * 1000, 3
                ),
            )
            assert origin.cancel_result in {"eof", "reset"}, origin.cancel_result
            assert origin.cancel_observed_at >= client_close_started_at
            assert [record["target"] for record in origin.records] == [
                "/before", "/cancel-response", "/after-cancel", "/after-cancel-again"
            ]


def test_http1_handoff_preserves_request_trailers(proxy_backend, tmp_path, request):
    """A chunked request trailer reaches the origin as a body terminal field."""
    if proxy_backend == "python":
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason="Python comparator does not complete a request with trailers",
        ))
    with _origin() as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(_LIMIT)
            client.connect(proxy.paths["alice"])
            try:
                parser = _RawHttp(client)
                client.sendall((
                    f"POST http://{authority}/trailers HTTP/1.1\r\n"
                    f"Host: {authority}\r\nTransfer-Encoding: chunked\r\n"
                    "TE: trailers\r\nTrailer: X-Request-Proof\r\nConnection: close\r\n\r\n"
                    "5\r\nhello\r\n0\r\nX-Request-Proof: retained\r\n\r\n"
                ).encode())
                response = parser.message()
                assert response["status"] == 200
                _retain_evidence(
                    "request-trailers", proxy, origin, backend=proxy_backend,
                    outcome="chunked request trailer reached raw origin",
                )
            finally:
                client.close()
        _wait_until(lambda: len(origin.records) == 1)
        assert origin.records[0]["body"] == b"hello"
        assert ("trailer", "X-Request-Proof") in origin.records[0]["headers"]
        assert origin.records[0]["trailers"] == [("x-request-proof", "retained")]


@pytest.mark.parametrize("framing", ["truncated-length", "truncated-chunk"])
def test_http1_handoff_rejects_truncated_request_before_origin_completion(
    proxy_backend, tmp_path, framing
):
    """A malformed body is a negative control: no partial request is completed upstream."""
    with _origin() as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(_LIMIT)
            client.connect(proxy.paths["alice"])
            if framing == "truncated-length":
                request = (
                    f"POST http://{authority}/bad HTTP/1.1\r\n"
                    f"Host: {authority}\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabc"
                ).encode()
            else:
                request = (
                    f"POST http://{authority}/bad HTTP/1.1\r\n"
                    f"Host: {authority}\r\nTransfer-Encoding: chunked\r\n"
                    "Connection: close\r\n\r\n3\r\nabc\r\n"
                ).encode()
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            try:
                response = _RawHttp(client).message()
            except (ConnectionError, OSError, TimeoutError, AssertionError):
                # Closing without a response is also a valid rejection of an
                # incomplete HTTP message. If a backend returns a response,
                # it must be an error and must not claim an origin result.
                pass
            else:
                assert response["status"] >= 400
            _retain_evidence(
                f"negative-{framing}", proxy, origin, backend=proxy_backend,
                outcome="truncated request rejected before origin completion",
                framing=framing,
            )
            client.close()
        time.sleep(0.1)
        assert origin.headers_received == []
        assert origin.records == []
