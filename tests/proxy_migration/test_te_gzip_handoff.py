"""Keep transfer coding and a following response honest across the real proxies."""

from __future__ import annotations

import gzip
import json
import os
import socket
import threading
from contextlib import contextmanager
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer

import pytest

from tests.proxy_migration.harness import launch_proxy
from tests.proxy_migration.run import proxy_identity
from tests.proxy_migration.scenarios import POLICY

CANARY = b"te-gzip-origin-canary\x00complete"
GZIP_CANARY = gzip.compress(CANARY, mtime=0)


class _Wire:
    def __init__(self, stream):
        self.stream = stream
        self.buffer = bytearray()
        self.observed = bytearray()

    def until(self, marker):
        while marker not in self.buffer:
            data = self.stream.recv(4096)
            if not data:
                raise AssertionError(f"peer closed before {marker!r}")
            self.observed.extend(data)
            self.buffer.extend(data)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def exact(self, size):
        while len(self.buffer) < size:
            data = self.stream.recv(4096)
            if not data:
                raise AssertionError(f"peer closed with {size - len(self.buffer)} bytes missing")
            self.observed.extend(data)
            self.buffer.extend(data)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def head(self):
        raw = self.until(b"\r\n\r\n")
        lines = raw[:-4].split(b"\r\n")
        headers = []
        for line in lines[1:]:
            name, colon, value = line.partition(b":")
            assert colon, line
            headers.append((name.lower(), value.strip()))
        return lines[0], headers, raw

    def response(self):
        status_line, headers, head = self.head()
        assert status_line.startswith(b"HTTP/1."), status_line
        fields = dict(headers)
        transfer = fields.get(b"transfer-encoding", b"").lower()
        wire = bytearray(head)
        if transfer:
            assert transfer.split(b",")[-1].strip() == b"chunked", transfer
            body = bytearray()
            while True:
                size_line = self.until(b"\r\n")
                wire.extend(size_line)
                size = int(size_line[:-2].split(b";", 1)[0], 16)
                if size:
                    data = self.exact(size + 2)
                    assert data.endswith(b"\r\n")
                    wire.extend(data)
                    body.extend(data[:-2])
                else:
                    while True:
                        trailer = self.until(b"\r\n")
                        wire.extend(trailer)
                        if trailer == b"\r\n":
                            break
                    break
        else:
            assert b"content-length" in fields, headers
            body = self.exact(int(fields[b"content-length"]))
            wire.extend(body)
        return {"status": int(status_line.split()[1]), "headers": headers,
                "body": bytes(body), "wire": bytes(wire)}


class _Origin(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, coding):
        self.coding = coding
        self.requests = []
        self.responses = []
        self.errors = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _OriginHandler)


class _OriginHandler(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        reader = _Wire(self.request)
        while True:
            try:
                line, headers, head = reader.head()
            except (AssertionError, OSError):
                return
            try:
                target = line.split(b" ", 2)[1]
                if target.endswith(b"/first"):
                    body = GZIP_CANARY if self.server.coding == "gzip" else CANARY
                    transfer = (b"gzip, chunked" if self.server.coding == "gzip"
                                else b"chunked")
                    response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: " + transfer
                                + b"\r\nConnection: keep-alive\r\n\r\n"
                                + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                elif target.endswith(b"/second"):
                    response = (b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
                                b"Connection: keep-alive\r\n\r\nsecond")
                else:
                    raise AssertionError(f"unexpected origin target: {target!r}")
                with self.server.lock:
                    self.server.requests.append({"line": line, "headers": headers, "wire": head})
                    self.server.responses.append(response)
                self.request.sendall(response)
            except (AssertionError, OSError) as error:
                with self.server.lock:
                    self.server.errors.append(repr(error))
                return


@contextmanager
def _origin(coding):
    origin = _Origin(coding)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        yield origin
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def _assert_exchange(first, second, requests, coding):
    assert [record["line"].split(b" ", 2)[1].split(b"/")[-1]
            for record in requests] == [b"first", b"second"]
    assert all(name != b"te" for name, _ in requests[0]["headers"])
    assert first["status"] == second["status"] == 200
    first_fields = dict(first["headers"])
    expected_transfer = b"gzip, chunked" if coding == "gzip" else b"chunked"
    assert first_fields[b"transfer-encoding"].lower() == expected_transfer
    assert b"content-length" not in first_fields
    expected_body = GZIP_CANARY if coding == "gzip" else CANARY
    assert first["body"] == expected_body
    if coding == "gzip":
        assert gzip.decompress(first["body"]) == CANARY
    second_fields = dict(second["headers"])
    assert b"transfer-encoding" not in second_fields
    assert second_fields[b"content-length"] == b"6"
    assert second["body"] == b"second"
    assert second["wire"].startswith(b"HTTP/1.1 200 ")


def _retain(backend, case, proxy, origin, sent, reader, responses):
    destination = os.environ.get("SAFEYOLO_TE_GZIP_EVIDENCE")
    if not destination:
        return
    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    with origin.lock:
        requests = list(origin.requests)
        origin_responses = list(origin.responses)
        errors = list(origin.errors)
    payload = {
        "backend": backend, "case": case, "proxy_identity": proxy_identity(proxy),
        "client_sent_hex": [item.hex() for item in sent],
        "client_received_hex": reader.observed.hex(),
        "parsed_response_hex": [item["wire"].hex() for item in responses],
        "origin_request_hex": [item["wire"].hex() for item in requests],
        "origin_response_hex": [item.hex() for item in origin_responses],
        "origin_errors": errors,
    }
    (output / f"{backend}-{case}.json").write_text(json.dumps(payload, indent=2) + "\n")


@pytest.mark.parametrize("coding,request_te", [
    ("gzip", True), ("gzip", False), ("plain", True),
], ids=["gzip-nominated-te", "gzip-no-request-te", "plain-chunked-control"])
def test_transfer_coding_and_next_response(proxy_backend, tmp_path, coding, request_te):
    with _origin(coding) as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(proxy.paths["alice"])
                reader = _Wire(client)
                first_request = (
                    f"GET http://{authority}/first HTTP/1.1\r\nHost: {authority}\r\n"
                    + ("TE: gzip\r\nConnection: TE\r\n" if request_te else "")
                    + "\r\n"
                ).encode()
                second_request = (
                    f"GET http://{authority}/second HTTP/1.1\r\nHost: {authority}\r\n\r\n"
                ).encode()
                sent = [first_request]
                responses = []
                try:
                    client.sendall(first_request)
                    responses.append(reader.response())
                    sent.append(second_request)
                    client.sendall(second_request)
                    responses.append(reader.response())
                    with origin.lock:
                        requests = list(origin.requests)
                        errors = list(origin.errors)
                    assert not errors, errors
                    _assert_exchange(*responses, requests, coding)
                    assert not reader.buffer, "bytes remain after the second response"
                finally:
                    _retain(proxy_backend, f"{coding}-{'te' if request_te else 'no-te'}",
                            proxy, origin, sent, reader, responses)


def test_native_http10_rejects_unrepresentable_transfer_coding(proxy_backend, tmp_path):
    if proxy_backend != "rust":
        pytest.skip("the native HTTP/1.0 transfer-coding fallback is Rust-specific")
    with _origin("gzip") as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(proxy.paths["alice"])
                reader = _Wire(client)
                request = (
                    f"GET http://{authority}/first HTTP/1.0\r\nHost: {authority}\r\n\r\n"
                ).encode()
                responses = []
                try:
                    client.sendall(request)
                    responses.append(reader.response())
                    assert responses[0]["status"] == 502
                    assert GZIP_CANARY not in responses[0]["wire"]
                    with origin.lock:
                        assert len(origin.requests) == 1
                        assert not origin.errors
                finally:
                    _retain(proxy_backend, "http10-rejection", proxy, origin,
                            [request], reader, responses)


def test_transfer_coding_oracle_rejects_false_success():
    """A changed declaration, canary, or following response must fail the oracle."""
    requests = [{"line": b"GET /first HTTP/1.1", "headers": [], "wire": b""},
                {"line": b"GET /second HTTP/1.1", "headers": [], "wire": b""}]
    first = {"status": 200, "headers": [(b"transfer-encoding", b"gzip, chunked")],
             "body": GZIP_CANARY, "wire": b"HTTP/1.1 200 OK\r\n"}
    second = {"status": 200, "headers": [(b"content-length", b"6")],
              "body": b"second", "wire": b"HTTP/1.1 200 OK\r\n"}
    _assert_exchange(first, second, requests, "gzip")
    for changed_first, changed_second, changed_requests in (
        ({**first, "headers": [(b"transfer-encoding", b"chunked")]}, second, requests),
        ({**first, "body": CANARY}, second, requests),
        ({**first, "body": GZIP_CANARY[:-1]}, second, requests),
        (first, {**second, "body": b"xsecond"}, requests),
        (first, {**second, "body": b"secon"}, requests),
        (first, second, [{**requests[0], "headers": [(b"te", b"gzip")]}, requests[1]]),
    ):
        with pytest.raises(AssertionError):
            _assert_exchange(changed_first, changed_second, changed_requests, "gzip")
