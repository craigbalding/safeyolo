"""Allowed HTTP/1.1 chunked uploads must finish at an owned origin.

This checks transport framing on both sides of the configured 10 MiB Python
streaming threshold. It does not establish body inspection beyond that window.
"""

import hashlib
import http.client
import io
import json
import os
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.proxy_migration.harness import connection, launch_proxy, read_events
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, POLICY

THRESHOLD = 10 * 1024 * 1024


class FramingOrigin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.requests = []
        self.condition = threading.Condition()
        self.body_started = threading.Event()
        super().__init__(("127.0.0.1", 0), FramingHandler)

    def get_request(self):
        stream, address = super().get_request()
        stream.settimeout(4)
        return stream, address

    def wait_requests(self, count):
        with self.condition:
            assert self.condition.wait_for(lambda: len(self.requests) >= count, timeout=5)
            return list(self.requests)


class FramingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        observed = {
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body_bytes": 0,
            "body_sha256": None,
            "complete": False,
            "framing": None,
        }
        digest = hashlib.sha256()
        try:
            transfer = self.headers.get_all("Transfer-Encoding", [])
            lengths = self.headers.get_all("Content-Length", [])
            if len(transfer) == 1 and transfer[0].lower() == "chunked" and not lengths:
                observed["framing"] = "chunked"
                while True:
                    size_line = self.rfile.readline()
                    assert size_line.endswith(b"\r\n"), "missing chunk size"
                    size = int(size_line[:-2].split(b";", 1)[0], 16)
                    if not size:
                        assert self.rfile.readline() == b"\r\n", "missing chunk terminator"
                        break
                    part = self.rfile.read(size)
                    assert len(part) == size, "truncated chunk"
                    digest.update(part)
                    observed["body_bytes"] += len(part)
                    self.server.body_started.set()
                    assert self.rfile.read(2) == b"\r\n", "missing chunk delimiter"
            elif not transfer and len(lengths) == 1:
                observed["framing"] = "content-length"
                remaining = int(lengths[0])
                while remaining:
                    part = self.rfile.read(min(remaining, 65536))
                    assert part, "truncated fixed-length body"
                    digest.update(part)
                    observed["body_bytes"] += len(part)
                    self.server.body_started.set()
                    remaining -= len(part)
            else:
                observed["framing"] = "missing-or-ambiguous"
                return  # Incomplete framing never receives an origin 200.
            observed["complete"] = True
            observed["body_sha256"] = digest.hexdigest()
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"ok")
        except (AssertionError, OSError, ValueError) as error:
            observed["error"] = f"{type(error).__name__}: {error}"
        finally:
            self.close_connection = True
            with self.server.condition:
                self.server.requests.append(observed)
                self.server.condition.notify_all()


@contextmanager
def framing_origin():
    server = FramingOrigin()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def send_chunked(client, target, payload):
    try:
        client.request("POST", target, body=io.BytesIO(payload), encode_chunked=True, headers={
            "Transfer-Encoding": "chunked",
            "Connection": "X-Hop, Transfer-Encoding, close",
            "X-Hop": "remove-me",
            "Proxy-Authorization": "Basic fixture",
            "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
        })
        response = client.getresponse()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        client.close()


def send_streamed_chunked(path, target, payload, origin):
    """Hold the terminator until the origin receives body bytes."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(8)
        client.connect(path)
        client.sendall((
            f"POST {target} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin.server_address[1]}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: X-Hop, Transfer-Encoding, close\r\n"
            "X-Hop: remove-me\r\n"
            "Proxy-Authorization: Basic fixture\r\n"
            f"X-SafeYolo-Request-Id: {FORGED_REQUEST_ID}\r\n\r\n"
        ).encode())
        for start in range(0, len(payload), 65536):
            part = payload[start:start + 65536]
            client.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        assert origin.body_started.wait(timeout=5), "origin saw no body before request completion"
        assert len(origin.requests) == 1, "origin completed before the zero chunk"
        client.settimeout(0.1)
        with pytest.raises(socket.timeout):
            client.recv(1)
        client.settimeout(8)
        client.sendall(b"0\r\n\r\n")
        response = http.client.HTTPResponse(client)
        response.begin()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()


def retain_observation(backend, size, directory, origin, response, requests, egress, audit):
    destination = os.environ.get("SAFEYOLO_CHUNKED_FRAMING_EVIDENCE")
    if destination is None:
        return
    output = Path(destination)
    output.mkdir(parents=True, exist_ok=True)
    status, headers, body = response
    observation = {
        "backend": backend,
        "body_bytes_sent": size,
        "response": {"status": status, "headers": headers, "body": body.decode("latin-1")},
        "origin": list(origin.requests),
        "proxy_request": requests,
        "proxy_egress": egress,
        "proxy_audit": audit,
        "proxy_config": json.loads((directory / "proxy.json").read_text()),
    }
    (output / f"{backend}-{size}.json").write_text(json.dumps(observation, indent=2) + "\n")


@pytest.mark.parametrize("size", [19, THRESHOLD + 1], ids=["buffered", "streamed"])
def test_allowed_chunked_request_finishes_at_origin(proxy_backend, tmp_path, size):
    payload = b"x" * size
    digest = hashlib.sha256(payload).hexdigest()
    with framing_origin() as origin:
        port = origin.server_address[1]
        direct = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        assert send_chunked(direct, "/direct", payload)[:1] == (200,)
        assert origin.wait_requests(1)[0]["complete"] is True
        assert origin.requests[0]["body_sha256"] == digest
        origin.body_started.clear()

        directory = tmp_path / proxy_backend
        with launch_proxy(proxy_backend, directory, POLICY, stream_large_bodies="10m") as proxy:
            target = f"http://127.0.0.1:{port}/allowed"
            if size > THRESHOLD:
                status, headers, body = send_streamed_chunked(
                    proxy.paths["alice"], target, payload, origin
                )
            else:
                client = connection(proxy.paths["alice"])
                client.sock.settimeout(8)
                status, headers, body = send_chunked(client, target, payload)
            requests = proxy.events("proxy.request")
            egress = proxy.events("proxy.egress")
            audit = read_events(directory / "audit.jsonl")
            retain_observation(
                proxy_backend, size, directory, origin,
                (status, headers, body), requests, egress, audit,
            )
            assert status == 200 and body == b"ok", (
                status, headers, body, origin.requests, egress, requests, audit,
            )
            assert "x-blocked-by" not in headers
            assert headers["x-safeyolo-request-id"] != FORGED_REQUEST_ID
            assert len(requests) == 1
            assert requests[0]["decision"] == "allow" and requests[0]["status"] == 200
            assert len(egress) == 1 and egress[0]["port"] == port
            assert not any(row.get("decision") == "deny" for row in audit)

        assert len(origin.wait_requests(2)) == 2, origin.requests
        observed = origin.requests[1]
        assert observed["complete"] is True, observed
        assert observed["body_bytes"] == size
        assert observed["body_sha256"] == digest
        if size > THRESHOLD:
            assert observed["framing"] == "chunked"
        else:
            assert observed["framing"] in {"chunked", "content-length"}
        assert not ({"connection", "x-hop", "proxy-authorization", "x-safeyolo-request-id"}
                    & observed["headers"].keys())
