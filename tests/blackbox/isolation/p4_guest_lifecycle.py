#!/usr/bin/env python3
"""Selected P4 traffic through one installed guest bridge."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import struct
import time
from pathlib import Path

from tests.blackbox.isolation.p1_guest_requests import GUEST_PROXY, GUEST_SOCKET, forwarder_identity
from tests.blackbox.isolation.p2_guest_traffic import _event
from tests.proxy_migration.websocket_peer import Peer, read_head

PROXY = ("127.0.0.1", 8080)
FIXTURE = "failing.test"
SELF_SIGNED = Path("/safeyolo/guest-only-trust-anchor.crt")
RELEASE = Path("/safeyolo/p4-passthrough-go")


def http_echo(marker: str) -> dict:
    client = http.client.HTTPConnection(*PROXY, timeout=10)
    path = f"/p4/echo/{marker}"
    try:
        client.request("GET", f"http://{FIXTURE}{path}", headers={"Host": FIXTURE})
        response = client.getresponse()
        body = response.read(1024)
        status = response.status
        blocked = response.getheader("X-Blocked-By")
        if status == 200:
            assert body == f"echo:{marker}".encode(), (status, body)
        else:
            assert status == 403 and blocked == "network-guard", (status, blocked, body)
        return {"status": status, "blocked_by": blocked, "body": body.decode() if status == 200 else None}
    finally:
        client.close()


def denied_canary(marker: str) -> dict:
    client = http.client.HTTPConnection(*PROXY, timeout=10)
    try:
        client.request("GET", f"http://evil.com/p4/canary/{marker}", headers={"Host": "evil.com"})
        response = client.getresponse()
        response.read(4096)
        assert response.status == 403 and response.getheader("X-Blocked-By") == "network-guard"
        return {"status": 403, "blocked_by": "network-guard"}
    finally:
        client.close()


def connect_tls(host: str, context: ssl.SSLContext) -> tuple[ssl.SSLSocket, bytes]:
    raw = socket.create_connection(PROXY, timeout=10)
    raw.settimeout(12)
    try:
        raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        head, _ = read_head(raw)
        assert head.split()[1] == "200", head
        stream = context.wrap_socket(raw, server_hostname=host)
        return stream, stream.getpeercert(binary_form=True)
    except Exception:
        raw.close()
        raise


def tls_get(host: str, marker: str, context: ssl.SSLContext) -> tuple[int, bytes, str]:
    stream, certificate = connect_tls(host, context)
    with stream:
        stream.sendall(f"GET /p4/tls/{marker} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        status = response.status
        body = response.read(4096)
    return status, body, hashlib.sha256(certificate).hexdigest()


def tls_cases(marker: str) -> dict:
    selected = {}
    for name in (
        "example-chain-test.test",
        "wrong-san.test",
        "self-signed.test",
        "future-leaf.test",
        "expired-leaf.test",
    ):
        status, body, fingerprint = tls_get(name, marker, ssl.create_default_context())
        expected = 200 if name == "example-chain-test.test" else 502
        assert status == expected, (name, status, body)
        if status == 200:
            assert json.loads(body)["host"] == name, body
        selected[name] = {"status": status, "client_leaf_sha256": fingerprint}
    return selected


def sse(marker: str) -> dict:
    stream = socket.create_connection(PROXY, timeout=10)
    stream.settimeout(20)
    with stream:
        stream.sendall(
            (f"GET http://{FIXTURE}/p2/sse/{marker} HTTP/1.1\r\nHost: {FIXTURE}\r\nConnection: close\r\n\r\n").encode()
        )
        head, _ = read_head(stream)
        assert head.split()[1] == "200", head
        first = _event(stream)
        assert first == f"data: first:{marker}\n\n".encode(), first
        print("P4_READY=sse", flush=True)
        last = _event(stream)
        assert last == f"data: last:{marker}\n\n".encode(), last
        assert stream.recv(1) == b""
    return {"first": first.decode(), "last": last.decode()}


def passthrough_held(marker: str) -> dict:
    assert SELF_SIGNED.is_file()
    expected = ssl.PEM_cert_to_DER_cert(SELF_SIGNED.read_text())
    context = ssl.create_default_context(cafile=str(SELF_SIGNED))
    stream, certificate = connect_tls("self-signed.test", context)
    with stream:
        assert certificate == expected, "configured passthrough did not expose the origin leaf"
        print("P4_READY=passthrough", flush=True)
        deadline = time.monotonic() + 12
        while not RELEASE.is_file():
            assert time.monotonic() < deadline, "operator did not remove the passthrough entry"
            time.sleep(0.05)
        stream.sendall(
            (f"GET /p4/tls/{marker} HTTP/1.1\r\nHost: self-signed.test\r\nConnection: close\r\n\r\n").encode()
        )
        response = http.client.HTTPResponse(stream)
        response.begin()
        body = response.read(4096)
        assert response.status == 200 and json.loads(body)["host"] == "self-signed.test", body
    return {"status_after_removal": 200, "origin_leaf_sha256": hashlib.sha256(certificate).hexdigest()}


def drain(marker: str) -> dict:
    http_marker = marker
    sse_marker = "p2-" + marker[3:]
    http_connection = http.client.HTTPConnection(*PROXY, timeout=20)
    event = ws = tunnel = None
    try:
        http_connection.request("GET", f"http://{FIXTURE}/p4/hold/{http_marker}", headers={"Host": FIXTURE})
        held = http_connection.getresponse()
        assert held.status == 200
        first_http = f"first:{http_marker}\n".encode()
        assert held.read(len(first_http)) == first_http

        event = socket.create_connection(PROXY, timeout=10)
        event.settimeout(20)
        event.sendall(
            (
                f"GET http://{FIXTURE}/p2/sse/{sse_marker} HTTP/1.1\r\nHost: {FIXTURE}\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        head, _ = read_head(event)
        assert head.split()[1] == "200", head
        first_event = _event(event)
        assert first_event == f"data: first:{sse_marker}\n\n".encode()

        ws = socket.create_connection(PROXY, timeout=10)
        ws.settimeout(20)
        key = base64.b64encode(os.urandom(16)).decode()
        ws.sendall(
            (
                f"GET http://{FIXTURE}/p2/ws/{sse_marker} HTTP/1.1\r\n"
                f"Host: {FIXTURE}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        head, _ = read_head(ws)
        assert head.split()[1] == "101", head
        peer = Peer(ws, client=True, compressed=False)
        peer.send(1, f"client:{sse_marker}".encode())
        assert peer.receive() == (1, f"server:{sse_marker}".encode())

        tunnel, _ = connect_tls(FIXTURE, ssl.create_default_context())
        tunnel.settimeout(20)
        print("P4_READY=drain", flush=True)

        last_http = f"last:{http_marker}\n".encode()
        assert held.read() == last_http
        assert _event(event) == f"data: last:{sse_marker}\n\n".encode()
        close_opcode, close_payload = peer.receive()
        assert close_opcode == 8 and close_payload == struct.pack("!H", 1001), (close_opcode, close_payload)
        try:
            closed = tunnel.recv(1) == b""
        except (ssl.SSLEOFError, ConnectionResetError):
            closed = True
        assert closed, "admitted CONNECT remained open after stop"
        return {"http": "completed", "sse": "completed", "websocket_close": 1001, "connect_closed": True}
    finally:
        http_connection.close()
        for connection in (event, ws, tunnel):
            if connection is not None:
                connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase", choices=("echo", "canary", "tls", "self-signed", "sse", "passthrough", "drain"), required=True
    )
    parser.add_argument("--marker", required=True)
    parser.add_argument("--agent", required=True)
    args = parser.parse_args()
    assert args.marker.startswith("p4-") and len(args.marker) == 35
    assert os.environ["HTTP_PROXY"] == GUEST_PROXY
    assert GUEST_SOCKET.is_socket()
    forwarder = forwarder_identity()
    if args.phase == "echo":
        result = http_echo(args.marker)
    elif args.phase == "canary":
        result = denied_canary(args.marker)
    elif args.phase == "tls":
        result = tls_cases(args.marker)
    elif args.phase == "self-signed":
        status, _, fingerprint = tls_get("self-signed.test", args.marker, ssl.create_default_context())
        assert status == 502, status
        result = {"status": status, "client_leaf_sha256": fingerprint}
    elif args.phase == "sse":
        result = sse("p2-" + args.marker[3:])
    elif args.phase == "passthrough":
        result = passthrough_held(args.marker)
    else:
        result = drain(args.marker)
    print(
        "P4_OBSERVATION="
        + json.dumps(
            {"phase": args.phase, "agent": args.agent, "forwarder": forwarder, "result": result}, sort_keys=True
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
