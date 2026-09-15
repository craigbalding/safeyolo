"""WS/WSS wire contracts with owned peers and independent raw DEFLATE state.

The peers deliberately do not use wsproto: its historical handling of control
frames inside compressed fragmented messages is one behavior under comparison.
Every transport specimen also runs directly against the identical owned peer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import signal
import socket
import socketserver
import ssl
import stat
import struct
import threading
import time
import zlib
from contextlib import contextmanager
from pathlib import Path

import pytest
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy as _launch_proxy
from tests.proxy_migration.harness import read_events
from tests.proxy_migration.scenarios import POLICY
from tests.proxy_migration.test_http2_contract import origin_certificate

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
TEXT = ("bounded compressed websocket message 📦 " * 32).encode()
BINARY = bytes(range(256)) * 8
PATTERN = '''
[[scan_patterns]]
name = "project-id"
pattern = "PROJ-[0-9]{5}"
target = "both"
scope = ["body"]
action = "block"
'''


@contextmanager
def launch_proxy(backend, directory, policy, **options):
    """Exercise native Rust policy while retaining the Python comparator."""
    if backend == "rust":
        options["native_policy"] = True
    with _launch_proxy(backend, directory, policy, **options) as proxy:
        if backend == "rust":
            config = json.loads((directory / "proxy.json").read_text())
            policy_socket = Path(proxy.paths["alice"]).parents[1] / "policy.sock"
            assert Path(config["policy_file"]) == directory / "policy.toml"
            assert "temporary_policy_socket" not in config
            assert proxy.policy_process is None
            assert not (directory / "policy-bridge").exists()
            assert not policy_socket.exists()
        yield proxy
        # Fixture exceptions propagate before these assertions. Shutdown cases
        # can already have stopped the child; inspect its retained events only.
        if backend == "rust":
            requests = proxy.events("proxy.request")
            assert requests, "Fixture completed without request evidence"
            # Outer CONNECT uses the network guard; inner HTTP also runs circuits.
            assert all(row.get("coverage") in {
                "native_network_guard_only", "native_network_guard_and_circuits",
            } for row in requests)
            native_ids = {row["request_id"] for row in proxy.events("proxy.network_guard")}
            for row in requests:
                if row["status"] in {101, 403}:
                    assert row["request_id"] in native_ids


def exact(stream, length):
    """Read exactly the requested finite fixture bytes or expose premature EOF."""
    result = bytearray()
    while len(result) < length:
        piece = stream.recv(length - len(result))
        if not piece:
            raise EOFError("WebSocket peer ended before the expected bytes")
        result.extend(piece)
    return bytes(result)


def read_head(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        result.extend(exact(stream, 1))
    lines = result.decode("latin1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if line:
            name, value = line.split(":", 1)
            headers.setdefault(name.lower(), []).append(value.strip())
    return lines[0], headers


def frame(opcode, payload, *, final=True, compressed=False, masked=False):
    first = (0x80 if final else 0) | (0x40 if compressed else 0) | opcode
    mask_bit = 0x80 if masked else 0
    length = len(payload)
    if length < 126:
        head = bytes([first, mask_bit | length])
    elif length < 65536:
        head = bytes([first, mask_bit | 126]) + struct.pack("!H", length)
    else:
        head = bytes([first, mask_bit | 127]) + struct.pack("!Q", length)
    if masked:
        mask = b"\x12\x34\x56\x78"
        head += mask
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return head + payload


class Peer:
    """Finite test peer preserving distinct send/receive compression dictionaries."""

    def __init__(self, stream, *, client, compressed):
        self.stream = stream
        self.client = client
        self.compressed = compressed
        self.encoder = zlib.compressobj(wbits=-15)
        self.decoder = zlib.decompressobj(wbits=-15)
        self.controls = []
        self.data_frames = 0

    def send(self, opcode, payload, *, fragmented=False, control=None):
        encoded = payload
        if self.compressed:
            encoded = (self.encoder.compress(payload) + self.encoder.flush(zlib.Z_SYNC_FLUSH))[:-4]
        if fragmented:
            split = len(encoded) // 2
            wire = frame(opcode, encoded[:split], final=False,
                         compressed=self.compressed, masked=self.client)
            if control is not None:
                wire += frame(control, b"control", masked=self.client)
            wire += frame(0, encoded[split:], masked=self.client)
        else:
            wire = frame(opcode, encoded, compressed=self.compressed, masked=self.client)
        self.stream.sendall(wire)

    def close(self, code=1000, reason=b"fixture complete"):
        self.stream.sendall(frame(8, struct.pack("!H", code) + reason, masked=self.client))

    def receive(self):
        pieces = bytearray()
        message_opcode = None
        compressed = False
        while True:
            first, second = exact(self.stream, 2)
            final, opcode = bool(first & 0x80), first & 15
            assert not first & 0x30, "Unnegotiated reserved frame bits"
            assert bool(second & 0x80) != self.client, "Incorrect peer masking direction"
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", exact(self.stream, 2))[0]
                assert length >= 126
            elif length == 127:
                length = struct.unpack("!Q", exact(self.stream, 8))[0]
                assert 65536 <= length < 2**63
            mask = exact(self.stream, 4) if second & 0x80 else None
            payload = exact(self.stream, length)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode in (8, 9, 10):
                assert final and not first & 0x40 and length <= 125
                if opcode == 8:
                    return opcode, payload
                self.controls.append((opcode, payload))
                if opcode == 9:
                    self.stream.sendall(frame(10, payload, masked=self.client))
                continue
            if opcode in (1, 2):
                assert message_opcode is None
                message_opcode, compressed = opcode, bool(first & 0x40)
                assert self.compressed or not compressed
            else:
                assert opcode == 0 and message_opcode is not None and not first & 0x40
            self.data_frames += 1
            pieces.extend(payload)
            if final:
                decoded = bytes(pieces)
                if compressed:
                    decoded = self.decoder.decompress(decoded + b"\x00\x00\xff\xff")
                if message_opcode == 1:
                    decoded.decode("utf-8")
                return message_opcode, decoded


class OwnedOrigin(socketserver.ThreadingTCPServer):
    """Thread failures are returned to the controlling test, never suppressed."""

    def __init__(self, script, *, pem=None, compressed=False):
        self.script = script
        self.compressed = compressed
        self.accepts = 0
        self.results = queue.Queue()
        self.errors = queue.Queue()
        self.context = None
        if pem:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(pem)
            self.context.set_alpn_protocols(["http/1.1"])
        super().__init__(("127.0.0.1", 0), OriginHandler)

    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        return result

    @property
    def authority(self):
        return f"127.0.0.1:{self.server_address[1]}"


class OriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # socketserver otherwise prints worker exceptions and lets tests pass.
        # Propagate ordinary failures through the parent-owned error queue.
        try:
            stream = self.request
            stream.settimeout(5)
            if self.server.context:
                stream = self.server.context.wrap_socket(stream, server_side=True)
            with stream:
                request_line, headers = read_head(stream)
                assert request_line.startswith("GET ")
                assert headers["sec-websocket-version"] == ["13"]
                assert headers["upgrade"] == ["websocket"]
                key = headers["sec-websocket-key"][0]
                assert len(base64.b64decode(key, validate=True)) == 16
                accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
                response = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
                            "Sec-WebSocket-Protocol: fixture\r\n")
                if self.server.compressed:
                    assert "permessage-deflate" in ",".join(headers["sec-websocket-extensions"])
                    response += "Sec-WebSocket-Extensions: permessage-deflate\r\n"
                stream.sendall((response + "\r\n").encode())
                peer = Peer(stream, client=False, compressed=self.server.compressed)
                self.server.script(peer, self.server.results)
        except Exception as error:
            self.server.errors.put(error)


@contextmanager
def origin_server(script, *, pem=None, compressed=False):
    origin = OwnedOrigin(script, pem=pem, compressed=compressed)
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    try:
        yield origin
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        if not origin.errors.empty():
            raise origin.errors.get_nowait()


@contextmanager
def connect_peer(origin, *, path=None, ca=None, compressed=False):
    stream = socket.socket(socket.AF_UNIX) if path else socket.socket()
    stream.settimeout(5)
    try:
        stream.connect(path if path else origin.server_address)
        if ca:
            if path:
                stream.sendall((f"CONNECT {origin.authority} HTTP/1.1\r\n"
                                f"Host: {origin.authority}\r\n\r\n").encode())
                response, _ = read_head(stream)
                assert response.split()[1] == "200", response
            context = ssl.create_default_context(cafile=ca)
            context.set_alpn_protocols(["http/1.1"])
            stream = context.wrap_socket(stream, server_hostname="127.0.0.1")
        target = "/socket" if ca or not path else f"http://{origin.authority}/socket"
        request = (f"GET {target} HTTP/1.1\r\nHost: {origin.authority}\r\n"
                   "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"
                   f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n"
                   "Sec-WebSocket-Protocol: fixture, another\r\n")
        if compressed:
            request += "Sec-WebSocket-Extensions: permessage-deflate\r\n"
        stream.sendall((request + "\r\n").encode())
        response, headers = read_head(stream)
        assert response.split()[1] == "101", (response, headers)
        assert headers["sec-websocket-accept"] == [
            base64.b64encode(hashlib.sha1((KEY + GUID).encode()).digest()).decode()]
        assert headers["sec-websocket-protocol"] == ["fixture"]
        assert ("sec-websocket-extensions" in headers) == compressed
        yield Peer(stream, client=True, compressed=compressed)
    finally:
        stream.close()


def prepare_tls(directory, tls):
    directory.mkdir(parents=True, exist_ok=True)
    if not tls:
        return None, None, None
    pem, public = origin_certificate(directory)
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    return pem, public, directory / "ca/mitmproxy-ca-cert.pem"


def drain_shutdown(stream):
    """Observe termination after a completed exchange, including an abrupt TLS close."""
    try:
        while stream.recv(8192):
            pass
    except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
        # Historical process shutdown can tear down TLS without close_notify;
        # OpenSSL then reports the closed transport instead of returning EOF.
        # Timeouts and other TLS errors remain failures.
        return


def exchange(origin, *, direction, opcode, payload, control, path=None, ca=None):
    with connect_peer(origin, path=path, ca=ca, compressed=origin.compressed) as peer:
        if direction == "request":
            peer.send(opcode, payload, fragmented=True, control=control)
        observed = peer.receive()
        if observed[0] != 8:
            if direction == "response":
                peer.send(1, b"ack")
            peer.close()
            assert peer.receive() == (8, struct.pack("!H", 1000) + b"fixture complete")
        result, controls = origin.results.get(timeout=5)
        destination = result if direction == "request" else observed
        destination_controls = controls if direction == "request" else peer.controls
        return destination, destination_controls


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("opcode,payload", [(1, TEXT), (2, BINARY)], ids=["text", "binary"])
@pytest.mark.parametrize("compressed,control", [
    (False, None), (False, 9), (False, 10), (True, None), (True, 9), (True, 10),
], ids=["plain", "plain-ping", "plain-pong", "deflate", "deflate-ping", "deflate-pong"])
def test_complete_fragmented_messages(proxy_backend, tmp_path, request, tls, direction,
                                      opcode, payload, compressed, control):
    directory = tmp_path / proxy_backend
    pem, public, proxy_ca = prepare_tls(directory, tls)

    def script(peer, results):
        if direction == "response":
            peer.send(opcode, payload, fragmented=True, control=control)
        result = peer.receive()
        results.put((result, list(peer.controls)))
        if result[0] != 8:
            if direction == "request":
                peer.send(1, b"ack")
            assert peer.receive()[0] == 8
            peer.close()

    with origin_server(script, pem=pem, compressed=compressed) as origin:
        direct, direct_controls = exchange(origin, direction=direction, opcode=opcode, payload=payload,
                                           control=control, ca=public)
        assert direct == (opcode, payload)
        assert control is None or (control, b"control") in direct_controls
        with launch_proxy(proxy_backend, directory, POLICY, tls=tls, upstream_ca=public,
                          inspection={}) as proxy:
            delivered, controls = exchange(origin, direction=direction, opcode=opcode, payload=payload,
                                            control=control, path=proxy.paths["alice"], ca=proxy_ca)
            assert control is None or (control, b"control") in controls
            if proxy_backend == "python" and compressed and control is not None:
                # Captured first without an xfail: all 48 direct specimens
                # passed, and precisely these 16 WS/WSS deliveries failed.
                # Keep setup, handshake and control forwarding outside the
                # expected-failure region; a repaired source must report XPASS.
                request.node.add_marker(pytest.mark.xfail(
                    strict=True, reason="D32: historical wsproto loses compression state across control frames"))
            assert delivered == (opcode, payload)


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
def test_denied_websocket_opens_no_origin_connection(proxy_backend, tmp_path, tls):
    directory = tmp_path / proxy_backend
    _, public, _ = prepare_tls(directory, tls)
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.2)
        authority = f"127.0.0.1:{origin.getsockname()[1]}"
        with launch_proxy(proxy_backend, directory, POLICY, tls=tls, upstream_ca=public) as proxy:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(proxy.paths["bob"])
                target = authority if tls else f"http://{authority}/socket"
                method = "CONNECT" if tls else "GET"
                client.sendall((f"{method} {target} HTTP/1.1\r\nHost: {authority}\r\n"
                                "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                                f"Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
                response, _ = read_head(client)
                assert response.split()[1] == "403"
            with pytest.raises(TimeoutError):
                origin.accept()
            assert proxy.events("proxy.egress") == []


@pytest.mark.parametrize("scheme", ["ws", "wss"])
def test_websocket_schemes_rejected_before_origin_contact(proxy_backend, tmp_path, scheme):
    """HTTP proxy absolute-form uses http/https even when upgrading to WebSocket."""
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.2)
        authority = f"127.0.0.1:{origin.getsockname()[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(proxy.paths["alice"])
                client.sendall((f"GET {scheme}://{authority}/socket HTTP/1.1\r\nHost: {authority}\r\n"
                                "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                                f"Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n"
                                "Sec-WebSocket-Protocol: fixture\r\n\r\n").encode())
                response, _ = read_head(client)
                assert response.split()[1] == "400"
            with pytest.raises(TimeoutError):
                origin.accept()
            assert proxy.events("proxy.egress") == []


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("opcode", [1, 2], ids=["text", "binary"])
@pytest.mark.parametrize("mode", ["block", "log", "opposite", "rule-log"])
def test_scanning_modes_and_compression_dictionary(proxy_backend, tmp_path, tls, direction, opcode, mode):
    """Dropping a complete message must not put its bytes in the outgoing dictionary."""
    directory = tmp_path / proxy_backend
    pem, public, proxy_ca = prepare_tls(directory, tls)
    repeated = (b"dictionary material used by the dropped middle message. " * 50)
    messages = [b"safe-start", b"PROJ-12345 " + repeated, b"safe-after " + repeated]
    expected = [messages[0], messages[2]] if mode == "block" else messages
    policy = POLICY + (PATTERN.replace('action = "block"', 'action = "log"') if mode == "rule-log" else PATTERN)
    block_direction = ("response" if direction == "request" else "request") if mode == "opposite" else direction
    options = {f"block_websocket_{block_direction}": mode != "log"}

    def script(peer, results):
        if direction == "response":
            for payload in messages:
                peer.send(opcode, payload, fragmented=True)
            assert peer.receive() == (1, b"ack")
        else:
            received = []
            while not received or received[-1] != messages[-1]:
                message_type, payload = peer.receive()
                assert message_type == opcode
                received.append(payload)
            results.put(received)
            peer.send(1, b"ack")
        assert peer.receive()[0] == 8
        peer.close()

    with origin_server(script, pem=pem, compressed=True) as origin:
        with launch_proxy(proxy_backend, directory, policy, tls=tls, upstream_ca=public,
                          inspection=options) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"], ca=proxy_ca, compressed=True) as peer:
                if direction == "request":
                    for payload in messages:
                        peer.send(opcode, payload, fragmented=True)
                    assert peer.receive() == (1, b"ack")
                    received = origin.results.get(timeout=5)
                else:
                    received = []
                    while not received or received[-1] != messages[-1]:
                        message_type, payload = peer.receive()
                        assert message_type == opcode
                        received.append(payload)
                    peer.send(1, b"ack")
                peer.close()
                assert peer.receive() == (8, struct.pack("!H", 1000) + b"fixture complete")
                assert received == expected


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
def test_rule_reload_applies_to_an_existing_websocket(proxy_backend, tmp_path, tls):
    directory = tmp_path / proxy_backend
    pem, public, proxy_ca = prepare_tls(directory, tls)

    def script(peer, results):
        while True:
            opcode, payload = peer.receive()
            if opcode == 8:
                peer.close()
                return
            peer.send(opcode, payload)

    with origin_server(script, pem=pem, compressed=True) as origin:
        initial = POLICY + PATTERN.replace("PROJ-[0-9]{5}", "PROJ-99999")
        with launch_proxy(proxy_backend, directory, initial, tls=tls, upstream_ca=public,
                          inspection={"block_websocket_request": True}) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"], ca=proxy_ca, compressed=True) as peer:
                peer.send(1, b"PROJ-12345")
                assert peer.receive() == (1, b"PROJ-12345")
                replacement = directory / "policy.next.toml"
                replacement.write_text(POLICY + PATTERN)
                replacement.replace(directory / "policy.toml")
                if proxy_backend == "rust":
                    proxy.process.send_signal(signal.SIGHUP)
                # The historical LocalPolicyClient really watches file mtimes
                # every 2 seconds. It has no SIGHUP handler. Observe the rule
                # taking effect on this open socket instead of simulating it.
                deadline = time.monotonic() + 6
                while True:
                    peer.send(1, b"PROJ-12345")
                    peer.send(1, b"round-complete")
                    received = []
                    while not received or received[-1] != b"round-complete":
                        opcode, payload = peer.receive()
                        assert opcode == 1
                        received.append(payload)
                    if received == [b"round-complete"]:
                        break
                    assert received == [b"PROJ-12345", b"round-complete"]
                    assert time.monotonic() < deadline, "Edited policy never reached the open WebSocket"
                    time.sleep(0.05)
                assert origin.accepts == 1
                replacement.write_text("[[scan_patterns\n")
                replacement.replace(directory / "policy.toml")
                if proxy_backend == "rust":
                    proxy.process.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 6
                while True:
                    if proxy_backend == "python":
                        rejected = any(row["event"] == "ops.policy_error"
                                       for row in read_events(directory / "audit.jsonl"))
                    else:
                        rejected = "configuration reload failed:" in (directory / "process.log").read_text()
                    if rejected:
                        break
                    assert time.monotonic() < deadline, "Malformed policy was not observed by the loader"
                    time.sleep(0.025)
                peer.send(1, b"PROJ-12345")
                peer.send(1, b"last-good-rule-retained")
                assert peer.receive() == (1, b"last-good-rule-retained")
                peer.close()
                assert peer.receive()[0] == 8


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("compressed", [False, True], ids=["plain", "deflate"])
def test_message_preceding_close_is_delivered(proxy_backend, tmp_path, tls, direction, compressed):
    """One write contains a spill-sized data message immediately followed by Close."""
    directory = tmp_path / proxy_backend
    pem, public, proxy_ca = prepare_tls(directory, tls)
    payload = TEXT * 64
    encoded = payload
    if compressed:
        encoder = zlib.compressobj(wbits=-15)
        encoded = (encoder.compress(payload) + encoder.flush(zlib.Z_SYNC_FLUSH))[:-4]
    close_payload = struct.pack("!H", 1000) + b"fixture complete"

    def wire(masked):
        return (frame(1, encoded, compressed=compressed, masked=masked)
                + frame(8, close_payload, masked=masked))

    def script(peer, results):
        if direction == "response":
            peer.stream.sendall(wire(False))
        else:
            results.put(peer.receive())
        assert peer.receive() == (8, close_payload)
        if direction == "request":
            peer.close()

    with origin_server(script, pem=pem, compressed=compressed) as origin:
        with launch_proxy(proxy_backend, directory, POLICY, tls=tls, upstream_ca=public,
                          inspection={}) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"], ca=proxy_ca, compressed=compressed) as peer:
                if direction == "request":
                    peer.stream.sendall(wire(True))
                else:
                    assert peer.receive() == (1, payload)
                assert peer.receive() == (8, close_payload)
                if direction == "request":
                    assert origin.results.get(timeout=5) == (1, payload)


@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("opcode,payload,code", [(1, b"\xff", 1007), (0, b"orphan", 1002)],
                         ids=["invalid-text", "orphan-continuation"])
def test_protocol_error_close_codes(proxy_backend, tmp_path, direction, opcode, payload, code):
    directory = tmp_path / proxy_backend

    def script(peer, results):
        if direction == "response":
            peer.stream.sendall(frame(opcode, payload))
        results.put(peer.receive())

    with origin_server(script) as origin:
        with launch_proxy(proxy_backend, directory, POLICY, inspection={}) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"]) as peer:
                if direction == "request":
                    peer.stream.sendall(frame(opcode, payload, masked=True))
                for close_opcode, close_payload in [peer.receive(), origin.results.get(timeout=5)]:
                    assert close_opcode == 8
                    assert struct.unpack("!H", close_payload[:2])[0] == code


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
def test_shutdown_closes_open_websocket_peers(proxy_backend, tmp_path, tls):
    directory = tmp_path / proxy_backend
    pem, public, proxy_ca = prepare_tls(directory, tls)

    def script(peer, results):
        assert peer.receive() == (1, b"ready")
        peer.send(1, b"ready")
        drain_shutdown(peer.stream)
        results.put("origin closed")

    with origin_server(script, pem=pem) as origin:
        with launch_proxy(proxy_backend, directory, POLICY, tls=tls, upstream_ca=public,
                          inspection={}) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"], ca=proxy_ca) as peer:
                peer.send(1, b"ready")
                assert peer.receive() == (1, b"ready")
                proxy.process.terminate()
                assert proxy.process.wait(timeout=5) == 0
                drain_shutdown(peer.stream)
                assert origin.results.get(timeout=5) == "origin closed"
                assert not proxy.readiness_file.exists()
                if proxy_backend == "rust":
                    # These events belong to the native migration seam. The
                    # historical focused launcher does not emit WS evidence.
                    # This small-message exchange does not test cancellation
                    # while a CPU-intensive pattern scan is pending.
                    ended = proxy.events("proxy.websocket.end")
                    assert len(ended) == 1
                    assert ended[0]["agent"] == "alice"
                    assert ended[0]["outcome"] == "shutdown"
                    assert ended[0]["drained"] is True


@pytest.fixture
def native_development_proxy(request):
    """Run native implementation lifecycle evidence only when explicitly selected."""
    if "rust" not in request.config.getoption("--proxy-backend"):
        pytest.skip("Native lifecycle evidence requires --proxy-backend rust")
    if not os.path.isdir("/proc/self/task"):
        pytest.skip("Native worker/file lifecycle evidence requires Linux procfs")
    return "rust"


def anonymous_files(pid):
    """Identify live anonymous regular files by inode, independent of descriptor reuse."""
    result = {}
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(descriptor)
            metadata = descriptor.stat()
        except FileNotFoundError:
            # A worker may close its descriptor between enumeration and stat.
            continue
        if target.endswith(" (deleted)") and stat.S_ISREG(metadata.st_mode):
            result[(metadata.st_dev, metadata.st_ino)] = metadata.st_size
    return result


def thread_cpu_seconds(pid):
    """Read cumulative user+system CPU from Linux task stat, without attaching."""
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    result = {}
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            fields = (task / "stat").read_text().rsplit(") ", 1)[1].split()
        except FileNotFoundError:
            # Completed worker threads can disappear while taking a snapshot.
            continue
        # Fields after the parenthesized command start at stat field 3;
        # utime/stime are fields 14/15, hence offsets 11/12 here.
        result[int(task.name)] = (int(fields[11]) + int(fields[12])) / ticks_per_second
    return result


@pytest.mark.parametrize("tls", [False, True], ids=["ws", "wss"])
def test_native_pending_fragment_disconnect(native_development_proxy, tmp_path, tls):
    directory = tmp_path / native_development_proxy
    pem, public, proxy_ca = prepare_tls(directory, tls)

    def script(peer, results):
        observed = peer.receive()
        results.put((observed, peer.data_frames))

    with origin_server(script, pem=pem) as origin:
        with launch_proxy(native_development_proxy, directory, POLICY, tls=tls, upstream_ca=public,
                          inspection={}) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"], ca=proxy_ca) as peer:
                before = anonymous_files(proxy.process.pid)
                payload = b"unfinished binary message " + b"x" * (256 * 1024)
                peer.stream.sendall(frame(2, payload, final=False, masked=True))
                deadline = time.monotonic() + 5
                while True:
                    pending = {inode: size for inode, size in anonymous_files(proxy.process.pid).items()
                               if inode not in before}
                    if pending and max(pending.values()) >= len(payload):
                        break
                    assert time.monotonic() < deadline, "Pending frame never reached an anonymous spool"
                    time.sleep(0.01)
                assert proxy.events("proxy.websocket.message") == []
                peer.stream.close()
                observed, frames = origin.results.get(timeout=5)
                assert observed[0] == 8
                assert frames == 0, "Unfinished message data escaped to the origin"
                deadline = time.monotonic() + 3
                while not proxy.events("proxy.websocket.end"):
                    assert time.monotonic() < deadline, "Disconnected WebSocket did not finish"
                    time.sleep(0.01)
                assert proxy.process.poll() is None
                assert pending.keys().isdisjoint(anonymous_files(proxy.process.pid))
                assert proxy.events("proxy.websocket.message") == []
                ended = proxy.events("proxy.websocket.end")
                assert len(ended) == 1
                assert ended[0]["closed_by_client"] is True
                assert ended[0]["drained"] is True
                (directory / "lifecycle.json").write_text(json.dumps({
                    "pending_spool_bytes": max(pending.values()),
                    "pending_spool_count": len(pending),
                    "pending_spools_retained": 0,
                    "origin_data_frames": frames,
                    "complete_message_events": len(proxy.events("proxy.websocket.message")),
                    "end": ended[0],
                }, indent=2) + "\n")


@pytest.mark.parametrize("trigger", ["peer_close", "shutdown"])
def test_native_running_vm_inspection_cancellation(native_development_proxy, tmp_path, trigger):
    """Cancel an executing backreference VM; opaque regex delegates are outside this proof."""
    directory = tmp_path / native_development_proxy
    close_requested = threading.Event()
    policy = POLICY + '''
[[scan_patterns]]
name = "vm-cancellation"
pattern = '^(a|aa)*\\1$'
target = "request"
scope = ["body"]
action = "log"
'''

    def script(peer, results):
        if trigger == "peer_close":
            assert close_requested.wait(timeout=7), "Test never requested cancellation"
            peer.close()
        observed = peer.receive()
        results.put((observed, peer.data_frames))

    with origin_server(script) as origin:
        with launch_proxy(native_development_proxy, directory, policy, inspection={}) as proxy:
            with connect_peer(origin, path=proxy.paths["alice"]) as peer:
                before = thread_cpu_seconds(proxy.process.pid)
                peer.send(1, b"a" * 4096 + b"b")
                deadline = time.monotonic() + 5
                while True:
                    current = thread_cpu_seconds(proxy.process.pid)
                    running = [thread for thread, seconds in current.items()
                               if seconds - before.get(thread, 0) >= 0.15]
                    if running:
                        break
                    assert proxy.events("proxy.websocket.message") == [], "VM specimen finished before cancellation"
                    assert time.monotonic() < deadline, "No worker executed enough CPU to establish an active scan"
                    time.sleep(0.01)
                assert proxy.events("proxy.websocket.message") == []
                running_cpu = {thread: current[thread] - before.get(thread, 0) for thread in running}
                started = time.monotonic()
                if trigger == "peer_close":
                    close_requested.set()
                else:
                    proxy.process.terminate()
                observed = peer.receive()
                assert observed[0] == 8
                assert struct.unpack("!H", observed[1][:2])[0] == (1000 if trigger == "peer_close" else 1001)
                origin_observed, frames = origin.results.get(timeout=5)
                assert origin_observed[0] == 8
                assert frames == 0
                idle_cpu = {}
                if trigger == "shutdown":
                    assert proxy.process.wait(timeout=3) == 0
                else:
                    deadline = started + 3
                    while not proxy.events("proxy.websocket.end"):
                        assert time.monotonic() < deadline, "Cancelled scan kept the WebSocket alive"
                        time.sleep(0.01)
                    idle_start = thread_cpu_seconds(proxy.process.pid)
                    time.sleep(0.3)
                    idle_end = thread_cpu_seconds(proxy.process.pid)
                    assert proxy.process.poll() is None
                    for thread in running:
                        idle_cpu[thread] = idle_end.get(thread, 0) - idle_start.get(thread, 0)
                        assert idle_cpu[thread] <= 0.03, "VM worker kept executing"
                assert time.monotonic() - started < 3
                ended = proxy.events("proxy.websocket.end")
                assert len(ended) == 1
                assert ended[0]["outcome"] == trigger
                assert ended[0]["drained"] is True
                assert proxy.events("proxy.websocket.message") == []
                (directory / "lifecycle.json").write_text(json.dumps({
                    "trigger": trigger,
                    "worker_cpu_seconds_before_cancel": running_cpu,
                    "worker_cpu_seconds_after_end_over_300ms": idle_cpu,
                    "cancel_and_verification_elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                    "origin_data_frames": frames,
                    "complete_message_events": len(proxy.events("proxy.websocket.message")),
                    "process_returncode": proxy.process.poll(),
                    "end": ended[0],
                }, indent=2) + "\n")
