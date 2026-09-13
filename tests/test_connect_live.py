"""Real mitmproxy admission: zero upstream accepts on denial, and usable tunnels.

All destinations are ephemeral loopback test servers inside the test process.
No host service or external destination is probed.
"""

import base64
import hashlib
import http.client
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), OriginHandler)
        self.accepts = 0
        self.requests = []

    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        return result


class OriginHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        line = self.rfile.readline()
        if line == b"raw-hello\n":
            self.wfile.write(b"raw-reply\n")
            return
        headers = {}
        while (header := self.rfile.readline()) not in (b"\r\n", b"\n", b""):
            name, value = header.decode().split(":", 1)
            headers[name.lower()] = value.strip()
        self.server.requests.append(line)
        if "sec-websocket-key" in headers:
            key = headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            accept = base64.b64encode(hashlib.sha1(key.encode()).digest())
            self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            frame = self.rfile.read(2)
            mask = self.rfile.read(4)
            data = self.rfile.read(frame[1] & 127)
            unmasked = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
            self.wfile.write(bytes([0x81, len(unmasked)]) + unmasked)
        else:
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")


@pytest.fixture
def origin():
    server = Origin()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def proxy(tmp_path, effect, *, raw=False, strategy="lazy", inner_deny=False, allowed_port=None):
    repo = Path(__file__).resolve().parents[1]
    policy = {"permissions": [
        *([{"action": "network:request", "resource": "*", "effect": "deny", "condition": {"method": "POST"}}] if inner_deny else []),
        {"action": "network:request", "resource": "*", "effect": effect or "allow"},
    ]}
    if allowed_port is not None:
        policy["permissions"] = [
            {"action": "network:request", "resource": "127.0.0.1/*", "effect": "allow", "condition": {"port": allowed_port}},
            {"action": "network:request", "resource": "*", "effect": "deny"},
        ]
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(json.dumps(policy))
    script = tmp_path / "connect_addons.py"
    script.write_text('''
from pdp import PolicyClientConfig, configure_policy_client
from safeyolo.mitm_addons.network_guard import NetworkGuard
from safeyolo.mitm_addons.request_id import RequestIdGenerator
''' + (f"configure_policy_client(PolicyClientConfig(baseline_path={str(policy_path)!r}))\n" if effect else "") + '''
addons = [RequestIdGenerator(), NetworkGuard()]
''')
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(repo / "cli/src"), str(repo)])
    env["SAFEYOLO_LOG_PATH"] = str(tmp_path / "audit.jsonl")
    command = [str(Path(sys.executable).with_name("mitmdump")), "-s", str(script),
               "--listen-host", "127.0.0.1", "--listen-port", str(port),
               "--set", f"confdir={tmp_path / 'ca'}", "--set", "flow_detail=0",
               "--set", f"connection_strategy={strategy}", "--set", "ssl_insecure=true"]
    if raw:
        command += ["--tcp-hosts", "127\\.0\\.0\\.1"]
    with (tmp_path / "proxy.log").open("w+") as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, (tmp_path / "proxy.log").read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "proxy readiness deadline expired"
                    time.sleep(0.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.mark.parametrize("effect,status", [("deny", 403), ("prompt", 428), (None, 403)])
@pytest.mark.parametrize("strategy", ["lazy", "eager"])
def test_denied_connect_never_opens_upstream(tmp_path, origin, effect, status, strategy):
    with proxy(tmp_path, effect, strategy=strategy) as port:
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        client.request("CONNECT", f"127.0.0.1:{origin.server_address[1]}", headers={"X-SafeYolo-Trace": "1"})
        response = client.getresponse()
        assert response.status == status
        assert response.getheader("X-Blocked-By") == "network-guard"
        assert response.getheader("X-SafeYolo-Request-Id").startswith("req-")
        assert json.loads(response.read())
        client.close()
    assert origin.accepts == 0
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    decisions = [event for event in events if event.get("event") == "security.network_guard"]
    assert decisions
    assert decisions[-1]["details"]["method"] == "CONNECT"
    assert decisions[-1]["details"]["port"] == origin.server_address[1]


def test_allowed_raw_tunnel_exchanges_bytes(tmp_path, origin):
    with proxy(tmp_path, "allow", raw=True, allowed_port=origin.server_address[1]) as port:
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        client.set_tunnel("127.0.0.1", origin.server_address[1])
        client.connect()
        client.sock.sendall(b"raw-hello\n")
        assert client.sock.recv(100) == b"raw-reply\n"
        client.close()
    assert origin.accepts == 1


@pytest.mark.parametrize("websocket", [False, True])
def test_allowed_https_and_wss_exchange(tmp_path, origin, websocket):
    # A locally generated CA is also sufficient as this isolated origin cert.
    from mitmproxy.certs import CertStore

    CertStore.from_store(tmp_path / "origin-ca", "origin", 2048)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(tmp_path / "origin-ca/origin-ca.pem")
    origin.socket = server_tls.wrap_socket(origin.socket, server_side=True)
    with proxy(tmp_path, "allow", allowed_port=origin.server_address[1]) as port:
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        client.set_tunnel("127.0.0.1", origin.server_address[1])
        client.connect()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        client.sock = tls.wrap_socket(client.sock, server_hostname="localhost")
        headers = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="} if websocket else {}
        client.request("GET", "/ws" if websocket else "/", headers=headers)
        response = client.getresponse()
        if websocket:
            assert response.status == 101
            client.sock.sendall(b"\x81\x85\x00\x00\x00\x00hello")
            assert response.fp.read(7) == b"\x81\x05hello"
        else:
            assert response.status == 200
            assert response.read() == b"hello"
        client.close()
    assert origin.requests


def test_inner_http_is_still_evaluated(tmp_path, origin):
    with proxy(tmp_path, "allow", inner_deny=True) as port:
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        client.set_tunnel("127.0.0.1", origin.server_address[1])
        client.connect()
        client.request("POST", "/denied")
        response = client.getresponse()
        assert response.status == 403
        assert response.getheader("X-Blocked-By") == "network-guard"
        response.read()
        client.close()
    assert origin.requests == []


@pytest.mark.parametrize("method", ["GET", "CONNECT"])
def test_endpoint_permission_does_not_open_other_port(tmp_path, origin, method):
    # Reserve an allowed port that differs from the observed denied origin.
    with socket.socket() as allowed:
        allowed.bind(("127.0.0.1", 0))
        with proxy(tmp_path, "allow", allowed_port=allowed.getsockname()[1]) as port:
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            target = f"127.0.0.1:{origin.server_address[1]}"
            client.request(method, target if method == "CONNECT" else f"http://{target}/")
            response = client.getresponse()
            assert response.status == 403
            response.read()
            client.close()
    assert origin.accepts == 0
