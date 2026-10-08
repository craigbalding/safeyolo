"""Focused tests for the installed native blackbox lane's owned parent."""

import http.client
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit

from tests.blackbox.harness.native_parent_config import current, current_ca, restore, select

HARNESS = Path(__file__).parent / "blackbox" / "harness"


def test_native_parent_selection_restores_config_after_interruption(tmp_path):
    """Prior CA and parent survive interruption; unrelated edits remain intact."""
    data = tmp_path / "data"
    data.mkdir()
    config = tmp_path / "config.toml"
    original_ca = tmp_path / "original-ca.pem"
    original_ca.write_text("original-ca\n")
    test_ca = tmp_path / "test-ca.pem"
    test_ca.write_text("test-ca\n")
    config.write_text('parent_proxy = "http://original:8080"\nupstream_ca_file = "original-ca.pem"\n')
    config.chmod(0o600)
    assert current(tmp_path) == "http://original:8080"
    assert current_ca(tmp_path) == str(original_ca)
    select(tmp_path, "http://127.0.0.1:17777", test_ca)
    trust = data / "native-parent-trust.pem"
    selected = tomlkit.parse(config.read_text())
    assert selected['parent_proxy'] == "http://127.0.0.1:17777"
    assert selected['upstream_ca_file'] == str(trust)
    assert trust.read_text() == "original-ca\n\ntest-ca\n"
    selected['admin_port'] = 12345
    config.write_text(selected.as_string())
    restore(tmp_path)
    restored = tomlkit.parse(config.read_text())
    assert restored['parent_proxy'] == "http://original:8080"
    assert restored['upstream_ca_file'] == "original-ca.pem"
    assert restored['admin_port'] == 12345
    assert config.stat().st_mode & 0o777 == 0o600
    assert not (data / "native-parent-original.json").exists()
    assert not trust.exists()


def test_native_parent_failed_ca_selection_restores_and_preserves_later_parent_edit(tmp_path):
    (tmp_path / 'data').mkdir()
    config = tmp_path / 'config.toml'
    config.write_text('admin_port = 9090\n')
    import pytest
    with pytest.raises(OSError):
        select(tmp_path, 'http://selected:8080', tmp_path / 'missing-ca')
    assert config.read_text() == 'admin_port = 9090\n'
    test_ca = tmp_path / 'test-ca'
    test_ca.write_text('test-ca')
    select(tmp_path, 'http://selected:8080', test_ca)
    selected = tomlkit.parse(config.read_text())
    selected['parent_proxy'] = 'http://operator-edit:8081'
    config.write_text(selected.as_string())
    restore(tmp_path)
    restored = tomlkit.parse(config.read_text())
    assert restored['parent_proxy'] == 'http://operator-edit:8081'
    assert 'upstream_ca_file' not in restored


def test_native_parent_routes_synthetic_http_and_connect_but_chains_other_hosts(tmp_path):
    """Owned test destinations stay local; ordinary destinations use the prior parent."""
    received = []

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.path, self.headers.get("Host")))
            if self.path == "/ws":
                self.send_response(101)
                self.send_header("Connection", "Upgrade")
                self.send_header("Upgrade", "websocket")
                self.end_headers()
                self.connection.sendall(self.connection.recv(64))
                return
            body = b"owned-origin-marker"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(self.request.recv(64))

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    tunnel = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    threads = [threading.Thread(target=server.serve_forever) for server in (origin, upstream, tunnel)]
    for thread in threads:
        thread.start()
    port_file = tmp_path / "parent.port"
    environment = {
        **os.environ,
        "SAFEYOLO_SINKHOLE_HTTP_PORT": str(origin.server_address[1]),
        "SAFEYOLO_SINKHOLE_HTTPS_PORT": str(tunnel.server_address[1]),
    }
    process = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(HARNESS / "sinkhole_parent.py"),
                "--port-file",
                str(port_file),
                "--parent",
                f"http://127.0.0.1:{upstream.server_address[1]}",
            ],
            env=environment,
        )
        deadline = time.monotonic() + 5
        while not port_file.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert process.poll() is None and port_file.exists()
        parent_port = int(port_file.read_text())

        connection = http.client.HTTPConnection("127.0.0.1", parent_port, timeout=5)
        connection.request("GET", "http://httpbin.org/get?marker=one", headers={"Host": "httpbin.org"})
        response = connection.getresponse()
        assert (response.status, response.read()) == (200, b"owned-origin-marker")
        connection.close()
        assert received[-1] == ("/get?marker=one", "httpbin.org")

        connection = http.client.HTTPConnection("127.0.0.1", parent_port, timeout=5)
        connection.request("GET", "http://other.test/item", headers={"Host": "other.test"})
        response = connection.getresponse()
        assert (response.status, response.read()) == (200, b"owned-origin-marker")
        connection.close()
        assert received[-1] == ("http://other.test/item", "other.test")

        with socket.create_connection(("127.0.0.1", parent_port), timeout=5) as client:
            client.sendall(b"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n")
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                head.extend(client.recv(1))
            assert head.startswith(b"HTTP/1.1 200 ")
            client.sendall(b"tunnel-marker")
            assert client.recv(64) == b"tunnel-marker"

        with socket.create_connection(("127.0.0.1", parent_port), timeout=5) as client:
            client.sendall(
                b"GET http://httpbin.org/ws HTTP/1.1\r\nHost: httpbin.org\r\n"
                b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                head.extend(client.recv(1))
            assert head.startswith((b"HTTP/1.1 101 ", b"HTTP/1.0 101 "))
            client.sendall(b"ws-marker")
            assert client.recv(64) == b"ws-marker"
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=5)
        for server in (origin, upstream, tunnel):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
