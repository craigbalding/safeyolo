"""Tests for agent HTTP preview sessions."""

from __future__ import annotations

import http.client
import io
import json
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from safeyolo.commands.agent import agent_app
from safeyolo.config import get_desktop_size
from safeyolo.preview import (
    TOKEN_COOKIE_PREFIX,
    TOKEN_HEADER,
    UNLOCK_PATH,
    PreviewConfig,
    PreviewError,
    build_guest_relay_command,
    build_upstream_request,
    normalize_display_path,
    parse_ttl,
    preferred_vnc_geometry,
    preview_cookie_name,
    preview_token_from_cookie,
    resolve_vnc_geometry,
    sanitize_request_headers,
    serve_agent_preview,
    start_preview_server,
    strip_preview_cookies,
    validate_guest_port,
)
from safeyolo.tailnet import (
    TailnetServeSession,
    start_tailnet_serve,
    validate_tailnet_port,
)
from safeyolo.tailnet import (
    run_tailscale_json as _run_tailscale_json,
)
from safeyolo.tailnet import (
    tailnet_mapping_ready as _tailnet_mapping_ready,
)
from safeyolo.tailnet import (
    tailnet_port_in_use as _tailnet_port_in_use,
)


class NoRelayPlatform:
    def __init__(self):
        self.calls = []

    def popen_binary_in_sandbox(self, name, command, user="agent"):  # noqa: ARG002
        self.calls.append({"name": name, "command": command, "user": user})
        raise AssertionError("relay should not start")


class LocalRelayPlatform:
    def __init__(self):
        self.calls = []

    def popen_binary_in_sandbox(self, name, command, user="agent"):
        self.calls.append({"name": name, "command": command, "user": user})
        return subprocess.Popen(
            ["bash", "-lc", command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )


class HalfCloseSensitiveProcess:
    """Relay double matching gVisor's response-losing stdin half-close."""

    def __init__(self):
        self.stdin = io.BytesIO()
        self.stdout = self.Response(self.stdin)
        self.returncode = 0

    class Response:
        def __init__(self, request):
            self.request = request
            self.response = io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrelay-ok\n")

        def read(self, size=-1):
            if self.request.closed:
                return b""
            return self.response.read(size)

    def poll(self):
        return self.returncode


class HalfCloseSensitivePlatform:
    def __init__(self):
        self.process = None

    def popen_port_forward(self, name, guest_port, user="agent"):  # noqa: ARG002
        self.process = HalfCloseSensitiveProcess()
        return self.process


class FakePlatform:
    def __init__(self, running=True):
        self.running = running
        self.exec_calls = []

    def is_sandbox_running(self, name):
        return self.running

    def exec_in_sandbox(self, name, command, user="agent", interactive=True):
        self.exec_calls.append({"name": name, "command": command, "user": user, "interactive": interactive})
        return 0


class BlockingFakeProcess:
    def __init__(self):
        self.returncode = None
        self.stdout = io.StringIO("")
        self._done = threading.Event()

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15
        self._done.set()

    def kill(self):
        self.returncode = -9
        self._done.set()

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired("tailscale", timeout)
        return self.returncode


class TinyHandler(BaseHTTPRequestHandler):
    last_headers = None
    last_path = ""

    def do_GET(self):
        type(self).last_headers = self.headers
        type(self).last_path = self.path
        body = b"helper-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class ChunkedHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"6\r\nhello \r\n5\r\nthere\r\n0\r\n\r\n")

    def log_message(self, format, *args):
        pass


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _request(server, path, headers=None, method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        response_body = resp.read()
        return resp, response_body
    finally:
        conn.close()


def _recv_until(sock, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class FakeWebSocketUpstream:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.handshake = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.sock.close()

    def _run(self):
        conn, _ = self.sock.accept()
        with conn:
            self.handshake = _recv_until(conn, b"\r\n\r\n")
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            data = conn.recv(4)
            if data == b"ping":
                conn.sendall(b"pong")


def test_parse_ttl():
    assert parse_ttl(None) is None
    assert parse_ttl("30") == 30
    assert parse_ttl("30s") == 30
    assert parse_ttl("10m") == 600
    assert parse_ttl("1h") == 3600


def test_validate_guest_port_rejects_reserved():
    for port in (8080, 9090):
        try:
            validate_guest_port(port)
        except ValueError as exc:
            assert "reserved" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ValueError")


def test_validate_tailnet_port_rejects_out_of_range():
    for port in (0, 65536, True):
        with pytest.raises(ValueError, match="tailnet HTTPS port"):
            validate_tailnet_port(port)


def test_cookie_helpers_strip_preview_token():
    cookie_name = preview_cookie_name(8443)
    cookie = f"session=abc; {cookie_name}=secret; theme=dark"
    assert preview_token_from_cookie(cookie, cookie_name) == "secret"
    assert strip_preview_cookies(cookie) == "session=abc; theme=dark"


def test_preview_cookie_helpers_isolate_ports_and_strip_all_preview_cookies():
    cookie_8443 = preview_cookie_name(8443)
    cookie_8444 = preview_cookie_name(8444)
    raw = f"{cookie_8443}=first; {cookie_8444}=second; app=ok"

    assert cookie_8443 != cookie_8444
    assert preview_token_from_cookie(raw, cookie_8443) == "first"
    assert preview_token_from_cookie(raw, cookie_8444) == "second"
    assert strip_preview_cookies(raw) == "app=ok"


def test_preview_servers_scope_cookies_to_browser_facing_ports():
    local = start_preview_server(
        PreviewConfig(agent="local", guest_port=8000),
        NoRelayPlatform(),
        "local-session",
        "1234-5678",
    )
    tailnet = start_preview_server(
        PreviewConfig(agent="tailnet", guest_port=8001, tailnet_port=8444),
        NoRelayPlatform(),
        "tailnet-session",
        "1234-5678",
    )
    try:
        assert local.token_cookie == preview_cookie_name(local.server_address[1])
        assert tailnet.token_cookie == preview_cookie_name(8444)
        assert local.token_cookie != tailnet.token_cookie
    finally:
        local.server_close()
        tailnet.server_close()


def test_tailnet_status_detects_node_ports_without_counting_services():
    status = {
        "TCP": {"443": {"HTTPS": True}},
        "Foreground": {
            "session-a": {"TCP": {"8443": {"HTTPS": True}}},
        },
        "Services": {
            "svc:other": {"TCP": {"9443": {"HTTPS": True}}},
        },
    }

    assert _tailnet_port_in_use(status, 443)
    assert _tailnet_port_in_use(status, 8443)
    assert not _tailnet_port_in_use(status, 9443)


def test_tailnet_status_matches_exact_foreground_target():
    target = "http://127.0.0.1:54321"
    status = {
        "Foreground": {
            "session-a": {
                "TCP": {"8443": {"HTTPS": True}},
                "Web": {
                    "host.example.ts.net:8443": {
                        "Handlers": {"/": {"Proxy": target}},
                    },
                },
            },
        },
    }

    assert _tailnet_mapping_ready(status, 8443, target)
    assert not _tailnet_mapping_ready(status, 8444, target)
    assert not _tailnet_mapping_ready(status, 8443, "http://127.0.0.1:12345")
    assert not _tailnet_mapping_ready(status, 8443, f"{target[:-1]}")


def test_start_tailnet_serve_uses_foreground_mapping(monkeypatch):
    process = BlockingFakeProcess()
    target = "http://127.0.0.1:54321"
    responses = iter(
        [
            {
                "BackendState": "Running",
                "Self": {"DNSName": "host.example.ts.net."},
            },
            {},
            {
                "Foreground": {
                    "owned-session": {
                        "TCP": {"8443": {"HTTPS": True}},
                        "Web": {
                            "host.example.ts.net:8443": {
                                "Handlers": {"/": {"Proxy": target}},
                            },
                        },
                    },
                },
            },
        ]
    )
    monkeypatch.setattr("safeyolo.tailnet.shutil.which", lambda command: "/usr/bin/tailscale")
    monkeypatch.setattr("safeyolo.tailnet.run_tailscale_json", lambda *args: next(responses))

    with patch("safeyolo.tailnet.subprocess.Popen", return_value=process) as popen:
        session = start_tailnet_serve(54321, 8443)

    assert session.url("/") == "https://host.example.ts.net:8443/"
    command = popen.call_args.args[0]
    assert command == [
        "tailscale",
        "serve",
        "--yes",
        "--https=8443",
        target,
    ]
    assert "--bg" not in command
    assert "funnel" not in command
    assert popen.call_args.kwargs["stdout"].seekable()
    session.close()
    assert process.returncode == -15


def test_start_tailnet_serve_refuses_existing_mapping(monkeypatch):
    responses = iter(
        [
            {
                "BackendState": "Running",
                "Self": {"DNSName": "host.example.ts.net."},
            },
            {"TCP": {"8443": {"HTTPS": True}}},
        ]
    )
    monkeypatch.setattr("safeyolo.tailnet.shutil.which", lambda command: "/usr/bin/tailscale")
    monkeypatch.setattr("safeyolo.tailnet.run_tailscale_json", lambda *args: next(responses))

    with patch("safeyolo.tailnet.subprocess.Popen") as popen, pytest.raises(PreviewError, match="already has"):
        start_tailnet_serve(54321, 8443)

    popen.assert_not_called()


def test_start_tailnet_serve_cleans_process_on_readiness_failure(monkeypatch):
    process = BlockingFakeProcess()
    responses = iter(
        [
            {
                "BackendState": "Running",
                "Self": {"DNSName": "host.example.ts.net."},
            },
            {},
        ]
    )
    monkeypatch.setattr("safeyolo.tailnet.shutil.which", lambda command: "/usr/bin/tailscale")
    monkeypatch.setattr("safeyolo.tailnet.run_tailscale_json", lambda *args: next(responses))
    monkeypatch.setattr("safeyolo.tailnet.TAILSCALE_READY_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr("safeyolo.tailnet.subprocess.Popen", lambda *args, **kwargs: process)

    with pytest.raises(PreviewError, match="did not publish"):
        start_tailnet_serve(54321, 8443)

    assert process.returncode == -15


def test_tailscale_serve_empty_status_accepts_json_null(monkeypatch):
    completed = subprocess.CompletedProcess(
        ["tailscale", "serve", "status", "--json"],
        0,
        stdout="null\n",
        stderr="",
    )
    monkeypatch.setattr("safeyolo.tailnet.subprocess.run", lambda *args, **kwargs: completed)

    assert _run_tailscale_json("serve", "status", "--json") == {}


def test_guest_relay_command_streams_http_response():
    upstream = HTTPServer(("127.0.0.1", 0), TinyHandler)
    _serve(upstream)
    proc = subprocess.Popen(
        ["bash", "-lc", build_guest_relay_command(upstream.server_address[1])],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(
            f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{upstream.server_address[1]}\r\nConnection: close\r\n\r\n".encode()
        )
        proc.stdin.flush()
        proc.stdin.close()
        response = proc.stdout.read()
        assert b"200 OK" in response
        assert b"helper-ok" in response
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()


def test_sanitize_request_headers_strips_preview_authority():
    cookie_name = preview_cookie_name(8443)
    headers = {
        "Host": "127.0.0.1:5000",
        TOKEN_HEADER: "secret",
        "Cookie": f"a=b; {cookie_name}=secret",
        "Connection": "close",
        "Accept": "text/html",
        "Tailscale-User-Login": "operator@example.com",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "preview.example.ts.net:8443",
    }
    out = dict(sanitize_request_headers(headers, 8000))
    assert out["Host"] == "127.0.0.1:8000"
    assert out["Cookie"] == "a=b"
    assert out["Accept"] == "text/html"
    assert TOKEN_HEADER not in out
    assert out["Connection"] == "close"
    assert "Tailscale-User-Login" not in out
    assert "X-Forwarded-Proto" not in out
    assert "X-Forwarded-Host" not in out


def test_preview_server_requires_unlock(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = NoRelayPlatform()
    server = start_preview_server(PreviewConfig(agent="codey", guest_port=8000), platform, "session", "1234-5678")
    _serve(server)
    try:
        resp, body = _request(server, "/")
        assert resp.status == 200
        assert b"Unlock Preview" in body
        assert platform.calls == []
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_unlocks_with_one_time_code(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = NoRelayPlatform()
    server = start_preview_server(PreviewConfig(agent="codey", guest_port=8000), platform, "session", "1234-5678")
    _serve(server)
    try:
        resp, body = _request(
            server,
            UNLOCK_PATH,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": f"127.0.0.1:{server.server_address[1]}",
                "Origin": f"http://127.0.0.1:{server.server_address[1]}",
            },
            body="code=1234-5678",
        )
        assert resp.status == 303
        assert body == b""
        assert resp.getheader("Location") == "/"
        cookie = resp.getheader("Set-Cookie")
        assert f"{server.token_cookie}=session" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie
        assert platform.calls == []

        resp2, body2 = _request(
            server,
            UNLOCK_PATH,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": f"127.0.0.1:{server.server_address[1]}",
                "Origin": f"http://127.0.0.1:{server.server_address[1]}",
            },
            body="code=1234-5678",
        )
        assert resp2.status == 423
        assert b"locked" in body2
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_unlocks_behind_tailnet_https(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        NoRelayPlatform(),
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        resp, _ = _request(
            server,
            UNLOCK_PATH,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": f"127.0.0.1:{server.server_address[1]}",
                "Origin": "https://codey.example.ts.net:8443",
                "X-Forwarded-Host": "codey.example.ts.net:8443",
                "X-Forwarded-Proto": "https",
                "Sec-Fetch-Site": "same-origin",
            },
            body="code=1234-5678",
        )

        assert resp.status == 303
        assert "Secure" in resp.getheader("Set-Cookie")
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_rejects_bad_unlock_and_locks(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = NoRelayPlatform()
    server = start_preview_server(PreviewConfig(agent="codey", guest_port=8000), platform, "session", "1234-5678")
    _serve(server)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": f"127.0.0.1:{server.server_address[1]}",
        "Origin": f"http://127.0.0.1:{server.server_address[1]}",
    }
    try:
        for _ in range(5):
            resp, _ = _request(server, UNLOCK_PATH, method="POST", headers=headers, body="code=wrong")
            assert resp.status == 403
        resp, body = _request(server, UNLOCK_PATH, method="POST", headers=headers, body="code=1234-5678")
        assert resp.status == 423
        assert b"locked" in body
        assert platform.calls == []
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_streams_http_and_strips_preview_cookie(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    upstream = HTTPServer(("127.0.0.1", 0), TinyHandler)
    _serve(upstream)
    platform = LocalRelayPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=upstream.server_address[1]),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        resp, body = _request(
            server,
            "/",
            headers={"Cookie": f"{server.token_cookie}=session; app=ok", TOKEN_HEADER: "session"},
        )
        assert resp.status == 200
        assert body == b"helper-ok"
        assert resp.getheader("X-SafeYolo-Agent") == "codey"
        assert resp.getheader("X-SafeYolo-Preview-Port") == str(upstream.server_address[1])
        assert len(platform.calls) == 1
        assert TinyHandler.last_path == "/"
        assert TinyHandler.last_headers["Host"] == f"127.0.0.1:{upstream.server_address[1]}"
        assert TOKEN_COOKIE_PREFIX not in TinyHandler.last_headers["Cookie"]
        assert TinyHandler.last_headers["Cookie"] == "app=ok"
        assert TOKEN_HEADER not in TinyHandler.last_headers
    finally:
        server.shutdown()
        server.server_close()
        upstream.shutdown()
        upstream.server_close()


def test_preview_server_keeps_relay_write_side_open_until_response(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = HalfCloseSensitivePlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=6080),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        resp, body = _request(server, "/vnc.html", headers={TOKEN_HEADER: "session"})
        assert resp.status == 200
        assert body == b"relay-ok\n"
        assert platform.process is not None
        assert not platform.process.stdin.closed
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_preserves_chunked_response(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    upstream = HTTPServer(("127.0.0.1", 0), ChunkedHandler)
    _serve(upstream)
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=upstream.server_address[1]),
        LocalRelayPlatform(),
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        resp, body = _request(server, "/", headers={"Cookie": f"{server.token_cookie}=session"})
        assert resp.status == 200
        assert resp.getheader("Transfer-Encoding") == "chunked"
        assert body == b"hello there"
    finally:
        server.shutdown()
        server.server_close()
        upstream.shutdown()
        upstream.server_close()


def test_preview_control_paths_are_not_forwarded(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = NoRelayPlatform()
    server = start_preview_server(PreviewConfig(agent="codey", guest_port=8000), platform, "session", "1234-5678")
    _serve(server)
    try:
        resp, body = _request(
            server,
            "/_safeyolo_preview/not-real",
            headers={"Cookie": f"{server.token_cookie}=session"},
        )
        assert resp.status == 404
        assert b"not found" in body
        assert platform.calls == []
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_tunnels_websocket_upgrade(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    upstream = FakeWebSocketUpstream()
    upstream.start()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=upstream.port),
        LocalRelayPlatform(),
        "session",
        "1234-5678",
    )
    _serve(server)
    sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5)
    try:
        sock.sendall(
            (
                "GET /ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{server.server_address[1]}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Cookie: {server.token_cookie}=session; app=ok\r\n"
                f"{TOKEN_HEADER}: session\r\n"
                "\r\n"
            ).encode()
        )
        response = _recv_until(sock, b"\r\n\r\n")
        assert b"101 Switching Protocols" in response
        assert b"X-SafeYolo-Agent: codey" in response
        sock.sendall(b"ping")
        assert sock.recv(4) == b"pong"
    finally:
        sock.close()
        server.shutdown()
        server.server_close()
        upstream.close()

    upstream.thread.join(timeout=5)
    assert upstream.handshake is not None
    assert b"GET /ws HTTP/1.1" in upstream.handshake
    assert f"Host: 127.0.0.1:{upstream.port}".encode() in upstream.handshake
    assert TOKEN_COOKIE_PREFIX.encode() not in upstream.handshake
    assert TOKEN_HEADER.encode() not in upstream.handshake
    assert b"Cookie: app=ok" in upstream.handshake


def test_preview_command_builds_single_agent_config():
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve,
    ):
        result = runner.invoke(
            agent_app,
            ["preview", "codey", "8000", "--host-port", "54321", "--ttl", "30s"],
        )

    assert result.exit_code == 0
    config, platform = mock_serve.call_args.args
    assert platform is fake_platform
    assert config.agent == "codey"
    assert config.guest_port == 8000
    assert config.host_port == 54321
    assert config.ttl_seconds == 30


def test_preview_command_can_start_host_sized_vnc(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr("safeyolo.preview.detect_host_display_size", lambda: (1920, 1080))

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher") as mock_stage,
        patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve,
    ):
        result = runner.invoke(agent_app, ["preview", "codey", "6080", "--start-vnc"])

    assert result.exit_code == 0
    mock_stage.assert_called_once_with("codey", preferred_size="auto")
    assert fake_platform.exec_calls == [
        {
            "name": "codey",
            "command": ("SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start 1760x900"),
            "user": "agent",
            "interactive": False,
        }
    ]
    config, platform = mock_serve.call_args.args
    assert platform is fake_platform
    assert config.guest_port == 6080
    assert config.display_path == "/vnc.html#autoconnect=true&resize=remote"


def test_preview_command_can_start_browser_url(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr("safeyolo.preview.detect_host_display_size", lambda: (1920, 1080))

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher"),
        patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve,
    ):
        result = runner.invoke(
            agent_app,
            ["preview", "codey", "6080", "-b", "https://example.com/a b"],
        )

    assert result.exit_code == 0
    assert fake_platform.exec_calls[0]["command"] == (
        "SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start 1760x900"
        " && /safeyolo/guest-desktop browser 'https://example.com/a b'"
    )
    config, platform = mock_serve.call_args.args
    assert platform is fake_platform
    assert config.display_path == "/vnc.html#autoconnect=true&resize=remote"


def test_preview_command_requires_running_agent():
    runner = CliRunner()

    with (
        patch("safeyolo.platform.get_platform", return_value=FakePlatform(running=False)),
        patch(
            "safeyolo.commands.agent.reserve_agent_tailnet_port_change",
        ) as mock_reserve,
    ):
        result = runner.invoke(agent_app, ["preview", "codey", "8000"])

    assert result.exit_code == 1
    assert "is not running" in result.output
    mock_reserve.assert_not_called()


def test_desktop_command_starts_core_launcher_and_preview(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr("safeyolo.preview.detect_host_display_size", lambda: (1920, 1080))

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher") as mock_stage,
        patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve,
    ):
        result = runner.invoke(
            agent_app,
            ["desktop", "codey", "--open", "--ttl", "15m", "--browser", "https://example.com/a b"],
        )

    assert result.exit_code == 0
    mock_stage.assert_called_once_with("codey", preferred_size="auto")
    assert fake_platform.exec_calls == [
        {
            "name": "codey",
            "command": (
                "SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start 1760x900"
                " && /safeyolo/guest-desktop browser 'https://example.com/a b'"
            ),
            "user": "agent",
            "interactive": False,
        }
    ]
    config, platform = mock_serve.call_args.args
    assert platform is fake_platform
    assert config.agent == "codey"
    assert config.guest_port == 6080
    assert config.ttl_seconds == 900
    assert config.open_browser is True
    assert config.display_path == "/vnc.html#autoconnect=true&resize=remote"


def test_desktop_command_uses_persistent_host_size(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr(
        "safeyolo.config.load_config",
        lambda: {"desktop": {"size": "1280x1246"}},
    )

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher"),
        patch("safeyolo.preview.serve_agent_preview", return_value=0),
    ):
        result = runner.invoke(agent_app, ["desktop", "codey"])

    assert result.exit_code == 0
    assert fake_platform.exec_calls[0]["command"] == (
        "SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start 1280x1246"
    )


def test_desktop_command_explicit_size_overrides_host_preference(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr(
        "safeyolo.config.load_config",
        lambda: {"desktop": {"size": "1280x1246"}},
    )

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher"),
        patch("safeyolo.preview.serve_agent_preview", return_value=0),
    ):
        result = runner.invoke(agent_app, ["desktop", "codey", "--size", "1600x900"])

    assert result.exit_code == 0
    assert fake_platform.exec_calls[0]["command"].endswith("start 1600x900")


def test_desktop_command_remembers_explicit_host_size(tmp_config_dir):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher") as mock_stage,
        patch("safeyolo.preview.serve_agent_preview", return_value=0),
    ):
        result = runner.invoke(
            agent_app,
            [
                "desktop",
                "codey",
                "--size",
                "1280x1246",
                "--remember-size",
            ],
        )

    assert result.exit_code == 0
    config = yaml.safe_load((tmp_config_dir / "config.yaml").read_text())
    assert config["desktop"]["size"] == "1280x1246"
    mock_stage.assert_called_once_with("codey", preferred_size="1280x1246")


def test_desktop_command_remember_requires_explicit_size():
    runner = CliRunner()

    result = runner.invoke(agent_app, ["desktop", "codey", "--remember-size"])

    assert result.exit_code == 2
    assert "requires an explicit --size" in result.output


def test_desktop_command_requires_running_agent():
    runner = CliRunner()

    with patch("safeyolo.platform.get_platform", return_value=FakePlatform(running=False)):
        result = runner.invoke(agent_app, ["desktop", "codey"])

    assert result.exit_code == 1
    assert "Agent 'codey' is not running" in result.output
    assert "safeyolo agent run codey" in result.output


def test_desktop_status_uses_core_launcher_without_preview():
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher"),
        patch("safeyolo.preview.serve_agent_preview") as mock_serve,
    ):
        result = runner.invoke(agent_app, ["desktop", "codey", "--status"])

    assert result.exit_code == 0
    assert fake_platform.exec_calls[0]["command"] == "/safeyolo/guest-desktop status"
    mock_serve.assert_not_called()


def test_desktop_rejects_conflicting_lifecycle_options():
    runner = CliRunner()

    result = runner.invoke(agent_app, ["desktop", "codey", "--status", "--stop"])

    assert result.exit_code == 2
    assert "only one" in result.output


def test_desktop_command_reserves_tailnet_port(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr("safeyolo.preview.detect_host_display_size", lambda: None)

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher"),
        patch(
            "safeyolo.commands.agent.reserve_agent_tailnet_port_change",
            return_value=(8443, None),
        ) as mock_reserve,
        patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve,
    ):
        result = runner.invoke(
            agent_app,
            ["desktop", "codey", "--share", "tailnet"],
        )

    assert result.exit_code == 0
    mock_reserve.assert_called_once_with("codey", None)
    config, platform = mock_serve.call_args.args
    assert platform is fake_platform
    assert config.tailnet_port == 8443


def test_desktop_restores_changed_port_when_preview_start_fails(monkeypatch):
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)
    monkeypatch.setattr("safeyolo.preview.detect_host_display_size", lambda: None)

    with (
        patch("safeyolo.platform.get_platform", return_value=fake_platform),
        patch("safeyolo.commands.agent.stage_guest_desktop_launcher"),
        patch(
            "safeyolo.commands.agent.reserve_agent_tailnet_port_change",
            return_value=(8444, 8443),
        ),
        patch("safeyolo.commands.agent.restore_agent_tailnet_port") as mock_restore,
        patch(
            "safeyolo.preview.serve_agent_preview",
            side_effect=RuntimeError("serve denied"),
        ),
    ):
        result = runner.invoke(
            agent_app,
            ["desktop", "codey", "--share", "tailnet", "--tailnet-port", "8444"],
        )

    assert result.exit_code == 1
    assert "serve denied" in result.output
    mock_restore.assert_called_once_with("codey", 8444, 8443)


def test_desktop_rejects_tailnet_port_with_local_share():
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)

    with patch("safeyolo.platform.get_platform", return_value=fake_platform):
        result = runner.invoke(
            agent_app,
            ["desktop", "codey", "--tailnet-port", "10443"],
        )

    assert result.exit_code == 1
    assert "--tailnet-port requires --share tailnet" in result.output


def test_serve_agent_preview_prints_clean_url(monkeypatch, capsys):
    class FakeServePlatform:
        pass

    class FakeServer:
        server_address = ("127.0.0.1", 54321)

        def serve_forever(self):
            return None

        def server_close(self):
            pass

    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("safeyolo.preview.generate_unlock_code", lambda: "1234-5678")
    monkeypatch.setattr("safeyolo.preview.start_preview_server", lambda *args: FakeServer())

    assert serve_agent_preview(PreviewConfig(agent="codey", guest_port=8000), FakeServePlatform()) == 0

    out = capsys.readouterr().out
    assert "http://127.0.0.1:54321/" in out
    assert "safeyolo_preview_token" not in out
    assert "1234-5678" in out


def test_serve_agent_preview_prints_display_path(monkeypatch, capsys):
    class FakeServePlatform:
        pass

    class FakeServer:
        server_address = ("127.0.0.1", 54321)

        def serve_forever(self):
            return None

        def server_close(self):
            pass

    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("safeyolo.preview.generate_unlock_code", lambda: "1234-5678")
    monkeypatch.setattr("safeyolo.preview.start_preview_server", lambda *args: FakeServer())

    config = PreviewConfig(agent="web", guest_port=6080, display_path="/vnc.html#autoconnect=true&resize=remote")
    assert serve_agent_preview(config, FakeServePlatform()) == 0

    out = capsys.readouterr().out
    assert "http://127.0.0.1:54321/vnc.html#autoconnect=true&resize=remote" in out


def test_serve_agent_preview_uses_and_cleans_tailnet_mapping(monkeypatch, capsys):
    class FakeServePlatform:
        pass

    class FakeServer:
        server_address = ("127.0.0.1", 54321)

        def serve_forever(self):
            return None

        def shutdown(self):
            return None

        def server_close(self):
            return None

    process = BlockingFakeProcess()
    session = TailnetServeSession(
        process=process,
        dns_name="preview.example.ts.net",
        exposed_port=8443,
        target="http://127.0.0.1:54321",
    )
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("safeyolo.preview.generate_unlock_code", lambda: "1234-5678")
    monkeypatch.setattr("safeyolo.preview.start_preview_server", lambda *args: FakeServer())
    monkeypatch.setattr(
        "safeyolo.preview.start_tailnet_serve",
        lambda local_port, exposed_port: session,
    )

    config = PreviewConfig(
        agent="web",
        guest_port=6080,
        display_path="/vnc.html#autoconnect=true&resize=remote",
        tailnet_port=8443,
    )
    assert serve_agent_preview(config, FakeServePlatform()) == 0

    out = capsys.readouterr().out
    assert "Tailnet preview:" in out
    assert "https://preview.example.ts.net:8443/vnc.html" in out
    assert process.returncode == -15


def test_unlock_redirect_uses_display_path(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000, display_path="/vnc.html#autoconnect=true&resize=remote"),
        NoRelayPlatform(),
        "session",
        "1234-5678",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(*server.server_address)
        conn.request(
            "POST",
            UNLOCK_PATH,
            body="code=1234-5678",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": f"{server.server_address[0]}:{server.server_address[1]}",
            },
        )
        response = conn.getresponse()
        response.read()
        assert response.status == 303
        assert response.headers["Location"] == "/vnc.html#autoconnect=true&resize=remote"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_resolve_vnc_geometry_auto_uses_detected_display(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.detect_host_display_size", lambda: (2560, 1440))

    assert resolve_vnc_geometry("auto") == ("2400x1260", (2560, 1440))


def test_get_desktop_size_uses_host_preference(monkeypatch):
    monkeypatch.setattr(
        "safeyolo.config.load_config",
        lambda: {"desktop": {"size": "1280x1246"}},
    )

    assert get_desktop_size(None) == "1280x1246"
    assert get_desktop_size("1600x900") == "1600x900"


def test_resolve_vnc_geometry_accepts_explicit_size():
    assert resolve_vnc_geometry("1600x900") == ("1600x900", None)


def test_preferred_vnc_geometry_falls_back_without_display():
    assert preferred_vnc_geometry(None) == (1280, 800)


def test_normalize_display_path_rejects_absolute_urls():
    assert normalize_display_path("/vnc.html") == "/vnc.html"
    assert normalize_display_path("/vnc.html#autoconnect=true") == "/vnc.html#autoconnect=true"
    assert normalize_display_path("vnc.html") == "/"
    assert normalize_display_path("http://example.test/vnc.html") == "/"


class SlowUpstreamHandler(BaseHTTPRequestHandler):
    """Upstream that pauses before responding, so the client can disconnect first."""

    def do_GET(self):
        import time as _t
        _t.sleep(0.4)
        body = b"slow-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # Expected when the preview relay closed after the client left.

    def log_message(self, format, *args):
        pass


class LargeBodyHandler(BaseHTTPRequestHandler):
    """Upstream that streams a body big enough to see mid-response disconnect."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body_size = 512 * 1024
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(body_size))
        self.end_headers()
        try:
            # Write in 16KB slices so the client has room to close mid-stream.
            written = 0
            chunk = b"a" * 16384
            while written < body_size:
                self.wfile.write(chunk)
                written += len(chunk)
        except OSError:
            pass  # Expected when the client hung up mid-response.

    def log_message(self, format, *args):
        pass


def _raw_request(server, request_bytes: bytes, *, read_bytes: int = 0) -> None:
    """Send a raw HTTP request and close the socket after optionally reading a bit."""
    with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5) as sock:
        sock.sendall(request_bytes)
        if read_bytes > 0:
            try:
                sock.recv(read_bytes)
            except OSError:
                pass


def _capture_events(monkeypatch) -> list[tuple[str, dict]]:
    """Intercept write_event so tests can assert which events actually reached the sink.

    Returns a list of (event, kwargs) tuples that grows as events are emitted.
    """
    captured: list[tuple[str, dict]] = []
    def _record(event, **kwargs):
        captured.append((event, kwargs))
    monkeypatch.setattr("safeyolo.preview.write_event", _record)
    return captured


def _wait_for(condition, *, timeout: float = 6.0, poll: float = 0.05) -> bool:
    """Poll until `condition()` becomes true, or timeout. Returns whether it did."""
    import time as _t
    deadline = _t.monotonic() + timeout
    while _t.monotonic() < deadline:
        if condition():
            return True
        _t.sleep(poll)
    return False


def test_preview_server_survives_client_disconnect_before_response_head(monkeypatch):
    """Client closes the socket before the upstream begins responding.

    Regression: without the fix, the preview handler's outer catch tried to
    send a 502 JSON body on the already-dead socket. That sendall raised a
    second BrokenPipeError inside the except block, so control never reached
    the completion _log_event call. We assert the completion event is present:
    proving the handler unwound cleanly instead of double-faulting.
    """
    events = _capture_events(monkeypatch)
    upstream = HTTPServer(("127.0.0.1", 0), SlowUpstreamHandler)
    _serve(upstream)
    platform = LocalRelayPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=upstream.server_address[1]),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.server_address[1]}\r\n"
            f"Cookie: {cookie}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        _raw_request(server, request)  # peer closes; upstream will respond ~400ms later
        completion_events = {"traffic.preview_response", "traffic.preview_error"}
        # Poll: on master the completion event never arrives because the outer
        # catch double-faults on _send_json. Timeout accommodates the upstream
        # sleep (0.4s) and relay cleanup (up to ~3s).
        arrived = _wait_for(
            lambda: any(name in completion_events for name, _ in events),
            timeout=6.0,
        )
        emitted = [name for name, _ in events]
        assert emitted.count("traffic.preview_request") == 1, emitted
        assert arrived, f"completion event missing (only got {emitted})"
    finally:
        server.shutdown()
        server.server_close()
        upstream.shutdown()
        upstream.server_close()


def test_preview_server_survives_client_disconnect_mid_response(monkeypatch):
    """Client closes after reading a bit of a large response.

    Regression: mid-body sendall raised BrokenPipeError, propagated to the
    outer catch, and the outer catch double-faulted on _send_json. Assertion
    (same shape as the pre-head disconnect test): completion event present.
    """
    events = _capture_events(monkeypatch)
    upstream = HTTPServer(("127.0.0.1", 0), LargeBodyHandler)
    _serve(upstream)
    platform = LocalRelayPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=upstream.server_address[1]),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.server_address[1]}\r\n"
            f"Cookie: {cookie}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        _raw_request(server, request, read_bytes=1024)  # read a bit, then close
        completion_events = {"traffic.preview_response", "traffic.preview_error"}
        arrived = _wait_for(
            lambda: any(name in completion_events for name, _ in events),
            timeout=6.0,
        )
        emitted = [name for name, _ in events]
        assert emitted.count("traffic.preview_request") == 1, emitted
        assert arrived, f"completion event missing (only got {emitted})"
    finally:
        server.shutdown()
        server.server_close()
        upstream.shutdown()
        upstream.server_close()


def test_preview_server_survives_broken_audit_sink(monkeypatch):
    """write_event failures must not take down request handling.

    Regression: an unwrapped write_event(...) in _log_event could raise
    (disk full, log rotation race, permissions regression), taking down
    the request thread and cascading into a double-fault when the outer
    error handler tried to log its own event.
    """
    def broken_write_event(*args, **kwargs):
        raise OSError("simulated audit sink failure")
    monkeypatch.setattr("safeyolo.preview.write_event", broken_write_event)
    upstream = HTTPServer(("127.0.0.1", 0), TinyHandler)
    _serve(upstream)
    platform = LocalRelayPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=upstream.server_address[1]),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie})
        assert resp.status == 200
        assert body == b"helper-ok"
    finally:
        server.shutdown()
        server.server_close()
        upstream.shutdown()
        upstream.server_close()


class _RacyProc:
    """Popen-shape whose terminate/kill/wait race with the process's own exit.

    Not a MagicMock: this is a minimal fake that models one specific race
    (ProcessLookupError / ChildProcessError from post-exit wait). Real
    subprocess.Popen cannot be coerced into this behavior reliably in a test.
    """

    def __init__(self, *, wait_error: type[Exception] = ProcessLookupError):
        self.stdin = None
        self.stdout = None
        self.returncode = None
        self._wait_error = wait_error
        self.terminated = False
        self.killed = False

    def poll(self):
        return None  # Appears alive even though it just exited.

    def wait(self, timeout=None):
        raise self._wait_error(3, "No such process")

    def terminate(self):
        self.terminated = True
        raise ProcessLookupError(3, "No such process")

    def kill(self):
        self.killed = True
        raise ProcessLookupError(3, "No such process")


def test_close_relay_tolerates_dead_process():
    """_close_relay must not raise if the relay process exited while we were closing it.

    Regression: an unhandled OSError from terminate/kill/wait would propagate
    through _proxy_stream's finally clause and mask the real exception that
    caused us to be tearing down in the first place.
    """
    from safeyolo.preview import PreviewRequestHandler

    handler = PreviewRequestHandler.__new__(PreviewRequestHandler)
    # subprocess.TimeoutExpired path: wait times out, terminate raises ESRCH.
    handler._close_relay(_RacyProc(wait_error=subprocess.TimeoutExpired))
    # Post-exit path: wait itself raises because the child is already reaped.
    handler._close_relay(_RacyProc(wait_error=ChildProcessError))
    handler._close_relay(_RacyProc(wait_error=ProcessLookupError))


class _RaisingTailnetSession:
    """TailnetServeSession stand-in whose close() raises.

    Not a MagicMock; models one exact failure: close() blowing up during
    shutdown (zombie tailscale process, /tmp cleanup race, etc).
    """

    def __init__(self, *, dns_name: str = "preview.example.ts.net", port: int = 8443):
        self.dns_name = dns_name
        self.exposed_port = port
        self.closing = False
        self.close_called = False

        class _Proc:
            returncode = None
            def poll(self):
                return None
            def wait(self, timeout=None):  # noqa: ARG002
                return 0
        self.process = _Proc()

    def url(self, display_path: str = "/") -> str:
        return f"https://{self.dns_name}:{self.exposed_port}{display_path}"

    def close(self) -> None:
        self.close_called = True
        raise RuntimeError("simulated tailnet close failure")

    def read_output(self) -> str:
        return ""


class _FakeServer:
    """Minimal serve_agent_preview target with observable close hook."""

    def __init__(self, *, close_raises: bool = False):
        self.server_address = ("127.0.0.1", 54321)
        self.close_raises = close_raises
        self.server_close_called = False

    def serve_forever(self):
        return None

    def shutdown(self):
        return None

    def server_close(self):
        self.server_close_called = True
        if self.close_raises:
            raise RuntimeError("simulated server_close failure")


def test_serve_agent_preview_still_closes_server_when_tailnet_close_raises(monkeypatch):
    """A raise from tailnet_session.close() must not skip server_close or the audit event.

    Regression: the old finally was a straight-line sequence; the first raise
    skipped every subsequent step, leaking the server socket and dropping
    the agent.preview_close event.
    """
    events: list[str] = []
    monkeypatch.setattr(
        "safeyolo.preview.write_event",
        lambda event, **kwargs: events.append(event),
    )
    monkeypatch.setattr("safeyolo.preview.generate_unlock_code", lambda: "1234-5678")
    fake_server = _FakeServer()
    monkeypatch.setattr("safeyolo.preview.start_preview_server", lambda *a: fake_server)
    session = _RaisingTailnetSession()
    monkeypatch.setattr(
        "safeyolo.preview.start_tailnet_serve",
        lambda local_port, exposed_port: session,
    )

    config = PreviewConfig(agent="web", guest_port=6080, tailnet_port=8443)
    assert serve_agent_preview(config, object()) == 0
    assert session.close_called, "tailnet close should have been attempted"
    assert fake_server.server_close_called, "server_close was skipped by the raising tailnet close"
    assert "agent.preview_close" in events, f"preview_close event dropped: {events}"


def test_serve_agent_preview_still_writes_close_event_when_server_close_raises(monkeypatch):
    """A raise from server.server_close() must not skip the audit event."""
    events: list[str] = []
    monkeypatch.setattr(
        "safeyolo.preview.write_event",
        lambda event, **kwargs: events.append(event),
    )
    monkeypatch.setattr("safeyolo.preview.generate_unlock_code", lambda: "1234-5678")
    fake_server = _FakeServer(close_raises=True)
    monkeypatch.setattr("safeyolo.preview.start_preview_server", lambda *a: fake_server)

    config = PreviewConfig(agent="codey", guest_port=8000)
    assert serve_agent_preview(config, object()) == 0
    assert fake_server.server_close_called
    assert "agent.preview_close" in events, f"preview_close event dropped: {events}"


def _run_preview_in_subprocess(tmp_path, *, guest_port: int):
    """Start serve_agent_preview in a real subprocess.

    The runner script monkeypatches write_event to append names to an
    events file, and touches a `ready` file when agent.preview_open is
    emitted. This lets the test wait deterministically without polling
    for stdout parsing.
    """
    import sys as _sys
    events_file = tmp_path / "events.log"
    ready_file = tmp_path / "ready"
    exit_file = tmp_path / "exit_code"
    runner = tmp_path / "runner.py"
    runner.write_text(
        "import sys\n"
        f"import safeyolo.preview as p\n"
        f"events_path = {str(events_file)!r}\n"
        f"ready_path = {str(ready_file)!r}\n"
        f"exit_path = {str(exit_file)!r}\n"
        "def _capture(event, **_kw):\n"
        "    with open(events_path, 'a') as f:\n"
        "        f.write(event + '\\n')\n"
        "    if event == 'agent.preview_open':\n"
        "        with open(ready_path, 'w') as f:\n"
        "            f.write('go')\n"
        "p.write_event = _capture\n"
        "class Plat:\n"
        "    def popen_binary_in_sandbox(self, name, command, user='agent'):\n"
        "        raise AssertionError('no relay expected')\n"
        f"cfg = p.PreviewConfig(agent='sigtest', guest_port={guest_port})\n"
        "code = p.serve_agent_preview(cfg, Plat())\n"
        "with open(exit_path, 'w') as f:\n"
        "    f.write(str(code))\n"
    )
    proc = subprocess.Popen(
        [_sys.executable, str(runner)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, events_file, ready_file


def _wait_for_file(path, *, timeout: float = 5.0) -> bool:
    import time as _t
    deadline = _t.monotonic() + timeout
    while _t.monotonic() < deadline:
        if path.exists():
            return True
        _t.sleep(0.05)
    return False


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGHUP"])
def test_serve_agent_preview_cleans_up_on_signal(tmp_path, signame):
    """Real subprocess, real signal, real HTTP server.

    Regression: only SIGINT (KeyboardInterrupt) was caught. SIGTERM or SIGHUP
    killed the process mid serve_forever, leaking the Tailscale Serve
    mapping and dropping the agent.preview_close event. Now the signal
    handler shuts down the server from a background thread so the finally
    clause runs cleanly.
    """
    import os as _os
    import signal as _signal
    sig = getattr(_signal, signame, None)
    if sig is None:
        pytest.skip(f"{signame} not available on this platform")

    proc, events_file, ready_file = _run_preview_in_subprocess(tmp_path, guest_port=8000)
    try:
        assert _wait_for_file(ready_file, timeout=5.0), "preview did not open"
        _os.kill(proc.pid, sig)
        exit_code = proc.wait(timeout=5.0)
        assert exit_code == 0, f"expected clean exit, got {exit_code}"
        emitted = events_file.read_text().splitlines() if events_file.exists() else []
        assert "agent.preview_open" in emitted, emitted
        assert "agent.preview_close" in emitted, emitted
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)


class _RelayFailPlatform:
    """Platform whose port-forward call raises a chosen exception.

    Used to verify _open_guest_relay converts raw platform errors into
    PreviewError with an actionable message, rather than letting the raw
    class name land in the 502 body.
    """

    def __init__(self, *, exc: Exception):
        self._exc = exc

    def popen_port_forward(self, name, guest_port, user="agent"):  # noqa: ARG002
        raise self._exc


class _RelayFailPlatformNoPortForward:
    """Same as _RelayFailPlatform but exercises the popen_binary_in_sandbox arm."""

    def __init__(self, *, exc: Exception):
        self._exc = exc

    def popen_binary_in_sandbox(self, name, command, user="agent"):  # noqa: ARG002
        raise self._exc


def test_open_guest_relay_reports_agent_stopped_clearly(monkeypatch):
    """RuntimeError from the port-forward call becomes an actionable 502."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = _RelayFailPlatform(exc=RuntimeError("runsc port-forward exited 1: container 'codey' not found"))
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie})
        assert resp.status == 502
        payload = json.loads(body)
        detail = payload.get("detail", "")
        # Actionable: mentions the agent name and hints at the sandbox.
        assert "codey" in detail, detail
        assert "reach" in detail or "sandbox" in detail or "not accepting" in detail, detail
    finally:
        server.shutdown()
        server.server_close()


def test_open_guest_relay_reports_relay_binary_missing_clearly(monkeypatch):
    """FileNotFoundError from popen_binary_in_sandbox becomes an actionable 502."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = _RelayFailPlatformNoPortForward(
        exc=FileNotFoundError(2, "No such file or directory: 'runsc'"),
    )
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie})
        assert resp.status == 502
        detail = json.loads(body).get("detail", "")
        assert "missing" in detail or "not found" in detail.lower(), detail
    finally:
        server.shutdown()
        server.server_close()


def test_open_guest_relay_reports_permission_denied(monkeypatch):
    """PermissionError from the platform becomes an actionable 502.

    "Permission denied" is already in str(exc) for PermissionError, so
    that string alone doesn't discriminate the fix from master. We check
    for the added context ("platform") that only PR4's rewrap adds.
    """
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    platform = _RelayFailPlatform(exc=PermissionError(13, "Permission denied"))
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie})
        assert resp.status == 502
        detail = json.loads(body).get("detail", "")
        assert "platform" in detail.lower(), detail
        assert "denied" in detail.lower(), detail
    finally:
        server.shutdown()
        server.server_close()


def test_build_upstream_request_rejects_non_latin1_header_value():
    """A non-latin-1 header value must produce a PreviewError, not a raw traceback.

    RFC 7230 forbids non-latin-1 in header field values; hitting this means
    a client sent an out-of-spec header (or a guest is trying to smuggle
    one through). The old code would raise UnicodeEncodeError deep inside
    _proxy_stream and rely on the outer catch to report the class name.
    """
    class _Headers:
        """Minimum header container matching what BaseHTTPRequestHandler exposes."""
        def items(self):
            return [
                ("X-Fine", "ok"),
                ("X-Snowman", "hello ☃"),  # non-latin-1
            ]
        def get(self, name, default=""):
            return default
        def __iter__(self):
            return iter([k for k, _ in self.items()])

    with pytest.raises(PreviewError) as excinfo:
        build_upstream_request(
            method="GET",
            path="/",
            version="HTTP/1.1",
            headers=_Headers(),
            guest_port=8000,
            is_upgrade=False,
        )
    assert "non-latin-1" in str(excinfo.value)


def test_serve_agent_preview_reports_broken_browser_launcher(monkeypatch, capsys):
    """webbrowser.open failure must not abort the preview.

    Regression: webbrowser.open ran before serve_forever; if it raised
    (headless host, broken $BROWSER, xdg-open missing), the preview never
    started.
    """
    events: list[str] = []
    monkeypatch.setattr(
        "safeyolo.preview.write_event",
        lambda event, **kwargs: events.append(event),
    )
    monkeypatch.setattr("safeyolo.preview.generate_unlock_code", lambda: "1234-5678")
    fake_server = _FakeServer()
    monkeypatch.setattr("safeyolo.preview.start_preview_server", lambda *a: fake_server)

    def broken_open(url):  # noqa: ARG001
        raise RuntimeError("no browser available on this host")
    monkeypatch.setattr("safeyolo.preview.webbrowser.open", broken_open)

    config = PreviewConfig(agent="codey", guest_port=8000, open_browser=True)
    assert serve_agent_preview(config, object()) == 0
    err = capsys.readouterr().err
    assert "Could not open browser" in err, err
    # Preview still opened and closed successfully.
    assert "agent.preview_open" in events
    assert "agent.preview_close" in events


# ---------------------------------------------------------------------------
# Silent retry + waiting room for restarting-app case
# ---------------------------------------------------------------------------


def _refused_exc(agent: str = "codey") -> RuntimeError:
    """Reproduce the exact runsc stderr signature the bug report shows."""
    return RuntimeError(
        f"runsc port-forward exited 128: doStream: PortForward: "
        f"port forwarding to sandbox: creating netstack port forward "
        f"connection: connecting endpoint: connection was refused "
        f"(agent={agent})",
    )


class _RefusedThenOKPlatform:
    """Refuses the first `fail_count` calls, then returns a fake OK process.

    Models the 'app restarted mid-request' scenario: the port-forward
    briefly refuses until the app rebinds the port, then succeeds. The
    silent-retry loop should ride through the transient refuseds.
    """

    def __init__(self, fail_count: int, ok_process):
        self.fail_count = fail_count
        self.ok_process = ok_process
        self.attempts = 0

    def popen_port_forward(self, name, guest_port, user="agent"):  # noqa: ARG002
        self.attempts += 1
        if self.attempts <= self.fail_count:
            raise _refused_exc(agent=name)
        return self.ok_process


class _AlwaysRefusedPlatform:
    """Every port-forward attempt raises the ECONNREFUSED signature."""

    def __init__(self):
        self.attempts = 0

    def popen_port_forward(self, name, guest_port, user="agent"):  # noqa: ARG002
        self.attempts += 1
        raise _refused_exc(agent=name)


class _StubUpstreamProcess:
    """Minimal Popen-alike that returns a small valid HTTP response."""

    def __init__(self, response_bytes: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(response_bytes)
        self.returncode = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):  # noqa: ARG002
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass


def _fast_retry(monkeypatch, window=0.5, interval=0.05):
    """Shrink the retry constants so tests finish in a few seconds, not
    tens of seconds. Default window is deliberately half a second — long
    enough that nested/compounded retry loops become visible (the
    countdown-oscillation bug hid at sub-second windows because both
    loops finished almost instantly)."""
    monkeypatch.setattr("safeyolo.preview.PREVIEW_SILENT_RETRY_WINDOW_SECONDS", window)
    monkeypatch.setattr("safeyolo.preview.PREVIEW_SILENT_RETRY_INTERVAL_SECONDS", interval)


def test_is_upstream_refused_matches_runsc_signature():
    """The specific runsc ECONNREFUSED phrasing must trigger the retry path."""
    from safeyolo.preview import _is_upstream_refused

    assert _is_upstream_refused(_refused_exc())
    assert _is_upstream_refused(RuntimeError("blah: connection refused blah"))
    # Different failures must not match.
    assert not _is_upstream_refused(RuntimeError("runsc port-forward exited 1: container not found"))
    assert not _is_upstream_refused(FileNotFoundError("runsc"))
    assert not _is_upstream_refused(PermissionError("denied"))


def test_prefers_html_negotiation():
    """Browser navigation prefers HTML; JSON/XHR/`*/*` does not."""
    from safeyolo.preview import _prefers_html

    assert _prefers_html("text/html,application/xhtml+xml,*/*;q=0.9")
    assert _prefers_html("text/html")
    assert not _prefers_html("*/*")
    assert not _prefers_html("application/json")
    assert not _prefers_html("")


def test_silent_retry_rides_through_transient_eager_refused(monkeypatch):
    """First few port-forward attempts refuse eagerly (Popen raises
    RuntimeError), next one succeeds → no waiting-room. Companion to
    test_lazy_eof_recovers_within_silent_window which covers the
    lazy failure shape."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch, window=1.0, interval=0.01)

    upstream = _StubUpstreamProcess()
    platform = _RefusedThenOKPlatform(fail_count=3, ok_process=upstream)
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie})
        assert resp.status == 200
        assert body == b"ok"
        assert platform.attempts >= 4  # 3 refuseds + 1 success
        # No waiting-room marker on the successful response.
        assert resp.getheader("X-SafeYolo-Waiting-Room") is None
    finally:
        server.shutdown()
        server.server_close()


def test_waiting_room_html_served_when_html_client_and_refused_beyond_window(monkeypatch):
    """Browser navigation past the silent window → 200 + waiting-room HTML."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch)

    platform = _AlwaysRefusedPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(
            server,
            "/",
            headers={
                "Cookie": cookie,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
            },
        )
        assert resp.status == 200
        assert resp.getheader("X-SafeYolo-Waiting-Room") == "1"
        assert resp.getheader("Content-Type", "").startswith("text/html")
        # Must contain the agent name, the port, and JS that polls.
        text = body.decode()
        assert "codey" in text
        assert "8000" in text
        assert "fetch(" in text
        assert 'http-equiv="refresh"' in text  # JS-off fallback
        # Silent-retry loop ran at least once before giving up.
        assert platform.attempts >= 1
    finally:
        server.shutdown()
        server.server_close()


def test_503_served_for_non_html_client_when_refused_beyond_window(monkeypatch):
    """XHR/JSON client past the silent window → 503 + Retry-After + JSON body."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch)

    platform = _AlwaysRefusedPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(
            server,
            "/api/status",
            headers={"Cookie": cookie, "Accept": "application/json"},
        )
        assert resp.status == 503
        assert resp.getheader("Retry-After") == "2"
        assert resp.getheader("X-SafeYolo-Waiting-Room") == "1"
        payload = json.loads(body)
        assert payload.get("error") == "upstream not ready"
        assert "codey" in payload.get("detail", "")
    finally:
        server.shutdown()
        server.server_close()


def test_non_refused_error_still_becomes_immediate_502(monkeypatch):
    """Regression: non-ECONNREFUSED errors must NOT enter the silent-retry path.

    'Container not found' (agent stopped, wrong id, etc.) is a real
    problem the operator needs to see fast — the waiting-room would
    mask it and stall the browser instead of surfacing the fault.
    """
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch, window=10.0, interval=1.0)  # long window; must not be entered

    class _NotFoundPlatform:
        attempts = 0

        def popen_port_forward(self, name, guest_port, user="agent"):  # noqa: ARG002
            self.attempts += 1
            raise RuntimeError("runsc port-forward exited 1: container 'codey' not found")

    platform = _NotFoundPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie, "Accept": "text/html"})
        assert resp.status == 502
        assert resp.getheader("X-SafeYolo-Waiting-Room") is None
        # Exactly one attempt: no retry loop.
        assert platform.attempts == 1
        payload = json.loads(body)
        assert "not found" in payload.get("detail", "")
    finally:
        server.shutdown()
        server.server_close()


class _LazyEOFPlatform:
    """popen returns a fake proc whose stdout reads empty (EOF) before headers.

    Reproduces the macOS failure mode: SSH+socat inside the sandbox
    succeeds at Popen time but fails when the guest port has no
    listener. The failure surfaces as "preview relay closed before
    response headers" from read_http_response_head.
    """

    def __init__(self):
        self.attempts = 0

    def popen_binary_in_sandbox(self, name, command, user="agent"):  # noqa: ARG002
        self.attempts += 1
        return _StubUpstreamProcess(response_bytes=b"")  # empty → EOF before headers


class _LazyEOFThenOKPlatform:
    """First N popens return empty-response procs (EOF before headers);
    subsequent popens return a working proc. Models the app-restart case
    where the port comes back mid-retry."""

    def __init__(self, fail_count: int, ok_response: bytes):
        self.fail_count = fail_count
        self.ok_response = ok_response
        self.attempts = 0

    def popen_binary_in_sandbox(self, name, command, user="agent"):  # noqa: ARG002
        self.attempts += 1
        if self.attempts <= self.fail_count:
            return _StubUpstreamProcess(response_bytes=b"")
        return _StubUpstreamProcess(response_bytes=self.ok_response)


def test_lazy_eof_beyond_silent_window_serves_waiting_room(monkeypatch):
    """macOS-style: Popen succeeds, stdout is EOF immediately. Silent-retry
    then waiting-room, same as the eager Linux path.

    Regression for the live-test failure — the observed traceback ended in
    read_http_response_head raising 'preview relay closed before response
    headers'. This routes that specific failure through the retry loop and
    ultimately into the waiting-room UI, matching what the eager
    RuntimeError path does.
    """
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch)

    platform = _LazyEOFPlatform()
    server = start_preview_server(
        PreviewConfig(agent="claude", guest_port=3000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(
            server,
            "/",
            headers={"Cookie": cookie, "Accept": "text/html,*/*;q=0.9"},
        )
        assert resp.status == 200
        assert resp.getheader("X-SafeYolo-Waiting-Room") == "1"
        assert resp.getheader("Content-Type", "").startswith("text/html")
        assert "claude" in body.decode()
        assert platform.attempts >= 2  # more than one attempt during silent retry
    finally:
        server.shutdown()
        server.server_close()


def test_lazy_eof_recovers_within_silent_window(monkeypatch):
    """Lazy-EOF platform recovers mid-silent-retry → real response, no waiting-room."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch, window=1.0, interval=0.01)

    platform = _LazyEOFThenOKPlatform(
        fail_count=3,
        ok_response=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    )
    server = start_preview_server(
        PreviewConfig(agent="claude", guest_port=3000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(server, "/", headers={"Cookie": cookie})
        assert resp.status == 200
        assert body == b"hello"
        assert resp.getheader("X-SafeYolo-Waiting-Room") is None
        assert platform.attempts >= 4  # 3 EOFs + 1 real
    finally:
        server.shutdown()
        server.server_close()


def test_lazy_eof_returns_503_for_non_html_client(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch)

    platform = _LazyEOFPlatform()
    server = start_preview_server(
        PreviewConfig(agent="claude", guest_port=3000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, body = _request(
            server, "/api/x",
            headers={"Cookie": cookie, "Accept": "application/json"},
        )
        assert resp.status == 503
        assert resp.getheader("Retry-After") == "2"
        assert json.loads(body).get("error") == "upstream not ready"
    finally:
        server.shutdown()
        server.server_close()


def test_waiting_room_poll_skips_silent_retry(monkeypatch):
    """Requests carrying X-SafeYolo-Waiting-Room-Poll:1 must not sit in
    the server-side silent-retry loop.

    Regression for the live-macOS demo: the waiting-room JS polls the
    same URL every ~1s. Without this signal each poll blocked for
    PREVIEW_SILENT_RETRY_WINDOW_SECONDS server-side, making the
    countdown UI oscillate (60 → 55 → 60 → 55) instead of counting
    down smoothly.

    Assertion: with the poll header set and the platform always
    refusing, the total request time is well under the silent-retry
    window — proof that the retry loop was skipped.
    """
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    # Silent window deliberately long so the assertion is meaningful.
    monkeypatch.setattr("safeyolo.preview.PREVIEW_SILENT_RETRY_WINDOW_SECONDS", 2.0)
    monkeypatch.setattr("safeyolo.preview.PREVIEW_SILENT_RETRY_INTERVAL_SECONDS", 0.5)

    platform = _AlwaysRefusedPlatform()
    server = start_preview_server(
        PreviewConfig(agent="claude", guest_port=3000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        import time as _time
        t0 = _time.monotonic()
        resp, _body = _request(
            server, "/",
            headers={
                "Cookie": cookie,
                "Accept": "text/html",
                "X-SafeYolo-Waiting-Room-Poll": "1",
            },
        )
        elapsed = _time.monotonic() - t0
        # Waiting room still served (server had nothing to relay).
        assert resp.status == 200
        assert resp.getheader("X-SafeYolo-Waiting-Room") == "1"
        # But we did NOT sit in the 2s silent-retry loop.
        assert elapsed < 1.0, f"poll blocked for {elapsed:.2f}s — silent retry did not skip"
        # Exactly one port-forward attempt for the fast-fail poll.
        assert platform.attempts == 1
    finally:
        server.shutdown()
        server.server_close()


def test_websocket_upgrade_gets_503_not_waiting_room(monkeypatch):
    """WS upgrades never see the waiting-room — a stalled upgrade is worse than a fast fail."""
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    _fast_retry(monkeypatch)

    platform = _AlwaysRefusedPlatform()
    server = start_preview_server(
        PreviewConfig(agent="codey", guest_port=8000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        resp, _body = _request(
            server,
            "/ws",
            headers={
                "Cookie": cookie,
                "Accept": "text/html",  # browser navigation would normally get HTML
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert resp.status == 503
        assert resp.getheader("Retry-After") == "2"
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Invariant regression guards for bugs we hit in live macOS testing
# ---------------------------------------------------------------------------


def test_total_wall_time_bounded_by_single_silent_window(monkeypatch):
    """Guard against nested/compounded retry loops.

    The countdown-oscillation bug was caused by _open_guest_relay
    running its own silent-retry loop unaware of the outer loop in
    _proxy_stream — each request effectively consumed 2× the silent
    window. Assertion: total wall-time ≤ 1.5× window even under a
    long window where compounding would be obvious. Any future
    refactor that accidentally re-nests retry loops trips this.
    """
    import time as _time

    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("safeyolo.preview.PREVIEW_SILENT_RETRY_WINDOW_SECONDS", 1.0)
    monkeypatch.setattr("safeyolo.preview.PREVIEW_SILENT_RETRY_INTERVAL_SECONDS", 0.1)

    platform = _AlwaysRefusedPlatform()
    server = start_preview_server(
        PreviewConfig(agent="claude", guest_port=3000),
        platform,
        "session",
        "1234-5678",
    )
    _serve(server)
    try:
        cookie = f"{server.token_cookie}=session"
        t0 = _time.monotonic()
        resp, _body = _request(
            server, "/",
            headers={"Cookie": cookie, "Accept": "text/html"},
        )
        elapsed = _time.monotonic() - t0
        assert resp.status == 200  # waiting-room served
        assert elapsed < 1.5, (
            f"total request took {elapsed:.2f}s > 1.5× silent window (1.0s) — "
            "retry loops compounded (nested?)"
        )
    finally:
        server.shutdown()
        server.server_close()


def test_open_guest_relay_does_exactly_one_attempt():
    """Lock in the single-attempt semantic of _open_guest_relay.

    Any silent-retry now lives in _proxy_stream so poll requests
    (X-SafeYolo-Waiting-Room-Poll) can bypass it cleanly. If a future
    change re-adds an inner retry loop, the poll-header fast-fail
    would silently break and the countdown-oscillation bug would
    return.

    Uses a zero-length silent window so the outer loop also does
    exactly one attempt; the resulting single-attempt count is the
    intersection of BOTH loops being disciplined.
    """
    from safeyolo.preview import _UpstreamRefused

    with patch(
        "safeyolo.preview.PREVIEW_SILENT_RETRY_WINDOW_SECONDS", 0.0,
    ):
        platform = _AlwaysRefusedPlatform()
        server = start_preview_server(
            PreviewConfig(agent="claude", guest_port=3000),
            platform,
            "session",
            "1234-5678",
        )
        _serve(server)
        try:
            cookie = f"{server.token_cookie}=session"
            resp, _body = _request(
                server, "/",
                headers={"Cookie": cookie, "Accept": "text/html"},
            )
            # Waiting-room served (window == 0 → immediate)
            assert resp.status == 200
            assert resp.getheader("X-SafeYolo-Waiting-Room") == "1"
            # Exactly one port-forward attempt — no nesting on either loop.
            assert platform.attempts == 1
        finally:
            server.shutdown()
            server.server_close()
    # Suppress unused-import warning for _UpstreamRefused (it documents
    # the raise semantics of _open_guest_relay for the reader).
    assert _UpstreamRefused.__name__ == "_UpstreamRefused"


def test_waiting_room_html_carries_poll_header_name():
    """Drift check: the JS in the waiting-room template must send the
    same poll header that the server special-cases for fast-fail.

    Renaming WAITING_ROOM_POLL_HEADER without updating the HTML
    template silently breaks the fast-fail path — the countdown
    starts oscillating again in production and no server-side
    unit test would notice.
    """
    from safeyolo.preview import (
        WAITING_ROOM_POLL_HEADER,
        _render_waiting_room_html,
    )

    html = _render_waiting_room_html(
        agent="claude", guest_port=3000, timeout_seconds=60,
    )
    # The header name must appear in the JS.
    assert WAITING_ROOM_POLL_HEADER in html, (
        f"waiting-room HTML doesn't reference {WAITING_ROOM_POLL_HEADER} — "
        "server's poll fast-fail path can't fire"
    )
    # And it must be inside a fetch() call, not just a stray string.
    assert "fetch(" in html
    # Sanity: the meta-refresh should NOT be short (would compete with JS poll).
    # Timeout=60 → meta-refresh interval should be ≥ 30 (JS-off fallback only).
    import re
    refreshes = re.findall(r'http-equiv="refresh" content="(\d+)"', html)
    assert refreshes, "waiting-room HTML lost its meta-refresh JS-off fallback"
    for interval in refreshes:
        assert int(interval) >= 30, (
            f"meta-refresh interval {interval}s competes with the 1s JS poll — "
            "countdown will oscillate"
        )
