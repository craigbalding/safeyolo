"""Tests for agent HTTP preview sessions."""

from __future__ import annotations

import http.client
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from typer.testing import CliRunner

from safeyolo.commands.agent import agent_app
from safeyolo.preview import (
    TOKEN_COOKIE,
    TOKEN_HEADER,
    UNLOCK_PATH,
    PreviewConfig,
    build_guest_relay_command,
    normalize_display_path,
    parse_ttl,
    preferred_vnc_geometry,
    preview_token_from_cookie,
    resolve_vnc_geometry,
    sanitize_request_headers,
    serve_agent_preview,
    start_preview_server,
    strip_preview_cookie,
    validate_guest_port,
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


class FakePlatform:
    def __init__(self, running=True):
        self.running = running
        self.exec_calls = []

    def is_sandbox_running(self, name):
        return self.running

    def exec_in_sandbox(self, name, command, user="agent", interactive=True):
        self.exec_calls.append({"name": name, "command": command, "user": user, "interactive": interactive})
        return 0


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
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"\r\n"
            )
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


def test_cookie_helpers_strip_preview_token():
    cookie = f"session=abc; {TOKEN_COOKIE}=secret; theme=dark"
    assert preview_token_from_cookie(cookie) == "secret"
    assert strip_preview_cookie(cookie) == "session=abc; theme=dark"


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
    headers = {
        "Host": "127.0.0.1:5000",
        TOKEN_HEADER: "secret",
        "Cookie": f"a=b; {TOKEN_COOKIE}=secret",
        "Connection": "close",
        "Accept": "text/html",
    }
    out = dict(sanitize_request_headers(headers, 8000))
    assert out["Host"] == "127.0.0.1:8000"
    assert out["Cookie"] == "a=b"
    assert out["Accept"] == "text/html"
    assert TOKEN_HEADER not in out
    assert out["Connection"] == "close"


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
        assert f"{TOKEN_COOKIE}=session" in cookie
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
            headers={"Cookie": f"{TOKEN_COOKIE}=session; app=ok", TOKEN_HEADER: "session"},
        )
        assert resp.status == 200
        assert body == b"helper-ok"
        assert resp.getheader("X-SafeYolo-Agent") == "codey"
        assert resp.getheader("X-SafeYolo-Preview-Port") == str(upstream.server_address[1])
        assert len(platform.calls) == 1
        assert TinyHandler.last_path == "/"
        assert TinyHandler.last_headers["Host"] == f"127.0.0.1:{upstream.server_address[1]}"
        assert TOKEN_COOKIE not in TinyHandler.last_headers["Cookie"]
        assert TinyHandler.last_headers["Cookie"] == "app=ok"
        assert TOKEN_HEADER not in TinyHandler.last_headers
    finally:
        server.shutdown()
        server.server_close()
        upstream.shutdown()
        upstream.server_close()


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
        resp, body = _request(server, "/", headers={"Cookie": f"{TOKEN_COOKIE}=session"})
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
            headers={"Cookie": f"{TOKEN_COOKIE}=session"},
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
                f"Cookie: {TOKEN_COOKIE}=session; app=ok\r\n"
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
    assert TOKEN_COOKIE.encode() not in upstream.handshake
    assert TOKEN_HEADER.encode() not in upstream.handshake
    assert b"Cookie: app=ok" in upstream.handshake


def test_preview_command_builds_single_agent_config():
    runner = CliRunner()
    fake_platform = FakePlatform(running=True)

    with patch("safeyolo.platform.get_platform", return_value=fake_platform), \
         patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve:
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

    with patch("safeyolo.platform.get_platform", return_value=fake_platform), \
         patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve:
        result = runner.invoke(agent_app, ["preview", "codey", "6080", "--start-vnc"])

    assert result.exit_code == 0
    assert fake_platform.exec_calls == [
        {
            "name": "codey",
            "command": (
                "port_open() { (exec 3<>/dev/tcp/127.0.0.1/$1) >/dev/null 2>&1; }; "
                "command -v startvnc >/dev/null 2>&1 || "
                "{ echo 'startvnc not found; use an agent rootfs with the noVNC helper' >&2; exit 127; }; "
                "if port_open 6080; then "
                "echo 'noVNC already running in the agent on 127.0.0.1:6080'; "
                "else "
                "SAFEYOLO_PREVIEW_MANAGED=1 startvnc 1760x900; "
                "fi"
            ),
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

    with patch("safeyolo.platform.get_platform", return_value=fake_platform), \
         patch("safeyolo.preview.serve_agent_preview", return_value=0) as mock_serve:
        result = runner.invoke(
            agent_app,
            ["preview", "codey", "6080", "-b", "https://example.com/a b"],
        )

    assert result.exit_code == 0
    assert "if port_open 9222; then" in fake_platform.exec_calls[0]["command"]
    assert "http://127.0.0.1:9222/json/new?https%3A%2F%2Fexample.com%2Fa%20b" in fake_platform.exec_calls[0]["command"]
    assert "setsid chrome 'https://example.com/a b'" in fake_platform.exec_calls[0]["command"]
    config, platform = mock_serve.call_args.args
    assert platform is fake_platform
    assert config.display_path == "/vnc.html#autoconnect=true&resize=remote"


def test_preview_command_requires_running_agent():
    runner = CliRunner()

    with patch("safeyolo.platform.get_platform", return_value=FakePlatform(running=False)):
        result = runner.invoke(agent_app, ["preview", "codey", "8000"])

    assert result.exit_code == 1
    assert "is not running" in result.output


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


def test_resolve_vnc_geometry_accepts_explicit_size():
    assert resolve_vnc_geometry("1600x900") == ("1600x900", None)


def test_preferred_vnc_geometry_falls_back_without_display():
    assert preferred_vnc_geometry(None) == (1280, 800)


def test_normalize_display_path_rejects_absolute_urls():
    assert normalize_display_path("/vnc.html") == "/vnc.html"
    assert normalize_display_path("/vnc.html#autoconnect=true") == "/vnc.html#autoconnect=true"
    assert normalize_display_path("vnc.html") == "/"
    assert normalize_display_path("http://example.test/vnc.html") == "/"
