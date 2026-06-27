"""Tests for agent HTTP preview sessions."""

from __future__ import annotations

import base64
import http.client
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from typer.testing import CliRunner

from safeyolo.commands.agent import agent_app
from safeyolo.preview import (
    TOKEN_COOKIE,
    TOKEN_HEADER,
    TOKEN_QUERY_PARAM,
    PreviewConfig,
    build_guest_helper_command,
    parse_ttl,
    preview_token_from_cookie,
    sanitize_request_headers,
    start_preview_server,
    strip_preview_cookie,
    strip_query_token,
    validate_guest_port,
)


class FakeBridge:
    def __init__(self):
        self.calls = []

    def request(self, *, method, path, headers, body):
        self.calls.append({"method": method, "path": path, "headers": headers, "body": body})
        return {
            "status": 200,
            "headers": [["Content-Type", "text/plain"], ["Connection", "close"]],
            "body_b64": base64.b64encode(b"hello from preview").decode(),
        }


class FakePlatform:
    def __init__(self, running=True):
        self.running = running

    def is_sandbox_running(self, name):
        return self.running


class TinyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"helper-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _request(server, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        return resp, body
    finally:
        conn.close()


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


def test_strip_query_token_preserves_other_params():
    path, token = strip_query_token("/assets/app.css?x=1&safeyolo_preview_token=secret&y=2")
    assert path == "/assets/app.css?x=1&y=2"
    assert token == "secret"


def test_cookie_helpers_strip_preview_token():
    cookie = f"session=abc; {TOKEN_COOKIE}=secret; theme=dark"
    assert preview_token_from_cookie(cookie) == "secret"
    assert strip_preview_cookie(cookie) == "session=abc; theme=dark"


def test_guest_helper_command_keeps_stdin_for_request_frames():
    upstream = HTTPServer(("127.0.0.1", 0), TinyHandler)
    _serve(upstream)
    proc = subprocess.Popen(
        ["bash", "-lc", build_guest_helper_command(upstream.server_address[1])],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None
        req = {
            "method": "GET",
            "path": "/",
            "headers": {"Host": f"127.0.0.1:{upstream.server_address[1]}"},
            "body_b64": "",
        }
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        resp = json.loads(line)
        assert resp["status"] == 200
        assert base64.b64decode(resp["body_b64"]) == b"helper-ok"
        assert proc.poll() is None
    finally:
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
    out = sanitize_request_headers(headers, 8000)
    assert out["Host"] == "127.0.0.1:8000"
    assert out["Cookie"] == "a=b"
    assert out["Accept"] == "text/html"
    assert TOKEN_HEADER not in out
    assert "Connection" not in out


def test_preview_server_requires_token(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    bridge = FakeBridge()
    server = start_preview_server(PreviewConfig(agent="codey", guest_port=8000), bridge, "secret")
    _serve(server)
    try:
        resp, body = _request(server, "/")
        assert resp.status == 401
        assert b"preview token required" in body
        assert bridge.calls == []
    finally:
        server.shutdown()
        server.server_close()


def test_preview_server_forwards_only_bound_session(monkeypatch):
    monkeypatch.setattr("safeyolo.preview.write_event", lambda *args, **kwargs: None)
    bridge = FakeBridge()
    server = start_preview_server(PreviewConfig(agent="codey", guest_port=8000), bridge, "secret")
    _serve(server)
    try:
        resp, body = _request(server, f"/?{TOKEN_QUERY_PARAM}=secret")
        assert resp.status == 200
        assert body == b"hello from preview"
        assert resp.getheader("X-SafeYolo-Agent") == "codey"
        assert resp.getheader("X-SafeYolo-Preview-Port") == "8000"
        cookie = resp.getheader("Set-Cookie")
        assert TOKEN_COOKIE in cookie
        assert "SameSite=Strict" in cookie
        assert bridge.calls[0]["path"] == "/"
        assert bridge.calls[0]["headers"]["Host"] == "127.0.0.1:8000"

        resp2, body2 = _request(server, "/asset.css", headers={"Cookie": cookie.split(";", 1)[0]})
        assert resp2.status == 200
        assert body2 == b"hello from preview"
        assert bridge.calls[1]["path"] == "/asset.css"
    finally:
        server.shutdown()
        server.server_close()


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


def test_preview_command_requires_running_agent():
    runner = CliRunner()

    with patch("safeyolo.platform.get_platform", return_value=FakePlatform(running=False)):
        result = runner.invoke(agent_app, ["preview", "codey", "8000"])

    assert result.exit_code == 1
    assert "is not running" in result.output
