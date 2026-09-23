"""Production Python proxy must reject a streamed header credential before egress."""

from __future__ import annotations

import fcntl
import json
import os
import pty
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.proxy_migration.harness import REPO

_LARGE_BODY = 12 * 1024 * 1024
_SMALL_BODY = 2 * 1024 * 1024
_FORBIDDEN = "key-forbidden"


class _Origin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.accepts = 0
        self.body_bytes = 0
        self.authorizations = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _OriginHandler)

    def get_request(self):
        connection = super().get_request()
        with self.lock:
            self.accepts += 1
        return connection


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        with self.server.lock:
            self.server.authorizations.append(self.headers.get("Authorization"))
        remaining = int(self.headers["Content-Length"])
        while remaining:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            with self.server.lock:
                self.server.body_bytes += len(chunk)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")


@contextmanager
def _origin():
    server = _Origin()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextmanager
def _production_proxy(tmp_path: Path):
    config = tmp_path / "config"
    data = config / "data"
    logs = tmp_path / "logs"
    coord = tmp_path / "coord"
    socket_root = tempfile.TemporaryDirectory(prefix="sy-credential-stream-")
    listener = Path(socket_root.name) / "10.0.0.2_alice"
    for directory in (config, data, logs, coord, listener, config / "services"):
        directory.mkdir(parents=True)
    shutil.copyfile(REPO / "config/addons.yaml", config / "addons.yaml")
    (config / "policy.toml").write_text(
        'budget = 60000\n[hosts]\n"*" = { egress = "allow", unknown_credentials = "deny" }\n'
        '[[credential_rules]]\nname = "synthetic"\npatterns = ["key-[a-z]+"]\n'
        'allowed_hosts = ["example.invalid"]\nheader_names = ["authorization"]\n'
        '[addons.credential_guard]\nuse_default_credential_rules = false\n'
    )
    for name in ("agent_token", "admin_token", "web_password"):
        token_file = data / name
        token_file.touch(mode=0o600)
        token_file.write_text("synthetic-test-token\n")
    (data / "agent_map.json").write_text(json.dumps({"alice": {"ip": "10.0.0.2"}}))
    settings = {"root": str(tmp_path), "admin_port": _port(), "web_port": _port()}
    (tmp_path / "settings.json").write_text(json.dumps(settings))
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("SAFEYOLO_") or name in {
            "MITMPROXY_LOG_PATH", "CREDGUARD_HMAC_SECRET", "NETWORK_GUARD_BLOCK",
            "CREDGUARD_BLOCK", "PATTERN_BLOCK", "TEST_CONTEXT_BLOCK",
        }:
            env.pop(name)
    env.update({
        "PYTHONPATH": os.pathsep.join((str(REPO / "cli/src"), str(REPO))),
        "SAFEYOLO_CONFIG_DIR": str(config),
        "SAFEYOLO_DATA_DIR": str(data),
        "SAFEYOLO_LOGS_DIR": str(logs),
        "SAFEYOLO_LOG_PATH": str(logs / "audit.jsonl"),
        "MITMPROXY_LOG_PATH": str(logs / "mitmproxy.log"),
        "SAFEYOLO_COORD_DATA_DIR": str(coord),
        "SAFEYOLO_PROXY_PID_FILE": str(tmp_path / "ready"),
        "SAFEYOLO_DEFER_PROXY_READY": "1",
        "SAFEYOLO_INITIAL_MODES": json.dumps([f"unix:{listener / 'proxy.sock'}"]),
        "SAFEYOLO_WEB_PASSWORD_FILE": str(data / "web_password"),
        "SAFEYOLO_VIA_TOKEN": "fixture-credential-stream",
        "SAFEYOLO_DEV_MODE": "1",
        "SAFEYOLO_DEV_SOURCE_ROOTS": json.dumps({
            "pdp": str(REPO / "pdp"), "safeyolo": str(REPO / "cli/src/safeyolo"),
        }),
        "TERM": "xterm-256color",
    })
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
    process = subprocess.Popen(
        [sys.executable, "-m", "tests.proxy_migration.full_production", "--launch-config", str(tmp_path / "settings.json")],
        env=env, cwd=REPO, stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
    )
    os.close(slave)
    output = bytearray()

    def drain():
        while True:
            try:
                data = os.read(master, 16384)
            except OSError:
                return
            if not data:
                return
            output.extend(data)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        deadline = time.monotonic() + 30
        while not (tmp_path / "ready").exists():
            assert process.poll() is None, output[-3000:].decode(errors="replace")
            assert time.monotonic() < deadline, output[-3000:].decode(errors="replace")
            time.sleep(0.03)
        yield listener / "proxy.sock", logs / "audit.jsonl"
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        reader.join(timeout=2)
        socket_root.cleanup()


def _send_head(proxy: Path, port: int, *, size: int, credential: str | None, path: str, expect: bool = False):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(str(proxy))
    headers = [
        f"POST http://127.0.0.1:{port}{path} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        f"Content-Length: {size}",
        "Connection: close",
    ]
    if credential:
        headers.append(f"Authorization: Bearer {credential}")
    if expect:
        headers.append("Expect: 100-continue")
    client.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
    return client


def _response(client: socket.socket):
    raw = bytearray()
    while True:
        try:
            chunk = client.recv(65536)
        except ConnectionResetError:
            break
        if not chunk:
            break
        raw.extend(chunk)
        if b"\r\n\r\n" in raw:
            head, body = bytes(raw).split(b"\r\n\r\n", 1)
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    if len(body) >= int(line.split(b":", 1)[1].strip()):
                        return int(raw.split(b" ", 2)[1]), bytes(raw)
    return int(raw.split(b" ", 2)[1]), bytes(raw)


def _audit(audit_path: Path, path: str):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if audit_path.exists():
            rows = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
            responses = [
                row for row in rows
                if row.get("event") == "traffic.response" and row.get("details", {}).get("path") == path
            ]
            if responses:
                matches = [
                    row for row in rows
                    if row.get("event") == "security.credential_guard"
                    and row.get("request_id") == responses[-1].get("request_id")
                ]
                if matches:
                    return matches[-1]
        time.sleep(0.03)
    raise AssertionError(f"missing credential audit for {path}")


def test_production_python_denies_streamed_credential_before_origin(tmp_path):
    with _origin() as origin, _production_proxy(tmp_path) as (proxy, audit_path):
        observations = {}
        port = origin.server_address[1]
        client = _send_head(proxy, port, size=_LARGE_BODY, credential=_FORBIDDEN, path="/denied-large")
        try:
            time.sleep(0.25)
            assert origin.accepts == 0, "denied request head reached the origin"
            status, raw = _response(client)
            assert status == 403, raw[:500]
            assert b"X-Blocked-By: credential-guard" in raw
            assert origin.accepts == 0
            assert origin.body_bytes == 0
            assert not origin.authorizations
            observations["denied_large"] = {
                "status": status, "origin_accepts": origin.accepts,
                "origin_body_bytes": origin.body_bytes, "origin_authorizations": len(origin.authorizations),
                "client_body_bytes_sent": 0,
            }
        finally:
            client.close()
        deny = _audit(audit_path, "/denied-large")
        assert deny["decision"] == "deny", deny
        assert f"X-SafeYolo-Request-Id: {deny['request_id']}".encode() in raw

        client = _send_head(
            proxy, port, size=_LARGE_BODY, credential=_FORBIDDEN,
            path="/denied-expect", expect=True,
        )
        try:
            status, raw = _response(client)
            assert status == 403, raw[:500]
            assert b"100 Continue" not in raw
            assert origin.accepts == 0
            observations["denied_expect"] = {"status": status, "origin_accepts": origin.accepts}
        finally:
            client.close()
        assert _audit(audit_path, "/denied-expect")["decision"] == "deny"

        client = _send_head(proxy, port, size=_SMALL_BODY, credential=_FORBIDDEN, path="/denied-buffered")
        try:
            client.settimeout(0.2)
            with pytest.raises(TimeoutError):
                client.recv(1)
            client.settimeout(5)
            assert origin.accepts == 0
            client.sendall(b"a" * _SMALL_BODY)
            status, _ = _response(client)
            assert status == 403
            assert origin.accepts == 0
            observations["denied_buffered"] = {"status": status, "origin_accepts": origin.accepts}
        finally:
            client.close()
        assert _audit(audit_path, "/denied-buffered")["decision"] == "deny"

        client = _send_head(proxy, port, size=_LARGE_BODY, credential=None, path="/allowed-large")
        try:
            client.sendall(b"b" * 524288)
            deadline = time.monotonic() + 3
            while origin.body_bytes == 0 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert origin.body_bytes > 0, "allowed stream lost early forwarding"
            early_body_bytes = origin.body_bytes
            client.sendall(b"b" * (_LARGE_BODY - 524288))
            status, _ = _response(client)
            assert status == 200
            assert origin.body_bytes == _LARGE_BODY
            observations["allowed_large"] = {
                "status": status, "early_origin_body_bytes": early_body_bytes,
                "origin_body_bytes": origin.body_bytes,
            }
        finally:
            client.close()

        client = _send_head(proxy, port, size=5, credential=None, path="/allowed-small")
        try:
            client.sendall(b"hello")
            status, _ = _response(client)
            assert status == 200
            assert origin.body_bytes == _LARGE_BODY + 5
            observations["allowed_small"] = {"status": status, "origin_body_bytes": origin.body_bytes}
        finally:
            client.close()
        (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
