"""Agent HTTP preview sessions.

Provides a host-local, token-gated HTTP gateway to one agent-local HTTP
service. The browser-facing server is not a general router: each instance is
bound to one `(agent, guest_port)` pair and forwards through a command-owned
guest helper process.
"""

from __future__ import annotations

import base64
import http.server
import json
import logging
import secrets
import shlex
import subprocess
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie

from .core.audit_schema import EventKind, Severity
from .events import write_event

log = logging.getLogger("safeyolo.preview")

TOKEN_QUERY_PARAM = "safeyolo_preview_token"
TOKEN_HEADER = "X-SafeYolo-Preview-Token"
TOKEN_COOKIE = "safeyolo_preview_token"
RESERVED_GUEST_PORTS = {8080, 9090}
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
STRIP_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | {"content-length"}


@dataclass(frozen=True)
class PreviewConfig:
    agent: str
    guest_port: int
    host: str = "127.0.0.1"
    host_port: int = 0
    ttl_seconds: int | None = None
    open_browser: bool = False


class PreviewError(RuntimeError):
    """Preview session failed."""


class PreviewBridge:
    """Persistent JSON-line bridge to an agent-local HTTP helper."""

    def __init__(self, proc: subprocess.Popen[str]):
        if proc.stdin is None or proc.stdout is None:
            raise PreviewError("preview helper did not expose stdin/stdout")
        self.proc = proc
        self._lock = threading.Lock()

    def request(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> dict:
        payload = {
            "method": method,
            "path": path,
            "headers": headers,
            "body_b64": base64.b64encode(body).decode(),
        }
        with self._lock:
            if self.proc.poll() is not None:
                raise PreviewError(f"preview helper exited with rc={self.proc.returncode}")
            assert self.proc.stdin is not None
            assert self.proc.stdout is not None
            try:
                self.proc.stdin.write(json.dumps(payload) + "\n")
                self.proc.stdin.flush()
                line = self.proc.stdout.readline()
            except (BrokenPipeError, OSError) as exc:
                raise PreviewError(f"preview helper pipe failed: {type(exc).__name__}") from exc
        if not line:
            raise PreviewError("preview helper returned EOF")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PreviewError("preview helper returned invalid JSON") from exc
        if "error" in response:
            raise PreviewError(str(response["error"]))
        return response

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)


class PreviewHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[http.server.BaseHTTPRequestHandler],
        *,
        config: PreviewConfig,
        token: str,
        bridge: PreviewBridge,
    ):
        super().__init__(server_address, handler_class)
        self.config = config
        self.token = token
        self.bridge = bridge
        self.started_at = time.time()


class PreviewRequestHandler(http.server.BaseHTTPRequestHandler):
    server: PreviewHTTPServer

    def log_message(self, format, *args):
        log.debug("preview: " + format, *args)

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def _handle(self) -> None:
        started = time.time()
        cleaned_path, query_token = strip_query_token(self.path)
        provided = (
            self.headers.get(TOKEN_HEADER)
            or query_token
            or preview_token_from_cookie(self.headers.get("Cookie", ""))
        )
        if not provided:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "preview token required"})
            self._log_event("traffic.preview_error", "preview token missing", status=401, started=started)
            return
        if not secrets.compare_digest(provided, self.server.token):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "preview token invalid"})
            self._log_event("traffic.preview_error", "preview token invalid", status=403, started=started)
            return

        try:
            body = self._read_body()
            headers = sanitize_request_headers(self.headers, self.server.config.guest_port)
            self._log_event(
                "traffic.preview_request",
                f"preview {self.command} {cleaned_path}",
                status=None,
                started=started,
                bytes_in=len(body),
                path=cleaned_path,
            )
            response = self.server.bridge.request(
                method=self.command,
                path=cleaned_path,
                headers=headers,
                body=body,
            )
            self._send_bridge_response(response, set_cookie=bool(query_token))
            self._log_event(
                "traffic.preview_response",
                f"preview {self.command} {cleaned_path} -> {int(response['status'])}",
                status=int(response["status"]),
                started=started,
                bytes_in=len(body),
                bytes_out=len(base64.b64decode(response.get("body_b64", ""))),
                path=cleaned_path,
            )
        except Exception as exc:  # noqa: BLE001 - convert to HTTP boundary
            log.exception("preview request failed")
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "preview request failed", "detail": str(exc)})
            self._log_event("traffic.preview_error", str(exc), status=502, started=started, path=cleaned_path)

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        try:
            n = int(length)
        except ValueError:
            return b""
        return self.rfile.read(max(n, 0))

    def _send_bridge_response(self, response: dict, *, set_cookie: bool) -> None:
        status = int(response["status"])
        body = base64.b64decode(response.get("body_b64", ""))
        self.send_response(status)
        for key, value in response.get("headers", []):
            if str(key).lower() in STRIP_RESPONSE_HEADERS:
                continue
            self.send_header(str(key), str(value))
        if set_cookie:
            self.send_header(
                "Set-Cookie",
                f"{TOKEN_COOKIE}={self.server.token}; Path=/; HttpOnly; SameSite=Strict",
            )
        self.send_header("X-SafeYolo-Agent", self.server.config.agent)
        self.send_header("X-SafeYolo-Preview-Port", str(self.server.config.guest_port))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log_event(
        self,
        event: str,
        summary: str,
        *,
        status: int | None,
        started: float,
        path: str | None = None,
        bytes_in: int = 0,
        bytes_out: int = 0,
    ) -> None:
        cfg = self.server.config
        details = {
            "agent": cfg.agent,
            "guest_port": cfg.guest_port,
            "host_port": self.server.server_address[1],
            "method": self.command,
            "path": path or self.path,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "duration_ms": round((time.time() - started) * 1000, 1),
        }
        if status is not None:
            details["status"] = status
        write_event(
            event,
            kind=EventKind.TRAFFIC,
            severity=Severity.LOW,
            summary=summary,
            agent=cfg.agent,
            addon="agent-preview",
            details=details,
        )


def validate_guest_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError("guest port must be 1-65535")
    if port in RESERVED_GUEST_PORTS:
        raise ValueError(f"guest port {port} is reserved for SafeYolo plumbing")


def parse_ttl(value: str | None) -> int | None:
    if value is None:
        return None
    raw = value.strip().lower()
    if not raw:
        raise ValueError("ttl cannot be empty")
    suffix = raw[-1]
    if suffix in {"s", "m", "h"}:
        number = raw[:-1]
        multiplier = {"s": 1, "m": 60, "h": 3600}[suffix]
    else:
        number = raw
        multiplier = 1
    try:
        ttl = int(number) * multiplier
    except ValueError as exc:
        raise ValueError("ttl must be an integer with optional s, m, or h suffix") from exc
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    return ttl


def strip_query_token(path: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(path)
    kept: list[tuple[str, str]] = []
    token = ""
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if key == TOKEN_QUERY_PARAM:
            token = value
        else:
            kept.append((key, value))
    query = urllib.parse.urlencode(kept, doseq=True)
    return urllib.parse.urlunsplit(("", "", parsed.path, query, parsed.fragment)), token


def preview_token_from_cookie(raw_cookie: str) -> str:
    if not raw_cookie:
        return ""
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return ""
    morsel = cookie.get(TOKEN_COOKIE)
    return morsel.value if morsel else ""


def sanitize_request_headers(headers, guest_port: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        lk = key.lower()
        if lk in HOP_BY_HOP_HEADERS or lk == "host" or lk == TOKEN_HEADER.lower():
            continue
        if lk == "cookie":
            value = strip_preview_cookie(value)
            if not value:
                continue
        out[key] = value
    out["Host"] = f"127.0.0.1:{guest_port}"
    out["X-SafeYolo-Preview"] = "1"
    return out


def strip_preview_cookie(raw_cookie: str) -> str:
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return raw_cookie
    if TOKEN_COOKIE in cookie:
        del cookie[TOKEN_COOKIE]
    return "; ".join(f"{key}={morsel.value}" for key, morsel in cookie.items())


def build_guest_helper_command(guest_port: int) -> str:
    script = r'''
import base64
import http.client
import json
import os
import sys

port = int(os.environ["SAFEYOLO_PREVIEW_PORT"])

for line in sys.stdin:
    try:
        req = json.loads(line)
        body = base64.b64decode(req.get("body_b64", ""))
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        try:
            conn.request(req["method"], req["path"], body=body, headers=req.get("headers", {}))
            resp = conn.getresponse()
            data = resp.read()
            out = {
                "status": resp.status,
                "reason": resp.reason,
                "headers": [[k, v] for k, v in resp.getheaders()],
                "body_b64": base64.b64encode(data).decode(),
            }
        finally:
            conn.close()
    except Exception as exc:
        out = {"error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
'''
    script_b64 = base64.b64encode(script.encode()).decode()
    bootstrap = 'import base64, os; exec(base64.b64decode(os.environ["SAFEYOLO_PREVIEW_HELPER_B64"]))'
    return (
        f"SAFEYOLO_PREVIEW_PORT={shlex.quote(str(guest_port))} "
        f"SAFEYOLO_PREVIEW_HELPER_B64={shlex.quote(script_b64)} "
        f"python3 -u -c {shlex.quote(bootstrap)}"
    )


def start_preview_server(config: PreviewConfig, bridge: PreviewBridge, token: str) -> PreviewHTTPServer:
    validate_guest_port(config.guest_port)
    return PreviewHTTPServer(
        (config.host, config.host_port),
        PreviewRequestHandler,
        config=config,
        token=token,
        bridge=bridge,
    )


def serve_agent_preview(config: PreviewConfig, platform) -> int:
    validate_guest_port(config.guest_port)
    command = build_guest_helper_command(config.guest_port)
    proc = platform.popen_in_sandbox(config.agent, command, user="agent")
    bridge = PreviewBridge(proc)
    try:
        token = secrets.token_urlsafe(32)
        server = start_preview_server(config, bridge, token)
    except Exception:
        bridge.close()
        raise
    host, port = server.server_address
    url = f"http://{host}:{port}/?{TOKEN_QUERY_PARAM}={urllib.parse.quote(token)}"

    write_event(
        "agent.preview_open",
        kind=EventKind.AGENT,
        severity=Severity.LOW,
        summary=f"Preview opened for {config.agent}:127.0.0.1:{config.guest_port}",
        agent=config.agent,
        addon="agent-preview",
        details={"agent": config.agent, "guest_port": config.guest_port, "host": host, "host_port": port},
    )

    print("Preview open:")
    print(f"  {url}")
    print("Agent:")
    print(f"  {config.agent} -> 127.0.0.1:{config.guest_port}")
    print("Press Ctrl-C to close.")

    if config.open_browser:
        webbrowser.open(url)

    try:
        if config.ttl_seconds:
            timer = threading.Timer(config.ttl_seconds, server.shutdown)
            timer.daemon = True
            timer.start()
        server.serve_forever()
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
        bridge.close()
        write_event(
            "agent.preview_close",
            kind=EventKind.AGENT,
            severity=Severity.LOW,
            summary=f"Preview closed for {config.agent}:127.0.0.1:{config.guest_port}",
            agent=config.agent,
            addon="agent-preview",
            details={"agent": config.agent, "guest_port": config.guest_port, "host_port": port},
        )
