"""Agent HTTP preview sessions.

Provides a host-local, token-gated HTTP gateway to one agent-local HTTP
service. The browser-facing server is not a general router: each instance is
bound to one `(agent, guest_port)` pair and forwards through a command-owned
guest helper process.
"""

from __future__ import annotations

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

TOKEN_HEADER = "X-SafeYolo-Preview-Token"
TOKEN_COOKIE = "safeyolo_preview_token"
CONTROL_PREFIX = "/_safeyolo_preview"
UNLOCK_PATH = f"{CONTROL_PREFIX}/unlock"
UNLOCK_CODE_TTL_SECONDS = 300
MAX_UNLOCK_FAILURES = 5
RESERVED_GUEST_PORTS = {8080, 9090}
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
}
REQUEST_BODY_CHUNK_SIZE = 64 * 1024
MAX_RESPONSE_HEADER_BYTES = 128 * 1024
STREAM_CHUNK_SIZE = 64 * 1024


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


class PreviewHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[http.server.BaseHTTPRequestHandler],
        *,
        config: PreviewConfig,
        platform,
        session_token: str,
        unlock_code: str,
    ):
        super().__init__(server_address, handler_class)
        self.config = config
        self.platform = platform
        self.session_token = session_token
        self.unlock_code = unlock_code
        self.unlock_expires_at = time.time() + UNLOCK_CODE_TTL_SECONDS
        self.unlock_failures = 0
        self.unlock_locked = False
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
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith(CONTROL_PREFIX):
            self._handle_control_path(started, path)
            return

        if not self._is_authorized():
            self._send_unlock_page()
            self._log_event("traffic.preview_error", "preview session missing", status=401, started=started)
            return
        try:
            is_upgrade = is_websocket_upgrade(self.headers)
            self._log_event(
                "traffic.preview_request",
                f"preview {self.command} {self.path}",
                status=None,
                started=started,
                bytes_in=0,
                path=self.path,
            )
            status, bytes_out = self._proxy_stream(is_upgrade=is_upgrade)
            if not is_upgrade:
                self.close_connection = True
            self._log_event(
                "traffic.preview_response",
                f"preview {self.command} {self.path} -> {status}",
                status=status,
                started=started,
                bytes_in=0,
                bytes_out=bytes_out,
                path=self.path,
            )
        except Exception as exc:  # noqa: BLE001 - convert to HTTP boundary
            log.exception("preview request failed")
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "preview request failed", "detail": str(exc)})
            self._log_event("traffic.preview_error", str(exc), status=502, started=started, path=self.path)

    def _handle_control_path(self, started: float, path: str) -> None:
        if path != UNLOCK_PATH:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "preview control path not found"})
            return
        if self.command == "GET":
            self._send_unlock_page()
            return
        if self.command != "POST":
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
            return

        if not self._unlock_request_has_local_origin():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "unlock request rejected"})
            self._log_event("traffic.preview_error", "preview unlock origin rejected", status=403, started=started)
            return
        if self.server.unlock_locked or self.server.unlock_code is None:
            self._send_json(HTTPStatus.LOCKED, {"error": "preview unlock is locked"})
            self._log_event("traffic.preview_error", "preview unlock locked", status=423, started=started)
            return
        if time.time() > self.server.unlock_expires_at:
            self.server.unlock_locked = True
            self._send_json(HTTPStatus.GONE, {"error": "preview unlock code expired"})
            self._log_event("traffic.preview_error", "preview unlock expired", status=410, started=started)
            return

        provided = self._read_unlock_code()
        if not secrets.compare_digest(provided, self.server.unlock_code):
            self.server.unlock_failures += 1
            if self.server.unlock_failures >= MAX_UNLOCK_FAILURES:
                self.server.unlock_locked = True
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "preview unlock code invalid"})
            self._log_event("traffic.preview_error", "preview unlock failed", status=403, started=started)
            return

        self.server.unlock_code = None
        self._set_session_cookie_and_redirect()
        self._log_event("agent.preview_unlock", "preview unlocked", status=303, started=started)

    def _is_authorized(self) -> bool:
        provided = (
            self.headers.get(TOKEN_HEADER)
            or preview_token_from_cookie(self.headers.get("Cookie", ""))
        )
        return bool(provided) and secrets.compare_digest(provided, self.server.session_token)

    def _unlock_request_has_local_origin(self) -> bool:
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        if origin:
            parsed = urllib.parse.urlsplit(origin)
            if parsed.scheme != "http" or parsed.netloc != host:
                return False
        sec_fetch_site = self.headers.get("Sec-Fetch-Site")
        return sec_fetch_site not in {"cross-site", "same-site"}

    def _read_unlock_code(self) -> str:
        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            return ""
        try:
            body = self._read_body().decode()
        except UnicodeDecodeError:
            return ""
        values = urllib.parse.parse_qs(body, keep_blank_values=True)
        return values.get("code", [""])[0].strip()

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        try:
            n = int(length)
        except ValueError:
            return b""
        return self.rfile.read(max(n, 0))

    def _proxy_stream(self, *, is_upgrade: bool) -> tuple[int, int]:
        proc = self._open_guest_relay()
        try:
            assert proc.stdin is not None
            assert proc.stdout is not None
            request = build_upstream_request(
                method=self.command,
                path=self.path,
                version=self.request_version,
                headers=self.headers,
                guest_port=self.server.config.guest_port,
                is_upgrade=is_upgrade,
            )
            proc.stdin.write(request)
            self._copy_request_body(proc.stdin, is_upgrade=is_upgrade)
            proc.stdin.flush()
            if not is_upgrade:
                proc.stdin.close()

            status, bytes_out = self._forward_response_head(proc.stdout)
            if is_upgrade and status == HTTPStatus.SWITCHING_PROTOCOLS:
                bytes_out += self._relay_upgraded_connection(proc)
            else:
                bytes_out += self._copy_response_body(proc.stdout)
            return int(status), bytes_out
        finally:
            self._close_relay(proc)

    def _open_guest_relay(self) -> subprocess.Popen[bytes]:
        command = build_guest_relay_command(self.server.config.guest_port)
        proc = self.server.platform.popen_binary_in_sandbox(self.server.config.agent, command, user="agent")
        if proc.stdin is None or proc.stdout is None:
            raise PreviewError("preview relay did not expose stdin/stdout")
        return proc

    def _copy_request_body(self, dst, *, is_upgrade: bool) -> None:
        if is_upgrade:
            return
        transfer_encoding = self.headers.get("Transfer-Encoding", "")
        if transfer_encoding and transfer_encoding.lower() != "identity":
            raise PreviewError("chunked request bodies are not supported by preview")
        length = self.headers.get("Content-Length")
        if not length:
            return
        try:
            remaining = int(length)
        except ValueError as exc:
            raise PreviewError("invalid request Content-Length") from exc
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, REQUEST_BODY_CHUNK_SIZE))
            if not chunk:
                raise PreviewError("client closed before request body completed")
            dst.write(chunk)
            remaining -= len(chunk)

    def _forward_response_head(self, src) -> tuple[int, int]:
        head, rest = read_http_response_head(src)
        status = parse_response_status(head)
        self.connection.sendall(add_preview_response_headers(head, self.server.config))
        bytes_out = 0
        if rest:
            self.connection.sendall(rest)
            bytes_out += len(rest)
        return status, bytes_out

    def _copy_response_body(self, src) -> int:
        bytes_out = 0
        while True:
            chunk = src.read(STREAM_CHUNK_SIZE)
            if not chunk:
                return bytes_out
            self.connection.sendall(chunk)
            bytes_out += len(chunk)

    def _relay_upgraded_connection(self, proc: subprocess.Popen[bytes]) -> int:
        assert proc.stdin is not None
        assert proc.stdout is not None
        done = threading.Event()

        def client_to_guest() -> None:
            try:
                while not done.is_set():
                    data = self.connection.recv(STREAM_CHUNK_SIZE)
                    if not data:
                        break
                    proc.stdin.write(data)
                    proc.stdin.flush()
            except OSError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        thread = threading.Thread(target=client_to_guest, daemon=True)
        thread.start()
        try:
            return self._copy_response_body(proc.stdout)
        finally:
            done.set()
            thread.join(timeout=1)

    def _close_relay(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.wait(timeout=1)
            return
        except subprocess.TimeoutExpired:
            proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

    def _send_unlock_page(self) -> None:
        body = (
            b"<!doctype html><html><head><meta charset=\"utf-8\">"
            b"<title>SafeYolo Preview Unlock</title>"
            b"<style>body{font-family:system-ui,sans-serif;margin:3rem;max-width:32rem}"
            b"input,button{font:inherit;padding:.6rem;margin-top:.5rem}</style>"
            b"</head><body><h1>Unlock Preview</h1>"
            b"<form method=\"post\" action=\"/_safeyolo_preview/unlock\">"
            b"<label>Unlock code<br><input name=\"code\" autocomplete=\"one-time-code\" autofocus></label><br>"
            b"<button type=\"submit\">Unlock</button></form></body></html>"
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _set_session_cookie_and_redirect(self) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"{TOKEN_COOKIE}={self.server.session_token}; Path=/; HttpOnly; SameSite=Strict",
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

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
            kind=EventKind.AGENT if event.startswith("agent.") else EventKind.TRAFFIC,
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


def is_websocket_upgrade(headers) -> bool:
    upgrade = headers.get("Upgrade", "")
    connection = headers.get("Connection", "")
    return upgrade.lower() == "websocket" and "upgrade" in connection.lower()


def sanitize_request_headers(headers, guest_port: int, *, is_upgrade: bool = False) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in headers.items():
        lk = key.lower()
        if lk == "host" or lk == TOKEN_HEADER.lower():
            continue
        if lk in HOP_BY_HOP_HEADERS and not (is_upgrade and lk in {"connection", "upgrade"}):
            continue
        if lk == "cookie":
            value = strip_preview_cookie(value)
            if not value:
                continue
        out.append((key, value))
    out.insert(0, ("Host", f"127.0.0.1:{guest_port}"))
    out.append(("X-SafeYolo-Preview", "1"))
    if not is_upgrade:
        out.append(("Connection", "close"))
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


def generate_unlock_code() -> str:
    value = secrets.randbelow(100_000_000)
    raw = f"{value:08d}"
    return f"{raw[:4]}-{raw[4:]}"


def build_upstream_request(
    *,
    method: str,
    path: str,
    version: str,
    headers,
    guest_port: int,
    is_upgrade: bool,
) -> bytes:
    lines = [f"{method} {path} {version}"]
    for key, value in sanitize_request_headers(headers, guest_port, is_upgrade=is_upgrade):
        lines.append(f"{key}: {value}")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("iso-8859-1")


def read_http_response_head(src) -> tuple[bytes, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = src.read(4096)
        if not chunk:
            raise PreviewError("preview relay closed before response headers")
        data += chunk
        if len(data) > MAX_RESPONSE_HEADER_BYTES:
            raise PreviewError("preview response headers too large")
    head, rest = data.split(b"\r\n\r\n", 1)
    return head + b"\r\n\r\n", rest


def parse_response_status(head: bytes) -> int:
    first_line = head.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        raise PreviewError("preview relay returned malformed HTTP response")
    try:
        return int(parts[1])
    except ValueError as exc:
        raise PreviewError("preview relay returned malformed HTTP status") from exc


def add_preview_response_headers(head: bytes, config: PreviewConfig) -> bytes:
    prefix = head[:-4]
    preview_headers = (
        f"\r\nX-SafeYolo-Agent: {config.agent}"
        f"\r\nX-SafeYolo-Preview-Port: {config.guest_port}"
        "\r\n\r\n"
    ).encode("iso-8859-1")
    return prefix + preview_headers


def build_guest_relay_command(guest_port: int) -> str:
    return f"exec socat - TCP:127.0.0.1:{shlex.quote(str(guest_port))}"


def start_preview_server(
    config: PreviewConfig,
    platform,
    session_token: str,
    unlock_code: str,
) -> PreviewHTTPServer:
    validate_guest_port(config.guest_port)
    return PreviewHTTPServer(
        (config.host, config.host_port),
        PreviewRequestHandler,
        config=config,
        platform=platform,
        session_token=session_token,
        unlock_code=unlock_code,
    )


def serve_agent_preview(config: PreviewConfig, platform) -> int:
    validate_guest_port(config.guest_port)
    try:
        session_token = secrets.token_urlsafe(32)
        unlock_code = generate_unlock_code()
        server = start_preview_server(config, platform, session_token, unlock_code)
    except Exception:
        raise
    host, port = server.server_address
    url = f"http://{host}:{port}/"

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
    print("Unlock code:")
    print(f"  {unlock_code}")
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
        write_event(
            "agent.preview_close",
            kind=EventKind.AGENT,
            severity=Severity.LOW,
            summary=f"Preview closed for {config.agent}:127.0.0.1:{config.guest_port}",
            agent=config.agent,
            addon="agent-preview",
            details={"agent": config.agent, "guest_port": config.guest_port, "host_port": port},
        )
