"""Agent HTTP preview sessions.

Provides a host-local, token-gated HTTP gateway to one agent-local HTTP
service. The browser-facing server is not a general router: each instance is
bound to one `(agent, guest_port)` pair and forwards through a command-owned
platform relay.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import logging
import os
import re
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie

from .core.audit_schema import EventKind, Severity, sanitize_for_log
from .events import write_event
from .tailnet import (
    TailnetServeError,
    TailnetServeSession,
    start_tailnet_serve,
)

log = logging.getLogger("safeyolo.preview")

TOKEN_HEADER = "X-SafeYolo-Preview-Token"
TOKEN_COOKIE_PREFIX = "safeyolo_preview_token_"
CONTROL_PREFIX = "/_safeyolo_preview"
UNLOCK_PATH = f"{CONTROL_PREFIX}/unlock"
UNLOCK_CODE_TTL_SECONDS = 300
MAX_UNLOCK_FAILURES = 5
RESERVED_GUEST_PORTS = {8080, 9090}

# When an agent's app inside the sandbox restarts (dev server reload, crash
# and recover, port switch), the port-forward briefly gets ECONNREFUSED with
# the specific runsc stderr signature checked by _is_upstream_refused below.
# We handle this transparently in two phases:
#
#   1. Silent retry: hold the browser's request for up to
#      PREVIEW_SILENT_RETRY_WINDOW_SECONDS, re-attempting the port-forward
#      every PREVIEW_SILENT_RETRY_INTERVAL_SECONDS. Sub-window restarts are
#      invisible to the operator — the page just loads slightly slower.
#      Same trick nginx/traefik do by default.
#
#   2. Waiting room: if the silent window elapses without recovery, serve a
#      minimal HTML page (or 503 for non-HTML requests) that polls the URL
#      and reloads when the app comes back. Each waiting-room page has a
#      client-side heartbeat via <meta refresh> at
#      PREVIEW_WAITING_ROOM_HEARTBEAT_SECONDS — the page reloads on that
#      cadence, fetching a fresh waiting-room from the server. Not a hard
#      timeout; the waiting-room persists indefinitely.
#
# Only the specific "connection was refused" from runsc port-forward enters
# this path. Every other error (sandbox down, runsc missing, TLS, etc.)
# still surfaces as the actionable 502 the operator needs.
PREVIEW_SILENT_RETRY_WINDOW_SECONDS = 5.0
PREVIEW_SILENT_RETRY_INTERVAL_SECONDS = 0.5
PREVIEW_WAITING_ROOM_HEARTBEAT_SECONDS = 60
WAITING_ROOM_HEADER = "X-SafeYolo-Waiting-Room"
WAITING_ROOM_POLL_HEADER = "X-SafeYolo-Waiting-Room-Poll"
# Max request-body size we'll buffer for the silent-retry path. Bodies
# larger than this bypass the retry (proc opens, streams straight
# through, EOF surfaces as the original 502). 1 MiB covers typical dev
# form POSTs; anything above is likely a file upload that shouldn't be
# quietly retried anyway.
PREVIEW_MAX_RETRYABLE_BODY_BYTES = 1 * 1024 * 1024
_UPSTREAM_REFUSED_MARKERS = (
    "connection was refused",   # gVisor netstack ECONNREFUSED phrasing
    "connection refused",       # BSD-style variant (defensive)
)
_STREAM_CLOSED_BEFORE_HEADERS = "preview relay closed before response headers"
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
DEFAULT_VNC_GEOMETRY = "1280x800"
FORWARDED_PREVIEW_HEADERS = {
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}


@dataclass(frozen=True)
class PreviewConfig:
    agent: str
    guest_port: int
    host: str = "127.0.0.1"
    host_port: int = 0
    ttl_seconds: int | None = None
    open_browser: bool = False
    display_path: str = "/"
    tailnet_port: int | None = None


PreviewError = TailnetServeError


class _UpstreamRefused(Exception):
    """The guest port had no listener across the full silent-retry window.

    Signals _proxy_stream to serve a waiting-room page (or 503 for non-HTML
    requests) instead of the generic 502. Only raised when the failure is
    the specific ECONNREFUSED-on-port-forward pattern — every other
    failure surfaces via PreviewError like before.
    """

    def __init__(self, agent: str, guest_port: int, elapsed: float, cause: Exception):
        super().__init__(f"upstream port {guest_port} refused after {elapsed:.1f}s")
        self.agent = agent
        self.guest_port = guest_port
        self.elapsed = elapsed
        self.__cause__ = cause


def _prefers_html(accept_header: str) -> bool:
    """True if the client's Accept header prefers HTML over JSON.

    Simple heuristic — full RFC 7231 q-value negotiation isn't necessary
    here; the two clients we care about are browsers (send `text/html`
    with high preference) and JS fetch()/XHR (usually `application/json`
    or `*/*`). A browser navigation always prefers HTML; anything else
    gets JSON with proper Retry-After semantics.
    """
    if not accept_header:
        return False
    accept = accept_header.lower()
    if "text/html" not in accept:
        return False
    # `*/*` alone → not a browser navigation
    if accept.strip() == "*/*":
        return False
    return True


def _render_waiting_room_html(*, agent: str, guest_port: int, heartbeat_seconds: int) -> str:
    """Return the HTML for the waiting-room page.

    Kept minimal and inline: one file, one page, no external assets so a
    slow-first-paint restart still shows the page instantly. Both a JS
    poller AND a meta-refresh fallback are included, so JS-disabled
    browsers still reload.

    The client-side JS polls the same URL and reloads only when the
    response does not carry the WAITING_ROOM_HEADER. That distinguishes
    "the app is back and returned any status" from "still waiting-room
    from us" — a 500 from the real app is treated as success (the app
    is up; the reload will show that 500).

    heartbeat_seconds is the meta-refresh cadence AND the JS-side
    countdown reset interval. NOT a hard timeout — the page reloads
    on this cadence (fetching a fresh waiting-room), so the room
    persists indefinitely until the upstream comes back.
    """
    # HTML-escape user-controlled values. Agent names come from a
    # validated set (see agents_store), but guarding here is cheap and
    # keeps the template robust if that constraint ever loosens.
    from html import escape as _e

    # Countdown updates smoothly via setInterval independent of the poll,
    # so a slow network round-trip doesn't stall the visible timer.
    #
    # Meta-refresh interval matches the heartbeat — long enough not to
    # compete with the 1s JS poll (short values cause flicker / counter
    # oscillation). Purely a JS-off fallback.
    #
    # Every fetch carries the poll header so the server-side
    # silent-retry doesn't apply — we're already polling client-side.
    return (
        "<!doctype html>\n"
        "<html lang=\"en\"><head>\n"
        "<meta charset=\"utf-8\">\n"
        f"<meta http-equiv=\"refresh\" content=\"{heartbeat_seconds}\">\n"
        f"<title>Waiting for {_e(agent)}…</title>\n"
        "<style>\n"
        "  body{font-family:-apple-system,system-ui,sans-serif;"
        "margin:3rem auto;max-width:32rem;color:#222;text-align:center}\n"
        "  h1{font-weight:500;font-size:1.4rem;margin-bottom:0.5rem}\n"
        "  code{background:#f4f4f4;padding:0.1rem 0.3rem;border-radius:3px}\n"
        "  .spinner{margin:2rem auto;width:2.5rem;height:2.5rem;"
        "border:3px solid #e0e0e0;border-top-color:#666;border-radius:50%;"
        "animation:spin 1s linear infinite}\n"
        "  @keyframes spin{to{transform:rotate(360deg)}}\n"
        "  .detail{color:#888;font-size:0.9rem;margin-top:1.5rem}\n"
        "</style>\n"
        "</head><body>\n"
        f"<h1>Waiting for <code>{_e(agent)}</code></h1>\n"
        f"<p>Port {guest_port} inside the sandbox has no listener — the app is probably restarting.</p>\n"
        "<div class=\"spinner\"></div>\n"
        "<p class=\"detail\">This page reloads automatically. Next reload in "
        "<span id=\"t\">" + str(heartbeat_seconds) + "</span>s.</p>\n"
        "<script>\n"
        "(function(){\n"
        "  var start = Date.now();\n"
        f"  var heartbeat = {heartbeat_seconds} * 1000;\n"
        f"  var header = \"{WAITING_ROOM_HEADER}\";\n"
        f"  var pollHeader = \"{WAITING_ROOM_POLL_HEADER}\";\n"
        "  var el = document.getElementById(\"t\");\n"
        "  var pollHeaders = {};\n"
        "  pollHeaders[pollHeader] = \"1\";\n"
        "  function updateCountdown(){\n"
        "    if (el) el.textContent = Math.max(0, Math.round((heartbeat - (Date.now() - start)) / 1000));\n"
        "  }\n"
        "  setInterval(updateCountdown, 250);\n"
        "  async function poll(){\n"
        "    if (Date.now() - start > heartbeat) return;\n"
        "    try {\n"
        "      var r = await fetch(location.href, {cache:\"no-store\", credentials:\"include\", headers: pollHeaders});\n"
        "      if (!r.headers.get(header)) { location.reload(); return; }\n"
        "    } catch (e) {}\n"
        "    setTimeout(poll, 1000);\n"
        "  }\n"
        "  poll();\n"
        "})();\n"
        "</script>\n"
        "</body></html>\n"
    )


def _is_upstream_refused(exc: BaseException) -> bool:
    """True if `exc` matches the runsc-port-forward ECONNREFUSED signature.

    The full runsc stderr line for this class of failure is::

        runsc port-forward exited N: doStream: PortForward:
        port forwarding to sandbox: creating netstack port forward
        connection: connecting endpoint: connection was refused

    We match on the trailing marker so this catches the specific case we
    want to retry, not every RuntimeError from the platform.
    """
    message = str(exc).lower()
    return any(marker in message for marker in _UPSTREAM_REFUSED_MARKERS)


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
        browser_port = config.tailnet_port or self.server_address[1]
        self.token_cookie = preview_cookie_name(browser_port)
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
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as exc:
            # Client (browser or Tailscale Serve) closed mid-request. Nothing
            # to send back; do not attempt an error response on a dead socket.
            log.debug("preview client disconnected: %s", exc)
            self.close_connection = True
            self._log_event(
                "traffic.preview_error",
                f"client disconnected: {exc}",
                status=499,
                started=started,
                path=self.path,
            )
        except Exception as exc:  # noqa: BLE001 - convert to HTTP boundary
            log.exception("preview request failed")
            self.close_connection = True
            self._try_send_json(HTTPStatus.BAD_GATEWAY, {"error": "preview request failed", "detail": str(exc)})
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
        provided = self.headers.get(TOKEN_HEADER) or preview_token_from_cookie(
            self.headers.get("Cookie", ""),
            self.server.token_cookie,
        )
        return bool(provided) and secrets.compare_digest(provided, self.server.session_token)

    def _unlock_request_has_local_origin(self) -> bool:
        scheme = "http"
        host = self.headers.get("Host", "")
        if self.client_address[0] in {"127.0.0.1", "::1"}:
            forwarded_proto = self.headers.get("X-Forwarded-Proto", "")
            forwarded_host = self.headers.get("X-Forwarded-Host", "")
            if forwarded_proto == "https" and forwarded_host:
                scheme = forwarded_proto
                host = forwarded_host
        origin = self.headers.get("Origin")
        if origin:
            parsed = urllib.parse.urlsplit(origin)
            if parsed.scheme != scheme or parsed.netloc != host:
                return False
        sec_fetch_site = self.headers.get("Sec-Fetch-Site")
        return sec_fetch_site not in {"cross-site", "same-site"}

    def _is_forwarded_https(self) -> bool:
        return (
            self.client_address[0] in {"127.0.0.1", "::1"}
            and self.headers.get("X-Forwarded-Proto") == "https"
            and bool(self.headers.get("X-Forwarded-Host"))
        )

    def _read_unlock_code(self) -> str:
        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            return ""
        try:
            body = self._read_body().decode()
        except UnicodeDecodeError:
            log.debug("preview unlock body was not UTF-8; treating as empty code")
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
            # `length` is attacker-controlled; sanitize before logging.
            # `sanitize_for_log` is CodeQL-recognised as a log-injection
            # barrier (see cli/src/safeyolo/core/audit_schema.py).
            log.debug(
                "preview request had non-integer Content-Length %s; treating as empty",
                sanitize_for_log(length),
            )
            return b""
        return self.rfile.read(max(n, 0))

    def _proxy_stream(self, *, is_upgrade: bool) -> tuple[int, int]:
        # Two failure modes both look like "app not listening":
        #
        #   EAGER — port-forward Popen raises RuntimeError("... connection
        #     was refused") synchronously. Linux runsc under some conditions.
        #     Caught in _open_guest_relay as _UpstreamRefused.
        #
        #   LAZY — port-forward Popen returns a live-looking proc, we write
        #     the request, upstream (socat inside macOS sandbox, or the
        #     gVisor sentry) attempts the TCP connect on our behalf, gets
        #     refused, closes the stream. Response-head read returns EOF
        #     immediately. Surfaces as PreviewError with the specific
        #     "closed before response headers" message.
        #
        # Both must route through the same silent-retry + waiting-room path.
        # For LAZY we retry the whole request, which requires the body to be
        # replayable — so buffer it up front for retryable methods, or fall
        # back to a single-shot attempt for streaming/large-body requests.
        if is_upgrade:
            # WebSocket upgrades can't retry mid-handshake without
            # re-drawing state. One shot, no waiting room; a stalled
            # upgrade is worse than a fast failure. _serve_waiting_room
            # handles the WS case by returning 503 + Retry-After (no HTML).
            try:
                return self._do_relay_attempt(request_body=None, is_upgrade=True)
            except _UpstreamRefused as refused:
                return self._serve_waiting_room(refused, is_upgrade=True)

        try:
            request_body = self._buffer_request_body_for_retry()
        except PreviewError:
            # Body too large or client already gave up. Fall through to a
            # single-shot attempt so the original error surfaces cleanly.
            return self._do_relay_attempt(request_body=None, is_upgrade=False)

        # Waiting-room JS polls carry a header signalling "I am the poller,
        # do not silent-retry — I'm already polling client-side". Without
        # this each poll would block for PREVIEW_SILENT_RETRY_WINDOW_SECONDS
        # inside the server, breaking the client-side countdown UI and
        # making polls take 5-6s each. Bug found in live macOS demo:
        # countdown oscillated 55 → 60 → 55 → 60 because polls were
        # queueing behind the server-side retry.
        is_waiting_room_poll = self.headers.get(WAITING_ROOM_POLL_HEADER) == "1"
        silent_window = 0.0 if is_waiting_room_poll else PREVIEW_SILENT_RETRY_WINDOW_SECONDS
        started = time.monotonic()
        deadline = started + silent_window
        last_failure: Exception
        while True:
            try:
                return self._do_relay_attempt(
                    request_body=request_body, is_upgrade=False,
                )
            except _UpstreamRefused as refused:
                last_failure = refused  # eager
            except PreviewError as pe:
                if str(pe) != _STREAM_CLOSED_BEFORE_HEADERS:
                    raise  # unrelated failure — surface as 502
                last_failure = _UpstreamRefused(
                    agent=self.server.config.agent,
                    guest_port=self.server.config.guest_port,
                    elapsed=time.monotonic() - started,
                    cause=pe,
                )  # lazy — treat like eager for retry purposes

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.info(
                    "preview %s port %d refused after %.1fs silent retry — waiting-room",
                    self.server.config.agent,
                    self.server.config.guest_port,
                    time.monotonic() - started,
                )
                assert isinstance(last_failure, _UpstreamRefused)
                return self._serve_waiting_room(last_failure, is_upgrade=False)
            time.sleep(min(PREVIEW_SILENT_RETRY_INTERVAL_SECONDS, remaining))

    def _buffer_request_body_for_retry(self) -> bytes | None:
        """Read the request body into memory so it can be replayed on retry.

        Returns None when there's no body (Content-Length: 0 or absent and
        not chunked). Raises PreviewError if the body is too large to
        buffer, or if chunked encoding is used (chunked is rejected
        outright by _copy_request_body anyway).
        """
        transfer_encoding = self.headers.get("Transfer-Encoding", "")
        if transfer_encoding and transfer_encoding.lower() != "identity":
            raise PreviewError("chunked request bodies cannot be buffered for retry")
        length = self.headers.get("Content-Length")
        if not length:
            return None
        try:
            n = int(length)
        except ValueError as exc:
            raise PreviewError("invalid request Content-Length") from exc
        if n <= 0:
            return b""
        if n > PREVIEW_MAX_RETRYABLE_BODY_BYTES:
            raise PreviewError(
                f"request body {n}B exceeds retry buffer "
                f"{PREVIEW_MAX_RETRYABLE_BODY_BYTES}B",
            )
        data = self.rfile.read(n)
        if len(data) != n:
            raise PreviewError("client closed before request body completed")
        return data

    def _do_relay_attempt(
        self, *, request_body: bytes | None, is_upgrade: bool,
    ) -> tuple[int, int]:
        """One attempt: open relay, write request, read response.

        Raises:
          - _UpstreamRefused if the open failed eagerly with the ECONNREFUSED
            signature (from _open_guest_relay).
          - PreviewError("preview relay closed before response headers")
            if the stream returned EOF before the response head — the
            LAZY ECONNREFUSED case. Caller decides whether to retry.
          - Other PreviewError / OSError for genuine failures.
        """
        proc = self._open_guest_relay()  # may raise _UpstreamRefused
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
            if is_upgrade:
                pass  # no body for upgrade
            elif request_body is not None:
                if request_body:
                    proc.stdin.write(request_body)
            else:
                # Body wasn't buffered (too large / streaming). Fall back
                # to the pre-fix streaming behaviour so at least the
                # happy path works.
                self._copy_request_body(proc.stdin, is_upgrade=False)
            proc.stdin.flush()
            # Do not close stdin here. Across gVisor's exec and port-forward
            # relays, a host-side write EOF can close the whole guest stream
            # before its HTTP response reaches stdout. Relay cleanup closes it
            # after the response has been consumed.

            status, bytes_out = self._forward_response_head(proc.stdout)
            if is_upgrade and status == HTTPStatus.SWITCHING_PROTOCOLS:
                bytes_out += self._relay_upgraded_connection(proc)
            else:
                bytes_out += self._copy_response_body(proc.stdout)
            return int(status), bytes_out
        finally:
            self._close_relay(proc)

    def _open_guest_relay(self):
        """Single attempt to open the relay. Silent-retry lives in the
        caller (_proxy_stream) so poll requests can bypass it.

        Raises _UpstreamRefused for the eager ECONNREFUSED pattern —
        Linux runsc port-forward exits nonzero with 'connection was
        refused' before we've written anything. macOS's lazy path
        (ssh+socat succeeding at Popen but EOF-ing when the guest port
        has no listener) surfaces separately in _do_relay_attempt when
        the response head read returns empty; both route to the same
        outer retry / waiting-room via _proxy_stream.
        """
        agent = self.server.config.agent
        guest_port = self.server.config.guest_port
        open_port_forward = getattr(self.server.platform, "popen_port_forward", None)

        try:
            if open_port_forward is None:
                command = build_guest_relay_command(guest_port)
                proc = self.server.platform.popen_binary_in_sandbox(agent, command, user="agent")
            else:
                proc = open_port_forward(agent, guest_port, user="agent")
        except FileNotFoundError as exc:
            # Platform sandbox binary (runsc, socat) not on PATH. The
            # user sees a 502 instead of a raw traceback; the message
            # tells them what to check.
            raise PreviewError(
                f"preview relay binary missing on the host: {exc}"
            ) from exc
        except PermissionError as exc:
            raise PreviewError(
                f"preview relay was denied by the platform: {exc}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PreviewError(
                f"preview relay timed out opening a stream to agent '{agent}'; "
                "check whether the agent sandbox is still running"
            ) from exc
        except (RuntimeError, OSError) as exc:
            # Native runsc port-forward surfaces RuntimeError with
            # detail; UDS bind errors on Linux surface as OSError. Both
            # usually mean the agent sandbox is not accepting
            # connections (stopped, or its app briefly down for a
            # restart). The specific "connection was refused" pattern
            # is signalled up as _UpstreamRefused so _proxy_stream's
            # retry loop can catch it; every other flavour surfaces as
            # an actionable 502 immediately.
            if _is_upstream_refused(exc):
                raise _UpstreamRefused(agent, guest_port, 0.0, exc) from exc
            raise PreviewError(
                f"preview relay could not reach agent '{agent}': {exc}"
            ) from exc

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
        if not self._safe_send(add_preview_response_headers(head, self.server.config)):
            return status, 0
        bytes_out = 0
        if rest and self._safe_send(rest):
            bytes_out += len(rest)
        return status, bytes_out

    def _copy_response_body(self, src) -> int:
        bytes_out = 0
        while True:
            chunk = src.read(STREAM_CHUNK_SIZE)
            if not chunk:
                return bytes_out
            if not self._safe_send(chunk):
                return bytes_out
            bytes_out += len(chunk)

    def _safe_send(self, data: bytes) -> bool:
        """Write to the client socket, treating client disconnect as a soft stop.

        Returns True if the write succeeded, False if the client is gone.
        Raising OSError from every sendall in every copy loop is expensive
        (each raise is a candidate for double-fault when the error handler
        itself tries to write). Returning False lets loops unwind cleanly.
        """
        try:
            self.connection.sendall(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
            return False
        return True

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
                # The client or relay process closed the upgraded stream.
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    # stdin may already be closed by the relay process.
                    pass

        thread = threading.Thread(target=client_to_guest, daemon=True)
        thread.start()
        try:
            return self._copy_response_body(proc.stdout)
        finally:
            done.set()
            thread.join(timeout=1)

    def _close_relay(self, proc: subprocess.Popen[bytes]) -> None:
        try:
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
        except OSError as exc:
            # terminate()/kill()/wait() can race with the relay's own exit
            # (ProcessLookupError, ESRCH). The relay is effectively closed
            # in that case; suppress so we do not mask the primary exception
            # in the caller's finally.
            log.debug("preview relay close raced with process exit: %s", exc)

    def _serve_waiting_room(
        self, refused: _UpstreamRefused, *, is_upgrade: bool,
    ) -> tuple[int, int]:
        """Serve either an HTML waiting-room page or a 503 + Retry-After.

        Content-negotiation on the request's Accept header:

        - text/html preferred → 200 with a small HTML page that polls the
          same URL with fetch() and reloads once the app is back up. The
          WAITING_ROOM_HEADER on the response tells the client-side JS
          that the polled response was itself a waiting-room (so it
          keeps polling); any response without that header means the
          port-forward succeeded and JS should reload to show it.

        - Anything else (JSON APIs, XHR, WebSocket) → 503 with
          Retry-After: 2 and a short JSON body. Serving HTML into a JSON
          client would break the caller's contract.

        WebSocket upgrades never get the waiting room — a paused
        upgrade is worse than a fast failure.
        """
        if is_upgrade or not _prefers_html(self.headers.get("Accept", "")):
            body = json.dumps({
                "error": "upstream not ready",
                "detail": (
                    f"port {refused.guest_port} inside agent '{refused.agent}' "
                    f"has no listener; waited {refused.elapsed:.1f}s"
                ),
            }).encode()
            self.send_response(int(HTTPStatus.SERVICE_UNAVAILABLE))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Retry-After", "2")
            self.send_header(WAITING_ROOM_HEADER, "1")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return int(HTTPStatus.SERVICE_UNAVAILABLE), len(body)

        body = _render_waiting_room_html(
            agent=refused.agent,
            guest_port=refused.guest_port,
            heartbeat_seconds=PREVIEW_WAITING_ROOM_HEARTBEAT_SECONDS,
        ).encode()
        self.send_response(int(HTTPStatus.OK))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(WAITING_ROOM_HEADER, "1")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        return int(HTTPStatus.OK), len(body)

    def _send_unlock_page(self) -> None:
        body = (
            b'<!doctype html><html><head><meta charset="utf-8">'
            b"<title>SafeYolo Preview Unlock</title>"
            b"<style>body{font-family:system-ui,sans-serif;margin:3rem;max-width:32rem}"
            b"input,button{font:inherit;padding:.6rem;margin-top:.5rem}</style>"
            b"</head><body><h1>Unlock Preview</h1>"
            b'<form method="post" action="/_safeyolo_preview/unlock">'
            b'<label>Unlock code<br><input name="code" autocomplete="one-time-code" autofocus></label><br>'
            b'<button type="submit">Unlock</button></form></body></html>'
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
        self.send_header("Location", normalize_display_path(self.server.config.display_path))
        secure = "; Secure" if self._is_forwarded_https() else ""
        self.send_header(
            "Set-Cookie",
            f"{self.server.token_cookie}={self.server.session_token}; Path=/; HttpOnly; SameSite=Strict{secure}",
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

    def _try_send_json(self, status: HTTPStatus, payload: dict) -> None:
        """Attempt to send a JSON error response, tolerating a dead socket.

        Used from error-handling paths where the client may already have
        closed the connection -- in that case an error response would raise
        a second exception on top of whatever we were reporting.
        """
        try:
            self._send_json(status, payload)
        except OSError as exc:
            log.debug("preview client gone before error response: %s", exc)

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
        try:
            write_event(
                event,
                kind=EventKind.AGENT if event.startswith("agent.") else EventKind.TRAFFIC,
                severity=Severity.LOW,
                summary=summary,
                agent=cfg.agent,
                addon="agent-preview",
                details=details,
            )
        except Exception:  # noqa: BLE001 - auditing must not break request handling
            # write_event failures (disk full, log rotation race, permissions
            # regression) previously took down the request-handling thread
            # and cascaded into a double-fault when the error handler tried
            # to log its own event. Auditing is best-effort at this layer.
            log.warning("preview audit event write failed: %s", event, exc_info=True)


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


def parse_vnc_geometry(value: str) -> tuple[int, int]:
    raw = value.strip().lower()
    match = re.fullmatch(r"([1-9][0-9]{2,4})x([1-9][0-9]{2,4})", raw)
    if not match:
        raise ValueError("vnc size must be auto or WIDTHxHEIGHT")
    width = int(match.group(1))
    height = int(match.group(2))
    if width < 640 or height < 480:
        raise ValueError("vnc size must be at least 640x480")
    return width, height


def _parse_geometry_from_text(text: str) -> tuple[int, int] | None:
    match = re.search(r"([1-9][0-9]{2,4})\s*x\s*([1-9][0-9]{2,4})", text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _darwin_coregraphics_display_size() -> tuple[int, int] | None:
    try:
        import ctypes
    except ImportError:
        return None

    class CGPoint(ctypes.Structure):
        _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

    class CGSize(ctypes.Structure):
        _fields_ = [("width", ctypes.c_double), ("height", ctypes.c_double)]

    class CGRect(ctypes.Structure):
        _fields_ = [("origin", CGPoint), ("size", CGSize)]

    try:
        core_graphics = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        core_graphics.CGMainDisplayID.restype = ctypes.c_uint32
        core_graphics.CGDisplayBounds.argtypes = [ctypes.c_uint32]
        core_graphics.CGDisplayBounds.restype = CGRect
        bounds = core_graphics.CGDisplayBounds(core_graphics.CGMainDisplayID())
    except Exception:
        return None

    width = int(bounds.size.width)
    height = int(bounds.size.height)
    if width >= 640 and height >= 480:
        return width, height
    return None


def detect_host_display_size() -> tuple[int, int] | None:
    override = os.environ.get("SAFEYOLO_PREVIEW_SCREEN_SIZE")
    if override:
        return parse_vnc_geometry(override)

    if sys.platform == "darwin":
        display_size = _darwin_coregraphics_display_size()
        if display_size:
            return display_size

        try:
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        sizes: list[tuple[int, int]] = []

        def walk(value) -> None:
            if isinstance(value, dict):
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
            elif isinstance(value, str):
                parsed = _parse_geometry_from_text(value)
                if parsed:
                    sizes.append(parsed)

        walk(payload)
        return max(sizes, key=lambda size: size[0] * size[1], default=None)

    if sys.platform.startswith("linux"):
        commands = [
            ["xdpyinfo"],
            ["xrandr", "--current"],
        ]
        for command in commands:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode != 0:
                continue
            parsed = _parse_geometry_from_text(result.stdout)
            if parsed:
                return parsed
    return None


def preferred_vnc_geometry(display_size: tuple[int, int] | None) -> tuple[int, int]:
    if display_size is None:
        return parse_vnc_geometry(DEFAULT_VNC_GEOMETRY)
    width, height = display_size
    return min(2560, max(640, width - 160)), min(1440, max(480, height - 180))


def resolve_vnc_geometry(value: str) -> tuple[str, tuple[int, int] | None]:
    raw = value.strip().lower()
    if raw == "auto":
        display_size = detect_host_display_size()
        width, height = preferred_vnc_geometry(display_size)
        return f"{width}x{height}", display_size
    width, height = parse_vnc_geometry(raw)
    return f"{width}x{height}", None


def normalize_display_path(path: str) -> str:
    if not path.startswith("/"):
        return "/"
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc:
        return "/"
    out = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))
    return out or "/"


def preview_cookie_name(browser_port: int) -> str:
    """Return the preview session cookie name for one browser-facing port."""
    return f"{TOKEN_COOKIE_PREFIX}{browser_port}"


def preview_token_from_cookie(raw_cookie: str, cookie_name: str) -> str:
    if not raw_cookie:
        return ""
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return ""
    morsel = cookie.get(cookie_name)
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
        if lk.startswith("tailscale-") or lk in FORWARDED_PREVIEW_HEADERS:
            # Tailscale Serve identity belongs to the operator/host boundary;
            # it must not become attacker-controlled authority inside a guest.
            continue
        if lk in HOP_BY_HOP_HEADERS and not (is_upgrade and lk in {"connection", "upgrade"}):
            continue
        if lk == "cookie":
            value = strip_preview_cookies(value)
            if not value:
                continue
        out.append((key, value))
    out.insert(0, ("Host", f"127.0.0.1:{guest_port}"))
    out.append(("X-SafeYolo-Preview", "1"))
    if not is_upgrade:
        out.append(("Connection", "close"))
    return out


def strip_preview_cookies(raw_cookie: str) -> str:
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return raw_cookie
    for key in list(cookie):
        if key.startswith(TOKEN_COOKIE_PREFIX):
            del cookie[key]
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
    try:
        return "\r\n".join(lines).encode("iso-8859-1")
    except UnicodeEncodeError as exc:
        # RFC 7230 forbids non-latin-1 in header field values. Hitting this
        # means a client sent an out-of-spec header (or a guest with a
        # hostile identity is trying to smuggle one through). Fail as a
        # PreviewError so the outer handler returns a 502 with a helpful
        # detail instead of a raw traceback.
        raise PreviewError(
            f"upstream request contains a non-latin-1 header value: {exc}"
        ) from exc


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
        f"\r\nX-SafeYolo-Agent: {config.agent}\r\nX-SafeYolo-Preview-Port: {config.guest_port}\r\n\r\n"
    ).encode("iso-8859-1")
    return prefix + preview_headers


def build_guest_relay_command(guest_port: int) -> str:
    return f"exec socat - TCP:127.0.0.1:{shlex.quote(str(guest_port))}"


_SHUTDOWN_SIGNALS: tuple[str, ...] = ("SIGTERM", "SIGHUP")


@contextlib.contextmanager
def _shutdown_on_signals(server):
    """Install signal handlers that shut down `server` from a background thread.

    Only SIGINT (KeyboardInterrupt) was handled previously. Closing the
    terminal (SIGHUP) or `kill <pid>` (SIGTERM) killed the process mid
    serve_forever without running the finally block, leaking the Tailscale
    Serve mapping and dropping the agent.preview_close audit event.

    `server.shutdown()` blocks until the serve_forever loop notices, so it
    cannot run on the signal-handling thread itself. We spawn a daemon
    thread instead.

    signal.signal() can only be called from the main thread. When called
    from another thread (some test fixtures), we skip installation rather
    than raise -- the KeyboardInterrupt path still works, and tests that
    need signal behavior explicitly run in a subprocess.
    """
    installed: dict[int, object] = {}
    if threading.current_thread() is threading.main_thread():
        def _shutdown(_sig, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        for name in _SHUTDOWN_SIGNALS:
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                installed[sig] = signal.signal(sig, _shutdown)
            except (OSError, ValueError):
                # Some POSIX signals cannot be caught in some environments
                # (e.g. containers with restricted signal masks). Skip and
                # let KeyboardInterrupt / lifecycle handle shutdown.
                log.debug("could not install shutdown handler for %s", name)
    try:
        yield
    finally:
        for sig, previous in installed.items():
            try:
                signal.signal(sig, previous)
            except (OSError, ValueError):
                pass


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
    session_token = secrets.token_urlsafe(32)
    unlock_code = generate_unlock_code()
    server = start_preview_server(config, platform, session_token, unlock_code)
    host, port = server.server_address
    display_path = normalize_display_path(config.display_path)
    tailnet_session: TailnetServeSession | None = None
    preview_opened = False
    try:
        if config.tailnet_port is not None:
            tailnet_session = start_tailnet_serve(port, config.tailnet_port)
            url = tailnet_session.url(display_path)
        else:
            url = f"http://{host}:{port}{display_path}"

        write_event(
            "agent.preview_open",
            kind=EventKind.AGENT,
            severity=Severity.LOW,
            summary=f"Preview opened for {config.agent}:127.0.0.1:{config.guest_port}",
            agent=config.agent,
            addon="agent-preview",
            details={
                "agent": config.agent,
                "guest_port": config.guest_port,
                "host": host,
                "host_port": port,
                "tailnet_port": config.tailnet_port,
            },
        )
        preview_opened = True

        print("Tailnet preview:" if tailnet_session else "Preview open:")
        print(f"  {url}")
        print("Unlock code:")
        print(f"  {unlock_code}")
        print("Agent:")
        print(f"  {config.agent} -> 127.0.0.1:{config.guest_port}")
        print("Press Ctrl-C to close.")

        if config.open_browser:
            try:
                webbrowser.open(url)
            except Exception as exc:  # noqa: BLE001 - webbrowser.open can raise anything
                # webbrowser.get() dispatches to platform-specific launchers
                # (BROWSER env, xdg-open, /usr/bin/open, ...). Any of them can
                # be missing or broken; that must not take down the preview.
                print(
                    f"Could not open browser automatically: {exc}",
                    file=sys.stderr,
                )

        if tailnet_session:

            def watch_tailnet_serve() -> None:
                tailnet_session.process.wait()
                if not tailnet_session.closing:
                    server.shutdown()

            threading.Thread(target=watch_tailnet_serve, daemon=True).start()
        if config.ttl_seconds:
            timer = threading.Timer(config.ttl_seconds, server.shutdown)
            timer.daemon = True
            timer.start()
        with _shutdown_on_signals(server):
            server.serve_forever()
        if tailnet_session and tailnet_session.process.poll() is not None:
            output = tailnet_session.read_output()
            suffix = f": {output}" if output else ""
            print(
                f"Tailscale Serve stopped unexpectedly (exit {tailnet_session.process.returncode}){suffix}",
                file=sys.stderr,
            )
            return 1
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        # Each cleanup step is independent: a failure in one must not skip
        # the others. Previously a raise from tailnet_session.close() would
        # leak the server socket and drop the audit event, and a raise from
        # server.server_close() would drop the audit event.
        if tailnet_session:
            try:
                tailnet_session.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                log.exception("preview tailnet close failed")
        try:
            server.server_close()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            log.exception("preview server close failed")
        if preview_opened:
            try:
                write_event(
                    "agent.preview_close",
                    kind=EventKind.AGENT,
                    severity=Severity.LOW,
                    summary=f"Preview closed for {config.agent}:127.0.0.1:{config.guest_port}",
                    agent=config.agent,
                    addon="agent-preview",
                    details={
                        "agent": config.agent,
                        "guest_port": config.guest_port,
                        "host_port": port,
                        "tailnet_port": config.tailnet_port,
                    },
                )
            except Exception:  # noqa: BLE001 - auditing must not mask exit path
                log.exception("preview close event write failed")
