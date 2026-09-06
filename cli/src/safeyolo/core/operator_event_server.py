"""Authenticated live audit-event hints for trusted operator clients."""

from __future__ import annotations

import http
import json
import logging
import secrets
import threading
from pathlib import Path
from typing import Any

from .audit_stream import AuditLineParser, follow_jsonl, resolved_approval_key

log = logging.getLogger("safeyolo.operator-events")


def is_operator_event(event: dict[str, Any]) -> bool:
    """Return whether an event belongs on the low-volume operator stream."""
    approval = event.get("approval", {})
    if approval.get("required"):
        return True
    if resolved_approval_key(event) is not None:
        return True

    event_type = event.get("event", "")
    if event_type.startswith("agent."):
        return True
    return event_type in {
        "ops.command_centre_tailnet_exited",
        "ops.command_centre_tailnet_failed",
        "ops.command_centre_tailnet_started",
        "ops.command_centre_tailnet_stopped",
        "ops.proxy_start",
        "ops.proxy_stop",
        "ops.proxy_start_failed",
    }


class OperatorEventServer:
    """Serve filtered AuditEvent objects over an authenticated WebSocket."""

    def __init__(
        self,
        *,
        log_path: Path,
        token: str,
        host: str = "127.0.0.1",
        port: int = 9091,
    ) -> None:
        self.log_path = log_path
        self.token = token
        self.host = host
        self.port = port
        self._stop = threading.Event()
        self._started = threading.Event()
        self._server = None
        self._thread: threading.Thread | None = None
        self._startup_error: BaseException | None = None

    def start(self) -> None:
        """Start the listener and wait until it has bound its socket."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="operator-event-server",
        )
        self._thread.start()
        if not self._started.wait(timeout=5):
            raise RuntimeError("operator event server did not start")
        if self._startup_error is not None:
            raise RuntimeError("operator event server failed to start") from self._startup_error

    def _run(self) -> None:
        try:
            from websockets.sync.server import serve

            def authenticate(connection, request):
                if request.path != "/admin/events":
                    return connection.respond(http.HTTPStatus.NOT_FOUND, "Not found\n")
                authorization = request.headers.get("Authorization", "")
                expected = f"Bearer {self.token}"
                if not secrets.compare_digest(authorization, expected):
                    return connection.respond(
                        http.HTTPStatus.UNAUTHORIZED,
                        "Missing or invalid Bearer token\n",
                    )
                try:
                    connection.safeyolo_audit_position = self.log_path.stat().st_size
                except OSError:
                    connection.safeyolo_audit_position = 0
                return None

            with serve(
                self._handle_connection,
                self.host,
                self.port,
                process_request=authenticate,
                server_header=None,
            ) as server:
                self._server = server
                self.port = server.socket.getsockname()[1]
                self._started.set()
                server.serve_forever()
        except BaseException as exc:
            self._startup_error = exc
            self._started.set()
            if not self._stop.is_set():
                log.exception("Operator event server stopped unexpectedly")

    def _handle_connection(self, connection) -> None:
        parser = AuditLineParser(on_schema_drift=lambda exc: log.warning("Audit schema drift: %s", exc))
        try:
            for event in follow_jsonl(
                self.log_path,
                parse_line=parser.parse,
                tick_interval=0.5,
                should_stop=self._stop.is_set,
                initial_position=getattr(connection, "safeyolo_audit_position", None),
            ):
                if event is not None and is_operator_event(event):
                    connection.send(json.dumps(event, separators=(",", ":")))
        except Exception as exc:
            if not self._stop.is_set():
                log.debug("Operator event client disconnected: %s", exc)

    def stop(self) -> None:
        """Stop the listener and connected stream handlers."""
        self._stop.set()
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
