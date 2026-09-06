"""Non-blocking Admin API and WebSocket client for the Qt application."""

from __future__ import annotations

import json
import threading
from urllib.parse import urlsplit, urlunsplit

from PySide6.QtCore import QByteArray, QObject, QTimer, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from PySide6.QtWebSockets import QWebSocket

from safeyolo.api import AdminAPI
from safeyolo.core.audit_stream import approval_dedup_key
from safeyolo.operator_approvals import approve, deny


def default_event_url(admin_url: str, events_port: int) -> str:
    """Derive a loopback WebSocket endpoint from the Admin API URL."""
    parts = urlsplit(admin_url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    hostname = parts.hostname or "127.0.0.1"
    return urlunsplit((scheme, f"{hostname}:{events_port}", "/admin/events", "", ""))


class SafeYoloClient(QObject):
    """Qt event-loop client for one SafeYolo instance."""

    instance_loaded = Signal(object)
    approvals_loaded = Signal(object)
    event_received = Signal(object)
    connection_changed = Signal(bool)
    action_finished = Signal(str, bool, object)
    error = Signal(str)
    _refresh_requested = Signal()

    def __init__(
        self,
        *,
        admin_url: str,
        events_url: str,
        token: str,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.admin_url = admin_url.rstrip("/")
        self.events_url = events_url
        self.token = token
        self._network = QNetworkAccessManager(self)
        self._websocket = QWebSocket(parent=self)
        self._stopping = False
        self._reconnect = QTimer(self)
        self._reconnect.setSingleShot(True)
        self._reconnect.setInterval(1000)
        self._reconnect.timeout.connect(self._open_websocket)
        self._websocket.connected.connect(self._connected)
        self._websocket.disconnected.connect(self._disconnected)
        self._websocket.textMessageReceived.connect(self._message_received)
        self._websocket.errorOccurred.connect(lambda _error: self.error.emit(self._websocket.errorString()))
        self._refresh_requested.connect(self.refresh_approvals)

    def start(self) -> None:
        self._stopping = False
        self.refresh_instance()
        self.refresh_approvals()
        self._open_websocket()

    def stop(self) -> None:
        self._stopping = True
        self._reconnect.stop()
        self._websocket.close()

    def _request(self, path: str, callback) -> None:
        request = QNetworkRequest(QUrl(f"{self.admin_url}{path}"))
        request.setRawHeader(
            QByteArray(b"Authorization"),
            QByteArray(f"Bearer {self.token}".encode()),
        )
        reply = self._network.get(request)
        reply.finished.connect(lambda: self._read_reply(reply, callback))

    def _read_reply(self, reply: QNetworkReply, callback) -> None:
        try:
            if reply.error() != QNetworkReply.NetworkError.NoError:
                self.error.emit(reply.errorString())
                return
            callback(json.loads(bytes(reply.readAll())))
        except (TypeError, ValueError) as exc:
            self.error.emit(f"Invalid Admin API response: {exc}")
        finally:
            reply.deleteLater()

    def refresh_instance(self) -> None:
        self._request("/admin/instance", self.instance_loaded.emit)

    def refresh_approvals(self) -> None:
        self._request(
            "/admin/approvals",
            lambda payload: self.approvals_loaded.emit(payload.get("approvals", [])),
        )

    def _open_websocket(self) -> None:
        request = QNetworkRequest(QUrl(self.events_url))
        request.setRawHeader(
            QByteArray(b"Authorization"),
            QByteArray(f"Bearer {self.token}".encode()),
        )
        self._websocket.open(request)

    def _connected(self) -> None:
        self.connection_changed.emit(True)
        self.refresh_approvals()

    def _disconnected(self) -> None:
        self.connection_changed.emit(False)
        if not self._stopping:
            self._reconnect.start()

    def _message_received(self, message: str) -> None:
        try:
            event = json.loads(message)
        except json.JSONDecodeError:
            self.error.emit("Invalid event received from SafeYolo")
            return
        self.event_received.emit(event)
        if event.get("approval", {}).get("required") or event.get("event", "").startswith("admin."):
            self.refresh_approvals()

    def resolve(
        self,
        event: dict,
        *,
        allow: bool,
        service_credential: str | None = None,
    ) -> None:
        """Resolve without blocking the Qt event loop."""
        key = approval_dedup_key(event)

        def mutate() -> None:
            try:
                api = AdminAPI(base_url=self.admin_url, token=self.token)
                if allow:
                    result = approve(
                        event,
                        api,
                        service_credential=service_credential,
                    )
                    message = result or "Approved"
                else:
                    deny(event, api)
                    message = "Denied"
                self.action_finished.emit(key, True, message)
                self._refresh_requested.emit()
            except Exception as exc:
                self.action_finished.emit(key, False, str(exc))

        threading.Thread(target=mutate, daemon=True, name="operator-action").start()
