"""Audit connection metadata for traffic that bypasses TLS inspection."""

import re
import time
from dataclasses import dataclass

from mitmproxy import ctx
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from safeyolo.core.audit_schema import EventKind, Severity
from safeyolo.core.utils import sanitize_for_log, write_event


@dataclass
class _PassthroughSession:
    host: str
    port: int
    started_at: float
    connected: bool = False


class IgnoredHostLogger:
    """Emit lifecycle events for connections matching ``ignore_hosts``."""

    name = "ignored-host-logger"

    def __init__(self) -> None:
        self._sessions: dict[str, _PassthroughSession] = {}

    @staticmethod
    def _candidates(data: ServerConnectionHookData) -> list[tuple[str, int]]:
        candidates: list[tuple[str, int]] = []
        if data.server.peername:
            candidates.append(data.server.peername)
        if data.server.address:
            candidates.append(data.server.address)
        if data.client.sni and data.server.address:
            candidates.append((data.client.sni, data.server.address[1]))
        return list(dict.fromkeys(candidates))

    @classmethod
    def _matched_destination(
        cls, data: ServerConnectionHookData
    ) -> tuple[str, int] | None:
        patterns = getattr(ctx.options, "ignore_hosts", ())
        for host, port in cls._candidates(data):
            destination = f"{host}:{port}"
            for pattern in patterns:
                try:
                    if re.search(pattern, destination, re.IGNORECASE):
                        return host, port
                except re.error:
                    continue
        return None

    @staticmethod
    def _agent(data: ServerConnectionHookData) -> str | None:
        return getattr(data.client.proxy_mode, "agent", None)

    @staticmethod
    def _client_ip(data: ServerConnectionHookData) -> str | None:
        return data.client.peername[0] if data.client.peername else None

    def server_connect(self, data: ServerConnectionHookData) -> None:
        destination = self._matched_destination(data)
        if destination is None:
            return
        host, port = destination
        self._sessions[data.server.id] = _PassthroughSession(
            host=host,
            port=port,
            started_at=time.monotonic(),
        )

    def server_connected(self, data: ServerConnectionHookData) -> None:
        session = self._sessions.get(data.server.id)
        if session is None:
            return
        session.connected = True
        write_event(
            "traffic.passthrough_start",
            kind=EventKind.TRAFFIC,
            severity=Severity.MEDIUM,
            summary=f"TLS passthrough connected to {sanitize_for_log(session.host)}:{session.port}",
            host=session.host,
            agent=self._agent(data),
            addon=self.name,
            details={
                "port": session.port,
                "transport": data.server.transport_protocol,
                "client": self._client_ip(data),
            },
        )

    def server_connect_error(self, data: ServerConnectionHookData) -> None:
        session = self._sessions.pop(data.server.id, None)
        if session is None:
            return
        write_event(
            "traffic.passthrough_error",
            kind=EventKind.TRAFFIC,
            severity=Severity.MEDIUM,
            summary=f"TLS passthrough failed for {sanitize_for_log(session.host)}:{session.port}",
            host=session.host,
            agent=self._agent(data),
            addon=self.name,
            details={
                "port": session.port,
                "transport": data.server.transport_protocol,
                "client": self._client_ip(data),
                "error": sanitize_for_log(data.server.error),
            },
        )

    def server_disconnected(self, data: ServerConnectionHookData) -> None:
        session = self._sessions.pop(data.server.id, None)
        if session is None or not session.connected:
            return
        duration_ms = max(0, round((time.monotonic() - session.started_at) * 1000))
        write_event(
            "traffic.passthrough_end",
            kind=EventKind.TRAFFIC,
            severity=Severity.LOW,
            summary=f"TLS passthrough disconnected from {sanitize_for_log(session.host)}:{session.port}",
            host=session.host,
            agent=self._agent(data),
            addon=self.name,
            details={
                "port": session.port,
                "transport": data.server.transport_protocol,
                "client": self._client_ip(data),
                "duration_ms": duration_ms,
            },
        )


addons = [IgnoredHostLogger()]
