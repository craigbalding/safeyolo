"""
memory_monitor.py - Process memory and connection state observability

Tracks active connections and WebSocket sessions to identify WHERE memory
is going (per-domain, per-connection). All state is self-cleaning:
connections are removed on disconnect, WS sessions on close.

Process memory is read from /proc/self/status (zero stored state).
Periodic ops.memory events are written at 60s intervals for post-mortem analysis.

Does NOT inherit SecurityAddon - this is infrastructure, not a security sensor.
Follows the simpler LoopGuard/AdminShield pattern.

Always on, no option to disable.

Usage:
    mitmdump -s addons/memory_monitor.py
"""

import logging
import time
from dataclasses import dataclass

from mitmproxy import connection, http

from safeyolo.core.audit_schema import EventKind, Severity
from safeyolo.core.utils import sanitize_for_log, write_event

log = logging.getLogger("safeyolo.memory-monitor")


def _read_proc_memory() -> tuple[int, int]:
    """Read VmRSS and VmHWM from /proc/self/status. Returns (rss_kb, hwm_kb).

    VmHWM (High Water Mark) is the peak *resident* memory.
    VmPeak is peak *virtual* memory (includes mmap, shared libs) - misleading for OOM analysis.
    """
    rss_kb = hwm_kb = 0
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                elif line.startswith("VmHWM:"):
                    hwm_kb = int(line.split()[1])
    except (OSError, ValueError) as exc:
        log.debug(f"Failed to read /proc/self/status: {type(exc).__name__}: {exc}")
    return rss_kb, hwm_kb


@dataclass
class ConnInfo:
    """Tracks a single client connection. Removed on disconnect."""

    domain: str | None  # Set on first request (unknown at connect time)
    started: float  # time.time() at connection open
    flow_count: int = 0  # Incremented on each request
    bytes_sent: int = 0  # Request body sizes
    bytes_received: int = 0  # Response body sizes (non-streaming only)


@dataclass
class WsInfo:
    """Tracks a single WebSocket session. Removed on ws_end."""

    domain: str
    started: float
    message_count: int = 0  # Just a counter, NOT the messages


class MemoryMonitor:
    """Track process memory and active connection state for OOM diagnostics."""

    name = "memory-monitor"

    def __init__(self):
        self._connections: dict[str, ConnInfo] = {}
        self._ws_sessions: dict[str, WsInfo] = {}
        self._rss_start_kb: int = 0
        self._started: float = 0.0
        self._last_event_time: float = 0.0
        self._total_flows: int = 0

    def running(self):
        """Capture baseline memory at startup."""
        self._rss_start_kb, _ = _read_proc_memory()
        self._started = time.time()
        self._last_event_time = time.time()
        write_event(
            "ops.startup",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary=f"Memory monitor started (baseline RSS: {self._rss_start_kb // 1024} MB)",
            addon=self.name,
            details={"rss_start_mb": round(self._rss_start_kb / 1024, 1)},
        )
        log.info(f"Memory monitor active (baseline RSS: {self._rss_start_kb // 1024} MB)")

    def client_connected(self, client: connection.Client):
        """Track new client connection."""
        self._connections[client.id] = ConnInfo(
            domain=None,
            started=time.time(),
        )

    def client_disconnected(self, client: connection.Client):
        """Clean up connection tracking on disconnect."""
        info = self._connections.pop(client.id, None)
        if info and info.flow_count > 0:
            lifetime = int(time.time() - info.started)
            domain = info.domain or "(unknown)"
            write_event(
                "ops.memory.conn_closed",
                kind=EventKind.OPS,
                severity=Severity.LOW,
                summary=f"Connection closed: {sanitize_for_log(domain)} ({info.flow_count} flows, {lifetime}s)",
                host=domain if info.domain else None,
                addon=self.name,
                details={
                    "flow_count": info.flow_count,
                    "lifetime_s": lifetime,
                    "bytes_sent": info.bytes_sent,
                    "bytes_received": info.bytes_received,
                },
            )

    def request(self, flow: http.HTTPFlow):
        """Track request on connection, emit periodic memory event."""
        self._total_flows += 1

        conn_id = flow.client_conn.id
        info = self._connections.get(conn_id)
        if info:
            info.flow_count += 1
            if info.domain is None:
                info.domain = flow.request.host
            info.bytes_sent += len(flow.request.content or b"")

        # Periodic memory event (at most once per 60s)
        now = time.time()
        if now - self._last_event_time >= 60:
            self._last_event_time = now
            self._emit_periodic_event(now)

    def response(self, flow: http.HTTPFlow):
        """Track response bytes (non-streaming only)."""
        if not flow.response:
            return
        if getattr(flow.response, "stream", False):
            return

        conn_id = flow.client_conn.id
        info = self._connections.get(conn_id)
        if info:
            info.bytes_received += len(flow.response.content or b"")

    def websocket_start(self, flow: http.HTTPFlow):
        """Track WebSocket session start."""
        conn_id = flow.client_conn.id
        self._ws_sessions[conn_id] = WsInfo(
            domain=flow.request.host,
            started=time.time(),
        )

    def websocket_message(self, flow: http.HTTPFlow):
        """Count WebSocket messages (do NOT store them)."""
        conn_id = flow.client_conn.id
        info = self._ws_sessions.get(conn_id)
        if info:
            info.message_count += 1

    def websocket_end(self, flow: http.HTTPFlow):
        """Clean up WebSocket session tracking."""
        conn_id = flow.client_conn.id
        info = self._ws_sessions.pop(conn_id, None)
        if info:
            lifetime = int(time.time() - info.started)
            write_event(
                "ops.memory.ws_closed",
                kind=EventKind.OPS,
                severity=Severity.LOW,
                summary=f"WebSocket closed: {sanitize_for_log(info.domain)} ({info.message_count} msgs, {lifetime}s)",
                host=info.domain,
                addon=self.name,
                details={
                    "message_count": info.message_count,
                    "lifetime_s": lifetime,
                },
            )

    def _emit_periodic_event(self, now: float):
        """Write ops.memory event with current state snapshot."""
        rss_kb, peak_kb = _read_proc_memory()
        top_connections = sorted(
            self._connections.values(),
            key=lambda c: c.flow_count,
            reverse=True,
        )[:10]

        rss_mb = round(rss_kb / 1024, 1)
        write_event(
            "ops.memory",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary=f"RSS {rss_mb}MB, {len(self._connections)} conns, {self._total_flows} flows",
            addon=self.name,
            details={
                "rss_mb": rss_mb,
                "rss_hwm_mb": round(peak_kb / 1024, 1),
                "rss_start_mb": round(self._rss_start_kb / 1024, 1),
                "active_connections": len(self._connections),
                "active_websockets": len(self._ws_sessions),
                "total_flows": self._total_flows,
                "top_connections": [
                    {
                        "domain": conn.domain or "(unknown)",
                        "flows": conn.flow_count,
                        "age_s": int(now - conn.started),
                    }
                    for conn in top_connections
                ],
            },
        )

    def get_stats(self) -> dict:
        """Return memory and connection stats for admin API."""
        rss_kb, peak_kb = _read_proc_memory()
        now = time.time()

        connections = []
        for info in sorted(self._connections.values(), key=lambda c: c.flow_count, reverse=True):
            connections.append({
                "domain": info.domain or "(unknown)",
                "flows": info.flow_count,
                "age_s": int(now - info.started),
                "bytes_sent": info.bytes_sent,
                "bytes_received": info.bytes_received,
            })

        ws_sessions = []
        for info in self._ws_sessions.values():
            ws_sessions.append({
                "domain": info.domain,
                "messages": info.message_count,
                "age_s": int(now - info.started),
            })

        return {
            "rss_mb": round(rss_kb / 1024, 1),
            "rss_hwm_mb": round(peak_kb / 1024, 1),
            "rss_start_mb": round(self._rss_start_kb / 1024, 1),
            "uptime_s": int(now - self._started) if self._started else 0,
            "total_flows": self._total_flows,
            "active_connections": len(self._connections),
            "connections": connections[:10],
            "active_websockets": len(self._ws_sessions),
            "websockets": ws_sessions,
        }


addons = [MemoryMonitor()]
