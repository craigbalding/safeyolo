"""
Tests for the memory_monitor addon.

The memory_monitor tracks active connections and WebSocket sessions
for OOM diagnostics. All tracked state must self-clean on disconnect.

Connection hooks (client_connected/client_disconnected) need manual
Client object creation since taddons.context doesn't dispatch them directly.
"""

import time
from unittest.mock import patch

from memory_monitor import ConnInfo, MemoryMonitor, WsInfo
from mitmproxy import connection
from mitmproxy.test import tflow


def _addon():
    return MemoryMonitor()


def _make_client(client_id="test-client-1"):
    """Create a minimal Client object for connection hook tests."""
    client = connection.Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=time.time(),
        state=connection.ConnectionState.OPEN,
    )
    # Override the auto-generated id for deterministic tests
    object.__setattr__(client, "id", client_id)
    return client


class TestClientConnected:
    """Tests for client_connected hook."""

    def test_client_connected_tracked(self):
        """New connection is tracked in _connections dict."""
        addon = _addon()
        client = _make_client("conn-1")

        addon.client_connected(client)

        assert "conn-1" in addon._connections
        info = addon._connections["conn-1"]
        assert info.domain is None
        assert info.flow_count == 0
        assert info.bytes_sent == 0
        assert info.bytes_received == 0

    def test_multiple_connections_tracked(self):
        """Multiple concurrent connections are all tracked."""
        addon = _addon()

        for idx in range(5):
            client = _make_client(f"conn-{idx}")
            addon.client_connected(client)

        assert len(addon._connections) == 5


class TestClientDisconnected:
    """Tests for client_disconnected hook."""

    def test_client_disconnected_cleaned(self):
        """Disconnected client is removed from _connections."""
        addon = _addon()
        client = _make_client("conn-1")

        addon.client_connected(client)
        assert "conn-1" in addon._connections

        addon.client_disconnected(client)
        assert "conn-1" not in addon._connections

    def test_disconnect_unknown_client_safe(self):
        """Disconnecting unknown client doesn't raise."""
        addon = _addon()
        client = _make_client("unknown")

        # Should not raise
        addon.client_disconnected(client)

    def test_self_cleaning_after_connect_disconnect(self):
        """After connect+disconnect cycle, _connections is empty."""
        addon = _addon()

        for idx in range(10):
            client = _make_client(f"conn-{idx}")
            addon.client_connected(client)

        for idx in range(10):
            client = _make_client(f"conn-{idx}")
            addon.client_disconnected(client)

        assert len(addon._connections) == 0


class TestRequestTracking:
    """Tests for request hook."""

    def test_request_increments_flow_count(self):
        """Request increments flow_count on connection."""
        addon = _addon()
        addon._last_event_time = time.time()  # Prevent periodic event

        flow = tflow.tflow()
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.request(flow)

        assert addon._connections[conn_id].flow_count == 1
        assert addon._total_flows == 1

    def test_request_sets_domain(self):
        """First request on connection sets domain."""
        addon = _addon()
        addon._last_event_time = time.time()

        flow = tflow.tflow()
        flow.request.url = "http://api.openai.com/v1/chat"
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.request(flow)

        assert addon._connections[conn_id].domain == "api.openai.com"

    def test_request_tracks_bytes_sent(self):
        """Request body size is tracked."""
        addon = _addon()
        addon._last_event_time = time.time()

        flow = tflow.tflow()
        flow.request.content = b"x" * 100
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.request(flow)

        assert addon._connections[conn_id].bytes_sent == 100

    def test_request_no_content_safe(self):
        """Request with None content doesn't crash."""
        addon = _addon()
        addon._last_event_time = time.time()

        flow = tflow.tflow()
        flow.request.content = None
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.request(flow)

        assert addon._connections[conn_id].bytes_sent == 0

    def test_domain_set_on_first_request_not_overwritten(self):
        """Domain is set on first request and preserved on subsequent requests to different hosts."""
        addon = _addon()
        addon._last_event_time = time.time()

        flow1 = tflow.tflow()
        flow1.request.url = "http://first.example.com/v1"
        conn_id = flow1.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.request(flow1)
        assert addon._connections[conn_id].domain == "first.example.com"

        # Second request on same connection to different host
        flow2 = tflow.tflow()
        flow2.request.url = "http://second.example.com/v2"
        # Reuse same client_conn id
        object.__setattr__(flow2.client_conn, "id", conn_id)

        addon.request(flow2)
        assert addon._connections[conn_id].domain == "first.example.com"

    def test_request_unknown_connection_safe(self):
        """Request for unknown connection doesn't crash."""
        addon = _addon()
        addon._last_event_time = time.time()

        flow = tflow.tflow()
        # Don't add to _connections

        addon.request(flow)  # Should not raise

        assert addon._total_flows == 1


class TestResponseTracking:
    """Tests for response hook."""

    def test_response_tracks_bytes(self):
        """Non-streaming response bytes are tracked."""
        addon = _addon()

        flow = tflow.tflow(resp=True)
        flow.response.content = b"y" * 200
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.response(flow)

        assert addon._connections[conn_id].bytes_received == 200

    def test_streaming_response_no_bytes(self):
        """Streaming response bytes are NOT counted."""
        addon = _addon()

        flow = tflow.tflow(resp=True)
        flow.response.content = b"z" * 500
        flow.response.stream = True
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        addon.response(flow)

        assert addon._connections[conn_id].bytes_received == 0

    def test_no_response_safe(self):
        """Flow without response doesn't crash."""
        addon = _addon()

        flow = tflow.tflow()
        flow.response = None

        addon.response(flow)  # Should not raise


class TestWebSocketLifecycle:
    """Tests for WebSocket hooks."""

    def test_websocket_lifecycle(self):
        """Full WS lifecycle: start -> messages -> end, with cleanup."""
        addon = _addon()

        flow = tflow.tflow()
        flow.request.url = "http://ws.example.com/stream"
        conn_id = flow.client_conn.id

        # Start
        addon.websocket_start(flow)
        assert conn_id in addon._ws_sessions
        info = addon._ws_sessions[conn_id]
        assert info.domain == "ws.example.com"
        assert info.message_count == 0

        # Messages
        addon.websocket_message(flow)
        addon.websocket_message(flow)
        addon.websocket_message(flow)
        assert addon._ws_sessions[conn_id].message_count == 3

        # End - should clean up
        addon.websocket_end(flow)
        assert conn_id not in addon._ws_sessions

    def test_websocket_end_unknown_safe(self):
        """Ending unknown WS session doesn't crash."""
        addon = _addon()
        flow = tflow.tflow()

        addon.websocket_end(flow)  # Should not raise

    def test_websocket_message_unknown_safe(self):
        """Message on unknown WS session doesn't crash."""
        addon = _addon()
        flow = tflow.tflow()

        addon.websocket_message(flow)  # Should not raise


class TestGetStats:
    """Tests for get_stats() admin API method."""

    def test_get_stats_structure(self):
        """get_stats() returns correct values for empty addon."""
        addon = _addon()
        addon._started = time.time()

        stats = addon.get_stats()

        assert stats["rss_start_mb"] == 0.0
        assert stats["total_flows"] == 0
        assert stats["active_connections"] == 0
        assert stats["connections"] == []
        assert stats["active_websockets"] == 0
        assert stats["websockets"] == []
        assert stats["uptime_s"] == 0
        # rss_mb and rss_hwm_mb come from /proc so just check type
        assert isinstance(stats["rss_mb"], float)
        assert isinstance(stats["rss_hwm_mb"], float)

    def test_get_stats_with_connections(self):
        """get_stats() includes connection details."""
        addon = _addon()
        addon._started = time.time()

        # Add a connection with some activity
        addon._connections["test-conn"] = _make_conn_info(
            domain="api.example.com",
            flow_count=42,
            bytes_sent=1000,
            bytes_received=5000,
        )

        stats = addon.get_stats()

        assert stats["active_connections"] == 1
        assert len(stats["connections"]) == 1
        conn = stats["connections"][0]
        assert conn["domain"] == "api.example.com"
        assert conn["flows"] == 42
        assert conn["bytes_sent"] == 1000
        assert conn["bytes_received"] == 5000

    def test_get_stats_connections_limited_to_10(self):
        """get_stats() returns at most 10 connections."""
        addon = _addon()
        addon._started = time.time()

        for idx in range(15):
            addon._connections[f"conn-{idx}"] = _make_conn_info(
                domain=f"host-{idx}.example.com",
                flow_count=idx,
            )

        stats = addon.get_stats()
        assert len(stats["connections"]) == 10

    def test_get_stats_connections_sorted_by_flow_count(self):
        """get_stats() sorts connections by flow_count descending."""
        addon = _addon()
        addon._started = time.time()

        addon._connections["low"] = _make_conn_info(domain="low.com", flow_count=1)
        addon._connections["high"] = _make_conn_info(domain="high.com", flow_count=100)
        addon._connections["mid"] = _make_conn_info(domain="mid.com", flow_count=50)

        stats = addon.get_stats()
        domains = [c["domain"] for c in stats["connections"]]
        assert domains == ["high.com", "mid.com", "low.com"]

    def test_get_stats_with_websockets(self):
        """get_stats() includes WebSocket session details."""
        addon = _addon()
        addon._started = time.time()

        addon._ws_sessions["ws-1"] = WsInfo(
            domain="ws.example.com",
            started=time.time() - 120,
            message_count=50,
        )

        stats = addon.get_stats()

        assert stats["active_websockets"] == 1
        assert len(stats["websockets"]) == 1
        ws = stats["websockets"][0]
        assert ws["domain"] == "ws.example.com"
        assert ws["messages"] == 50


class TestPeriodicEvent:
    """Tests for periodic ops.memory event emission."""

    def test_periodic_event_after_60s(self):
        """ops.memory event is written after 60s threshold."""
        addon = _addon()
        addon._last_event_time = time.time() - 61  # 61 seconds ago

        flow = tflow.tflow()
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        with patch("memory_monitor.write_event") as mock_write:
            addon.request(flow)

            # Should have emitted periodic event
            calls = [c for c in mock_write.call_args_list if c[0][0] == "ops.memory"]
            assert len(calls) == 1
            kwargs = calls[0][1]
            details = kwargs.get("details", {})
            assert "rss_mb" in details
            assert "active_connections" in details
            assert "total_flows" in details

    def test_no_periodic_event_before_60s(self):
        """ops.memory event is NOT written before 60s threshold."""
        addon = _addon()
        addon._last_event_time = time.time()  # Just now

        flow = tflow.tflow()
        conn_id = flow.client_conn.id
        addon._connections[conn_id] = _make_conn_info()

        with patch("memory_monitor.write_event") as mock_write:
            addon.request(flow)

            # Should NOT have emitted periodic event
            calls = [c for c in mock_write.call_args_list if c[0][0] == "ops.memory"]
            assert len(calls) == 0


class TestProcMemory:
    """Tests for /proc/self/status reading."""

    def test_proc_memory_read(self):
        """_read_proc_memory() returns positive values on Linux with peak >= rss."""
        from memory_monitor import _read_proc_memory

        rss_kb, peak_kb = _read_proc_memory()

        # On Linux (where tests run), both values should be positive
        assert rss_kb > 0
        assert peak_kb >= rss_kb


# ---- Helpers ----


def _make_conn_info(
    domain: str | None = None,
    flow_count: int = 0,
    bytes_sent: int = 0,
    bytes_received: int = 0,
) -> ConnInfo:
    """Create a ConnInfo for testing."""
    return ConnInfo(
        domain=domain,
        started=time.time(),
        flow_count=flow_count,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )
