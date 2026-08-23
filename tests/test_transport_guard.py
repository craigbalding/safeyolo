"""Tests for transport_guard addon (#213 B3).

Defense-in-depth: even if probe_sink is missing/misordered/broken and
mitmproxy tries to open an upstream connection to the reserved probe
host, the transport guard refuses that connection locally and writes
a distinctive audit event. Doctor uses this event to fail loudly.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from safeyolo.core.probe import PROBE_HOST


def _addon():
    from transport_guard import REFUSAL_MESSAGE, TransportGuard
    return TransportGuard(), REFUSAL_MESSAGE


def _hook_data(
    server_host: str | None = None,
    server_port: int = 80,
    sni: str | None = None,
    client_ip: str = "10.0.0.42",
    agent: str | None = None,
) -> MagicMock:
    """Minimal fake `ServerConnectionHookData` for the guard's checks."""
    data = MagicMock()
    data.server.address = (server_host, server_port) if server_host else None
    data.server.error = None
    data.client.peername = (client_ip, 5555)
    data.client.sni = sni
    data.client.proxy_mode = MagicMock()
    data.client.proxy_mode.agent = agent
    return data


class TestRefusalForProbeHost:
    def test_refuses_when_server_address_is_probe_host(self):
        addon, refusal = _addon()
        data = _hook_data(server_host=PROBE_HOST, server_port=80)

        with patch("transport_guard.write_event") as mock_write:
            addon.server_connect(data)

        assert data.server.error == refusal
        mock_write.assert_called_once()
        kwargs = mock_write.call_args[1]
        assert mock_write.call_args[0][0] == "security.probe_reached_upstream"
        assert kwargs["details"]["reason_code"] == "PROBE_REACHED_UPSTREAM"

    def test_refuses_case_insensitively(self):
        """DNS names are case-insensitive — a manipulated Host header
        that alters the casing must not evade the guard."""
        addon, refusal = _addon()
        data = _hook_data(server_host="_SAFEYOLO.PROBE.INTERNAL")

        with patch("transport_guard.write_event"):
            addon.server_connect(data)

        assert data.server.error == refusal

    def test_refuses_when_sni_is_probe_host(self):
        """TLS/CONNECT paths route by SNI, not by data.server.address host.
        The guard reads both so a probe destination reached via a
        connect-then-TLS path can't slip past."""
        addon, refusal = _addon()
        data = _hook_data(server_host="unrelated.example.com", sni=PROBE_HOST)

        with patch("transport_guard.write_event"):
            addon.server_connect(data)

        assert data.server.error == refusal


class TestNoOpForNonProbeHosts:
    def test_ignores_normal_upstream(self):
        addon, _ = _addon()
        data = _hook_data(server_host="httpbin.org", server_port=443)

        with patch("transport_guard.write_event") as mock_write:
            addon.server_connect(data)

        assert data.server.error is None
        mock_write.assert_not_called()

    def test_ignores_missing_address_and_sni(self):
        """If mitmproxy hasn't resolved either yet, nothing to check —
        must not crash and must not refuse."""
        addon, _ = _addon()
        data = _hook_data(server_host=None, sni=None)
        data.server.address = None

        with patch("transport_guard.write_event") as mock_write:
            addon.server_connect(data)

        assert data.server.error is None
        mock_write.assert_not_called()


class TestAuditEventShape:
    def test_event_carries_client_ip_and_agent(self):
        addon, _ = _addon()
        data = _hook_data(server_host=PROBE_HOST, client_ip="10.9.8.7", agent="test-agent")

        with patch("transport_guard.write_event") as mock_write:
            addon.server_connect(data)

        kwargs = mock_write.call_args[1]
        assert kwargs["agent"] == "test-agent"
        assert kwargs["details"]["client_ip"] == "10.9.8.7"
        assert kwargs["host"] == PROBE_HOST

    def test_event_severity_critical(self):
        """Probe reaching upstream means the sink layer failed — that's
        a critical operator-facing event, not informational."""
        from safeyolo.core.audit_schema import Severity

        addon, _ = _addon()
        data = _hook_data(server_host=PROBE_HOST)

        with patch("transport_guard.write_event") as mock_write:
            addon.server_connect(data)

        assert mock_write.call_args[1]["severity"] == Severity.CRITICAL
