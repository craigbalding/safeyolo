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
        # Shared lower-case constant (issue #213 review) — same string
        # used by both the audit event and the trace step reason.
        assert kwargs["details"]["reason_code"] == "probe_reached_upstream"

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


class TestErrorHookBridgesToTrace:
    """server_connect has no HTTPFlow — the audit event is not
    correlatable via /trace on its own. `error(flow)` runs when the
    resulting connection abort surfaces as a flow error, and gives us
    a real HTTPFlow to record trace evidence against. Issue #213
    review: doctor must be able to correlate probe failures
    deterministically through /trace.
    """

    def _flow(self, host=PROBE_HOST):
        from mitmproxy import http as mitm_http
        from mitmproxy.test import tflow

        flow = tflow.tflow()
        flow.request.host = host
        flow.metadata["trace"] = True
        # Agent must be set for the trace store's agent-scoped read
        # (issue #213 A-series: /trace refuses foreign records).
        flow.metadata["agent"] = "test-agent"
        # Simulate the transport-error surface mitmproxy would set
        # after server_connect's data.server.error triggers.
        flow.error = mitm_http.HTTPFlow  # any non-None marker; type is what we log
        return flow

    def test_error_records_trace_step_for_probe_flow(self):
        from safeyolo.core.trace import get_store, reset_store_for_tests

        reset_store_for_tests()
        from transport_guard import TransportGuard

        flow = self._flow()
        with patch("transport_guard.write_event"):
            TransportGuard().error(flow)

        rid = flow.metadata.get("request_id")
        assert rid is not None, "error() must ensure a request_id via ensure_request_id"

        rec = get_store().get(rid, flow.metadata.get("agent"))
        assert rec is not None, "trace step must be recorded so /trace can correlate"
        step = rec.steps[-1]
        assert step.addon == "transport-guard"
        assert step.state == "error"
        # Shared lower-case reason constant — matches the DAG YAML.
        assert step.reason == "probe_reached_upstream"

    def test_error_hook_ignores_non_probe_flow(self):
        """A non-probe host flow that errors must not produce a trace
        step for transport-guard — this hook is scoped strictly to the
        reserved probe destination.
        """
        from safeyolo.core.trace import get_store, reset_store_for_tests

        reset_store_for_tests()
        from transport_guard import TransportGuard

        flow = self._flow(host="httpbin.org")
        with patch("transport_guard.write_event"):
            TransportGuard().error(flow)

        rid = flow.metadata.get("request_id")
        # ensure_request_id may or may not have run — either way, there
        # must be no transport-guard step in the trace.
        if rid:
            rec = get_store().get(rid, flow.metadata.get("agent"))
            if rec:
                assert not any(s.addon == "transport-guard" for s in rec.steps)

    def test_error_hook_stamps_request_id_header_on_response(self):
        """When mitmproxy synthesises an error response, transport-guard
        stamps X-SafeYolo-Request-Id on it so the originating agent can
        correlate to /trace. Issue #213 promises correlation on every
        SafeYolo-originated response.
        """
        from mitmproxy import http as mitm_http

        from safeyolo.core.trace import reset_store_for_tests

        reset_store_for_tests()
        from transport_guard import TransportGuard

        flow = self._flow()
        flow.response = mitm_http.Response.make(502, b"", {})
        with patch("transport_guard.write_event"):
            TransportGuard().error(flow)

        rid = flow.metadata.get("request_id")
        assert flow.response.headers.get("X-SafeYolo-Request-Id") == rid
