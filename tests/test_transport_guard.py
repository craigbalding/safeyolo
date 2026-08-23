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

    def test_error_hook_self_sufficient_when_request_hook_never_ran(self):
        """The critical regression the fourth-pass review flagged:
        on the early-connect path `server_connect` preempts
        `RequestIdGenerator.request()`, so neither the trace opt-in
        flag nor `flow.metadata["agent"]` is set before `error(flow)`
        fires. `record_step` would then silently no-op (its `is_traced`
        gate reads `flow.metadata["trace"]`) and any forced step would
        be unowned by any agent.

        This test builds a raw probe flow with the X-SafeYolo-Trace
        header + a trusted UnixMode agent, DOES NOT call
        `RequestIdGenerator.request()` first, and asserts the trace
        step is created AND readable via the agent-scoped store.
        """
        from unittest.mock import MagicMock

        from mitmproxy.test import tflow

        from safeyolo.core.trace import get_store, reset_store_for_tests

        reset_store_for_tests()
        from request_id import TRACE_REQUEST_HEADER
        from transport_guard import TransportGuard

        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        # Client-side opt-in header — the ONLY thing carrying trace
        # intent when RequestIdGenerator.request() didn't consume it.
        flow.request.headers[TRACE_REQUEST_HEADER] = "1"
        # Trusted agent lives on the connection-level UnixMode. Simulate
        # the shape `flow.client_conn.proxy_mode.agent`.
        flow.client_conn.proxy_mode = MagicMock()
        flow.client_conn.proxy_mode.agent = "trusted-uds-agent"
        # Deliberately NOT calling RequestIdGenerator.request — the
        # premise is that the request-hook was preempted.

        assert "trace" not in flow.metadata  # premise: no opt-in yet
        assert "agent" not in flow.metadata  # premise: no attribution yet

        flow.error = OSError("simulated: refused by transport_guard")
        from unittest.mock import patch as _patch
        with _patch("transport_guard.write_event"):
            TransportGuard().error(flow)

        # The hook recovered the opt-in from the request header.
        assert flow.metadata.get("trace") is True
        # Header stripped so it never reaches upstream (if this flow
        # were ever forwarded).
        assert TRACE_REQUEST_HEADER not in flow.request.headers
        # Trusted agent recovered from proxy_mode.
        assert flow.metadata.get("agent") == "trusted-uds-agent"
        # request_id assigned.
        rid = flow.metadata["request_id"]
        # Trace record exists AND is readable via the trusted agent
        # scope (agent-scoped store refuses foreign records).
        rec = get_store().get(rid, "trusted-uds-agent")
        assert rec is not None, (
            "trace step must be recorded even when RequestIdGenerator "
            "and service-discovery didn't run — else the transport-guard "
            "error would be invisible on early-connect."
        )
        step = rec.steps[-1]
        assert step.addon == "transport-guard"
        assert step.state == "error"
        assert step.reason == "probe_reached_upstream"

    def test_error_hook_synthesises_correlated_response_when_none_exists(self):
        """The critical V3-correlation regression (issue #213 sixth-pass
        review). In the real `ResponseProtocolError` path
        (`server_connect` refusal → `HttpErrorHook`), mitmproxy fires
        error(flow) with `flow.error` set but `flow.response` still None
        — then generates its own generic protocol-error response for the
        client. Without a correlated response the client (doctor,
        agent) has no request-id to hand to `/trace`.

        `error(flow)` must synthesise the response itself so the client
        always receives an X-SafeYolo-Request-Id header tying the
        failure to the trace record.
        """
        import json as _json

        from mitmproxy.test import tflow

        from safeyolo.core.trace import get_store, reset_store_for_tests

        reset_store_for_tests()
        from transport_guard import TransportGuard

        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        flow.metadata["trace"] = True
        flow.metadata["agent"] = "test-agent"
        # Simulate the real mitmproxy ResponseProtocolError shape:
        # flow.error is set, flow.response is None.
        flow.error = OSError("simulated: server_connect refused")
        flow.response = None

        with patch("transport_guard.write_event"):
            TransportGuard().error(flow)

        # The critical assertion: flow.response was created by the hook,
        # not by a pre-existing setup.
        assert flow.response is not None, (
            "error() must synthesise a downstream response when none "
            "exists — otherwise the client has no correlation to /trace"
        )
        rid = flow.metadata["request_id"]
        assert flow.response.headers.get("X-SafeYolo-Request-Id") == rid
        # Body should also carry the request_id and reason for grep-ability.
        body = _json.loads(flow.response.content)
        assert body["request_id"] == rid
        assert body["reason_code"] == "probe_reached_upstream"
        assert body["host"] == PROBE_HOST
        assert flow.response.status_code == 502

        # Trace record must be readable at the trusted-agent scope so
        # /trace returns it.
        rec = get_store().get(rid, "test-agent")
        assert rec is not None
        step = rec.steps[-1]
        assert step.addon == "transport-guard"
        assert step.state == "error"
        assert step.reason == "probe_reached_upstream"

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
