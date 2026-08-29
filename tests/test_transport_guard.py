"""Tests for reserved-destination transport containment (#213, #398).

The probe and Agent API virtual hosts keep independent reason/audit contracts,
but neither may reach DNS or an upstream connection when its normal handler is
missing, disabled, or broken.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from mitmproxy import connection
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from safeyolo.core.probe import PROBE_HOST
from safeyolo.proxy_modes.unix_listener import UnixMode

pytestmark = pytest.mark.assurance_boundary


def _addon():
    from transport_guard import REFUSAL_MESSAGE, TransportGuard
    return TransportGuard(), REFUSAL_MESSAGE


def _hook_data(
    server_host: str | None = None,
    server_port: int = 80,
    sni: str | None = None,
    client_ip: str = "10.0.0.42",
    agent: str | None = None,
) -> ServerConnectionHookData:
    """Build real hook data with real mitmproxy connections and proxy mode."""
    proxy_mode = _unix_mode(client_ip, agent) if agent else None
    client_kwargs = {
        "peername": (client_ip, 5555),
        "sockname": ("127.0.0.1", 8080),
        "sni": sni,
    }
    if proxy_mode is not None:
        client_kwargs["proxy_mode"] = proxy_mode
    client = connection.Client(**client_kwargs)
    server = connection.Server(
        address=(server_host, server_port) if server_host else None,
    )
    return ServerConnectionHookData(server=server, client=client)


def _unix_mode(client_ip: str, agent: str) -> UnixMode:
    return UnixMode.parse(f"unix:/tmp/{client_ip}_{agent}/proxy.sock")


def _agent_api_flow(
    *,
    host: str = "_safeyolo.proxy.internal",
    path: str = "/health",
    token: str | None = None,
):
    from mitmproxy.test import tflow

    flow = tflow.tflow()
    flow.request.method = "GET"
    flow.request.url = f"http://{host}{path}"
    flow.request.host = host
    if token:
        flow.request.headers["authorization"] = f"Bearer {token}"
    return flow


class TestRefusalForProbeHost:
    def test_refuses_when_server_address_is_probe_host(self):
        addon, refusal = _addon()
        data = _hook_data(server_host=PROBE_HOST, server_port=80)

        with patch("transport_guard.write_event", autospec=True) as mock_write:
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

        with patch("transport_guard.write_event", autospec=True):
            addon.server_connect(data)

        assert data.server.error == refusal

    def test_refuses_when_sni_is_probe_host(self):
        """TLS/CONNECT paths route by SNI, not by data.server.address host.
        The guard reads both so a probe destination reached via a
        connect-then-TLS path can't slip past."""
        addon, refusal = _addon()
        data = _hook_data(server_host="unrelated.example.com", sni=PROBE_HOST)

        with patch("transport_guard.write_event", autospec=True):
            addon.server_connect(data)

        assert data.server.error == refusal


class TestNoOpForNonProbeHosts:
    def test_ignores_normal_upstream(self):
        addon, _ = _addon()
        data = _hook_data(server_host="httpbin.org", server_port=443)

        with patch("transport_guard.write_event", autospec=True) as mock_write:
            addon.server_connect(data)

        assert data.server.error is None
        mock_write.assert_not_called()

    def test_ignores_missing_address_and_sni(self):
        """No routing authority yet means there is nothing to refuse."""
        addon, _ = _addon()
        data = _hook_data(server_host=None, sni=None)
        data.server.address = None

        with patch("transport_guard.write_event", autospec=True) as mock_write:
            addon.server_connect(data)

        assert data.server.error is None
        mock_write.assert_not_called()


class TestAgentAPITransportRefusal:
    """The Agent API host has a distinct structural connect backstop."""

    @pytest.mark.parametrize(
        ("server_host", "sni"),
        [
            ("_safeyolo.proxy.internal", None),
            ("_SAFEYOLO.PROXY.INTERNAL", None),
            ("unrelated.example.com", "_sAfEyOlO.pRoXy.InTeRnAl"),
        ],
    )
    def test_refuses_address_and_sni_case_insensitively(self, server_host, sni):
        from transport_guard import AGENT_API_REFUSAL_MESSAGE, TransportGuard

        from safeyolo.core.internal_api import (
            AGENT_API_HOST,
            AGENT_API_REACHED_UPSTREAM_REASON,
        )

        data = _hook_data(server_host=server_host, server_port=443, sni=sni)
        with patch("transport_guard.write_event", autospec=True) as audit:
            TransportGuard().server_connect(data)

        assert data.server.error == AGENT_API_REFUSAL_MESSAGE
        audit.assert_called_once()
        assert audit.call_args.args[0] == "security.agent_api_reached_upstream"
        kwargs = audit.call_args.kwargs
        assert kwargs["host"] == AGENT_API_HOST
        assert kwargs["details"]["handler"] == "agent-api"
        assert (
            kwargs["details"]["reason_code"]
            == AGENT_API_REACHED_UPSTREAM_REASON
        )

    def test_audit_failure_cannot_undo_transport_refusal(self):
        from transport_guard import AGENT_API_REFUSAL_MESSAGE, TransportGuard

        data = _hook_data(server_host="_safeyolo.proxy.internal")
        with patch(
            "transport_guard.write_event",
            autospec=True,
            side_effect=OSError("audit unavailable"),
        ):
            TransportGuard().server_connect(data)

        assert data.server.error == AGENT_API_REFUSAL_MESSAGE

class TestAuditEventShape:
    def test_event_carries_client_ip_and_agent(self):
        addon, _ = _addon()
        data = _hook_data(server_host=PROBE_HOST, client_ip="10.9.8.7", agent="test-agent")

        with patch("transport_guard.write_event", autospec=True) as mock_write:
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

        with patch("transport_guard.write_event", autospec=True) as mock_write:
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
        with patch("transport_guard.write_event", autospec=True):
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
        with patch("transport_guard.write_event", autospec=True):
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
        flow.client_conn.proxy_mode = _unix_mode("10.0.0.42", "trusted-uds-agent")
        # Deliberately NOT calling RequestIdGenerator.request — the
        # premise is that the request-hook was preempted.

        assert "trace" not in flow.metadata  # premise: no opt-in yet
        assert "agent" not in flow.metadata  # premise: no attribution yet

        flow.error = OSError("simulated: refused by transport_guard")
        from unittest.mock import patch as _patch
        with _patch("transport_guard.write_event", autospec=True):
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

    def test_error_hook_does_NOT_synthesise_response_seventh_pass_review(self):
        """Reviewer's source check on mitmproxy 12.2.2 (seventh-pass
        review): setting `flow.response` from `error(flow)` does NOT
        reach the wire. `handle_protocol_error()` sends the raw
        `ResponseProtocolError` directly to the client without
        consulting `flow.response`.

        error() is now diagnostic-only: records the trace step, does
        NOT touch flow.response. The client-correlatable path is the
        request-hook failsafe covered in `TestRequestHookFailsafe`.
        """
        from mitmproxy.test import tflow

        from safeyolo.core.trace import reset_store_for_tests

        reset_store_for_tests()
        from transport_guard import TransportGuard

        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        flow.metadata["trace"] = True
        flow.metadata["agent"] = "test-agent"
        flow.error = OSError("simulated: server_connect refused")
        flow.response = None

        with patch("transport_guard.write_event", autospec=True):
            TransportGuard().error(flow)

        # Must NOT synthesise — that would be dishonest, since mitmproxy
        # 12.2.2 wouldn't deliver it. Response synthesis moved to
        # request(flow) where it actually works.
        assert flow.response is None, (
            "error() must NOT synthesise flow.response — mitmproxy "
            "12.2.2's handle_protocol_error() does not consult it. "
            "See TestRequestHookFailsafe for the working path."
        )

    def test_error_hook_does_NOT_touch_existing_response(self):
        """Companion: even when a response exists, error() no longer
        stamps its headers. All response management moved out of
        error(flow) entirely — it's now diagnostic-only.
        """
        from mitmproxy import http as mitm_http

        from safeyolo.core.trace import reset_store_for_tests

        reset_store_for_tests()
        from transport_guard import TransportGuard

        flow = self._flow()
        flow.response = mitm_http.Response.make(502, b"", {})
        original = dict(flow.response.headers)

        with patch("transport_guard.write_event", autospec=True):
            TransportGuard().error(flow)

        assert dict(flow.response.headers) == original


class TestRequestHookFailsafe:
    """The client-correlatable path added in the seventh-pass review.

    Loaded AFTER probe_sink. If sink terminated normally, request()
    is a no-op. If sink was missing/inert (no flow.response), request()
    synthesises a correlated 5xx with X-SafeYolo-Request-Id and records
    a trace step for `transport-guard/error/probe_sink_failed`.

    mitmproxy honours flow.response set from the request hook — this
    is the path that actually reaches the wire.
    """

    def _addon(self):
        from transport_guard import TransportGuard
        return TransportGuard()

    def test_noop_when_sink_already_responded(self):
        """Normal successful path: probe_sink terminated. transport_guard's
        request hook sees flow.response and does nothing.
        """
        from mitmproxy import http as mitm_http
        from mitmproxy.test import tflow

        addon = self._addon()
        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        # Pretend probe_sink already synthesised.
        flow.response = mitm_http.Response.make(200, b'{"probe_ok":true}', {})
        pre = flow.response

        with patch("transport_guard.write_event", autospec=True):
            addon.request(flow)

        # Response untouched.
        assert flow.response is pre

    def test_noop_when_non_probe_host(self):
        """Non-probe flows: request() is a no-op regardless of state."""
        from mitmproxy.test import tflow

        addon = self._addon()
        flow = tflow.tflow()
        flow.request.host = "example.com"
        with patch("transport_guard.write_event", autospec=True):
            addon.request(flow)
        assert flow.response is None

    def test_missing_sink_synthesises_correlated_5xx(self):
        """The critical case: probe_sink was absent/inert, so
        flow.response is None when transport_guard's request() runs.
        Must synthesise the 5xx with request-id header + body, and
        record trace step.
        """
        import json as _json

        from mitmproxy.test import tflow

        from safeyolo.core.trace import get_store, reset_store_for_tests

        reset_store_for_tests()
        addon = self._addon()

        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        # Simulate probe-marker set by probe_sink.requestheaders BEFORE
        # the sink's request hook was skipped/broken.
        flow.metadata["safeyolo_probe"] = True
        flow.metadata["trace"] = True
        flow.metadata["agent"] = "test-agent"
        assert flow.response is None

        with patch("transport_guard.write_event", autospec=True):
            addon.request(flow)

        # Correlated 5xx synthesised.
        assert flow.response is not None
        assert flow.response.status_code == 502
        rid = flow.metadata["request_id"]
        assert flow.response.headers.get("X-SafeYolo-Request-Id") == rid
        body = _json.loads(flow.response.content)
        assert body["reason_code"] == "probe_sink_failed"
        assert body["host"] == PROBE_HOST
        assert body["request_id"] == rid

        # Trace step recorded with the distinct probe_sink_failed reason
        # (NOT probe_reached_upstream — transport was never attempted).
        rec = get_store().get(rid, "test-agent")
        assert rec is not None
        step = rec.steps[-1]
        assert step.addon == "transport-guard"
        assert step.state == "error"
        assert step.reason == "probe_sink_failed"

    def test_missing_sink_sets_safeyolo_probe_marker_for_flowstore_suppression(self):
        """B4 invariant preserved on the missing-sink path (issue #213
        eighth-pass review): `flow_recorder` suppresses probe flows on
        `flow.metadata["safeyolo_probe"] is True`. That marker is
        normally set by `probe_sink.requestheaders`, but the very
        failure this failsafe exists to handle includes probe_sink
        being absent entirely. Without setting the marker here, doctor's
        diagnostic 502 (with a valid X-SafeYolo-Test-Context) would satisfy
        FlowStore's test_context gate and end up recorded.

        Explicit follow-through: the same helper `flow_recorder._should_record()`
        is exercised in the FlowStore-suppression regression test.
        """
        from mitmproxy.test import tflow

        addon = self._addon()

        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        flow.metadata["trace"] = True
        flow.metadata["agent"] = "test-agent"
        # Simulate real missing-sink state: NO safeyolo_probe marker
        # (probe_sink.requestheaders never ran) but test_context set
        # by test_context because doctor sent a valid X-SafeYolo-Test-Context.
        flow.metadata["test_context"] = {"run": "doctor", "agent": "x", "test": "y"}
        assert "safeyolo_probe" not in flow.metadata

        with patch("transport_guard.write_event", autospec=True):
            addon.request(flow)

        # Marker set — flow_recorder's _should_record will now short-
        # circuit before the test_context gate.
        assert flow.metadata.get("safeyolo_probe") is True

    def test_flowstore_regression_end_to_end_on_missing_sink(self, tmp_path):
        """End-to-end proof of the B4 invariant on the missing-sink path.
        Drives the exact scenario the reviewer flagged:
          - doctor sends X-SafeYolo-Test-Context → test_context sets test_context
          - probe_sink is absent (no marker on requestheaders)
          - transport_guard.request synthesises 502 AND sets marker
          - flow_recorder.response sees the flow → skips (marker present)
        """
        from flow_recorder import FlowRecorder
        from mitmproxy.test import taddons, tflow
        from transport_guard import TransportGuard

        addon = TransportGuard()

        # Build a flow like doctor's real probe.
        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        flow.metadata["trace"] = True
        flow.metadata["agent"] = "test-agent"
        flow.metadata["start_time"] = 0
        # Simulate test_context having accepted a valid X-SafeYolo-Test-Context.
        flow.metadata["test_context"] = {"run": "doctor", "agent": "x", "test": "y"}

        with patch("transport_guard.write_event", autospec=True):
            addon.request(flow)

        # Now simulate the response side going through flow_recorder.
        # Response is the 502 we synthesised.
        assert flow.response is not None
        assert flow.response.status_code == 502

        recorder = FlowRecorder()
        with taddons.context(recorder) as tctx:
            tctx.options.flow_store_enabled = True
            tctx.options.flow_store_db_path = str(tmp_path / "flows.sqlite3")
            # Bypass real store init — we only need the _should_record gate.
            recorder.store = object()
            skipped = not recorder._should_record(flow)

        assert skipped, (
            "flow_recorder must NOT record the diagnostic probe flow — "
            "the safeyolo_probe marker set by transport_guard is what "
            "keeps B4 suppression working on the missing-sink path."
        )

    def test_missing_sink_self_sufficient_without_prior_request_hooks(self):
        """Even if RequestIdGenerator and service-discovery didn't run
        (probe-marker set by requestheaders is enough), the failsafe
        recovers trace opt-in and trusted agent from the header + UnixMode.
        """
        from mitmproxy.test import tflow

        from safeyolo.core.trace import get_store, reset_store_for_tests

        reset_store_for_tests()
        addon = self._addon()
        from request_id import TRACE_REQUEST_HEADER

        flow = tflow.tflow()
        flow.request.host = PROBE_HOST
        flow.request.headers[TRACE_REQUEST_HEADER] = "1"
        flow.client_conn.proxy_mode = _unix_mode("10.0.0.42", "recovered-agent")
        # Deliberately no trace / agent / request_id metadata set.

        with patch("transport_guard.write_event", autospec=True):
            addon.request(flow)

        # Recovered opt-in + agent + request_id.
        assert flow.metadata.get("trace") is True
        assert flow.metadata.get("agent") == "recovered-agent"
        rid = flow.metadata["request_id"]
        # Trace record at the recovered-agent scope.
        rec = get_store().get(rid, "recovered-agent")
        assert rec is not None
        assert rec.steps[-1].reason == "probe_sink_failed"


class TestAgentAPIRequestContainment:
    """Early request containment survives every Agent API handler state."""

    def test_absent_handler_returns_safe_local_diagnostic(self, caplog):
        import json
        import logging

        from agent_api_guard import AgentAPIRequestGuard

        from safeyolo.core.internal_api import AGENT_API_UNAVAILABLE_REASON

        flow = _agent_api_flow(
            path="/health?access_token=query-secret",
            token="authorization-secret",
        )
        with (
            patch("agent_api_guard.write_event", autospec=True) as audit,
            caplog.at_level(logging.ERROR, logger="safeyolo.agent-api-guard"),
        ):
            AgentAPIRequestGuard().request(flow)

        assert flow.response.status_code == 503
        body = json.loads(flow.response.content)
        assert body == {
            "error": "SafeYolo Agent API handler unavailable",
            "reason_code": AGENT_API_UNAVAILABLE_REASON,
            "handler": "agent-api",
            "host": "_safeyolo.proxy.internal",
            "path": "/health",
            "request_id": flow.metadata["request_id"],
        }
        assert flow.response.headers["X-SafeYolo-Agent-API"] == "true"
        assert (
            flow.response.headers["X-SafeYolo-Request-Id"]
            == flow.metadata["request_id"]
        )
        assert flow.metadata["blocked_by"] == "agent-api-request-guard"
        assert "authorization" not in flow.request.headers
        assert flow.request.path == "/health"

        audit.assert_called_once()
        assert audit.call_args.args[0] == "security.agent_api_unavailable"
        details = audit.call_args.kwargs["details"]
        assert details == {
            "reason_code": AGENT_API_UNAVAILABLE_REASON,
            "handler": "agent-api",
            "method": "GET",
            "path": "/health",
        }
        emitted = f"{audit.call_args!r}\n{caplog.text}\n{flow.response.content!r}"
        assert "authorization-secret" not in emitted
        assert "query-secret" not in emitted

    @pytest.mark.parametrize(
        "host",
        ["_SAFEYOLO.PROXY.INTERNAL", "_SaFeYoLo.PrOxY.iNtErNaL"],
    )
    def test_request_host_matching_is_case_insensitive(self, host):
        from agent_api_guard import AgentAPIRequestGuard

        flow = _agent_api_flow(host=host)
        with patch("agent_api_guard.write_event", autospec=True):
            AgentAPIRequestGuard().request(flow)

        assert flow.response.status_code == 503

    def test_healthy_handler_response_is_untouched(self):
        import asyncio

        from agent_api import AgentAPI
        from agent_api_guard import AgentAPIRequestGuard
        from mitmproxy.test import taddons

        api = AgentAPI()
        guard = AgentAPIRequestGuard()
        flow = _agent_api_flow(host="_SAFEYOLO.PROXY.INTERNAL", token="good-token")
        with taddons.context(api) as tctx:
            tctx.options.agent_api_enabled = True
            with patch(
                "pdp.tokens.read_active_token",
                autospec=True,
                return_value="good-token",
            ):
                asyncio.run(api.request(flow))

        assert flow.response.status_code == 200
        response = flow.response
        headers = tuple(response.headers.items(multi=True))
        content = response.content
        with patch("agent_api_guard.write_event", autospec=True) as audit:
            guard.request(flow)

        assert flow.response is response
        assert tuple(response.headers.items(multi=True)) == headers
        assert response.content == content
        audit.assert_not_called()

    def test_response_without_handler_ownership_is_replaced(self):
        from agent_api_guard import AgentAPIRequestGuard
        from mitmproxy import http

        flow = _agent_api_flow()
        flow.response = http.Response.make(403, b"an earlier addon responded")

        with patch("agent_api_guard.write_event", autospec=True):
            AgentAPIRequestGuard().request(flow)

        assert flow.response.status_code == 503
        assert flow.metadata["blocked_by"] == "agent-api-request-guard"

    def test_disabled_handler_falls_through_to_local_503(self):
        import asyncio

        from agent_api import AgentAPI
        from agent_api_guard import AgentAPIRequestGuard
        from mitmproxy.test import taddons

        api = AgentAPI()
        flow = _agent_api_flow()
        with taddons.context(api) as tctx:
            tctx.options.agent_api_enabled = False
            asyncio.run(api.request(flow))
            assert flow.response is None

            with patch("agent_api_guard.write_event", autospec=True):
                AgentAPIRequestGuard().request(flow)
        assert flow.response.status_code == 503

    def test_handler_owned_exception_response_is_untouched(self):
        import asyncio
        import json

        from agent_api import AgentAPI
        from agent_api_guard import AgentAPIRequestGuard
        from mitmproxy.test import taddons

        class BrokenHealthAPI(AgentAPI):
            def _handle_health(self, flow):
                raise RuntimeError("deliberate handler failure")

        api = BrokenHealthAPI()
        flow = _agent_api_flow(token="good-token")
        with taddons.context(api) as tctx:
            tctx.options.agent_api_enabled = True
            with patch(
                "pdp.tokens.read_active_token",
                autospec=True,
                return_value="good-token",
            ):
                asyncio.run(api.request(flow))

        assert flow.response.status_code == 500
        assert json.loads(flow.response.content) == {
            "error": "Internal error: RuntimeError"
        }
        response = flow.response
        with patch("agent_api_guard.write_event", autospec=True) as audit:
            AgentAPIRequestGuard().request(flow)
        assert flow.response is response
        audit.assert_not_called()

    def test_uncaught_handler_exception_still_reaches_guard(self):
        import asyncio

        from agent_api_guard import AgentAPIRequestGuard
        from mitmproxy.proxy.layers.http import HttpRequestHook
        from mitmproxy.test import taddons

        class BrokenAgentAPI:
            name = "agent-api"

            async def request(self, flow):
                raise RuntimeError("deliberate addon failure")

        flow = _agent_api_flow()
        with taddons.context(BrokenAgentAPI(), AgentAPIRequestGuard()) as tctx:
            with patch("agent_api_guard.write_event", autospec=True):
                asyncio.run(
                    tctx.master.addons.trigger_event(HttpRequestHook(flow))
                )

        # AddonManager.safecall logs the first addon's exception and continues
        # through the chain. The adjacent independent guard owns the response.
        assert flow.response.status_code == 503
        assert flow.metadata["blocked_by"] == "agent-api-request-guard"

    @pytest.mark.parametrize("handler_state", ["absent", "disabled", "uncaught"])
    def test_production_order_contains_before_network_policy_and_logging(
        self, handler_state, caplog
    ):
        """The adjacent guard wins before NetworkGuard can inspect secrets."""
        import asyncio
        import logging

        from agent_api import AgentAPI
        from agent_api_guard import AgentAPIRequestGuard
        from mitmproxy.proxy.layers.http import HttpRequestHook
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard
        from request_logger import RequestLogger
        from transport_guard import TransportGuard

        from safeyolo.mitm_addons import ADDON_CHAIN

        assert ADDON_CHAIN.index("agent_api.py") < ADDON_CHAIN.index(
            "agent_api_guard.py"
        ) < ADDON_CHAIN.index("network_guard.py")
        assert ADDON_CHAIN.index("network_guard.py") < ADDON_CHAIN.index(
            "request_logger.py"
        )
        assert ADDON_CHAIN[-1] == "transport_guard.py"

        class BrokenAgentAPI:
            name = "agent-api"

            async def request(self, flow):
                raise RuntimeError("deliberate addon failure")

        guard = AgentAPIRequestGuard()
        network = NetworkGuard()
        request_logger = RequestLogger()
        final_guard = TransportGuard()
        if handler_state == "absent":
            chain = [guard, network, request_logger, final_guard]
        elif handler_state == "disabled":
            chain = [AgentAPI(), guard, network, request_logger, final_guard]
        else:
            chain = [
                BrokenAgentAPI(),
                guard,
                network,
                request_logger,
                final_guard,
            ]

        flow = _agent_api_flow(
            path="/health?lookup=query-secret-production-order",
            token="authorization-secret-production-order",
        )
        with taddons.context(*chain) as tctx:
            if handler_state == "disabled":
                tctx.options.agent_api_enabled = False
            with (
                patch("agent_api_guard.write_event", autospec=True) as audit,
                patch(
                    "request_logger.write_event", autospec=True
                ) as downstream_audit,
                caplog.at_level(logging.DEBUG),
            ):
                asyncio.run(
                    tctx.master.addons.trigger_event(HttpRequestHook(flow))
                )

        assert flow.response.status_code == 503
        assert flow.metadata["blocked_by"] == "agent-api-request-guard"
        assert flow.request.path == "/health"
        assert "authorization" not in flow.request.headers
        assert network.stats.checks == 0
        assert request_logger.requests_total == 1
        audit.assert_called_once()
        downstream_audit.assert_called_once()
        emitted = (
            f"{audit.call_args!r}\n{downstream_audit.call_args!r}\n"
            f"{caplog.text}\n{flow.response.content!r}"
        )
        assert "query-secret-production-order" not in emitted
        assert "authorization-secret-production-order" not in emitted

    def test_audit_failure_cannot_undo_local_response(self):
        from agent_api_guard import AgentAPIRequestGuard

        flow = _agent_api_flow()
        with patch(
            "agent_api_guard.write_event",
            autospec=True,
            side_effect=OSError("audit unavailable"),
        ):
            AgentAPIRequestGuard().request(flow)

        assert flow.response.status_code == 503

    def test_real_mitmdump_absent_handler_contains_http_and_https(
        self, tmp_path
    ):
        """Reproduce #397 with a real proxy process and no Agent API addon."""
        import http.client
        import json
        import os
        import socket
        import ssl
        import subprocess
        import sys
        import time
        from pathlib import Path

        from safeyolo.core.internal_api import AGENT_API_HOST

        repo = Path(__file__).resolve().parents[1]
        mitmdump = Path(sys.executable).with_name("mitmdump")
        assert mitmdump.is_file(), f"mitmdump missing next to {sys.executable}"
        guard_script = (
            repo
            / "cli"
            / "src"
            / "safeyolo"
            / "mitm_addons"
            / "agent_api_guard.py"
        )
        network_script = guard_script.with_name("network_guard.py")
        request_logger_script = guard_script.with_name("request_logger.py")
        transport_script = guard_script.with_name("transport_guard.py")

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        env = os.environ.copy()
        source_path = str(repo / "cli" / "src")
        env["PYTHONPATH"] = os.pathsep.join(
            value
            for value in (source_path, str(repo), env.get("PYTHONPATH"))
            if value
        )
        env["SAFEYOLO_LOG_PATH"] = str(tmp_path / "audit.jsonl")
        process = subprocess.Popen(
            [
                str(mitmdump),
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(port),
                "--set",
                "connection_strategy=lazy",
                "--set",
                "flow_detail=0",
                "--set",
                "termlog_verbosity=error",
                "--set",
                f"confdir={tmp_path / 'mitmproxy'}",
                "-s",
                str(guard_script),
                "-s",
                str(network_script),
                "-s",
                str(request_logger_script),
                "-s",
                str(transport_script),
            ],
            cwd=repo,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = ""
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    output = process.communicate(timeout=1)[0]
                    pytest.fail(f"mitmdump exited before readiness:\n{output}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        pytest.fail("mitmdump did not bind within 10 seconds")
                    time.sleep(0.05)

            connection_to_proxy = http.client.HTTPConnection(
                "127.0.0.1", port, timeout=5
            )
            connection_to_proxy.request(
                "GET",
                f"http://{AGENT_API_HOST}/health?token=query-secret",
                headers={
                    "Host": AGENT_API_HOST,
                    "Authorization": "Bearer authorization-secret",
                },
            )
            response = connection_to_proxy.getresponse()
            content = response.read()
            connection_to_proxy.close()

            assert response.status == 503
            body = json.loads(content)
            assert body["reason_code"] == "agent_api_unavailable"
            assert body["path"] == "/health"
            assert b"query-secret" not in content
            assert b"authorization-secret" not in content

            # Exercise the real CONNECT + TLS/SNI path. Lazy connection mode
            # lets mitmproxy terminate the tunnel locally, and the same final
            # request guard returns 503 without opening an upstream socket.
            tunnel = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            tunnel.set_tunnel(AGENT_API_HOST, 443)
            tunnel.connect()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            tunnel.sock = context.wrap_socket(
                tunnel.sock,
                server_hostname=AGENT_API_HOST,
            )
            tunnel.request(
                "GET",
                "/health?token=query-secret",
                headers={"Authorization": "Bearer authorization-secret"},
            )
            tls_response = tunnel.getresponse()
            tls_content = tls_response.read()
            tunnel.close()

            assert tls_response.status == 503
            tls_body = json.loads(tls_content)
            assert tls_body["reason_code"] == "agent_api_unavailable"
            assert tls_body["path"] == "/health"
            assert b"query-secret" not in tls_content
            assert b"authorization-secret" not in tls_content
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                output = process.communicate(timeout=5)[0]
            except subprocess.TimeoutExpired:
                process.kill()
                output = process.communicate(timeout=5)[0]

        audit_output = (tmp_path / "audit.jsonl").read_text()
        emitted = f"{output}\n{audit_output}"
        assert "security.agent_api_unavailable" in audit_output
        assert "query-secret" not in emitted
        assert "authorization-secret" not in emitted
        assert "Name or service not known" not in emitted
        assert "Temporary failure in name resolution" not in emitted
