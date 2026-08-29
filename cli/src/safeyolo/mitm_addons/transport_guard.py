"""
transport_guard.py - Local containment for SafeYolo-reserved destinations.

The reserved doctor probe host keeps its two-layer defense (#213 B3):

1. **Request-hook failsafe** (`request(flow)`, loaded AFTER `probe_sink`):
   the client-correlatable catch. If `probe_sink` was missing / inert /
   didn't synthesise a response, this hook does — with a real
   `X-SafeYolo-Request-Id` header and a `transport-guard/error/
   probe_sink_failed` trace step. mitmproxy honours `flow.response`
   set from a request hook, so the client receives the correlated
   response and can `GET /trace?request_id=...` to see the reason.

2. **`server_connect` structural backstop**: catastrophic-only.
   Fires if BOTH probe_sink and the request-hook failsafe above were
   absent (chain broken). Sets `data.server.error` to abort the
   upstream connection locally and writes an audit event
   (`security.probe_reached_upstream` at CRITICAL). This is
   audit-only — mitmproxy 12.2.2's `handle_protocol_error()` does NOT
   consult `flow.response` set from the `error(flow)` hook, so we
   cannot deliver a correlated HTTP response from that path
   (reviewer's source check on the pinned version). The normal
   missing-sink failure is caught before transport by layer 1, so the
   audit-only layer 2 is acceptable.

The Agent API virtual host has the same structural no-egress requirement but a
separate reason/audit contract (#398). Its adjacent ``agent_api_guard`` owns
early request containment; this addon's ``server_connect`` hook remains the
final structural backstop and refuses server-address and SNI matches. This
addon imports only shared host identity, never the Agent API handler.

Load order (see ADDON_CHAIN in cli/src/safeyolo/proxy.py):
  agent_api.py        # normal Agent API handler (earlier in the chain)
  agent_api_guard.py  # early independent request containment
  probe_sink.py       # normal terminator
  transport_guard.py  # probe request failsafe + final transport backstop
"""

from __future__ import annotations

import json
import logging

from mitmproxy import http
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.internal_api import (
    AGENT_API_HOST,
    AGENT_API_REACHED_UPSTREAM_REASON,
    is_agent_api_host,
)
from safeyolo.core.probe import (
    PROBE_HOST,
    PROBE_REACHED_UPSTREAM_REASON,
    PROBE_SINK_FAILED_REASON,
    is_probe_host,
)
from safeyolo.core.trace import STATE_ERROR, record_step
from safeyolo.core.utils import sanitize_for_log, write_event
from safeyolo.mitm_addons.request_id import (
    ensure_request_id,
    ensure_trace_opt_in,
    recover_trusted_agent,
)

log = logging.getLogger("safeyolo.transport-guard")

# The no-egress denial message set on data.server.error. Distinctive
# so operators (and doctor's own diagnostics) can grep for it.
REFUSAL_MESSAGE = f"SafeYolo: reserved pipeline-probe host must never egress ({PROBE_HOST})"
AGENT_API_REFUSAL_MESSAGE = (
    f"SafeYolo: Agent API virtual host must never egress ({AGENT_API_HOST})"
)


class TransportGuard:
    """Contain probe failures and backstop all reserved transports."""

    name = "transport-guard"

    def _client_ip(self, data: ServerConnectionHookData) -> str | None:
        return data.client.peername[0] if data.client.peername else None

    def _agent(self, data: ServerConnectionHookData) -> str | None:
        return getattr(data.client.proxy_mode, "agent", None)

    def _matches_probe(self, data: ServerConnectionHookData) -> bool:
        # Check the server address hostname (what mitmproxy will
        # actually connect to) AND the SNI value (for HTTPS/CONNECT
        # paths where the routed target lives in TLS metadata). Either
        # match indicates the probe host escaped the sink.
        if data.server.address and is_probe_host(data.server.address[0]):
            return True
        if data.client.sni and is_probe_host(data.client.sni):
            return True
        return False

    def _matches_agent_api(self, data: ServerConnectionHookData) -> bool:
        """Match the Agent API in either connection-routing authority."""
        if data.server.address and is_agent_api_host(data.server.address[0]):
            return True
        if data.client.sni and is_agent_api_host(data.client.sni):
            return True
        return False

    def _refuse_agent_api_connect(self, data: ServerConnectionHookData) -> None:
        """Refuse a late Agent API transport attempt before DNS/connect."""
        data.server.error = AGENT_API_REFUSAL_MESSAGE

        client_ip = self._client_ip(data)
        agent = self._agent(data)
        log.error(
            "AGENT API REACHED TRANSPORT — refusing local virtual host %s "
            "before upstream connect from %s (agent=%s, reason=%s).",
            AGENT_API_HOST,
            sanitize_for_log(client_ip),
            sanitize_for_log(agent),
            AGENT_API_REACHED_UPSTREAM_REASON,
        )
        try:
            write_event(
                "security.agent_api_reached_upstream",
                kind=EventKind.SECURITY,
                severity=Severity.CRITICAL,
                summary="Agent API virtual host reached the transport backstop",
                decision=Decision.DENY,
                host=AGENT_API_HOST,
                agent=agent,
                addon=self.name,
                details={
                    "reason_code": AGENT_API_REACHED_UPSTREAM_REASON,
                    "handler": "agent-api",
                    "client_ip": client_ip,
                    "server_address": (
                        list(data.server.address) if data.server.address else None
                    ),
                    "sni": data.client.sni,
                },
            )
        except Exception as exc:
            # Refusal is already committed above. Audit availability must not
            # turn a contained destination back into an upstream attempt.
            log.error(
                "Agent API transport-refusal audit failed: %s",
                type(exc).__name__,
            )

    def server_connect(self, data: ServerConnectionHookData) -> None:
        if self._matches_agent_api(data):
            self._refuse_agent_api_connect(data)
            return

        if not self._matches_probe(data):
            return

        # Refuse the connection locally. Setting data.server.error is
        # the documented mitmproxy way to abort at this stage; the
        # follow-on `server_connect_error` hook fires normally so any
        # other observer sees a coherent failure. Do NOT raise —
        # mitmproxy would swallow it and the connection might still
        # proceed depending on the exception path.
        data.server.error = REFUSAL_MESSAGE

        client_ip = self._client_ip(data)
        agent = self._agent(data)
        log.warning(
            "PROBE REACHED UPSTREAM — probe_sink layer failed. "
            "Refusing connection to %s from %s (agent=%s).",
            PROBE_HOST,
            sanitize_for_log(client_ip),
            sanitize_for_log(agent),
        )
        write_event(
            "security.probe_reached_upstream",
            kind=EventKind.SECURITY,
            severity=Severity.CRITICAL,
            summary=f"Probe host reached upstream connect stage — sink failed for {PROBE_HOST}",
            decision=Decision.DENY,
            host=PROBE_HOST,
            agent=agent,
            addon=self.name,
            details={
                "reason_code": PROBE_REACHED_UPSTREAM_REASON,
                "client_ip": client_ip,
                "server_address": list(data.server.address) if data.server.address else None,
                "sni": data.client.sni,
            },
        )

    def request(self, flow: http.HTTPFlow) -> None:
        """Late request-hook failsafe for reserved local destinations.

        Loaded AFTER `probe_sink` in ADDON_CHAIN. If the sink terminated
        normally, `flow.response` is already set and this hook does
        nothing. If the sink was missing/inert/broken, this synthesises
        a correlated 5xx with `X-SafeYolo-Request-Id` and records a
        `transport-guard/error/probe_sink_failed` trace step.

        mitmproxy 12.2.2's `HttpRequestHook` runs before
        `make_server_connection()`. Setting `flow.response` here causes
        mitmproxy to take the inline-response branch and never attempt
        the server connection (source-verified by reviewer). This is
        the client-correlatable path: the response DOES reach the wire,
        unlike anything set from `error(flow)`.

        Distinct reason from `server_connect`'s backstop
        (`probe_reached_upstream`) — this one is `probe_sink_failed`
        because transport was NOT attempted, only the sink layer failed.
        Operator triage can tell which caught it.
        """
        if not is_probe_host(flow.request.host):
            return
        # Sink ran normally — do nothing.
        if flow.response is not None:
            return

        # Sink was missing/inert. Recover trace opt-in and trusted agent
        # (both may be unset if we're catching an unusual pipeline state).
        ensure_trace_opt_in(flow)
        if not flow.metadata.get("agent"):
            trusted_agent = recover_trusted_agent(flow)
            if trusted_agent:
                flow.metadata["agent"] = trusted_agent
        request_id = ensure_request_id(flow)
        # Set the probe marker so flow_recorder's B4 suppression fires
        # even on the missing-sink path (probe_sink.requestheaders would
        # normally have done this, but by definition the sink is absent
        # here). Observability-only; every security addon has already
        # run its request hook at this load-order position, so none can
        # branch on it. Issue #213 seventh-pass review.
        flow.metadata["safeyolo_probe"] = True

        flow.response = http.Response.make(
            502,
            json.dumps({
                "error": "SafeYolo pipeline-probe sink failed",
                "reason_code": PROBE_SINK_FAILED_REASON,
                "host": PROBE_HOST,
                "request_id": request_id,
            }).encode(),
            {
                "Content-Type": "application/json",
                "X-SafeYolo-Request-Id": request_id,
            },
        )
        # Trace evidence — non-manifest error step; doctor classifier
        # fails on any non-manifest state=error (issue #213 fifth/sixth
        # pass reviews).
        record_step(
            flow,
            addon=self.name,
            hook="request",
            state=STATE_ERROR,
            reason=PROBE_SINK_FAILED_REASON,
        )
        log.warning(
            "PROBE SINK FAILED — request-hook failsafe caught missing "
            "sink for %s (rid=%s)",
            sanitize_for_log(flow.request.host),
            request_id,
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """Diagnostic trace breadcrumb for the catastrophic server_connect path.

        Fires when mitmproxy surfaces a flow error, INCLUDING the
        `ResponseProtocolError` produced by `server_connect` setting
        `data.server.error` above. Records a trace step for the
        transport-guard backstop path so `/trace` shows the diagnostic
        breadcrumb.

        Does NOT synthesise a response — mitmproxy 12.2.2's
        `handle_protocol_error()` does not consult `flow.response` set
        from the error hook (source-verified by reviewer). The normal
        missing-sink failure is caught by the request-hook failsafe
        above and is client-correlatable there. Reaching this hook
        means BOTH probe_sink and the request-hook failsafe were
        absent — that's a catastrophic chain failure, and audit-only
        evidence is the honest floor.
        """
        if not is_probe_host(flow.request.host):
            return
        # Recover trace/agent metadata from trusted inputs so the record
        # is agent-owned even on the earliest-connect path.
        ensure_trace_opt_in(flow)
        if not flow.metadata.get("agent"):
            trusted_agent = recover_trusted_agent(flow)
            if trusted_agent:
                flow.metadata["agent"] = trusted_agent
        request_id = ensure_request_id(flow)
        record_step(
            flow,
            addon=self.name,
            hook="request",
            state=STATE_ERROR,
            reason=PROBE_REACHED_UPSTREAM_REASON,
            details={"error_type": type(flow.error).__name__ if flow.error else None},
        )
        log.warning(
            "PROBE REACHED UPSTREAM — server_connect backstop fired for "
            "%s (rid=%s); trace-only, client sees mitmproxy protocol "
            "error (no correlated response — request-hook failsafe was "
            "also absent)",
            sanitize_for_log(flow.request.host),
            request_id,
        )


addons = [TransportGuard()]
