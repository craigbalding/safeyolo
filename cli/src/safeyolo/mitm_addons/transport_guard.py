"""
transport_guard.py - Defense-in-depth no-egress boundary for the reserved
pipeline-probe destination (#213 B3)

Belt-and-braces with `probe_sink`. In the normal path, probe_sink's
`request` hook sets `flow.response` for the reserved probe host, so
mitmproxy never attempts an upstream connection and `server_connect`
does not fire.

This addon exists for the case where probe_sink is:
- absent (someone removed it from ADDON_CHAIN),
- misordered (something responded after it, wrongly),
- broken (the sink hook raised),
- disabled at runtime, or
- shadowed by a future addon that consumes the probe marker without
  synthesising a response.

In any of those failures, mitmproxy would proceed to open an upstream
connection to `_safeyolo.probe.internal`. That host has no DNS entry
and no route, so the connection would fail anyway — but "connection
refused because there's no server" is not the same as "SafeYolo
guarantees this destination never egresses". Issue #213 requires the
latter: doctor's probe must never generate DNS lookups or TCP
connection attempts to real infrastructure, even under sink failure.

Contract:
- Fire on `server_connect`. Inspect the resolved server address
  (and any TLS SNI) for the reserved probe host.
- If matched: set `data.server.error` so mitmproxy aborts the
  connection locally, write an audit event with a distinctive
  reason code (`PROBE_REACHED_UPSTREAM`) so operators see clearly
  that the sink layer failed.
- The address check is case-insensitive (DNS names are).

Loading position: anywhere in the request half of the chain works
because `server_connect` runs on a different mitmproxy hook path than
`request` hooks — timing is decoupled. Loaded before probe_sink in
ADDON_CHAIN so this file's audit event is registered whenever the
proxy is up, independent of whether probe_sink itself loaded.
"""

from __future__ import annotations

import json
import logging

from mitmproxy import http
from mitmproxy.proxy.server_hooks import ServerConnectionHookData
from request_id import ensure_request_id, ensure_trace_opt_in, recover_trusted_agent

from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.probe import PROBE_HOST, PROBE_REACHED_UPSTREAM_REASON, is_probe_host
from safeyolo.core.trace import STATE_ERROR, record_step
from safeyolo.core.utils import sanitize_for_log, write_event

log = logging.getLogger("safeyolo.transport-guard")

# The no-egress denial message set on data.server.error. Distinctive
# so operators (and doctor's own diagnostics) can grep for it.
REFUSAL_MESSAGE = f"SafeYolo: reserved pipeline-probe host must never egress ({PROBE_HOST})"


class TransportGuard:
    """Refuse upstream connect attempts to the reserved probe host."""

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

    def server_connect(self, data: ServerConnectionHookData) -> None:
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

    def error(self, flow: http.HTTPFlow) -> None:
        """Bridge the server_connect refusal into HTTPFlow-aware trace evidence.

        server_connect (above) has no HTTPFlow reference — it operates
        on ServerConnectionHookData. That means the audit event is the
        only correlation surface unless we cross the boundary here in
        an HTTP-layer hook. The mitmproxy `error` hook fires with a
        real `http.HTTPFlow` when a flow encounters a transport/protocol
        error — including the connection abort we produce by setting
        `data.server.error` above.

        Contract (issue #213 review): when a probe host flow errors,
        record a trace step so `/trace?request_id=...` surfaces the
        failure alongside every other pipeline step, and so the DAG's
        `cls.trace_error` branch fires deterministically.

        Self-sufficient on the early-connect path (issue #213
        fourth-pass review): if `server_connect` preempts
        `RequestIdGenerator.request()`, then neither the trace opt-in
        flag nor `flow.metadata["agent"]` has been set — `record_step`
        would silently no-op and any recorded step would be unreadable
        via agent-scoped `/trace`. This hook recovers both from
        trusted inputs before recording:

          - `ensure_trace_opt_in(flow)` consumes and strips
            X-SafeYolo-Trace so tracing is opted-in even if the
            request-hook path never ran;
          - `recover_trusted_agent(flow)` reads the agent name from
            `flow.client_conn.proxy_mode.agent` (the UnixMode's
            source-of-truth attribution) so agent-scoped `/trace` can
            find the record;
          - `ensure_request_id(flow)` is idempotent and guarantees a
            correlation ID.
        """
        if not is_probe_host(flow.request.host):
            return

        # Recover the trace opt-in from the request header if
        # RequestIdGenerator.request() never ran (early-connect path).
        ensure_trace_opt_in(flow)
        # Recover trusted agent from the per-agent UDS mode if
        # service_discovery.request() never ran.
        if not flow.metadata.get("agent"):
            trusted_agent = recover_trusted_agent(flow)
            if trusted_agent:
                flow.metadata["agent"] = trusted_agent

        # Idempotent: preserves any earlier RequestIdGenerator assignment.
        request_id = ensure_request_id(flow)

        # Synthesise a correlated downstream response if none exists yet.
        # In the real ResponseProtocolError path (server_connection refusal
        # → HttpErrorHook), mitmproxy fires this hook with flow.error set
        # but flow.response still None; mitmproxy then generates its own
        # generic protocol-error response for the client. Setting
        # flow.response here BEFORE that generic response is generated
        # gives us a deterministic correlatable HTTP surface: the client
        # (doctor, agent) always receives an X-SafeYolo-Request-Id header
        # tying the failure to the `/trace` record we're about to write
        # (issue #213 review — V3 correlation contract).
        if flow.response is None:
            flow.response = http.Response.make(
                502,
                json.dumps({
                    "error": "SafeYolo pipeline-probe upstream refused",
                    "reason_code": PROBE_REACHED_UPSTREAM_REASON,
                    "host": PROBE_HOST,
                    "request_id": request_id,
                }).encode(),
                {
                    "Content-Type": "application/json",
                    "X-SafeYolo-Request-Id": request_id,
                },
            )
        elif "X-SafeYolo-Request-Id" not in flow.response.headers:
            # Response already exists — just stamp the correlation header.
            flow.response.headers["X-SafeYolo-Request-Id"] = request_id

        # Record explicit trace evidence. Uses the shared lower-case
        # reason constant so it matches the DAG YAML's `when:` clauses
        # exactly (see references/agent-api.md).
        record_step(
            flow,
            addon=self.name,
            hook="request",
            state=STATE_ERROR,
            reason=PROBE_REACHED_UPSTREAM_REASON,
            details={"error_type": type(flow.error).__name__ if flow.error else None},
        )
        log.warning(
            "PROBE ERROR bridged to trace for %s (rid=%s)",
            sanitize_for_log(flow.request.host),
            request_id,
        )


addons = [TransportGuard()]
