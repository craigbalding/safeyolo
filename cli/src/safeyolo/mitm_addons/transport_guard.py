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

import logging

from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.probe import PROBE_HOST, is_probe_host
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
                "reason_code": "PROBE_REACHED_UPSTREAM",
                "client_ip": client_ip,
                "server_address": list(data.server.address) if data.server.address else None,
                "sni": data.client.sni,
            },
        )


addons = [TransportGuard()]
