"""
loop_guard.py - Proxy loop detection via RFC 7230 Via header

Detects when a request has already passed through SafeYolo (loop) by
checking for our unique Via token. Breaks the loop with 508 Loop Detected.

Mechanism (all in requestheaders, which fires before request for all addons):
1. Check if our Via token is present -> 508 if yes (loop detected)
2. Inject our Via token so looped-back requests carry it

Note: Via is an RFC-standard proxy header designed to be forwarded.
The token is visible to upstreams — this is harmless and necessary
for loop detection to work (mitmproxy sends headers after requestheaders
but the request hook fires too late to strip without breaking detection).

Must be loaded early in the addon chain (Layer 0, after admin_shield).

Usage:
    mitmdump -s addons/loop_guard.py
"""

import logging

from mitmproxy import http
from request_id import ensure_request_id

from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.identity import resolve_agent_identity
from safeyolo.core.utils import find_addon, make_block_response, sanitize_for_log, write_event

log = logging.getLogger("safeyolo.loop-guard")


def _resolve_agent(flow: http.HTTPFlow) -> str | None:
    """Resolve the trusted agent before normal request hooks run.

    loop-guard fires in `requestheaders`, before `service_discovery.request()`
    would stamp `flow.metadata["agent"]`. But service_discovery's
    `get_client_for_ip()` is callable independently of its request hook, so
    we can attribute the audit event to the right agent even on this early
    path. Without this, `/explain` (which strictly filters by agent) would
    drop the loop-guard event and the 508's X-SafeYolo-Request-Id would
    lead the originating agent to a genuinely empty result (issue #213
    fifth-pass review).
    """
    sd = find_addon("service-discovery")
    identity = resolve_agent_identity(flow, sd)
    return identity.agent if identity.is_resolved else None


class LoopGuard:
    """Detect and break proxy loops using the Via header (RFC 7230)."""

    name = "loop-guard"
    VIA_TOKEN = "safeyolo"

    def requestheaders(self, flow: http.HTTPFlow):
        """Detect loop and inject Via token. Runs before all request hooks."""
        via = flow.request.headers.get("via", "")

        # Check for loop: our token is already present
        if self.VIA_TOKEN in via:
            # Assign a request_id here — RequestIdGenerator.request() would
            # normally do this but mitmproxy short-circuits `request` hooks
            # once a response is set. Without this the 508 would ship with
            # no X-SafeYolo-Request-Id, breaking #213's correlation-on-
            # every-SafeYolo-block promise (third-pass review).
            request_id = ensure_request_id(flow)
            # Resolve and stash agent identity so /explain finds this
            # event, and so downstream response-side hooks that read
            # flow.metadata["agent"] have the right value.
            agent = _resolve_agent(flow)
            if agent is not None:
                flow.metadata["agent"] = agent

            host = flow.request.host
            port = flow.request.port
            log.warning(f"Loop detected: {sanitize_for_log(host)}:{port} (via: {sanitize_for_log(via)})")
            write_event(
                "security.loop_guard",
                kind=EventKind.SECURITY,
                severity=Severity.HIGH,
                summary=f"Loop detected for {sanitize_for_log(host)}:{port}",
                decision=Decision.DENY,
                host=host,
                request_id=request_id,
                agent=agent,
                addon="loop-guard",
                details={"port": port, "via": via},
            )
            flow.response = make_block_response(
                508,
                {"error": "Loop Detected", "message": "Request would create a proxy loop"},
                self.name,
                request_id=request_id,
            )
            flow.metadata["blocked_by"] = self.name
            flow.metadata["block_reason"] = "proxy_loop"
            return

        # Inject our Via token for loop detection
        entry = f"1.1 {self.VIA_TOKEN}"
        flow.request.headers["via"] = f"{via}, {entry}" if via else entry

addons = [LoopGuard()]
