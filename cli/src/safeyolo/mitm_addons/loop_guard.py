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
from safeyolo.core.utils import make_block_response, sanitize_for_log, write_event

log = logging.getLogger("safeyolo.loop-guard")


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
