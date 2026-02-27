"""
request_id.py - Request ID generator and hop-by-hop header stripper

Runs FIRST in the addon chain to:
1. Assign a unique request_id to every request (for event correlation)
2. Strip hop-by-hop headers that must not be forwarded to origin servers

The request_id is stored in flow.metadata["request_id"] and should be included
in all logged events for traceability.

Hop-by-hop headers (RFC 7230 Section 6.1):
These are meaningful only for a single transport-level connection and must
not be forwarded by proxies. Proxy-Authorization is especially sensitive
as it could leak proxy credentials to upstream servers.

WebSocket exception: The Upgrade and Connection headers are preserved for
WebSocket handshakes (RFC 6455) so mitmproxy can proxy them correctly.
"""

import logging
import time
import uuid

from mitmproxy import http

log = logging.getLogger("safeyolo.request_id")

# RFC 7230 Section 6.1 - Hop-by-hop headers that must not be forwarded
# https://datatracker.ietf.org/doc/html/rfc7230#section-6.1
HOP_BY_HOP_HEADERS = frozenset([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
])

# Headers to preserve for WebSocket upgrades (RFC 6455)
WEBSOCKET_HEADERS = frozenset(["upgrade", "connection"])


def _is_websocket_upgrade(flow: http.HTTPFlow) -> bool:
    """Detect WebSocket upgrade requests (RFC 6455 Section 4.1).

    A valid WebSocket handshake requires both:
    - Upgrade: websocket
    - Connection: Upgrade (or connection header containing "upgrade")
    """
    upgrade = flow.request.headers.get("upgrade", "").lower()
    if upgrade != "websocket":
        return False
    connection = flow.request.headers.get("connection", "").lower()
    return "upgrade" in connection


class RequestIdGenerator:
    """
    Assigns unique request IDs and strips hop-by-hop headers.

    Must run before any security addons to ensure:
    - request_id is available for logging decisions
    - hop-by-hop headers don't leak to upstreams

    WebSocket upgrade requests preserve Upgrade + Connection headers
    so mitmproxy can proxy the handshake to the upstream.
    """

    name = "request-id"

    def request(self, flow: http.HTTPFlow):
        """Assign request_id, start_time, and strip hop-by-hop headers."""
        # 1. Assign unique request ID
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        flow.metadata["request_id"] = request_id
        flow.metadata["start_time"] = time.time()

        # 2. Detect WebSocket upgrades before stripping headers
        is_websocket = _is_websocket_upgrade(flow)
        if is_websocket:
            flow.metadata["is_websocket"] = True
            log.info(f"WebSocket upgrade: {flow.request.host}{flow.request.path}")

        # 3. Strip hop-by-hop headers (security: prevent credential leakage)
        # Check the Connection header for additional hop-by-hop headers
        connection_header = flow.request.headers.get("connection", "")
        extra_hop_by_hop = {h.strip().lower() for h in connection_header.split(",")} if connection_header else set()

        headers_to_remove = HOP_BY_HOP_HEADERS | extra_hop_by_hop
        # Preserve Upgrade + Connection for WebSocket handshakes
        if is_websocket:
            headers_to_remove = headers_to_remove - WEBSOCKET_HEADERS
        for header in list(flow.request.headers.keys()):
            if header.lower() in headers_to_remove:
                del flow.request.headers[header]


addons = [RequestIdGenerator()]
