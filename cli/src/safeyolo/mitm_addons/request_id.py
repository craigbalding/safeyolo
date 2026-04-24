"""
request_id.py - Request ID generator and hop-by-hop header stripper

Runs early in the addon chain to:
1. Assign a unique request_id to every request (for event correlation)
2. Strip hop-by-hop headers that must not be forwarded to origin servers

The request_id is stored in flow.metadata["request_id"] and should be included
in all logged events for traceability. The ID format is defined by
REQUEST_ID_PATTERN below — consumers (e.g. agent_api) import it so the
generator and validator cannot drift.

Note: the "runs FIRST" claim is not literally true — loop_guard, memory_monitor,
and admin_shield load before this addon. See Batch 9 (loop_guard review) for the
load-order question and the fix to ensure loop-detected audit events carry a
request_id.

Hop-by-hop headers (RFC 7230 Section 6.1):
These are meaningful only for a single transport-level connection and must
not be forwarded by proxies. Proxy-Authorization is especially sensitive
as it could leak proxy credentials to upstream servers.

WebSocket exception: The Upgrade and Connection headers are preserved for
WebSocket handshakes (RFC 6455) so mitmproxy can proxy them correctly.
"""

import logging
import re
import time
import uuid

from mitmproxy import http

from safeyolo.core.utils import sanitize_for_log

log = logging.getLogger("safeyolo.request_id")

# Cross-module contract: the format of flow.metadata["request_id"]. Consumers
# (agent_api, /explain) import these instead of hardcoding the format so the
# generator and validator cannot drift.
REQUEST_ID_PREFIX = "req-"
REQUEST_ID_PATTERN = re.compile(r"^req-[a-f0-9]{32}$")

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


def _connection_tokens(flow: http.HTTPFlow) -> frozenset[str]:
    """Parse the request's Connection header into a set of lowercase tokens.

    RFC 7230 §6.1 defines the Connection header as a comma-separated list of
    tokens. Empty tokens (from stray commas/whitespace) are discarded.

    Using tokenised comparison rather than substring matching avoids false
    positives like `Connection: upgrade-insecure-requests` being misread as
    containing an `upgrade` token.
    """
    raw = flow.request.headers.get("connection", "")
    if not raw:
        return frozenset()
    return frozenset(
        token for token in (t.strip().lower() for t in raw.split(",")) if token
    )


def _is_websocket_upgrade(flow: http.HTTPFlow) -> bool:
    """Detect WebSocket upgrade requests (RFC 6455 Section 4.1).

    A valid WebSocket handshake requires both:
    - Upgrade: websocket (exact value, case-insensitive per RFC 6455 §4.2.1)
    - Connection header containing the `upgrade` token (tokenised match,
      NOT substring — `upgrade-insecure-requests` is not a match)
    """
    upgrade = flow.request.headers.get("upgrade", "").lower()
    if upgrade != "websocket":
        return False
    return "upgrade" in _connection_tokens(flow)


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
        # 1. Assign unique request ID (128 bits of entropy from uuid4).
        #    Must match REQUEST_ID_PATTERN — consumers rely on the format.
        request_id = f"{REQUEST_ID_PREFIX}{uuid.uuid4().hex}"
        flow.metadata["request_id"] = request_id
        flow.metadata["start_time"] = time.time()

        # 2. Detect WebSocket upgrades before stripping headers
        is_websocket = _is_websocket_upgrade(flow)
        if is_websocket:
            flow.metadata["is_websocket"] = True
            log.info(
                "WebSocket upgrade: %s%s",
                sanitize_for_log(flow.request.host),
                sanitize_for_log(flow.request.path),
            )

        # 3. Strip hop-by-hop headers (security: prevent credential leakage)
        # Honour any extra hop-by-hop names listed in the Connection header
        # (RFC 7230 §6.1 permits clients to nominate per-hop headers there).
        extra_hop_by_hop = _connection_tokens(flow)

        headers_to_remove = HOP_BY_HOP_HEADERS | extra_hop_by_hop
        # Preserve Upgrade + Connection for WebSocket handshakes
        if is_websocket:
            headers_to_remove = headers_to_remove - WEBSOCKET_HEADERS
        for header in list(flow.request.headers.keys()):
            if header.lower() in headers_to_remove:
                del flow.request.headers[header]


addons = [RequestIdGenerator()]
