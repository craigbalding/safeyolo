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
"""

import time
import uuid

from mitmproxy import http

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


class RequestIdGenerator:
    """
    Assigns unique request IDs and strips hop-by-hop headers.

    Must run before any security addons to ensure:
    - request_id is available for logging decisions
    - hop-by-hop headers don't leak to upstreams
    """

    name = "request-id"

    def request(self, flow: http.HTTPFlow):
        """Assign request_id, start_time, and strip hop-by-hop headers."""
        # 1. Assign unique request ID
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        flow.metadata["request_id"] = request_id
        flow.metadata["start_time"] = time.time()

        # 2. Strip hop-by-hop headers (security: prevent credential leakage)
        # Check the Connection header for additional hop-by-hop headers
        connection_header = flow.request.headers.get("connection", "")
        extra_hop_by_hop = {h.strip().lower() for h in connection_header.split(",")} if connection_header else set()

        headers_to_remove = HOP_BY_HOP_HEADERS | extra_hop_by_hop
        for header in list(flow.request.headers.keys()):
            if header.lower() in headers_to_remove:
                del flow.request.headers[header]


addons = [RequestIdGenerator()]
