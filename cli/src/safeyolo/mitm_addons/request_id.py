"""
request_id.py - Request ID generator, trace-marker consumer, and header hygiene

Runs early in the addon chain to:
1. Assign a unique request_id to every request (for event correlation)
2. Consume opt-in `X-SafeYolo-Trace` and set flow.metadata["trace"]
3. Strip SafeYolo-internal correlation headers a client must not spoof or
   have forwarded upstream (X-SafeYolo-Trace, X-SafeYolo-Request-Id)
4. Strip hop-by-hop headers that must not be forwarded to origin servers
5. On response, stamp X-SafeYolo-Request-Id so the originating agent can
   correlate its request without asking the operator to search host logs

The request_id is stored in flow.metadata["request_id"] and should be included
in all logged events for traceability. The ID format is defined by
REQUEST_ID_PATTERN below — consumers (e.g. agent_api) import it so the
generator and validator cannot drift.

Note: this addon's `request` hook is not literally the first one to run —
loop_guard, memory_monitor, and admin_shield load before it. Any addon
that needs to respond from `requestheaders` (which fires before any
`request` hook) uses `ensure_request_id(flow)` to assign the id itself
so its block response can carry X-SafeYolo-Request-Id and its audit
event can be correlated (loop_guard uses this today).

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

# Response header used to hand the request_id back to the originating client.
# Also used as the *inbound* header name we strip from incoming requests so a
# client cannot supply its own value and have it either mistaken for identity
# or forwarded upstream.
RESPONSE_REQUEST_ID_HEADER = "X-SafeYolo-Request-Id"

# Opt-in trace marker (issue #213). Consumed by this addon; never forwarded.
TRACE_REQUEST_HEADER = "X-SafeYolo-Trace"

# All SafeYolo-internal correlation headers. Any inbound header matching one
# of these is deleted before the request reaches downstream addons or the
# upstream server. Keep this list narrow: add-only, never removed silently.
_INTERNAL_CORRELATION_HEADERS = frozenset({
    header.lower() for header in (
        RESPONSE_REQUEST_ID_HEADER,
        TRACE_REQUEST_HEADER,
    )
})

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


def ensure_request_id(flow: http.HTTPFlow) -> str:
    """Assign a request_id to a flow if it doesn't already have one.

    Returns the request_id (existing or newly assigned). Idempotent.

    Exists so addons that respond from `requestheaders` (loop-guard, in
    practice) can carry an X-SafeYolo-Request-Id on their block response —
    RequestIdGenerator.request() would otherwise never run for those
    flows because a synthesised response short-circuits mitmproxy's
    `request` hook (issue #213 third-pass review).
    """
    existing = flow.metadata.get("request_id")
    if existing:
        return existing
    request_id = f"{REQUEST_ID_PREFIX}{uuid.uuid4().hex}"
    flow.metadata["request_id"] = request_id
    return request_id


def ensure_trace_opt_in(flow: http.HTTPFlow) -> bool:
    """Consume `X-SafeYolo-Trace: 1` and set `flow.metadata["trace"] = True`.

    Returns True iff tracing is now opted-in for this flow (was already,
    or the header was present). Idempotent. Strips the header so it
    never reaches upstream.

    Exists so addons that respond outside the normal `request` hook —
    where `RequestIdGenerator.request()` would consume the header — can
    still recover the trace opt-in themselves. Without this, an early
    `server_connect` refusal for the reserved probe host would set a
    trace-error step that `record_step()` silently drops (the store's
    `is_traced(flow)` gate reads `flow.metadata["trace"]`, which
    `RequestIdGenerator.request()` may never have set).
    """
    if flow.metadata.get("trace") is True:
        return True
    header_value = flow.request.headers.get(TRACE_REQUEST_HEADER, "")
    if header_value:
        flow.metadata["trace"] = True
        # Strip so the header never reaches upstream. Mirrors the strip
        # step in `RequestIdGenerator.request()`.
        del flow.request.headers[TRACE_REQUEST_HEADER]
        return True
    return False


def recover_trusted_agent(flow: http.HTTPFlow) -> str | None:
    """Read the trusted agent name from the per-agent UDS mode metadata.

    Returns the agent name, or None if the mode doesn't expose one.

    Service-discovery stamps `flow.metadata["agent"]` in its `request`
    hook. When an earlier hook (e.g. transport_guard.error under an
    early-connect path) needs the agent before service-discovery has
    run, this helper reads it from the connection-level UnixMode where
    identity is authoritative — the mode's socket-path directory
    (`<ip>_<agent>/proxy.sock`) is the source of truth for agent
    attribution.

    Idempotent — callers can safely invoke and stash the result on
    `flow.metadata["agent"]` themselves.
    """
    from safeyolo.core.identity import resolve_agent_identity

    identity = resolve_agent_identity(flow)
    return identity.agent if identity.is_resolved else None


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
        """Assign request_id, consume the trace marker, strip internal + hop-by-hop headers."""
        # 1. Assign unique request ID via ensure_request_id so any earlier
        #    hook (loop-guard's `requestheaders`, in practice) that already
        #    reserved a correlation ID keeps it. Without this, the normal
        #    path would silently replace an early-hook-assigned ID and
        #    every log/event/response header would then reference a
        #    different id than the one on the wire.
        ensure_request_id(flow)
        # start_time is always freshly stamped — it's per-hook timing, not
        # per-request identity, so it doesn't inherit from an earlier hook.
        flow.metadata["start_time"] = time.time()

        # 2. Consume trace marker BEFORE stripping. Presence of the header
        #    (any non-empty value) opts this request into pipeline tracing;
        #    the header itself is stripped below alongside other internal
        #    correlation headers so it never reaches upstream services.
        trace_header = flow.request.headers.get(TRACE_REQUEST_HEADER, "")
        if trace_header:
            flow.metadata["trace"] = True

        # 3. Detect WebSocket upgrades before stripping headers
        is_websocket = _is_websocket_upgrade(flow)
        if is_websocket:
            flow.metadata["is_websocket"] = True
            log.info(
                "WebSocket upgrade: %s%s",
                sanitize_for_log(flow.request.host),
                sanitize_for_log(flow.request.path),
            )

        # 4. Strip SafeYolo-internal correlation headers + hop-by-hop headers.
        #    A client-supplied X-SafeYolo-Request-Id must never be trusted as
        #    identity or forwarded upstream; the trace marker was consumed in
        #    step 2 and now needs the same treatment.
        # Honour any extra hop-by-hop names listed in the Connection header
        # (RFC 7230 §6.1 permits clients to nominate per-hop headers there).
        extra_hop_by_hop = _connection_tokens(flow)

        headers_to_remove = (
            _INTERNAL_CORRELATION_HEADERS | HOP_BY_HOP_HEADERS | extra_hop_by_hop
        )
        # Preserve Upgrade + Connection for WebSocket handshakes
        if is_websocket:
            headers_to_remove = headers_to_remove - WEBSOCKET_HEADERS
        for header in list(flow.request.headers.keys()):
            if header.lower() in headers_to_remove:
                del flow.request.headers[header]

    def response(self, flow: http.HTTPFlow):
        """Stamp X-SafeYolo-Request-Id on the outbound response.

        Applies to every response the proxy hands back — upstream-served,
        SafeYolo-synthesised block, and Agent API — so the originating
        agent can always correlate its request without asking the operator
        to search host logs.

        SafeYolo owns this header. Assignment replaces every case-insensitive
        occurrence, including duplicate values supplied by an upstream. A
        mismatched value on a SafeYolo-generated response is an internal
        invariant failure, but the canonical metadata value still wins.
        """
        if not flow.response:
            return
        request_id = flow.metadata.get("request_id")
        if not request_id:
            return
        existing_values = flow.response.headers.get_all(RESPONSE_REQUEST_ID_HEADER)
        if flow.metadata.get("blocked_by") and any(
            value != request_id for value in existing_values
        ):
            log.error(
                "SafeYolo-generated response carried a non-canonical "
                "X-SafeYolo-Request-Id; replacing it"
            )
        flow.response.headers[
            RESPONSE_REQUEST_ID_HEADER
        ] = request_id  # SKILL: troubleshooting.md#logs-and-correlation


addons = [RequestIdGenerator()]
