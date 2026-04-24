"""Per-flow cache of request derivations mitmproxy doesn't memoize.

The raw request fields (`method`, `host`, `port`, `scheme`, `path`,
`url`, etc.) are already parsed once by mitmproxy and cached on the
`Request` object, so reading them repeatedly across addons is cheap.
Two derivations, though, are re-computed on every access:

  - lower-cased list of header names (iterating + lowering a dozen+
    keys) — consumed by `sensor_utils.build_http_event_from_flow`
  - `flow.request.path` with any `?query` suffix stripped — consumed
    by `sensor_utils`, `flow_recorder`, `agent_api`, `service_gateway`
    (five sites), `detection.matching`

This module memoizes both on `flow.metadata` under underscore-prefixed
keys so the Nth caller on the same flow gets an O(1) lookup instead
of redoing the iteration / split.

Library module, not a mitmproxy addon — no request/response hook.
Cache entries are naturally scoped to the flow's lifetime (mitmproxy
drops the flow when the connection ends).
"""
from __future__ import annotations

from mitmproxy import http


def headers_present_lower(flow: http.HTTPFlow) -> list[str]:
    """Lowercased request header names. Computed once per flow."""
    cached = flow.metadata.get("_headers_present_lower")
    if cached is not None:
        return cached
    result = [h.lower() for h in flow.request.headers.keys()]
    flow.metadata["_headers_present_lower"] = result
    return result


def path_no_query(flow: http.HTTPFlow) -> str:
    """`flow.request.path` with any `?query` suffix removed.

    mitmproxy's `request.path` sometimes includes the querystring
    (depending on how the request was received); this helper strips
    it so consumers that want just the resource path get a consistent
    value.
    """
    cached = flow.metadata.get("_path_no_query")
    if cached is not None:
        return cached
    path = flow.request.path.split("?", 1)[0]
    flow.metadata["_path_no_query"] = path
    return path


# No mitmproxy addon — this module is pure helpers, not a hook target.
addons: list = []
