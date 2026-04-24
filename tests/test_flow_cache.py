"""Tests for addons/flow_cache.py — per-flow memoized derivations."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_ADDONS_DIR = Path(__file__).resolve().parent.parent / "addons"
sys.path.insert(0, str(_ADDONS_DIR))

from safeyolo.core.flow_cache import headers_present_lower, path_no_query  # noqa: E402


def _flow(path: str = "/api", headers: dict | None = None):
    """Minimal stand-in for mitmproxy's HTTPFlow — only the attrs we read."""
    flow = MagicMock()
    flow.metadata = {}
    flow.request.path = path
    # mitmproxy's `headers.keys()` yields keys in insertion order,
    # preserving original case. MagicMock's default return for
    # `.headers.keys()` is another MagicMock; override with the list.
    hdr_dict = dict(headers or {})
    flow.request.headers.keys.return_value = list(hdr_dict.keys())
    flow.request.headers.get.side_effect = hdr_dict.get
    return flow


class TestHeadersPresentLower:
    def test_lowercases_and_preserves_order(self):
        flow = _flow(headers={"Authorization": "Bearer x", "X-Custom": "y"})
        assert headers_present_lower(flow) == ["authorization", "x-custom"]

    def test_empty_headers(self):
        flow = _flow(headers={})
        assert headers_present_lower(flow) == []

    def test_cached_on_second_call(self):
        flow = _flow(headers={"A": "1", "B": "2"})
        first = headers_present_lower(flow)
        # Mutate the underlying headers mock; the cache should still
        # return the first result because we store on flow.metadata.
        flow.request.headers.keys.return_value = ["C"]
        second = headers_present_lower(flow)
        assert first is second  # same list object — cached

    def test_cache_key_is_underscore_prefixed(self):
        """Cache stores under `_headers_present_lower` so it can't
        collide with addon-emitted metadata keys."""
        flow = _flow(headers={"A": "1"})
        headers_present_lower(flow)
        assert "_headers_present_lower" in flow.metadata


class TestPathNoQuery:
    def test_strips_query(self):
        flow = _flow(path="/search?q=foo&n=10")
        assert path_no_query(flow) == "/search"

    def test_no_query_returns_path_as_is(self):
        flow = _flow(path="/status")
        assert path_no_query(flow) == "/status"

    def test_empty_path(self):
        flow = _flow(path="")
        assert path_no_query(flow) == ""

    def test_only_query_marker(self):
        flow = _flow(path="/?")
        assert path_no_query(flow) == "/"

    def test_cached_on_second_call(self):
        flow = _flow(path="/a?b=c")
        first = path_no_query(flow)
        flow.request.path = "/mutated"
        second = path_no_query(flow)
        assert second == first == "/a"
        assert flow.metadata["_path_no_query"] == "/a"

    def test_independent_from_headers_cache(self):
        """The two helpers don't share metadata keys."""
        flow = _flow(path="/x?y=1", headers={"H": "v"})
        path_no_query(flow)
        headers_present_lower(flow)
        assert flow.metadata["_path_no_query"] == "/x"
        assert flow.metadata["_headers_present_lower"] == ["h"]
