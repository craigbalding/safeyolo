"""
Tests for the loop_guard addon.

The loop_guard addon detects proxy loops using the Via header (RFC 7230).
Detection and injection both happen in requestheaders, which fires before
all request hooks in mitmproxy's event lifecycle.

Via is intentionally forwarded to upstreams — it's a standard proxy header
and is required for loop detection to work.
"""

from mitmproxy.test import tflow


class TestLoopDetection:
    """Tests for loop detection in requestheaders hook."""

    def _addon(self):
        from loop_guard import LoopGuard
        return LoopGuard()

    def test_normal_request_passes(self):
        """Request without Via is not blocked and gets Via injected."""
        addon = self._addon()
        flow = tflow.tflow()

        addon.requestheaders(flow)

        assert flow.response is None
        assert flow.request.headers["via"] == "1.1 safeyolo"

    def test_loop_detected_returns_508(self):
        """Request with our Via token returns 508."""
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        addon.requestheaders(flow)

        assert flow.response is not None
        assert flow.response.status_code == 508

    def test_blocked_metadata_set(self):
        """Loop detection sets blocked_by and block_reason metadata."""
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        addon.requestheaders(flow)

        assert flow.metadata["blocked_by"] == "loop-guard"
        assert flow.metadata["block_reason"] == "proxy_loop"

    def test_via_appended_to_existing(self):
        """Our Via entry appends to existing Via, doesn't replace."""
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 other-proxy"

        addon.requestheaders(flow)

        assert flow.response is None
        via = flow.request.headers["via"]
        assert via == "1.1 other-proxy, 1.1 safeyolo"

    def test_existing_via_not_flagged_as_loop(self):
        """Via from other proxies does not trigger loop detection."""
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 squid, 1.0 nginx"

        addon.requestheaders(flow)

        assert flow.response is None

    def test_loop_detected_with_multiple_via_entries(self):
        """Loop detected even when other Via entries are present."""
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 other-proxy, 1.1 safeyolo"

        addon.requestheaders(flow)

        assert flow.response is not None
        assert flow.response.status_code == 508


class TestViaTokenPresence:
    """Tests that Via token is present for upstream to see."""

    def _addon(self):
        from loop_guard import LoopGuard
        return LoopGuard()

    def test_via_present_after_requestheaders(self):
        """Via token is in headers after requestheaders (will be sent upstream)."""
        addon = self._addon()
        flow = tflow.tflow()

        addon.requestheaders(flow)

        assert "safeyolo" in flow.request.headers.get("via", "")

    def test_existing_via_preserved(self):
        """Other proxy Via entries are preserved alongside ours."""
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 upstream"

        addon.requestheaders(flow)

        via = flow.request.headers["via"]
        assert "1.1 upstream" in via
        assert "1.1 safeyolo" in via


class TestLoopSimulation:
    """Simulate a request looping back through the proxy."""

    def _addon(self):
        from loop_guard import LoopGuard
        return LoopGuard()

    def test_first_pass_injects_second_pass_blocks(self):
        """First pass injects Via; second pass (simulating loop) gets 508."""
        addon = self._addon()

        # First pass: requestheaders injects Via
        flow1 = tflow.tflow()
        addon.requestheaders(flow1)
        assert flow1.response is None
        via_after_inject = flow1.request.headers["via"]

        # Second pass: looped request arrives with Via from first pass
        flow2 = tflow.tflow()
        flow2.request.headers["via"] = via_after_inject
        addon.requestheaders(flow2)
        assert flow2.response is not None
        assert flow2.response.status_code == 508
