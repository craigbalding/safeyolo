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


    def test_loop_response_body_is_json_with_error_message(self):
        """508 response body is JSON with 'error' and 'message' fields."""
        import json

        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        addon.requestheaders(flow)

        body = json.loads(flow.response.content)
        assert body == {
            "error": "Loop Detected",
            "message": "Request would create a proxy loop",
        }
        assert flow.response.headers["Content-Type"] == "application/json"


class TestLoopDetectionAudit:
    """Tests for audit event emission on loop detection."""

    def _addon(self):
        from loop_guard import LoopGuard
        return LoopGuard()

    def test_loop_detection_emits_audit_event(self):
        """Loop detection writes a security.loop_guard audit event with DENY decision."""
        from unittest.mock import patch

        from safeyolo.core.audit_schema import Decision, EventKind, Severity

        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        with patch("loop_guard.write_event") as mock_write:
            addon.requestheaders(flow)

            mock_write.assert_called_once()
            call_kwargs = mock_write.call_args[1]
            assert mock_write.call_args[0][0] == "security.loop_guard"
            assert call_kwargs["kind"] == EventKind.SECURITY
            assert call_kwargs["severity"] == Severity.HIGH
            assert call_kwargs["decision"] == Decision.DENY
            assert call_kwargs["addon"] == "loop-guard"


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


class TestLoopBlockCorrelationHeaders:
    """Issue #213: every SafeYolo block response must carry an
    X-SafeYolo-Request-Id so the originating agent can correlate the
    block without operator log access. loop-guard fires on `requestheaders`,
    before RequestIdGenerator's `request` hook would normally assign the
    id — so the addon has to ensure one exists itself before setting
    flow.response, otherwise the 508 ships without correlation.
    """

    def _addon(self):
        from loop_guard import LoopGuard
        return LoopGuard()

    def test_loop_508_carries_request_id_header(self):
        from request_id import REQUEST_ID_PATTERN

        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        addon.requestheaders(flow)

        assert flow.response is not None
        assert flow.response.status_code == 508
        rid_header = flow.response.headers.get("X-SafeYolo-Request-Id", "")
        assert REQUEST_ID_PATTERN.match(rid_header), (
            f"loop-guard 508 must carry X-SafeYolo-Request-Id in the "
            f"expected format (got {rid_header!r})"
        )
        # metadata also carries the same id so /explain can find it
        assert flow.metadata.get("request_id") == rid_header

    def test_loop_508_carries_blocked_by_header(self):
        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        addon.requestheaders(flow)

        assert flow.response.headers.get("X-Blocked-By") == "loop-guard"

    def test_loop_audit_event_carries_request_id(self):
        """The security.loop_guard event must include the request_id so
        /explain can correlate — the fix threads it into write_event."""
        from unittest.mock import patch

        addon = self._addon()
        flow = tflow.tflow()
        flow.request.headers["via"] = "1.1 safeyolo"

        with patch("loop_guard.write_event") as mock_write:
            addon.requestheaders(flow)
            kwargs = mock_write.call_args[1]
            assert kwargs.get("request_id") == flow.metadata["request_id"]

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
