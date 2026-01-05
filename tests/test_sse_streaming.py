"""
Tests for sse_streaming.py - SSE/streaming response support.

Tests content-type detection and streaming enablement.
"""

import pytest
from unittest.mock import Mock, patch


class TestSSEContentTypes:
    """Tests for SSE content type constants."""

    def test_sse_content_types_defined(self):
        """Test SSE content types are properly defined."""
        from addons.sse_streaming import SSE_CONTENT_TYPES

        assert "text/event-stream" in SSE_CONTENT_TYPES
        assert "application/x-ndjson" in SSE_CONTENT_TYPES


class TestSSEStreamingAddon:
    """Tests for SSEStreaming addon."""

    def test_addon_name(self):
        """Test addon has correct name."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()
        assert addon.name == "sse_streaming"

    def test_initial_stats_zero(self):
        """Test stats start at zero."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()
        assert addon.streams_enabled == 0
        assert addon.streams_by_domain == {}
        assert addon.streams_by_content_type == {}


class TestSSEStreamingDetection:
    """Tests for streaming detection logic."""

    def test_detects_event_stream_content_type(self):
        """Test detection of text/event-stream content type."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        flow = Mock()
        flow.response.headers.get.return_value = "text/event-stream"
        flow.request.host = "api.example.com"
        flow.metadata.get.return_value = None

        # Mock ctx.options
        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = True
            addon.responseheaders(flow)

        # Should enable streaming
        assert flow.response.stream is True
        assert addon.streams_enabled == 1
        assert addon.streams_by_domain.get("api.example.com") == 1

    def test_detects_ndjson_content_type(self):
        """Test detection of application/x-ndjson content type."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        flow = Mock()
        flow.response.headers.get.return_value = "application/x-ndjson"
        flow.request.host = "streaming.example.com"
        flow.metadata.get.return_value = None

        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = True
            addon.responseheaders(flow)

        assert flow.response.stream is True
        assert addon.streams_enabled == 1

    def test_ignores_non_streaming_content(self):
        """Test non-streaming content types are ignored."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        flow = Mock()
        flow.response.headers.get.return_value = "application/json"
        flow.request.host = "api.example.com"
        flow.metadata.get.return_value = None

        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = True
            addon.responseheaders(flow)

        # Should NOT enable streaming for plain JSON
        assert not hasattr(flow.response, 'stream') or flow.response.stream is not True
        assert addon.streams_enabled == 0

    def test_disabled_when_option_false(self):
        """Test streaming disabled when option is False."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        flow = Mock()
        flow.response.headers.get.return_value = "text/event-stream"

        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = False
            addon.responseheaders(flow)

        # Should NOT have been called to set stream
        assert addon.streams_enabled == 0


class TestSSEStreamingWithPolicy:
    """Tests for streaming with policy configuration."""

    def test_respects_policy_disabled(self):
        """Test addon respects policy disabling it."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        policy = Mock()
        policy.is_addon_enabled.return_value = False

        flow = Mock()
        flow.response.headers.get.return_value = "text/event-stream"
        flow.request.host = "api.example.com"
        flow.metadata.get.return_value = policy

        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = True
            addon.responseheaders(flow)

        # Should NOT enable streaming when policy disables addon
        assert addon.streams_enabled == 0

    def test_streams_json_when_policy_enabled(self):
        """Test JSON streaming when policy enables stream_json."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        policy = Mock()
        policy.is_addon_enabled.return_value = True
        policy.get_addon_settings.return_value = {"stream_json": True}

        flow = Mock()
        flow.response.headers.get.return_value = "application/json"
        flow.request.host = "ntfy.example.com"
        flow.metadata.get.return_value = policy

        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = True
            addon.responseheaders(flow)

        # Should enable streaming for JSON when policy says so
        assert flow.response.stream is True
        assert addon.streams_enabled == 1


class TestSSEStreamingStats:
    """Tests for stats tracking."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns proper structure."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()
        addon.streams_enabled = 5
        addon.streams_by_domain = {"api.example.com": 3, "other.com": 2}
        addon.streams_by_content_type = {"text/event-stream": 5}

        with patch('addons.sse_streaming.ctx') as mock_ctx:
            mock_ctx.options.sse_streaming_enabled = True
            stats = addon.get_stats()

        assert stats["streams_enabled_total"] == 5
        assert stats["streams_by_domain"]["api.example.com"] == 3
        assert stats["streams_by_content_type"]["text/event-stream"] == 5
        assert "enabled" in stats

    def test_record_stream_increments_counters(self):
        """Test _record_stream updates all counters."""
        from addons.sse_streaming import SSEStreaming

        addon = SSEStreaming()

        addon._record_stream("api.example.com", "text/event-stream")
        addon._record_stream("api.example.com", "text/event-stream")
        addon._record_stream("other.com", "application/x-ndjson")

        assert addon.streams_enabled == 3
        assert addon.streams_by_domain["api.example.com"] == 2
        assert addon.streams_by_domain["other.com"] == 1
        assert addon.streams_by_content_type["text/event-stream"] == 2
        assert addon.streams_by_content_type["application/x-ndjson"] == 1
