"""
Tests for base.py - SecurityAddon base class.

Tests base addon functionality including stats, options, and decision logging.
"""

from unittest.mock import Mock, patch


class TestAddonStats:
    """Tests for AddonStats dataclass."""

    def test_default_values(self):
        """Test stats initialize to zero."""
        from addons.base import AddonStats

        stats = AddonStats()
        assert stats.checks == 0
        assert stats.allowed == 0
        assert stats.blocked == 0
        assert stats.warned == 0

    def test_stats_increment(self):
        """Test stats can be incremented."""
        from addons.base import AddonStats

        stats = AddonStats()
        stats.checks += 1
        stats.allowed += 2
        stats.blocked += 3
        stats.warned += 4

        assert stats.checks == 1
        assert stats.allowed == 2
        assert stats.blocked == 3
        assert stats.warned == 4


class TestSecurityAddon:
    """Tests for SecurityAddon base class."""

    def test_stats_initialization(self):
        """Test addon initializes with empty stats."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()
        assert addon.stats.checks == 0
        assert addon.stats.allowed == 0
        assert addon.stats.blocked == 0
        assert addon.stats.warned == 0

    def test_option_prefix_conversion(self):
        """Test addon name converts to option prefix."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()
        assert addon._option_prefix() == "test_addon"

        class NetworkGuard(SecurityAddon):
            name = "network-guard"

        guard = NetworkGuard()
        assert guard._option_prefix() == "network_guard"

    def test_is_enabled_default_true(self):
        """Test is_enabled defaults to True when option not set."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()
        # Without mitmproxy context, get_option_safe returns default
        assert addon.is_enabled() is True

    def test_should_block_default_true(self):
        """Test should_block defaults to True when option not set."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()
        # Without mitmproxy context, get_option_safe returns default
        assert addon.should_block() is True


class TestSecurityAddonBypass:
    """Tests for addon bypass logic."""

    def test_bypassed_when_flow_has_response(self):
        """Test addon is bypassed when flow already has a response."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()

        # Create mock flow with a response already set
        flow = Mock()
        flow.response = Mock()  # Non-None response

        assert addon.is_bypassed(flow) is True

    def test_not_bypassed_when_no_response(self):
        """Test addon is not bypassed when flow has no response."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()

        # Create mock flow without response
        flow = Mock()
        flow.response = None
        flow.request.host = "example.com"

        # Mock get_policy_engine to return None (no engine)
        with patch('addons.base.get_policy_engine', return_value=None):
            assert addon.is_bypassed(flow) is False


class TestSecurityAddonBlocking:
    """Tests for addon blocking functionality."""

    def test_block_sets_response(self):
        """Test block() sets flow response correctly."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()

        flow = Mock()
        flow.metadata = {}
        flow.response = None

        body = {"error": "Blocked", "reason": "test"}
        addon.block(flow, 403, body)

        assert flow.response is not None
        assert flow.metadata["blocked_by"] == "test-addon"
        assert addon.stats.blocked == 1

    def test_block_with_extra_headers(self):
        """Test block() includes extra headers."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()

        flow = Mock()
        flow.metadata = {}
        flow.response = None

        body = {"error": "Rate limited"}
        extra_headers = {"Retry-After": "60"}
        addon.block(flow, 429, body, extra_headers)

        assert flow.response is not None
        assert addon.stats.blocked == 1


class TestSecurityAddonWarn:
    """Tests for addon warn functionality."""

    def test_warn_increments_warned_count(self):
        """Test warn() increments warned counter."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()
        flow = Mock()

        assert addon.stats.warned == 0
        addon.warn(flow)
        assert addon.stats.warned == 1
        addon.warn(flow)
        assert addon.stats.warned == 2


class TestSecurityAddonStats:
    """Tests for get_stats() method."""

    def test_get_stats_returns_dict(self):
        """Test get_stats() returns dict with all fields."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()
        addon.stats.checks = 10
        addon.stats.allowed = 5
        addon.stats.blocked = 3
        addon.stats.warned = 2

        stats = addon.get_stats()

        assert isinstance(stats, dict)
        assert stats["checks_total"] == 10
        assert stats["allowed_total"] == 5
        assert stats["blocked_total"] == 3
        assert stats["warned_total"] == 2
        assert "enabled" in stats


class TestSecurityAddonLogging:
    """Tests for decision logging."""

    def test_log_decision_calls_write_event(self):
        """Test log_decision() calls write_event with correct params."""
        from addons.base import SecurityAddon

        class TestAddon(SecurityAddon):
            name = "test-addon"

        addon = TestAddon()

        flow = Mock()
        flow.metadata = {"request_id": "req-123"}

        with patch('addons.base.write_event') as mock_write:
            addon.log_decision(flow, "block", reason="test", domain="example.com")

            mock_write.assert_called_once()
            call_args = mock_write.call_args

            # Check event type format
            assert call_args[0][0] == "security.test_addon"

            # Check kwargs
            assert call_args[1]["request_id"] == "req-123"
            assert call_args[1]["addon"] == "test-addon"
            assert call_args[1]["decision"] == "block"
            assert call_args[1]["reason"] == "test"
            assert call_args[1]["domain"] == "example.com"
