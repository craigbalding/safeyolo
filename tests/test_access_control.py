"""Tests for access_control addon."""

import pytest
from unittest.mock import MagicMock, patch


class TestAccessControl:
    """Tests for AccessControl addon."""

    def test_name(self):
        """Test addon has correct name."""
        from addons.access_control import AccessControl
        addon = AccessControl()
        assert addon.name == "access-control"

    def test_get_stats_initial(self):
        """Test initial stats are zeroed."""
        from addons.access_control import AccessControl
        addon = AccessControl()
        stats = addon.get_stats()
        assert stats["checks"] == 0
        assert stats["allowed"] == 0
        assert stats["blocked"] == 0

    def test_blocks_denied_request(self):
        """Test addon blocks requests with effect=deny."""
        from addons.access_control import AccessControl
        from addons.policy_engine import PolicyDecision

        addon = AccessControl()

        # Mock flow
        flow = MagicMock()
        flow.request.host = "evil.com"
        flow.request.path = "/malware"
        flow.request.method = "GET"
        flow.client_conn.peername = ("192.168.1.1", 12345)
        flow.metadata = {}

        # Mock policy engine returning deny
        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="deny",
            reason="Access denied to evil.com"
        )

        with patch("addons.access_control.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should have blocked
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "access-control"
        assert addon.stats.blocked == 1
        assert addon.stats.allowed == 0

    def test_allows_non_denied_request(self):
        """Test addon allows requests without effect=deny."""
        from addons.access_control import AccessControl
        from addons.policy_engine import PolicyDecision

        addon = AccessControl()

        flow = MagicMock()
        flow.request.host = "api.openai.com"
        flow.request.path = "/v1/chat"
        flow.request.method = "POST"
        flow.metadata = {}
        flow.response = None  # Explicitly set - MagicMock auto-creates attributes

        # Mock policy engine returning allow
        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="allow",
            reason="Allowed"
        )

        with patch("addons.access_control.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should NOT have blocked
        assert flow.response is None
        assert addon.stats.allowed == 1
        assert addon.stats.blocked == 0

    def test_allows_budget_effect(self):
        """Test addon passes through budget effect for rate limiter."""
        from addons.access_control import AccessControl
        from addons.policy_engine import PolicyDecision

        addon = AccessControl()

        flow = MagicMock()
        flow.request.host = "api.github.com"
        flow.request.path = "/repos"
        flow.request.method = "GET"
        flow.metadata = {}
        flow.response = None

        # Mock policy engine returning budget
        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="budget",
            reason="Rate limited"
        )

        with patch("addons.access_control.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should NOT have blocked - budget effect is for rate_limiter
        assert flow.response is None
        assert addon.stats.allowed == 1

    def test_warn_mode_does_not_block(self):
        """Test warn mode logs but doesn't block."""
        from addons.access_control import AccessControl
        from addons.policy_engine import PolicyDecision

        addon = AccessControl()

        flow = MagicMock()
        flow.request.host = "evil.com"
        flow.request.path = "/malware"
        flow.request.method = "GET"
        flow.client_conn.peername = ("192.168.1.1", 12345)
        flow.metadata = {}
        flow.response = None

        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="deny",
            reason="Access denied"
        )

        def option_side_effect(name, default=True):
            if name == "access_control_enabled":
                return True
            if name == "access_control_block":
                return False  # Warn mode
            return default

        with patch("addons.access_control.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", side_effect=option_side_effect):
                addon.request(flow)

        # Should NOT have blocked in warn mode
        assert flow.response is None
        assert "blocked_by" not in flow.metadata
        # But should still count as warned
        assert addon.stats.warned == 1

    def test_disabled_does_not_check(self):
        """Test disabled addon doesn't check anything."""
        from addons.access_control import AccessControl

        addon = AccessControl()

        flow = MagicMock()
        flow.request.host = "evil.com"
        flow.metadata = {}

        mock_engine = MagicMock()

        with patch("addons.access_control.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=False):
                addon.request(flow)

        # Should not have called policy engine
        mock_engine.evaluate_request.assert_not_called()
        assert addon.stats.checks == 0

    def test_no_engine_allows(self):
        """Test requests pass through if no policy engine."""
        from addons.access_control import AccessControl

        addon = AccessControl()

        flow = MagicMock()
        flow.request.host = "any.com"
        flow.metadata = {}
        flow.response = None

        with patch("addons.access_control.get_policy_engine", return_value=None):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # No engine = no blocking
        assert flow.response is None
        assert addon.stats.checks == 0


class TestAccessControlIntegration:
    """Integration tests with real PolicyEngine."""

    def test_deny_with_real_policy(self):
        """Test deny effect works with real policy engine."""
        from addons.access_control import AccessControl
        from addons.policy_engine import PolicyEngine, Permission, UnifiedPolicy

        # Create policy with deny rule
        policy = UnifiedPolicy(
            permissions=[
                Permission(
                    action="network:request",
                    resource="evil.com/*",
                    effect="deny",
                    tier="explicit",
                ),
                Permission(
                    action="network:request",
                    resource="*",
                    effect="allow",
                    tier="explicit",
                ),
            ]
        )

        engine = PolicyEngine()
        engine._baseline = policy

        addon = AccessControl()

        # Test denied domain
        decision = engine.evaluate_request("evil.com", "/path", "GET")
        assert decision.effect == "deny"

        # Test allowed domain
        decision = engine.evaluate_request("good.com", "/path", "GET")
        assert decision.effect == "allow"

    def test_allowlist_mode(self):
        """Test allowlist mode: allow specific, deny rest."""
        from addons.policy_engine import PolicyEngine, Permission, UnifiedPolicy

        policy = UnifiedPolicy(
            permissions=[
                # Explicit allows
                Permission(
                    action="network:request",
                    resource="api.openai.com/*",
                    effect="allow",
                    tier="explicit",
                ),
                Permission(
                    action="network:request",
                    resource="api.anthropic.com/*",
                    effect="allow",
                    tier="explicit",
                ),
                # Catch-all deny
                Permission(
                    action="network:request",
                    resource="*",
                    effect="deny",
                    tier="explicit",
                ),
            ]
        )

        engine = PolicyEngine()
        engine._baseline = policy

        # Allowed domains
        assert engine.evaluate_request("api.openai.com", "/v1/chat", "POST").effect == "allow"
        assert engine.evaluate_request("api.anthropic.com", "/messages", "POST").effect == "allow"

        # Denied domains (everything else)
        assert engine.evaluate_request("google.com", "/", "GET").effect == "deny"
        assert engine.evaluate_request("hacker.com", "/pwn", "GET").effect == "deny"
