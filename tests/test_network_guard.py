"""Tests for network_guard addon (combined access control + rate limiting)."""

import pytest
from unittest.mock import MagicMock, patch


class TestNetworkGuard:
    """Tests for NetworkGuard addon."""

    def test_name(self):
        """Test addon has correct name."""
        from addons.network_guard import NetworkGuard
        addon = NetworkGuard()
        assert addon.name == "network-guard"

    def test_get_stats_initial(self):
        """Test initial stats are zeroed."""
        from addons.network_guard import NetworkGuard
        addon = NetworkGuard()
        stats = addon.get_stats()
        assert stats["checks"] == 0
        assert stats["allowed"] == 0
        assert stats["blocked"] == 0
        assert stats["rate_limited"] == 0

    def test_blocks_denied_request(self):
        """Test addon blocks requests with effect=deny."""
        from addons.network_guard import NetworkGuard
        from addons.policy_engine import PolicyDecision

        addon = NetworkGuard()

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

        with patch("addons.network_guard.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should have blocked with 403
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "network-guard"
        assert addon.stats.blocked == 1
        assert addon.stats.allowed == 0

    def test_blocks_rate_limited_request(self):
        """Test addon blocks requests with effect=budget_exceeded."""
        from addons.network_guard import NetworkGuard
        from addons.policy_engine import PolicyDecision

        addon = NetworkGuard()

        flow = MagicMock()
        flow.request.host = "api.openai.com"
        flow.request.path = "/v1/chat"
        flow.request.method = "POST"
        flow.client_conn.peername = ("192.168.1.1", 12345)
        flow.metadata = {}

        # Mock policy engine returning budget_exceeded
        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="budget_exceeded",
            reason="Rate limit exceeded for api.openai.com"
        )

        with patch("addons.network_guard.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should have blocked with 429
        assert flow.response is not None
        assert flow.response.status_code == 429
        assert flow.metadata.get("blocked_by") == "network-guard"
        assert addon.stats.blocked == 1
        assert addon.rate_limited == 1

    def test_allows_non_denied_request(self):
        """Test addon allows requests without effect=deny or budget_exceeded."""
        from addons.network_guard import NetworkGuard
        from addons.policy_engine import PolicyDecision

        addon = NetworkGuard()

        flow = MagicMock()
        flow.request.host = "api.openai.com"
        flow.request.path = "/v1/chat"
        flow.request.method = "POST"
        flow.metadata = {}
        flow.response = None

        # Mock policy engine returning allow
        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="allow",
            reason="Allowed",
            budget_remaining=2999
        )

        with patch("addons.network_guard.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should NOT have blocked
        assert flow.response is None
        assert addon.stats.allowed == 1
        assert addon.stats.blocked == 0
        # Should have stored remaining budget
        assert flow.metadata.get("ratelimit_remaining") == 2999

    def test_warn_mode_does_not_block(self):
        """Test warn mode logs but doesn't block."""
        from addons.network_guard import NetworkGuard
        from addons.policy_engine import PolicyDecision

        addon = NetworkGuard()

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
            if name == "network_guard_enabled":
                return True
            if name == "network_guard_block":
                return False  # Warn mode
            return default

        with patch("addons.network_guard.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", side_effect=option_side_effect):
                addon.request(flow)

        # Should NOT have blocked in warn mode
        assert flow.response is None
        assert "blocked_by" not in flow.metadata
        assert addon.stats.warned == 1

    def test_disabled_does_not_check(self):
        """Test disabled addon doesn't check anything."""
        from addons.network_guard import NetworkGuard

        addon = NetworkGuard()

        flow = MagicMock()
        flow.request.host = "evil.com"
        flow.metadata = {}

        mock_engine = MagicMock()

        with patch("addons.network_guard.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=False):
                addon.request(flow)

        # Should not have called policy engine
        mock_engine.evaluate_request.assert_not_called()
        assert addon.stats.checks == 0

    def test_no_engine_allows(self):
        """Test requests pass through if no policy engine."""
        from addons.network_guard import NetworkGuard

        addon = NetworkGuard()

        flow = MagicMock()
        flow.request.host = "any.com"
        flow.request.path = "/"
        flow.request.method = "GET"
        flow.metadata = {}
        flow.response = None

        with patch("addons.network_guard.get_policy_engine", return_value=None):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # No engine = no blocking
        assert flow.response is None
        assert addon.stats.checks == 1
        assert addon.stats.allowed == 1


class TestNetworkGuardIntegration:
    """Integration tests with real PolicyEngine."""

    def test_deny_with_real_policy(self):
        """Test deny effect works with real policy engine."""
        from addons.network_guard import NetworkGuard
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
        engine._loader.set_baseline(policy)

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
        engine._loader.set_baseline(policy)

        # Allowed domains
        assert engine.evaluate_request("api.openai.com", "/v1/chat", "POST").effect == "allow"
        assert engine.evaluate_request("api.anthropic.com", "/messages", "POST").effect == "allow"

        # Denied domains (everything else)
        assert engine.evaluate_request("google.com", "/", "GET").effect == "deny"
        assert engine.evaluate_request("hacker.com", "/pwn", "GET").effect == "deny"

    def test_budget_with_real_policy(self):
        """Test budget/rate limiting with real policy engine."""
        from addons.policy_engine import PolicyEngine, Permission, UnifiedPolicy

        policy = UnifiedPolicy(
            permissions=[
                Permission(
                    action="network:request",
                    resource="api.openai.com/*",
                    effect="budget",
                    budget=2,  # Only 2 requests allowed (burst)
                    tier="explicit",
                ),
            ]
        )

        engine = PolicyEngine()
        engine._loader.set_baseline(policy)

        # First two requests should be allowed
        # (GCRA allows burst_capacity = max(1, budget//10) = 1, plus initial request)
        decision1 = engine.evaluate_request("api.openai.com", "/v1/chat", "POST")
        assert decision1.effect == "allow"

        decision2 = engine.evaluate_request("api.openai.com", "/v1/chat", "POST")
        assert decision2.effect == "allow"

        # Third request should be budget_exceeded
        decision3 = engine.evaluate_request("api.openai.com", "/v1/chat", "POST")
        assert decision3.effect == "budget_exceeded"

    def test_single_evaluation_per_request(self):
        """Test that NetworkGuard only calls evaluate_request once per request."""
        from addons.network_guard import NetworkGuard
        from addons.policy_engine import PolicyDecision

        addon = NetworkGuard()

        flow = MagicMock()
        flow.request.host = "api.openai.com"
        flow.request.path = "/v1/chat"
        flow.request.method = "POST"
        flow.metadata = {}
        flow.response = None

        mock_engine = MagicMock()
        mock_engine.evaluate_request.return_value = PolicyDecision(
            effect="allow",
            budget_remaining=100
        )

        with patch("addons.network_guard.get_policy_engine", return_value=mock_engine):
            with patch("addons.base.get_option_safe", return_value=True):
                addon.request(flow)

        # Should have called evaluate_request exactly once
        assert mock_engine.evaluate_request.call_count == 1


class TestHomoglyphDetection:
    """Tests for homoglyph attack detection in network guard."""

    def test_detects_cyrillic_in_domain(self):
        """Test detection of Cyrillic characters in domain names."""
        from addons.network_guard import detect_homoglyph_attack, HOMOGLYPH_ENABLED

        if not HOMOGLYPH_ENABLED:
            pytest.skip("confusable-homoglyphs not installed")

        # Cyrillic 'а' (U+0430) instead of Latin 'a'
        result = detect_homoglyph_attack("аpi.openai.com")
        assert result is not None
        assert result["dangerous"]

    def test_allows_normal_ascii_domain(self):
        """Test that normal ASCII domains pass."""
        from addons.network_guard import detect_homoglyph_attack, HOMOGLYPH_ENABLED

        if not HOMOGLYPH_ENABLED:
            pytest.skip("confusable-homoglyphs not installed")

        result = detect_homoglyph_attack("api.openai.com")
        assert result is None

    def test_blocks_homoglyph_domain_in_request(self):
        """Test that homoglyph domains are blocked in requests."""
        from addons.network_guard import NetworkGuard, HOMOGLYPH_ENABLED

        if not HOMOGLYPH_ENABLED:
            pytest.skip("confusable-homoglyphs not installed")

        addon = NetworkGuard()

        # Create mock flow with Cyrillic 'а' (U+0430) in domain
        flow = MagicMock()
        flow.request.host = "аpi.openai.com"  # Cyrillic 'а'
        flow.request.path = "/v1/chat"
        flow.request.method = "GET"
        flow.metadata = {}
        flow.response = None
        flow.client_conn.peername = ("127.0.0.1", 12345)

        # Mock should_block to return True
        addon.should_block = lambda: True
        addon._check_homoglyph = lambda: True

        with patch("addons.base.get_option_safe", return_value=True):
            addon.request(flow)

        # Should be blocked
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"homoglyph" in flow.response.content.lower()
