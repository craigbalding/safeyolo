"""Tests for network_guard addon (combined access control + rate limiting).

Contract under test:
  C1: On every request, evaluates the destination host against PDP policy.
  C2: DENY -> 403 block response with reason, type, action, reflection.
  C3: BUDGET_EXCEEDED -> 429 with Retry-After and X-RateLimit-Remaining headers.
  C4: REQUIRE_APPROVAL -> 428 with approval metadata.
  C5: ALLOW -> no response, flow continues; sets budget remaining in metadata if present.
  C6: ERROR from PDP -> fail-closed 403.
  C7: RuntimeError from get_policy_client() -> fail-closed 403.
  C8: Homoglyph detection: detects confusable Unicode in domain names -> 403.
  C9: Sets flow.metadata["blocked_by"] = "network-guard" on all blocks.
  C10: Emits security.network_guard audit events.
  C11: Warn mode: logs but does not set flow.response, increments warned stat.
  C12: Stats: checks, allowed, blocked, warned, rate_limited counters.
  C13: Per-flow bypass via is_bypassed() — early return if flow.response already set.
  C14: is_bypassed() is called in request() before any evaluation.
  C15: Disabled addon skips all checks.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from network_guard import HOMOGLYPH_ENABLED, NetworkGuard, detect_homoglyph_attack

from pdp import BudgetBlock, Effect

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_mock_decision(effect, reason="", budget_remaining=None):
    """Create a mock PolicyDecision with the given effect."""
    decision = MagicMock()
    decision.effect = effect
    decision.reason = reason
    decision.reason_codes = []

    if budget_remaining is not None:
        decision.budget = BudgetBlock(remaining=budget_remaining)
    else:
        decision.budget = None

    return decision


def make_flow(host="example.com", path="/", method="GET"):
    """Create a minimal mock flow suitable for NetworkGuard.request().

    CRITICAL: flow.response is set to None so is_bypassed() does not
    short-circuit.  Every test that calls addon.request() must use this
    helper or explicitly set flow.response = None.
    """
    flow = MagicMock()
    flow.response = None
    flow.request.host = host
    flow.request.path = path
    flow.request.method = method
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.headers = {}
    flow.request.content = b""
    flow.request.query = None
    flow.client_conn.peername = ("192.168.1.1", 12345)
    flow.metadata = {}
    return flow


# ---------------------------------------------------------------------------
# C2: DENY -> 403
# ---------------------------------------------------------------------------

class TestDenyDecision:
    """Requests denied by PDP produce a 403 with structured body."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_returns_403(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="Access denied to evil.com"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.status_code == 403

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_body_has_required_fields(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="Access denied to evil.com"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "access_denied"
        assert body["action"] == "self_correct"
        assert body["domain"] == "evil.com"
        assert body["reason"] == "Access denied to evil.com"
        assert "reflection" in body

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_sets_blocked_by_metadata(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="Access denied"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.metadata["blocked_by"] == "network-guard"

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_increments_blocked_stat(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="Access denied"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.blocked == 1
        assert addon.stats.allowed == 0

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_with_none_reason_uses_fallback(self, _bypass):
        """When PDP returns None reason, a human-readable fallback is used."""
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason=None
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["reason"] == "Access denied to evil.com"

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_x_blocked_by_header(self, _bypass):
        """Block response has X-Blocked-By: network-guard header."""
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="denied"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.headers["X-Blocked-By"] == "network-guard"


# ---------------------------------------------------------------------------
# C3: BUDGET_EXCEEDED -> 429
# ---------------------------------------------------------------------------

class TestRateLimitDecision:
    """Requests exceeding budget produce a 429 with rate-limit headers."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_budget_exceeded_returns_429(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="Rate limit exceeded"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.status_code == 429

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_budget_exceeded_body_has_required_fields(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="Rate limit exceeded"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "rate_limit_exceeded"
        assert body["action"] == "retry_with_backoff"
        assert body["domain"] == "api.openai.com"
        assert "reflection" in body

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_budget_exceeded_has_retry_after_header(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="Rate limit exceeded"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.headers["Retry-After"] == "60"

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_budget_exceeded_has_ratelimit_remaining_header(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="Rate limit exceeded"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.headers["X-RateLimit-Remaining"] == "0"

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_budget_exceeded_increments_rate_limited_stat(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="Rate limit exceeded"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.rate_limited == 1
        assert addon.stats.blocked == 1


# ---------------------------------------------------------------------------
# C4: REQUIRE_APPROVAL -> 428
# ---------------------------------------------------------------------------

class TestEgressApprovalDecision:
    """Requests needing egress approval produce a 428."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_require_approval_returns_428(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("unknown-host.com", "/api")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.REQUIRE_APPROVAL, reason="egress prompt"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("safeyolo.core.base.write_event"):
            addon.request(flow)

        assert flow.response.status_code == 428

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_require_approval_body_has_required_fields(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("unknown-host.com", "/api")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.REQUIRE_APPROVAL, reason="egress prompt"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("safeyolo.core.base.write_event"):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "egress_approval_required"
        assert body["action"] == "wait_for_approval"
        assert body["destination"] == "unknown-host.com"
        assert "reflection" in body

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_require_approval_sets_blocked_by(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("unknown-host.com", "/api")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.REQUIRE_APPROVAL, reason="egress prompt"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("safeyolo.core.base.write_event"):
            addon.request(flow)

        assert flow.metadata["blocked_by"] == "network-guard"


# ---------------------------------------------------------------------------
# C5: ALLOW -> pass through
# ---------------------------------------------------------------------------

class TestAllowDecision:
    """Allowed requests pass through with optional budget metadata."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_allow_does_not_set_response(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ALLOW, reason="Allowed", budget_remaining=2999
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is None

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_allow_increments_allowed_stat(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ALLOW, reason="Allowed", budget_remaining=2999
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.allowed == 1
        assert addon.stats.blocked == 0

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_allow_stores_budget_remaining_in_metadata(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ALLOW, reason="Allowed", budget_remaining=2999
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.metadata["ratelimit_remaining"] == 2999

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_allow_without_budget_does_not_set_metadata(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ALLOW, reason="Allowed"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert "ratelimit_remaining" not in flow.metadata


# ---------------------------------------------------------------------------
# C6: PDP ERROR -> fail-closed 403
# ---------------------------------------------------------------------------

class TestPDPErrorFailClosed:
    """PDP errors result in fail-closed denial."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_pdp_error_returns_403(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ERROR, reason="PDP unavailable"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.status_code == 403
        assert addon.stats.blocked == 1

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_pdp_error_body_contains_reason(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ERROR, reason="PDP unavailable"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert "PDP error" in body["reason"]


# ---------------------------------------------------------------------------
# C7: RuntimeError from get_policy_client() -> fail-closed 403
# ---------------------------------------------------------------------------

class TestRuntimeErrorFailClosed:
    """When PDP is not configured, get_policy_client() raises RuntimeError.
    NetworkGuard must catch it and fail closed."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_runtime_error_returns_403(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        with patch("network_guard.get_policy_client", side_effect=RuntimeError("not configured")), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.status_code == 403

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_runtime_error_sets_blocked_by(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        with patch("network_guard.get_policy_client", side_effect=RuntimeError("not configured")), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.metadata["blocked_by"] == "network-guard"

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_runtime_error_increments_blocked(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        with patch("network_guard.get_policy_client", side_effect=RuntimeError("not configured")), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.blocked == 1

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_runtime_error_body_mentions_fail_closed(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        with patch("network_guard.get_policy_client", side_effect=RuntimeError("not configured")), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert "PDP not configured" in body["reason"]


# ---------------------------------------------------------------------------
# C8: Homoglyph detection
# ---------------------------------------------------------------------------

class TestHomoglyphDetection:
    """Homoglyph attack detection blocks mixed-script domain spoofing."""

    @pytest.mark.skipif(not HOMOGLYPH_ENABLED, reason="confusable-homoglyphs not installed")
    def test_detects_cyrillic_in_domain(self):
        # Cyrillic 'a' (U+0430) instead of Latin 'a'
        result = detect_homoglyph_attack("\u0430pi.openai.com")
        assert result is not None
        assert result["dangerous"] is True
        assert result["domain"] == "\u0430pi.openai.com"
        assert "Mixed scripts" in result["message"]

    @pytest.mark.skipif(not HOMOGLYPH_ENABLED, reason="confusable-homoglyphs not installed")
    def test_normal_ascii_domain_returns_none(self):
        result = detect_homoglyph_attack("api.openai.com")
        assert result is None

    @pytest.mark.skipif(not HOMOGLYPH_ENABLED, reason="confusable-homoglyphs not installed")
    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_homoglyph_domain_blocked_with_403(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("\u0430pi.openai.com", "/v1/chat")

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["type"] == "homoglyph_attack"
        assert body["action"] == "abort"
        assert "reflection" in body

    @pytest.mark.skipif(not HOMOGLYPH_ENABLED, reason="confusable-homoglyphs not installed")
    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_homoglyph_sets_blocked_by(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("\u0430pi.openai.com", "/v1/chat")

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.metadata["blocked_by"] == "network-guard"

    def test_homoglyph_disabled_returns_none(self):
        """When HOMOGLYPH_ENABLED is False, detection always returns None."""
        with patch("network_guard.HOMOGLYPH_ENABLED", False):
            result = detect_homoglyph_attack("\u0430pi.openai.com")
        assert result is None

    @pytest.mark.skipif(not HOMOGLYPH_ENABLED, reason="confusable-homoglyphs not installed")
    def test_homoglyph_exception_returns_none(self):
        """If the homoglyph library raises, detection returns None (not crash)."""
        with patch("network_guard.confusables") as mock_conf:
            mock_conf.is_dangerous.side_effect = ValueError("boom")
            result = detect_homoglyph_attack("some.domain")
        assert result is None


# ---------------------------------------------------------------------------
# C11: Warn mode
# ---------------------------------------------------------------------------

class TestWarnMode:
    """Warn mode logs decisions but does not block requests."""

    def _option_warn(self, name, default=True):
        """Side effect: enabled=True, block=False (warn mode)."""
        if name == "network_guard_enabled":
            return True
        if name == "network_guard_block":
            return False
        if name == "network_guard_homoglyph":
            return True
        return default

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_warn_mode_deny_does_not_block(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="Access denied"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", side_effect=self._option_warn):
            addon.request(flow)

        assert flow.response is None
        assert "blocked_by" not in flow.metadata
        assert addon.stats.warned == 1
        assert addon.stats.blocked == 0

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_warn_mode_rate_limit_does_not_block(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="Rate limit exceeded"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", side_effect=self._option_warn):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1
        assert addon.rate_limited == 1

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_warn_mode_egress_approval_does_not_block(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("unknown-host.com", "/api")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.REQUIRE_APPROVAL, reason="egress prompt"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", side_effect=self._option_warn), \
             patch("safeyolo.core.base.write_event"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1

    @pytest.mark.skipif(not HOMOGLYPH_ENABLED, reason="confusable-homoglyphs not installed")
    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_warn_mode_homoglyph_does_not_block(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("\u0430pi.openai.com", "/v1/chat")

        with patch("safeyolo.core.base.get_option_safe", side_effect=self._option_warn):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1


# ---------------------------------------------------------------------------
# C13 + C14: Bypass behaviour
# ---------------------------------------------------------------------------

class TestBypassBehaviour:
    """is_bypassed() integration: flow.response set -> skip evaluation."""

    def test_flow_with_existing_response_is_bypassed(self):
        """If another addon already set flow.response, request() returns early."""
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")
        flow.response = MagicMock()  # truthy — simulates another addon's block

        mock_client = MagicMock()

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        # Evaluation should NOT have been called
        mock_client.evaluate.assert_not_called()
        assert addon.stats.checks == 0

    def test_is_bypassed_called_before_evaluation(self):
        """request() calls is_bypassed() before any PDP evaluation."""
        addon = NetworkGuard()
        flow = make_flow("any.com", "/")

        call_order = []

        def tracking_is_bypassed(f):
            call_order.append("is_bypassed")
            return True  # short-circuit

        mock_client = MagicMock()

        def tracking_evaluate(event):
            call_order.append("evaluate")
            return make_mock_decision(Effect.ALLOW)

        mock_client.evaluate.side_effect = tracking_evaluate

        with patch.object(addon, "is_bypassed", side_effect=tracking_is_bypassed), \
             patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert call_order == ["is_bypassed"]


# ---------------------------------------------------------------------------
# C15: Disabled addon
# ---------------------------------------------------------------------------

class TestDisabledAddon:
    """Disabled addon skips all checks."""

    def test_disabled_does_not_call_evaluate(self):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")

        mock_client = MagicMock()

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=False):
            addon.request(flow)

        mock_client.evaluate.assert_not_called()
        assert addon.stats.checks == 0


# ---------------------------------------------------------------------------
# C1: Single evaluation per request
# ---------------------------------------------------------------------------

class TestSingleEvaluation:
    """NetworkGuard calls PolicyClient.evaluate exactly once per request."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_evaluate_called_once(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("api.openai.com", "/v1/chat", "POST")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ALLOW, budget_remaining=100
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert mock_client.evaluate.call_count == 1


# ---------------------------------------------------------------------------
# C12: Stats
# ---------------------------------------------------------------------------

class TestStats:
    """get_stats() returns accurate counters after operations."""

    def test_initial_stats(self):
        addon = NetworkGuard()
        stats = addon.get_stats()
        assert stats == {
            "enabled": True,  # default from get_option_safe
            "checks": 0,
            "allowed": 0,
            "blocked": 0,
            "warned": 0,
            "rate_limited": 0,
        }

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_stats_after_deny_and_allow(self, _bypass):
        addon = NetworkGuard()

        # First request: deny
        flow1 = make_flow("evil.com", "/malware")
        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="denied"
        )
        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow1)

        # Second request: allow
        flow2 = make_flow("good.com", "/")
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.ALLOW, reason="allowed"
        )
        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow2)

        stats = addon.get_stats()
        assert stats["checks"] == 2
        assert stats["allowed"] == 1
        assert stats["blocked"] == 1
        assert stats["rate_limited"] == 0

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_stats_after_rate_limit(self, _bypass):
        addon = NetworkGuard()

        flow = make_flow("api.openai.com", "/v1/chat", "POST")
        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.BUDGET_EXCEEDED, reason="exceeded"
        )
        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        stats = addon.get_stats()
        assert stats["rate_limited"] == 1
        assert stats["blocked"] == 1
        assert stats["checks"] == 1

    def test_stats_checks_not_incremented_when_bypassed(self):
        """Bypassed flows should not increment checks counter."""
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")
        flow.response = MagicMock()  # truthy — triggers bypass

        mock_client = MagicMock()

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.checks == 0


# ---------------------------------------------------------------------------
# C10: Audit events
# ---------------------------------------------------------------------------

class TestAuditEvents:
    """Audit events emitted via write_event on security decisions."""

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_deny_emits_audit_event(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("evil.com", "/malware")
        flow.metadata["request_id"] = "req-123"

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.DENY, reason="Access denied"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("safeyolo.core.base.write_event") as mock_write:
            addon.request(flow)

        calls = [c for c in mock_write.call_args_list if c[0][0] == "security.network_guard"]
        assert len(calls) == 1
        kwargs = calls[0][1]
        assert kwargs["decision"].value == "deny"
        assert kwargs["host"] == "evil.com"

    @patch.object(NetworkGuard, "is_bypassed", return_value=False)
    def test_require_approval_emits_approval_metadata(self, _bypass):
        addon = NetworkGuard()
        flow = make_flow("unknown-host.com", "/api")

        mock_client = MagicMock()
        mock_client.evaluate.return_value = make_mock_decision(
            Effect.REQUIRE_APPROVAL, reason="egress prompt"
        )

        with patch("network_guard.get_policy_client", return_value=mock_client), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("safeyolo.core.base.write_event") as mock_write:
            addon.request(flow)

        calls = [c for c in mock_write.call_args_list if c[0][0] == "security.network_guard"]
        assert len(calls) >= 1
        kwargs = calls[-1][1]
        assert kwargs["approval"] is not None
        assert kwargs["approval"].approval_type == "network_egress"
        assert kwargs["approval"].key == "unknown-host.com"


# ---------------------------------------------------------------------------
# Module-level addon instance
# ---------------------------------------------------------------------------

class TestModuleInstance:
    """The module-level addons list is correct."""

    def test_addons_list_contains_network_guard(self):
        from network_guard import addons
        assert len(addons) == 1
        assert isinstance(addons[0], NetworkGuard)

    def test_addon_name(self):
        addon = NetworkGuard()
        assert addon.name == "network-guard"
