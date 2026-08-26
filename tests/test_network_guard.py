"""Behavioral tests for the network policy enforcement addon.

Assurance contract:
  C1: Each non-bypassed request is evaluated exactly once.
  C2: DENY produces a structured 403 response.
  C3: BUDGET_EXCEEDED produces a structured 429 response.
  C4: REQUIRE_APPROVAL produces a structured 428 response.
  C5: ALLOW passes through and preserves budget metadata.
  C6: PDP ERROR fails closed.
  C7: An unconfigured PDP fails closed.
  C8: Homoglyph attacks are detected and blocked.
  C9: Every block records ``blocked_by`` metadata.
  C10: Security decisions emit audit events.
  C11: Warn mode records but does not block violations.
  C12: Counters describe the observed outcomes.
  C13: Prior responses and policy-disabled domains bypass evaluation.
  C14: Bypass happens before evaluation.
  C15: A disabled addon performs no checks.

``NetworkGuard``, mitmproxy flows, PDP decisions, options, and ordinary policy
evaluation are real. Autospecced PolicyClient collaborators are used only to
inject boundary outcomes that are not practical to obtain from a static policy
(budget exhaustion and PDP failures).
"""

import json
from unittest.mock import create_autospec, patch

import pytest
from mitmproxy import ctx, http
from network_guard import HOMOGLYPH_ENABLED, NetworkGuard, detect_homoglyph_attack

from pdp import BudgetBlock, DecisionEventBlock, Effect, PolicyClient, PolicyDecision
from safeyolo.proxy_modes.unix_listener import UnixMode

pytestmark = pytest.mark.assurance_boundary


def make_decision(
    effect: Effect,
    *,
    reason: str = "decision injected by test",
    budget_remaining: int | None = None,
) -> PolicyDecision:
    """Return a schema-valid PDP decision, never a permissive data mock."""
    return PolicyDecision(
        event=DecisionEventBlock(
            event_id="evt-network-guard-test",
            policy_hash="test-policy-hash",
            engine_version="test-engine",
        ),
        effect=effect,
        reason=reason,
        reason_codes=[effect.value.upper()],
        budget=(BudgetBlock(remaining=budget_remaining) if budget_remaining is not None else None),
    )


@pytest.fixture
def network_flow(make_flow):
    """Create a real mitmproxy HTTPFlow with a concise network-test API."""

    def _make(
        host: str = "example.com",
        path: str = "/",
        method: str = "GET",
    ):
        # A real HTTP request carries an internationalized hostname in IDNA
        # wire form. mitmproxy decodes it back to Unicode in Request.host.
        wire_host = host.encode("idna").decode("ascii")
        return make_flow(method=method, url=f"https://{wire_host}{path}")

    return _make


@pytest.fixture
def policy_boundary():
    """Autospecced collaborator for exceptional PolicyClient outcomes."""
    return create_autospec(PolicyClient, instance=True, spec_set=True)


def evaluate_with(policy_boundary, decision):
    """Patch only NetworkGuard's PDP boundary with signature enforcement."""
    policy_boundary.evaluate.return_value = decision
    return patch(
        "network_guard.get_policy_client",
        autospec=True,
        return_value=policy_boundary,
    )


# ---------------------------------------------------------------------------
# C2, C4, C5: ordinary outcomes through the real LocalPolicyClient
# ---------------------------------------------------------------------------


class TestRealPolicyOutcomes:
    def test_identity_conflict_fails_closed_before_policy(self, network_guard, network_flow):
        # *.internal normally bypasses network_guard. A conflict must never
        # turn into that more permissive unscoped policy decision.
        flow = network_flow("safe.internal", "/resource")
        flow.client_conn.proxy_mode = UnixMode.parse(
            "unix:/tmp/10.0.0.5_alice/proxy.sock"
        )
        flow.metadata["agent"] = "bob"

        network_guard.request(flow)

        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert "identity sources disagree" in body["reason"]
        assert flow.metadata["agent_identity_status"] == "conflict"
        assert "agent" not in flow.metadata

    def test_deny_is_a_structured_403(self, network_guard, network_flow):
        flow = network_flow("evil.com", "/malware")

        network_guard.request(flow)

        assert flow.response.status_code == 403
        assert flow.response.headers["X-Blocked-By"] == "network-guard"
        body = json.loads(flow.response.content)
        assert body["type"] == "access_denied"
        assert body["action"] == "self_correct"
        assert body["domain"] == "evil.com"
        assert body["reason"]
        assert "reflection" in body
        assert flow.metadata["blocked_by"] == "network-guard"
        assert flow.metadata["block_reason"] == body["reason"]
        assert network_guard.stats.blocked == 1
        assert network_guard.stats.allowed == 0

    def test_approval_is_a_structured_428(self, network_guard, network_flow):
        flow = network_flow("unknown-host.com", "/api")

        network_guard.request(flow)

        assert flow.response.status_code == 428
        body = json.loads(flow.response.content)
        assert body["type"] == "egress_approval_required"
        assert body["action"] == "wait_for_approval"
        assert body["destination"] == "unknown-host.com"
        assert "reflection" in body
        assert flow.metadata["blocked_by"] == "network-guard"

    def test_allow_passes_through(self, network_guard, network_flow):
        flow = network_flow("good.com", "/resource")

        network_guard.request(flow)

        assert flow.response is None
        assert "blocked_by" not in flow.metadata
        assert "ratelimit_remaining" not in flow.metadata
        assert network_guard.stats.allowed == 1
        assert network_guard.stats.blocked == 0


# ---------------------------------------------------------------------------
# C1, C3, C5, C6, C7: exceptional PolicyClient boundary outcomes
# ---------------------------------------------------------------------------


class TestPolicyBoundaryOutcomes:
    def test_budget_exceeded_is_a_structured_429(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        flow = network_flow("api.openai.com", "/v1/chat", "POST")
        decision = make_decision(
            Effect.BUDGET_EXCEEDED,
            reason="Rate limit exceeded",
            budget_remaining=0,
        )

        with evaluate_with(policy_boundary, decision):
            network_guard.request(flow)

        assert flow.response.status_code == 429
        assert flow.response.headers["Retry-After"] == "60"
        assert flow.response.headers["X-RateLimit-Remaining"] == "0"
        body = json.loads(flow.response.content)
        assert body["type"] == "rate_limit_exceeded"
        assert body["action"] == "retry_with_backoff"
        assert body["domain"] == "api.openai.com"
        assert "reflection" in body
        assert flow.metadata["blocked_by"] == "network-guard"
        assert network_guard.rate_limited == 1
        assert network_guard.stats.blocked == 1

    def test_allow_preserves_budget_remaining(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        flow = network_flow("api.openai.com", "/v1/chat", "POST")
        decision = make_decision(
            Effect.ALLOW,
            reason="Allowed",
            budget_remaining=2999,
        )

        with evaluate_with(policy_boundary, decision):
            network_guard.request(flow)

        assert flow.response is None
        assert flow.metadata["ratelimit_remaining"] == 2999

    def test_empty_deny_reason_uses_fallback(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        """An empty string is schema-valid; ``None`` is not."""
        flow = network_flow("empty-reason.example", "/")
        decision = make_decision(Effect.DENY, reason="")

        with evaluate_with(policy_boundary, decision):
            network_guard.request(flow)

        body = json.loads(flow.response.content)
        assert body["reason"] == "Access denied to empty-reason.example"

    def test_pdp_error_fails_closed(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        flow = network_flow("any.com", "/")
        decision = make_decision(Effect.ERROR, reason="PDP unavailable")

        with evaluate_with(policy_boundary, decision):
            network_guard.request(flow)

        assert flow.response.status_code == 403
        assert network_guard.stats.blocked == 1
        body = json.loads(flow.response.content)
        assert body["reason"] == "PDP error: PDP unavailable"

    def test_unconfigured_pdp_fails_closed(self, network_guard, network_flow):
        flow = network_flow("any.com", "/")

        with patch(
            "network_guard.get_policy_client",
            autospec=True,
            side_effect=RuntimeError("not configured"),
        ):
            network_guard.request(flow)

        assert flow.response.status_code == 403
        assert flow.metadata["blocked_by"] == "network-guard"
        assert network_guard.stats.blocked == 1
        body = json.loads(flow.response.content)
        assert body["reason"] == "PDP not configured (fail-closed)"

    def test_each_request_is_evaluated_once(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        flow = network_flow("api.openai.com", "/v1/chat", "POST")
        decision = make_decision(Effect.ALLOW, budget_remaining=100)

        with evaluate_with(policy_boundary, decision):
            network_guard.request(flow)

        policy_boundary.evaluate.assert_called_once()
        event = policy_boundary.evaluate.call_args.args[0]
        assert event.http.host == "api.openai.com"
        assert event.http.path == "/v1/chat"
        assert event.http.method == "POST"


# ---------------------------------------------------------------------------
# C8: homoglyph detection
# ---------------------------------------------------------------------------


class TestHomoglyphDetection:
    @pytest.mark.skipif(
        not HOMOGLYPH_ENABLED,
        reason="confusable-homoglyphs not installed",
    )
    def test_detects_cyrillic_in_domain(self):
        result = detect_homoglyph_attack("\u0430pi.openai.com")

        assert result is not None
        assert result["dangerous"] is True
        assert result["domain"] == "\u0430pi.openai.com"
        assert "Mixed scripts" in result["message"]

    @pytest.mark.skipif(
        not HOMOGLYPH_ENABLED,
        reason="confusable-homoglyphs not installed",
    )
    def test_normal_ascii_domain_returns_none(self):
        assert detect_homoglyph_attack("api.openai.com") is None

    @pytest.mark.skipif(
        not HOMOGLYPH_ENABLED,
        reason="confusable-homoglyphs not installed",
    )
    def test_homoglyph_domain_is_blocked(self, network_guard, network_flow):
        flow = network_flow("\u0430pi.openai.com", "/v1/chat")

        network_guard.request(flow)

        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["type"] == "homoglyph_attack"
        assert body["action"] == "abort"
        assert "reflection" in body
        assert flow.metadata["blocked_by"] == "network-guard"

    def test_disabled_detector_returns_none(self):
        with patch("network_guard.HOMOGLYPH_ENABLED", False):
            result = detect_homoglyph_attack("\u0430pi.openai.com")

        assert result is None

    @pytest.mark.skipif(
        not HOMOGLYPH_ENABLED,
        reason="confusable-homoglyphs not installed",
    )
    def test_detector_failure_does_not_crash_request_path(self):
        with patch("network_guard.confusables", autospec=True) as confusables:
            confusables.is_dangerous.side_effect = ValueError("boom")
            result = detect_homoglyph_attack("some.domain")

        assert result is None


# ---------------------------------------------------------------------------
# C11: warn mode through real options
# ---------------------------------------------------------------------------


class TestWarnMode:
    def test_deny_warns_without_blocking(self, network_guard, network_flow):
        ctx.options.network_guard_block = False
        flow = network_flow("evil.com", "/malware")

        network_guard.request(flow)

        assert flow.response is None
        assert "blocked_by" not in flow.metadata
        assert network_guard.stats.warned == 1
        assert network_guard.stats.blocked == 0

    def test_approval_warns_without_blocking(self, network_guard, network_flow):
        ctx.options.network_guard_block = False
        flow = network_flow("unknown-host.com", "/api")

        network_guard.request(flow)

        assert flow.response is None
        assert network_guard.stats.warned == 1

    def test_rate_limit_warns_without_blocking(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        ctx.options.network_guard_block = False
        flow = network_flow("api.openai.com", "/v1/chat", "POST")
        decision = make_decision(Effect.BUDGET_EXCEEDED, reason="exceeded")

        with evaluate_with(policy_boundary, decision):
            network_guard.request(flow)

        assert flow.response is None
        assert network_guard.stats.warned == 1
        assert network_guard.rate_limited == 1

    @pytest.mark.skipif(
        not HOMOGLYPH_ENABLED,
        reason="confusable-homoglyphs not installed",
    )
    def test_homoglyph_warns_without_blocking(self, network_guard, network_flow):
        ctx.options.network_guard_block = False
        flow = network_flow("\u0430pi.openai.com", "/v1/chat")

        network_guard.request(flow)

        assert flow.response is None
        assert network_guard.stats.warned == 1


# ---------------------------------------------------------------------------
# C13, C14, C15: bypass and disabled behavior
# ---------------------------------------------------------------------------


class TestBypassAndDisable:
    def test_prior_response_bypasses_before_evaluation(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        flow = network_flow("evil.com", "/malware")
        flow.response = http.Response.make(451, b"blocked upstream")

        with patch(
            "network_guard.get_policy_client",
            autospec=True,
            return_value=policy_boundary,
        ):
            network_guard.request(flow)

        assert flow.response.status_code == 451
        policy_boundary.evaluate.assert_not_called()
        assert network_guard.stats.checks == 0

    def test_policy_disabled_domain_bypasses_before_evaluation(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        flow = network_flow("db.internal", "/query")

        with patch(
            "network_guard.get_policy_client",
            autospec=True,
            return_value=policy_boundary,
        ):
            network_guard.request(flow)

        assert flow.response is None
        policy_boundary.evaluate.assert_not_called()
        assert network_guard.stats.checks == 0

    def test_disabled_addon_performs_no_checks(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        ctx.options.network_guard_enabled = False
        flow = network_flow("evil.com", "/malware")

        with patch(
            "network_guard.get_policy_client",
            autospec=True,
            return_value=policy_boundary,
        ):
            network_guard.request(flow)

        assert flow.response is None
        policy_boundary.evaluate.assert_not_called()
        assert network_guard.stats.checks == 0


# ---------------------------------------------------------------------------
# C10, C12: audit evidence and counters
# ---------------------------------------------------------------------------


class TestAuditAndStats:
    def test_deny_emits_correlated_audit_event(self, network_guard, network_flow):
        flow = network_flow("evil.com", "/malware")
        flow.metadata["request_id"] = "req-123"

        with patch("safeyolo.core.base.write_event", autospec=True) as write_event:
            network_guard.request(flow)

        calls = [call for call in write_event.call_args_list if call.args[0] == "security.network_guard"]
        assert len(calls) == 1
        kwargs = calls[0].kwargs
        assert kwargs["decision"].value == "deny"
        assert kwargs["host"] == "evil.com"
        assert kwargs["request_id"] == "req-123"

    def test_approval_event_contains_approval_metadata(
        self,
        network_guard,
        network_flow,
    ):
        flow = network_flow("unknown-host.com", "/api")

        with patch("safeyolo.core.base.write_event", autospec=True) as write_event:
            network_guard.request(flow)

        calls = [call for call in write_event.call_args_list if call.args[0] == "security.network_guard"]
        assert len(calls) == 1
        approval = calls[0].kwargs["approval"]
        assert approval.approval_type == "network_egress"
        assert approval.key == "unknown-host.com"

    def test_stats_track_deny_allow_and_rate_limit(
        self,
        network_guard,
        network_flow,
        policy_boundary,
    ):
        network_guard.request(network_flow("evil.com", "/malware"))
        network_guard.request(network_flow("good.com", "/"))

        decision = make_decision(Effect.BUDGET_EXCEEDED, reason="exceeded")
        with evaluate_with(policy_boundary, decision):
            network_guard.request(network_flow("api.openai.com", "/v1/chat", "POST"))

        assert network_guard.get_stats() == {
            "enabled": True,
            "checks": 3,
            "allowed": 1,
            "blocked": 2,
            "warned": 0,
            "rate_limited": 1,
        }


class TestModuleContract:
    def test_module_exports_one_network_guard(self):
        from network_guard import addons

        assert len(addons) == 1
        assert isinstance(addons[0], NetworkGuard)
        assert addons[0].name == "network-guard"
