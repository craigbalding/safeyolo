"""
Tests for policy_engine.py - Unified IAM-style policy engine.

Tests destination-first credential evaluation, budget tracking, permission matching,
fail-closed defaults, policy mutation, and addon configuration.

Organised by contract area:
- TestPatternMatching: glob pattern matching helper
- TestConditionMatching: Condition model field matching
- TestGatewayCondition: gateway-specific condition fields (tactics, enables, etc.)
- TestCapabilityCondition: capability condition matching
- TestPolicyEngine: credential evaluation (evaluate_credential)
- TestAddCredentialApproval: runtime credential approval
- TestEvaluateRequest: network request evaluation (evaluate_request)
- TestEvaluateRequestAgentScoped: agent-scoped permission path
- TestBudgetTracking: per-host budget enforcement
- TestGlobalBudget: global budget cap (min of task/baseline)
- TestRiskyRouteEvaluation: gateway risk appetite rules
- TestGatewayRequestEvaluation: compiled capability route permissions
- TestAddonConfiguration: addon enable/disable/bypass/required
- TestGetBaseline: baseline access contract
- TestPolicyMutation: add_host_allowance, add_host_denial, update_host_rate
- TestPolicyLifecycle: replace_baseline, set_task_policy
- TestConsumeBudget: external budget consumption API
- TestResetBudgets: budget reset operations
- TestFailClosed: fail-closed default-deny scenarios
"""

import pytest

# =============================================================================
# Pattern Matching
# =============================================================================


class TestPatternMatching:
    """Tests for glob pattern matching."""

    @pytest.fixture
    def matches_pattern(self):
        """Get the pattern matching function."""
        from safeyolo.policy.engine import _matches_pattern

        return _matches_pattern

    def test_exact_match(self, matches_pattern):
        """Test exact resource matching."""
        assert matches_pattern("api.openai.com/*", "api.openai.com/*")
        assert not matches_pattern("api.openai.com/*", "api.anthropic.com/*")

    def test_wildcard_domain(self, matches_pattern):
        """Test wildcard domain matching."""
        assert matches_pattern("storage.googleapis.com/*", "*.googleapis.com/*")
        assert matches_pattern("auth.googleapis.com/*", "*.googleapis.com/*")
        # Must not match different TLD
        assert not matches_pattern("googleapis.com.evil.com/*", "*.googleapis.com/*")

    def test_universal_wildcard(self, matches_pattern):
        """Test * matches everything."""
        assert matches_pattern("anything.com/*", "*")
        assert matches_pattern("api.openai.com/v1/chat", "*")

    def test_wildcard_domain_matches_bare_domain(self, matches_pattern):
        """*.example.com also matches example.com itself."""
        assert matches_pattern("googleapis.com/*", "*.googleapis.com/*")

    def test_case_insensitive(self, matches_pattern):
        """Pattern matching is case-insensitive."""
        assert matches_pattern("API.OpenAI.com/*", "api.openai.com/*")
        assert matches_pattern("api.openai.com/*", "API.OPENAI.COM/*")


# =============================================================================
# Condition Matching
# =============================================================================


class TestConditionMatching:
    """Tests for Condition model matching."""

    @pytest.fixture
    def make_condition(self):
        """Factory for creating Condition objects."""
        from safeyolo.policy.engine import Condition

        return Condition

    def test_credential_type_match(self, make_condition):
        """Test credential type pattern matching."""
        cond = make_condition(credential=["openai:*"])

        # Should match openai type
        assert cond.matches({"credential_type": "openai", "credential_hmac": ""})

        # Should not match other types
        assert not cond.matches({"credential_type": "anthropic", "credential_hmac": ""})

    def test_credential_hmac_match(self, make_condition):
        """Test HMAC-based credential matching."""
        cond = make_condition(credential=["hmac:a1b2c3d4e5f6"])

        # Should match exact HMAC
        assert cond.matches({"credential_type": "unknown", "credential_hmac": "a1b2c3d4e5f6"})

        # Should not match different HMAC
        assert not cond.matches({"credential_type": "unknown", "credential_hmac": "different1234"})

    def test_mixed_credential_condition(self, make_condition):
        """Test condition with both type and HMAC patterns."""
        cond = make_condition(credential=["openai:*", "hmac:specific123"])

        # Should match openai type
        assert cond.matches({"credential_type": "openai", "credential_hmac": "whatever"})

        # Should match specific HMAC even with unknown type
        assert cond.matches({"credential_type": "unknown", "credential_hmac": "specific123"})

        # Should not match unknown type with different HMAC
        assert not cond.matches({"credential_type": "unknown", "credential_hmac": "different"})

    def test_method_match_case_insensitive(self, make_condition):
        """Method condition matches case-insensitively."""
        cond = make_condition(method="GET")
        assert cond.matches({"method": "get"})
        assert cond.matches({"method": "GET"})
        assert not cond.matches({"method": "POST"})

    def test_method_list(self, make_condition):
        """Method condition accepts a list of methods."""
        cond = make_condition(method=["GET", "HEAD"])
        assert cond.matches({"method": "GET"})
        assert cond.matches({"method": "HEAD"})
        assert not cond.matches({"method": "POST"})

    def test_path_prefix_match(self, make_condition):
        """Path prefix condition matches start of path."""
        cond = make_condition(path_prefix="/v1/")
        assert cond.matches({"path": "/v1/chat"})
        assert not cond.matches({"path": "/v2/chat"})

    def test_content_type_match(self, make_condition):
        """Content type condition matches substring."""
        cond = make_condition(content_type="application/json")
        assert cond.matches({"content_type": "application/json; charset=utf-8"})
        assert not cond.matches({"content_type": "text/html"})


class TestGatewayCondition:
    """Tests for gateway-specific Condition fields."""

    @pytest.fixture
    def make_condition(self):
        from safeyolo.policy.engine import Condition

        return Condition

    def test_tactics_any_match(self, make_condition):
        cond = make_condition(tactics=["exfiltration", "persistence"])
        assert cond.matches({"tactics": ["exfiltration"]})
        assert cond.matches({"tactics": ["persistence", "impact"]})
        assert not cond.matches({"tactics": ["collection"]})
        assert not cond.matches({"tactics": []})

    def test_enables_any_match(self, make_condition):
        cond = make_condition(enables=["credential_access"])
        assert cond.matches({"enables": ["credential_access", "lateral_movement"]})
        assert not cond.matches({"enables": ["defense_evasion"]})
        assert not cond.matches({"enables": []})

    def test_irreversible_exact_match(self, make_condition):
        cond = make_condition(irreversible=True)
        assert cond.matches({"irreversible": True})
        assert not cond.matches({"irreversible": False})
        assert not cond.matches({})

    def test_account_match(self, make_condition):
        cond = make_condition(account="operator")
        assert cond.matches({"account": "operator"})
        assert not cond.matches({"account": "agent"})

    def test_account_list_match(self, make_condition):
        cond = make_condition(account=["operator", "team-support"])
        assert cond.matches({"account": "operator"})
        assert cond.matches({"account": "team-support"})
        assert not cond.matches({"account": "agent"})

    def test_agent_glob_match(self, make_condition):
        cond = make_condition(agent="boris*")
        assert cond.matches({"agent": "boris"})
        assert cond.matches({"agent": "boris-2"})
        assert not cond.matches({"agent": "alice"})

    def test_service_glob_match(self, make_condition):
        cond = make_condition(service="g*")
        assert cond.matches({"service": "gmail"})
        assert cond.matches({"service": "github"})
        assert not cond.matches({"service": "slack"})

    def test_none_conditions_always_match(self, make_condition):
        """All None gateway conditions should match anything."""
        cond = make_condition()
        assert cond.matches({"tactics": ["exfiltration"], "account": "operator"})

    def test_combined_conditions(self, make_condition):
        """Multiple conditions must ALL match."""
        cond = make_condition(tactics=["exfiltration"], account="operator")
        assert cond.matches({"tactics": ["exfiltration"], "account": "operator"})
        assert not cond.matches({"tactics": ["exfiltration"], "account": "agent"})
        assert not cond.matches({"tactics": ["collection"], "account": "operator"})


class TestCapabilityCondition:
    """Tests for capability condition matching on Condition model."""

    @pytest.fixture
    def make_condition(self):
        from safeyolo.policy.engine import Condition

        return Condition

    def test_capability_exact_match(self, make_condition):
        cond = make_condition(capability="reader")
        assert cond.matches({"capability": "reader"})
        assert not cond.matches({"capability": "writer"})

    def test_capability_glob_match(self, make_condition):
        cond = make_condition(capability="*_manager")
        assert cond.matches({"capability": "category_manager"})
        assert cond.matches({"capability": "feed_manager"})
        assert not cond.matches({"capability": "reader"})

    def test_capability_wildcard_all(self, make_condition):
        cond = make_condition(capability="*")
        assert cond.matches({"capability": "anything"})

    def test_capability_none_matches_all(self, make_condition):
        cond = make_condition()  # capability is None
        assert cond.matches({"capability": "reader"})
        assert cond.matches({})


# =============================================================================
# Credential Evaluation
# =============================================================================


class TestPolicyEngine:
    """Tests for PolicyEngine credential evaluation."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with test baseline policy."""
        from safeyolo.policy.engine import PolicyEngine

        # Create test policy.yaml
        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test policy"

permissions:
  # OpenAI endpoints accept OpenAI credentials
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["openai:*"]

  # Anthropic endpoints accept Anthropic credentials
  - action: credential:use
    resource: "api.anthropic.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["anthropic:*"]

  # Specific HMAC approval for test endpoint
  - action: credential:use
    resource: "api.example.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["hmac:testhmac1234"]

  # Unknown destinations require approval
  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit

  # Rate limits
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 100
    tier: explicit

budgets:
  network:request: 1000

required:
  - credential_guard
  - network_guard

addons:
  credential_guard:
    enabled: true
  network_guard:
    enabled: true
""")

        engine = PolicyEngine(baseline_path=baseline)
        return engine

    def test_known_credential_to_correct_host(self, engine):
        """Test that known credentials are allowed to their designated hosts."""
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.openai.com",
            path="/v1/chat/completions",
        )
        assert decision.effect == "allow"

    def test_known_credential_to_wrong_host(self, engine):
        """Test that known credentials are blocked from wrong hosts."""
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.anthropic.com",  # Wrong host for OpenAI key
            path="/v1/messages",
        )
        # Should trigger prompt (catch-all) not allow
        assert decision.effect == "prompt"

    def test_unknown_credential_requires_approval(self, engine):
        """Test that unknown credentials require approval."""
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.newservice.com",
            path="/api/endpoint",
        )
        assert decision.effect == "prompt"

    def test_hmac_based_approval(self, engine):
        """Test that specific HMAC can be approved for destination."""
        # Should allow with correct HMAC
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.example.com",
            path="/api/endpoint",
            credential_hmac="testhmac1234",
        )
        assert decision.effect == "allow"

        # Should not allow with wrong HMAC
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.example.com",
            path="/api/endpoint",
            credential_hmac="wronghmac999",
        )
        assert decision.effect == "prompt"


# =============================================================================
# Runtime Credential Approval
# =============================================================================


class TestAddCredentialApproval:
    """Tests for adding credential approvals at runtime."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with minimal baseline."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test policy"

permissions:
  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit

budgets: {}
required: []
addons: {}
""")

        engine = PolicyEngine(baseline_path=baseline)
        return engine

    def test_add_type_approval(self, engine):
        """Test adding type-based approval."""
        # Initially should require approval
        decision = engine.evaluate_credential(
            credential_type="custom",
            destination="api.custom.com",
            path="/",
        )
        assert decision.effect == "prompt"

        # Add approval
        engine.add_credential_approval(
            destination="api.custom.com",
            cred_id="custom:*",
        )

        # Should now be allowed
        decision = engine.evaluate_credential(
            credential_type="custom",
            destination="api.custom.com",
            path="/",
        )
        assert decision.effect == "allow"

    def test_add_hmac_approval(self, engine):
        """Test adding HMAC-based approval."""
        # Initially should require approval
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.specific.com",
            path="/",
            credential_hmac="uniquehmac123",
        )
        assert decision.effect == "prompt"

        # Add HMAC-specific approval
        engine.add_credential_approval(
            destination="api.specific.com",
            cred_id="hmac:uniquehmac123",
        )

        # Should now be allowed with correct HMAC
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.specific.com",
            path="/",
            credential_hmac="uniquehmac123",
        )
        assert decision.effect == "allow"

        # Different HMAC should still require approval
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.specific.com",
            path="/",
            credential_hmac="differenthmac",
        )
        assert decision.effect == "prompt"


# =============================================================================
# Network Request Evaluation (evaluate_request)
# =============================================================================


class TestEvaluateRequest:
    """Tests for evaluate_request: network request permission evaluation."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with network request permissions."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Network eval test policy"

permissions:
  # Explicitly allowed host
  - action: network:request
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit

  # Explicitly denied host
  - action: network:request
    resource: "evil.example.com/*"
    effect: deny
    tier: explicit

  # Prompt-required host
  - action: network:request
    resource: "needs-approval.example.com/*"
    effect: prompt
    tier: explicit

  # Rate-limited host
  - action: network:request
    resource: "api.limited.com/*"
    effect: budget
    budget: 60
    tier: explicit

budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_allowed_host_returns_allow(self, engine):
        """Explicitly allowed host returns allow effect."""
        decision = engine.evaluate_request(host="api.openai.com", path="/v1/chat")
        assert decision.effect == "allow"
        assert decision.permission is not None
        assert decision.permission.effect == "allow"

    def test_denied_host_returns_deny(self, engine):
        """Explicitly denied host returns deny effect."""
        decision = engine.evaluate_request(host="evil.example.com", path="/")
        assert decision.effect == "deny"
        assert decision.permission is not None
        assert decision.permission.effect == "deny"

    def test_prompt_host_returns_prompt(self, engine):
        """Host requiring approval returns prompt effect."""
        decision = engine.evaluate_request(host="needs-approval.example.com", path="/")
        assert decision.effect == "prompt"
        assert decision.permission is not None

    def test_budget_host_returns_allow_with_remaining(self, engine):
        """Rate-limited host returns allow with budget_remaining on first request."""
        decision = engine.evaluate_request(host="api.limited.com", path="/endpoint")
        assert decision.effect == "allow"
        assert decision.budget_remaining is not None

    def test_unknown_host_defaults_to_deny(self, engine):
        """Host with no matching permission defaults to deny (fail-closed, B4 fix)."""
        decision = engine.evaluate_request(host="unknown.example.com", path="/")
        assert decision.effect == "deny"
        assert decision.reason == "No matching permission (default deny)"
        assert decision.permission is None


class TestEvaluateRequestAgentScoped:
    """Tests for agent-scoped permission evaluation in evaluate_request."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with agent-scoped and proxy-wide permissions."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Agent-scoped test policy"

permissions:
  # Agent-scoped: claude can access api.openai.com
  - action: network:request
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit
    condition:
      agent: claude

  # Agent-scoped: boris is denied api.openai.com
  - action: network:request
    resource: "api.openai.com/*"
    effect: deny
    tier: explicit
    condition:
      agent: boris

  # Proxy-wide allow for api.openai.com (lower priority than agent-scoped)
  - action: network:request
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit

  # Proxy-wide catch-all allow (so non-agent requests work)
  - action: network:request
    resource: "*"
    effect: allow
    tier: explicit

budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_agent_scoped_allow(self, engine):
        """Agent with explicit allow permission is allowed."""
        decision = engine.evaluate_request(
            host="api.openai.com", path="/v1/chat", agent="claude",
        )
        assert decision.effect == "allow"

    def test_agent_scoped_deny_overrides_proxy_wide_allow(self, engine):
        """Agent-scoped deny takes priority over proxy-wide allow."""
        decision = engine.evaluate_request(
            host="api.openai.com", path="/v1/chat", agent="boris",
        )
        assert decision.effect == "deny"

    def test_no_agent_uses_proxy_wide_permission(self, engine):
        """Request without agent falls through to proxy-wide permissions."""
        decision = engine.evaluate_request(
            host="api.openai.com", path="/v1/chat",
        )
        assert decision.effect == "allow"

    def test_unknown_agent_falls_through_to_proxy_wide(self, engine):
        """Agent with no specific rule falls through to proxy-wide permissions."""
        decision = engine.evaluate_request(
            host="api.openai.com", path="/v1/chat", agent="unknown-agent",
        )
        assert decision.effect == "allow"


# =============================================================================
# Budget Tracking
# =============================================================================


class TestBudgetTracking:
    """Tests for request budget/rate limiting."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with budget config."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test policy"

permissions:
  - action: network:request
    resource: "api.test.com/*"
    effect: budget
    budget: 60
    tier: explicit

budgets:
  network:request: 600

required: []
addons: {}
""")

        engine = PolicyEngine(baseline_path=baseline)
        return engine

    def test_budget_allows_initial_requests(self, engine):
        """Test that initial requests within burst allowance are permitted."""
        decision = engine.evaluate_request(
            host="api.test.com",
            path="/endpoint",
            method="GET",
        )
        assert decision.effect == "allow"
        assert decision.budget_remaining is not None

    def test_budget_exceeded_returns_budget_exceeded(self, engine):
        """Exhausting the budget produces a budget_exceeded decision.

        GCRA with budget=60 allows burst_capacity = max(1, 60//10) = 6 requests.
        After consuming the burst, the next request should be denied.
        """
        # Consume burst capacity (GCRA burst = budget // 10 = 6)
        effects = []
        for _ in range(10):
            decision = engine.evaluate_request(
                host="api.test.com", path="/endpoint", method="GET",
            )
            effects.append(decision.effect)

        # First request must be allowed
        assert effects[0] == "allow"
        # At least one request in the batch must be budget_exceeded
        assert "budget_exceeded" in effects


class TestGlobalBudget:
    """Tests for global budget cap enforcement (B3 fix: min of task/baseline)."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with baseline global budget."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "api.test.com/*"
    effect: budget
    budget: 100
    tier: explicit

budgets:
  network:request: 500

required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_baseline_global_budget_returned(self, engine):
        """Global budget returns baseline value when no task policy."""
        result = engine._get_global_budget("network:request")
        assert result == 500

    def test_task_budget_lower_than_baseline_uses_task(self, engine):
        """Task policy with lower budget wins (min semantics)."""
        engine.set_task_policy("test-task", {
            "permissions": [],
            "budgets": {"network:request": 200},
        })
        result = engine._get_global_budget("network:request")
        assert result == 200

    def test_task_budget_higher_than_baseline_uses_baseline(self, engine):
        """Task policy cannot escalate budget above baseline (B3 fix)."""
        engine.set_task_policy("test-task", {
            "permissions": [],
            "budgets": {"network:request": 999},
        })
        result = engine._get_global_budget("network:request")
        assert result == 500

    def test_task_budget_when_baseline_has_none(self, engine, tmp_path):
        """Task budget applies when baseline has no global budget for that action."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "no_budget.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
permissions: []
budgets: {}
required: []
addons: {}
""")
        engine2 = PolicyEngine(baseline_path=baseline)
        engine2.set_task_policy("test-task", {
            "permissions": [],
            "budgets": {"network:request": 300},
        })
        result = engine2._get_global_budget("network:request")
        assert result == 300

    def test_no_global_budget_returns_none(self, engine):
        """Action with no global budget in baseline or task returns None."""
        result = engine._get_global_budget("file:read")
        assert result is None


# =============================================================================
# Risky Route Evaluation
# =============================================================================


class TestRiskyRouteEvaluation:
    """Tests for PolicyEngine.evaluate_risky_route()."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test policy with risk appetite"

permissions:
  # Allow collection for agent accounts
  - action: gateway:risky_route
    resource: "*"
    effect: allow
    tier: explicit
    condition:
      tactics: [collection]
      account: agent

  # Require approval for exfiltration
  - action: gateway:risky_route
    resource: "*"
    effect: prompt
    tier: explicit
    condition:
      tactics: [exfiltration]

  # Deny irreversible actions on operator accounts
  - action: gateway:risky_route
    resource: "*"
    effect: deny
    tier: explicit
    condition:
      irreversible: true
      account: operator

  # Trust boris with github privilege_escalation
  - action: gateway:risky_route
    resource: "*"
    effect: allow
    tier: explicit
    condition:
      agent: boris
      service: github
      tactics: [privilege_escalation]

  # Catch-all credential rule
  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit

budgets: {}
required: []
addons: {}
""")

        return PolicyEngine(baseline_path=baseline)

    def test_collection_allowed_for_agent(self, engine):
        decision = engine.evaluate_risky_route(
            service="gmail",
            agent="boris",
            account="agent",
            tactics=["collection"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "allow"

    def test_exfiltration_requires_approval(self, engine):
        decision = engine.evaluate_risky_route(
            service="gmail",
            agent="boris",
            account="agent",
            tactics=["exfiltration", "persistence"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_irreversible_denied_for_operator(self, engine):
        decision = engine.evaluate_risky_route(
            service="gmail",
            agent="boris",
            account="operator",
            tactics=["impact"],
            enables=[],
            irreversible=True,
        )
        assert decision.effect == "deny"

    def test_agent_specific_allow(self, engine):
        decision = engine.evaluate_risky_route(
            service="github",
            agent="boris",
            account="agent",
            tactics=["privilege_escalation"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "allow"

    def test_agent_specific_no_match_other_agent(self, engine):
        """Different agent doesn't match boris-specific rule, falls through."""
        decision = engine.evaluate_risky_route(
            service="github",
            agent="alice",
            account="agent",
            tactics=["privilege_escalation"],
            enables=[],
            irreversible=False,
        )
        # No matching rule -> default fail-safe (prompt)
        assert decision.effect == "prompt"

    def test_default_failsafe_prompt(self, engine):
        """No matching risk appetite rule -> require approval."""
        decision = engine.evaluate_risky_route(
            service="unknown",
            agent="unknown",
            account="custom",
            tactics=["lateral_movement"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_no_risk_appetite_rules_failsafe(self, tmp_path):
        """Engine with no gateway:risky_route permissions defaults to prompt."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "empty_policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
permissions:
  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit
budgets: {}
required: []
addons: {}
""")
        engine = PolicyEngine(baseline_path=baseline)
        decision = engine.evaluate_risky_route(
            service="gmail",
            agent="boris",
            account="agent",
            tactics=["collection"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "prompt"


# =============================================================================
# Gateway Request Evaluation
# =============================================================================


class TestGatewayRequestEvaluation:
    """Tests for evaluate_gateway_request()."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
permissions:
  - action: gateway:request
    resource: "minifuse:/v1/feeds"
    effect: allow
    tier: explicit
    condition:
      agent: claude
      capability: reader
      method: [GET]

  - action: gateway:request
    resource: "minifuse:/v1/feeds/*"
    effect: allow
    tier: explicit
    condition:
      agent: claude
      capability: reader
      method: [GET]

  - action: gateway:request
    resource: "minifuse:/v1/categories/137/feeds"
    effect: allow
    tier: explicit
    condition:
      agent: claude
      capability: category_manager
      method: [GET]

  - action: gateway:request
    resource: "minifuse:/v1/feeds"
    effect: allow
    tier: explicit
    condition:
      agent: claude
      capability: category_manager
      method: [POST]

  - action: gateway:request
    resource: "minifuse:/v1/feeds"
    effect: deny
    tier: explicit
    condition:
      agent: blocked-agent
      capability: reader
      method: [GET]
""")
        return PolicyEngine(baseline_path=baseline)

    def test_allow_on_match(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="reader",
            agent="claude",
            method="GET",
            path="/v1/feeds",
        )
        assert decision.effect == "allow"

    def test_deny_on_no_match(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="reader",
            agent="claude",
            method="DELETE",
            path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_deny_wrong_capability(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="admin",
            agent="claude",
            method="GET",
            path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_deny_wrong_agent(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="reader",
            agent="unknown-agent",
            method="GET",
            path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_resolved_contract_path(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="category_manager",
            agent="claude",
            method="GET",
            path="/v1/categories/137/feeds",
        )
        assert decision.effect == "allow"

    def test_wildcard_path_match(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="reader",
            agent="claude",
            method="GET",
            path="/v1/feeds/42",
        )
        assert decision.effect == "allow"

    def test_operator_deny_override(self, engine):
        """Explicit deny for a specific agent overrides defaults."""
        decision = engine.evaluate_gateway_request(
            service="minifuse",
            capability="reader",
            agent="blocked-agent",
            method="GET",
            path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_default_deny_no_permissions(self, tmp_path):
        """Engine with no gateway:request permissions denies everything."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "empty.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
permissions: []
""")
        engine = PolicyEngine(baseline_path=baseline)
        decision = engine.evaluate_gateway_request(
            service="any",
            capability="any",
            agent="any",
            method="GET",
            path="/anything",
        )
        assert decision.effect == "deny"


# =============================================================================
# Addon Configuration
# =============================================================================


class TestAddonConfiguration:
    """Tests for addon enable/disable via policy."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with addon config."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test policy"

permissions: []
budgets: {}

required:
  - credential_guard

addons:
  credential_guard:
    enabled: true
  pattern_scanner:
    enabled: false
  network_guard:
    enabled: true

domains:
  "*.internal":
    bypass:
      - network_guard
      - pattern_scanner
      - credential_guard
""")

        engine = PolicyEngine(baseline_path=baseline)
        return engine

    def test_addon_enabled_default(self, engine):
        """Test default addon enabled state."""
        assert engine.is_addon_enabled("credential_guard", domain="api.openai.com")
        assert not engine.is_addon_enabled("pattern_scanner", domain="api.openai.com")

    def test_addon_bypassed_for_domain(self, engine):
        """Non-required addon is disabled by domain bypass."""
        assert not engine.is_addon_enabled("network_guard", domain="db.internal")

    def test_required_addon_resists_domain_bypass(self, engine):
        """Required addon remains enabled even when domain bypass lists it (B2 fix)."""
        assert engine.is_addon_enabled("credential_guard", domain="db.internal")

    def test_addon_not_in_config_defaults_to_enabled(self, engine):
        """Addon not mentioned in addons config defaults to enabled."""
        assert engine.is_addon_enabled("some_other_addon", domain="api.openai.com")

    def test_addon_disabled_in_config(self, engine):
        """Addon explicitly disabled in config returns False."""
        assert not engine.is_addon_enabled("pattern_scanner")

    def test_addon_settings_merged(self, engine):
        """get_addon_settings returns merged settings from config."""
        settings = engine.get_addon_settings("credential_guard")
        assert isinstance(settings, dict)


class TestAddonClientBypass:
    """Tests for client-based addon bypass with required addon enforcement."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions: []
budgets: {}

required:
  - credential_guard

addons:
  credential_guard:
    enabled: true
  network_guard:
    enabled: true

clients:
  "internal-tool":
    bypass:
      - network_guard
      - credential_guard
""")
        return PolicyEngine(baseline_path=baseline)

    def test_client_bypass_non_required_addon(self, engine):
        """Non-required addon is disabled by client bypass."""
        assert not engine.is_addon_enabled("network_guard", client_id="internal-tool")

    def test_client_bypass_required_addon_stays_enabled(self, engine):
        """Required addon remains enabled despite client bypass."""
        assert engine.is_addon_enabled("credential_guard", client_id="internal-tool")


class TestAddonTaskPolicy:
    """Tests for task policy addon override with required addon enforcement."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions: []
budgets: {}

required:
  - credential_guard

addons:
  credential_guard:
    enabled: true
  pattern_scanner:
    enabled: true
""")
        return PolicyEngine(baseline_path=baseline)

    def test_task_policy_can_disable_non_required(self, engine):
        """Task policy can disable non-required addons."""
        engine.set_task_policy("t1", {
            "permissions": [],
            "addons": {"pattern_scanner": {"enabled": False}},
        })
        assert not engine.is_addon_enabled("pattern_scanner")

    def test_task_policy_cannot_disable_required(self, engine):
        """Task policy cannot disable required addons."""
        engine.set_task_policy("t1", {
            "permissions": [],
            "addons": {"credential_guard": {"enabled": False}},
        })
        assert engine.is_addon_enabled("credential_guard")


# =============================================================================
# get_baseline Contract
# =============================================================================


class TestGetBaseline:
    """Tests for get_baseline return contract."""

    def test_returns_none_when_no_baseline_path(self, tmp_path):
        """get_baseline returns None when no baseline_path was configured."""
        from safeyolo.policy.engine import PolicyEngine

        engine = PolicyEngine(baseline_path=None)
        assert engine.get_baseline() is None

    def test_returns_policy_with_empty_permissions(self, tmp_path):
        """get_baseline returns policy even with zero IAM permissions (B1 fix).

        A policy with only credential_rules, scan_patterns, or gateway config
        but no permissions list is still meaningful.
        """
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions: []
budgets: {}
required: []
addons: {}

credential_rules:
  - name: openai
    patterns: ["sk-[a-zA-Z0-9]{20}"]
    allowed_hosts: ["api.openai.com"]
""")
        engine = PolicyEngine(baseline_path=baseline)
        policy = engine.get_baseline()
        assert policy is not None
        assert len(policy.permissions) == 0
        assert len(policy.credential_rules) == 1

    def test_returns_policy_with_populated_permissions(self, tmp_path):
        """get_baseline returns the full policy object when permissions exist."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "*"
    effect: allow
    tier: explicit
""")
        engine = PolicyEngine(baseline_path=baseline)
        policy = engine.get_baseline()
        assert policy is not None
        assert len(policy.permissions) >= 1


# =============================================================================
# Policy Mutation Operations
# =============================================================================


class TestPolicyMutation:
    """Tests for add_host_allowance, add_host_denial, update_host_rate."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "*"
    effect: allow
    tier: explicit

budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_add_host_allowance_makes_host_evaluable(self, engine):
        """After add_host_allowance, host evaluates to allow."""
        result = engine.add_host_allowance("cdn.example.com")
        assert result["status"] == "added"
        assert result["host"] == "cdn.example.com"
        assert result["rate"] is None
        assert result["agent"] is None

        decision = engine.evaluate_request(host="cdn.example.com", path="/asset.js")
        assert decision.effect == "allow"

    def test_add_host_allowance_with_rate(self, engine):
        """add_host_allowance with rate creates both allow and budget permissions."""
        result = engine.add_host_allowance("api.ratelimited.com", rate=30)
        assert result["status"] == "added"
        assert result["rate"] == 30

        # First request should be allowed (budget permission)
        decision = engine.evaluate_request(host="api.ratelimited.com", path="/")
        assert decision.effect == "allow"

    def test_add_host_allowance_upserts(self, engine):
        """Calling add_host_allowance twice does not accumulate duplicate permissions."""
        engine.add_host_allowance("cdn.example.com")
        engine.add_host_allowance("cdn.example.com")

        baseline = engine.get_baseline()
        matching = [
            p for p in baseline.permissions
            if p.action == "network:request"
            and p.resource == "cdn.example.com/*"
            and p.effect == "allow"
            and p.condition is None
        ]
        assert len(matching) == 1

    def test_add_host_allowance_with_agent(self, engine):
        """add_host_allowance with agent creates agent-scoped permission."""
        result = engine.add_host_allowance("api.openai.com", agent="claude")
        assert result["agent"] == "claude"

        decision = engine.evaluate_request(
            host="api.openai.com", path="/v1/chat", agent="claude",
        )
        assert decision.effect == "allow"

    def test_add_host_denial_makes_host_denied(self, engine):
        """After add_host_denial, host evaluates to deny."""
        result = engine.add_host_denial("dodgy-site.com")
        assert result["status"] == "denied"
        assert result["host"] == "dodgy-site.com"

        decision = engine.evaluate_request(host="dodgy-site.com", path="/")
        assert decision.effect == "deny"

    def test_add_host_denial_with_expires(self, engine):
        """add_host_denial accepts expires parameter."""
        result = engine.add_host_denial(
            "temp-block.com", expires="2026-12-31T23:59:59",
        )
        assert result["expires"] == "2026-12-31T23:59:59"

        decision = engine.evaluate_request(host="temp-block.com", path="/")
        assert decision.effect == "deny"

    def test_add_host_denial_upserts(self, engine):
        """Calling add_host_denial twice does not accumulate duplicate deny permissions."""
        engine.add_host_denial("dodgy-site.com")
        engine.add_host_denial("dodgy-site.com")

        baseline = engine.get_baseline()
        deny_count = sum(
            1 for p in baseline.permissions
            if p.action == "network:request"
            and p.resource == "dodgy-site.com/*"
            and p.effect == "deny"
            and p.condition is None
        )
        assert deny_count == 1

    def test_update_host_rate_modifies_existing(self, engine):
        """update_host_rate modifies an existing budget permission's rate."""
        # First, create a budget permission
        engine.add_host_allowance("api.ratelimited.com", rate=30)

        # Update the rate
        result = engine.update_host_rate("api.ratelimited.com", 60)
        assert result["status"] == "updated"
        assert result["host"] == "api.ratelimited.com"
        assert result["old_rate"] == 30
        assert result["new_rate"] == 60

    def test_update_host_rate_creates_new_when_missing(self, engine):
        """update_host_rate creates a new budget permission if none exists."""
        result = engine.update_host_rate("api.newhost.com", 100)
        assert result["status"] == "updated"
        assert result["old_rate"] is None
        assert result["new_rate"] == 100

    def test_update_host_rate_rejects_zero(self, engine):
        """update_host_rate raises ValueError for rate < 1."""
        with pytest.raises(ValueError, match="rate must be >= 1"):
            engine.update_host_rate("api.test.com", 0)


# =============================================================================
# Policy Lifecycle
# =============================================================================


class TestPolicyLifecycle:
    """Tests for replace_baseline and set_task_policy."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "*"
    effect: allow
    tier: explicit

budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_replace_baseline_applies_new_policy(self, engine):
        """replace_baseline validates and applies new policy data."""
        result = engine.replace_baseline({
            "permissions": [
                {
                    "action": "network:request",
                    "resource": "api.openai.com/*",
                    "effect": "allow",
                    "tier": "explicit",
                },
            ],
        })
        assert result["status"] == "updated"
        assert result["permission_count"] == 1

    def test_replace_baseline_rejects_invalid_data(self, engine):
        """replace_baseline raises ValueError for invalid policy data."""
        with pytest.raises(ValueError, match="Invalid policy data"):
            engine.replace_baseline({
                "permissions": [
                    {"action": "invalid:action", "resource": "*"},
                ],
            })

    def test_set_task_policy_applies_and_sets_task_id(self, engine):
        """set_task_policy validates, applies, and sets task_id in metadata."""
        result = engine.set_task_policy("task-abc", {
            "permissions": [
                {
                    "action": "network:request",
                    "resource": "api.openai.com/*",
                    "effect": "allow",
                    "tier": "explicit",
                },
            ],
        })
        assert result["status"] == "updated"
        assert result["task_id"] == "task-abc"
        assert result["permission_count"] == 1

        task = engine.get_task_policy()
        assert task is not None
        assert task.metadata.task_id == "task-abc"

    def test_set_task_policy_rejects_invalid_data(self, engine):
        """set_task_policy raises ValueError for invalid policy data."""
        with pytest.raises(ValueError, match="Invalid policy data"):
            engine.set_task_policy("task-bad", {
                "permissions": [
                    {"action": "nonexistent:thing", "resource": "*"},
                ],
            })

    def test_get_task_policy_returns_none_when_unset(self, engine):
        """get_task_policy returns None when no task policy loaded."""
        assert engine.get_task_policy() is None

    def test_get_task_policy_filters_by_task_id(self, engine):
        """get_task_policy(task_id=...) returns None if task_id doesn't match."""
        engine.set_task_policy("task-abc", {"permissions": []})
        assert engine.get_task_policy(task_id="task-abc") is not None
        assert engine.get_task_policy(task_id="wrong-task") is None

    def test_clear_task_policy(self, engine):
        """clear_task_policy removes the active task policy."""
        engine.set_task_policy("task-abc", {"permissions": []})
        assert engine.get_task_policy() is not None

        engine.clear_task_policy()
        assert engine.get_task_policy() is None


# =============================================================================
# Consume Budget (External API)
# =============================================================================


class TestConsumeBudget:
    """Tests for consume_budget external API."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "api.test.com/*"
    effect: budget
    budget: 60
    tier: explicit

  - action: network:request
    resource: "*"
    effect: allow
    tier: explicit

budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_consume_budget_with_matching_permission(self, engine):
        """consume_budget returns (True, remaining) when budget is available."""
        allowed, remaining = engine.consume_budget("network:request", "api.test.com")
        assert allowed is True
        assert remaining >= 0

    def test_consume_budget_no_budget_constraint(self, engine):
        """consume_budget returns (True, -1) when no budget permission matches."""
        allowed, remaining = engine.consume_budget("network:request", "unbounded.example.com")
        assert allowed is True
        assert remaining == -1

    def test_consume_budget_no_matching_permission(self, engine):
        """consume_budget returns (True, -1) for unknown action."""
        allowed, remaining = engine.consume_budget("file:read", "anything")
        assert allowed is True
        assert remaining == -1


# =============================================================================
# Reset Budgets
# =============================================================================


class TestResetBudgets:
    """Tests for reset_budgets operation."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "api.test.com/*"
    effect: budget
    budget: 60
    tier: explicit

budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_reset_specific_resource(self, engine):
        """reset_budgets with resource resets that resource only."""
        # Consume some budget
        engine.evaluate_request(host="api.test.com", path="/")

        result = engine.reset_budgets(resource="network:request:api.test.com")
        assert result["status"] == "reset"
        assert result["resource"] == "network:request:api.test.com"

    def test_reset_all_budgets(self, engine):
        """reset_budgets without resource resets all budget counters."""
        # Consume some budget
        engine.evaluate_request(host="api.test.com", path="/")

        result = engine.reset_budgets()
        assert result["status"] == "reset"
        assert result["resource"] == "all"


# =============================================================================
# Fail-Closed Defaults
# =============================================================================


class TestFailClosed:
    """Tests that the engine defaults to deny/prompt when no rules match.

    Security tool: every evaluation path must fail closed.
    """

    @pytest.fixture
    def empty_engine(self, tmp_path):
        """Engine with zero permissions -- pure default behaviour."""
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "empty.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
permissions: []
budgets: {}
required: []
addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_evaluate_request_no_permissions_returns_deny(self, empty_engine):
        """evaluate_request with no matching permission defaults to deny."""
        decision = empty_engine.evaluate_request(host="any.host.com", path="/")
        assert decision.effect == "deny"
        assert "default deny" in decision.reason.lower()

    def test_evaluate_credential_no_permissions_returns_prompt(self, empty_engine):
        """evaluate_credential with no matching permission defaults to prompt."""
        decision = empty_engine.evaluate_credential(
            credential_type="unknown", destination="any.host.com",
        )
        assert decision.effect == "prompt"

    def test_evaluate_risky_route_no_permissions_returns_prompt(self, empty_engine):
        """evaluate_risky_route with no matching permission defaults to prompt."""
        decision = empty_engine.evaluate_risky_route(
            service="any",
            agent="any",
            account="any",
            tactics=["any"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_evaluate_gateway_request_no_permissions_returns_deny(self, empty_engine):
        """evaluate_gateway_request with no matching permission defaults to deny."""
        decision = empty_engine.evaluate_gateway_request(
            service="any",
            capability="any",
            agent="any",
            method="GET",
            path="/any",
        )
        assert decision.effect == "deny"


# =============================================================================
# Specificity Score
# =============================================================================


class TestSpecificityScore:
    """Tests for _specificity_score ordering helper."""

    def test_wildcard_scores_zero(self):
        from safeyolo.policy.engine import _specificity_score

        assert _specificity_score("*") == 0

    def test_longer_patterns_score_higher(self):
        from safeyolo.policy.engine import _specificity_score

        score_short = _specificity_score("api.a.com/*")
        score_long = _specificity_score("api.example.com/*")
        assert score_long > score_short

    def test_wildcards_reduce_score(self):
        from safeyolo.policy.engine import _specificity_score

        score_exact = _specificity_score("api.openai.com/v1/chat")
        score_wild = _specificity_score("api.openai.com/*")
        # The exact path is longer and has no wildcard penalty
        assert score_exact > score_wild


# =============================================================================
# Model Validation
# =============================================================================


class TestPermissionValidation:
    """Tests for Permission model validation."""

    def test_budget_effect_requires_budget_field(self):
        """Permission with effect=budget must have budget set."""
        from safeyolo.policy.engine import Permission

        with pytest.raises(ValueError, match="budget must be set"):
            Permission(
                action="network:request",
                resource="api.test.com/*",
                effect="budget",
                # budget=None (omitted)
            )

    def test_budget_effect_with_budget_field_succeeds(self):
        """Permission with effect=budget and budget field is valid."""
        from safeyolo.policy.engine import Permission

        p = Permission(
            action="network:request",
            resource="api.test.com/*",
            effect="budget",
            budget=100,
        )
        assert p.budget == 100
        assert p.effect == "budget"

    def test_allow_effect_does_not_require_budget(self):
        """Permission with effect=allow does not require budget field."""
        from safeyolo.policy.engine import Permission

        p = Permission(
            action="network:request",
            resource="*",
            effect="allow",
        )
        assert p.budget is None


# =============================================================================
# Stats
# =============================================================================


class TestStats:
    """Tests for get_stats and get_budget_stats."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions:
  - action: network:request
    resource: "api.test.com/*"
    effect: budget
    budget: 60
    tier: explicit

budgets:
  network:request: 500

required:
  - credential_guard

addons: {}
""")
        return PolicyEngine(baseline_path=baseline)

    def test_get_stats_structure(self, engine):
        """get_stats returns expected keys."""
        stats = engine.get_stats()
        assert "baseline_path" in stats
        assert "evaluations" in stats
        assert "required_addons" in stats
        assert stats["required_addons"] == ["credential_guard"]
        assert stats["evaluations"] == 0

    def test_get_stats_evaluations_increment(self, engine):
        """Evaluation counter increments with each call."""
        engine.evaluate_request(host="api.test.com", path="/")
        stats = engine.get_stats()
        assert stats["evaluations"] == 1

    def test_get_budget_stats_structure(self, engine):
        """get_budget_stats returns expected keys."""
        stats = engine.get_budget_stats()
        assert "tracked_keys" in stats
        assert "budgets" in stats
        assert "global_budgets" in stats
        assert stats["global_budgets"] == {"network:request": 500}


# =============================================================================
# Credential Rules and Scan Patterns (merged from task)
# =============================================================================


class TestMergedRulesFromTask:
    """Tests for get_credential_rules and get_scan_patterns with task policy."""

    @pytest.fixture
    def engine(self, tmp_path):
        from safeyolo.policy.engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"

permissions: []
budgets: {}
required: []
addons: {}

credential_rules:
  - name: openai
    patterns: ["sk-[a-zA-Z0-9]{20}"]
    allowed_hosts: ["api.openai.com"]

scan_patterns:
  - name: api_key_leak
    pattern: "sk-[a-z]+"
    target: both
    action: log
""")
        return PolicyEngine(baseline_path=baseline)

    def test_credential_rules_baseline_only(self, engine):
        """Baseline credential rules returned when no task policy."""
        rules = engine.get_credential_rules()
        assert len(rules) == 1
        assert rules[0].name == "openai"

    def test_credential_rules_merged_with_task(self, engine):
        """Task credential rules are appended to baseline (additive)."""
        engine.set_task_policy("t1", {
            "permissions": [],
            "credential_rules": [
                {"name": "github", "patterns": ["ghp_[a-zA-Z0-9]{36}"], "allowed_hosts": ["api.github.com"]},
            ],
        })
        rules = engine.get_credential_rules()
        assert len(rules) == 2
        assert rules[0].name == "openai"
        assert rules[1].name == "github"

    def test_scan_patterns_baseline_only(self, engine):
        """Baseline scan patterns returned when no task policy."""
        patterns = engine.get_scan_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "api_key_leak"

    def test_scan_patterns_merged_with_task(self, engine):
        """Task scan patterns are appended to baseline (additive)."""
        engine.set_task_policy("t1", {
            "permissions": [],
            "scan_patterns": [
                {"name": "pii_check", "pattern": "\\d{3}-\\d{2}-\\d{4}"},
            ],
        })
        patterns = engine.get_scan_patterns()
        assert len(patterns) == 2
        assert patterns[0].name == "api_key_leak"
        assert patterns[1].name == "pii_check"
