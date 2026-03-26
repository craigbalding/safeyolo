"""
Tests for policy_engine.py - Unified IAM-style policy engine.

Tests destination-first credential evaluation, budget tracking, and permission matching.
"""

import pytest


class TestPatternMatching:
    """Tests for glob pattern matching."""

    @pytest.fixture
    def matches_pattern(self):
        """Get the pattern matching function."""
        from policy_engine import _matches_pattern
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


class TestConditionMatching:
    """Tests for Condition model matching."""

    @pytest.fixture
    def make_condition(self):
        """Factory for creating Condition objects."""
        from policy_engine import Condition
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


class TestPolicyEngine:
    """Tests for PolicyEngine credential evaluation."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with test baseline policy."""
        from policy_engine import PolicyEngine

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
            path="/v1/chat/completions"
        )
        assert decision.effect == "allow"

    def test_known_credential_to_wrong_host(self, engine):
        """Test that known credentials are blocked from wrong hosts."""
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.anthropic.com",  # Wrong host for OpenAI key
            path="/v1/messages"
        )
        # Should trigger prompt (catch-all) not allow
        assert decision.effect == "prompt"

    def test_unknown_credential_requires_approval(self, engine):
        """Test that unknown credentials require approval."""
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.newservice.com",
            path="/api/endpoint"
        )
        assert decision.effect == "prompt"

    def test_hmac_based_approval(self, engine):
        """Test that specific HMAC can be approved for destination."""
        # Should allow with correct HMAC
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.example.com",
            path="/api/endpoint",
            credential_hmac="testhmac1234"
        )
        assert decision.effect == "allow"

        # Should not allow with wrong HMAC
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.example.com",
            path="/api/endpoint",
            credential_hmac="wronghmac999"
        )
        assert decision.effect == "prompt"


class TestAddCredentialApproval:
    """Tests for adding credential approvals at runtime."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with minimal baseline."""
        from policy_engine import PolicyEngine

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
            path="/"
        )
        assert decision.effect == "prompt"

        # Add approval
        engine.add_credential_approval(
            destination="api.custom.com",
            cred_id="custom:*"
        )

        # Should now be allowed
        decision = engine.evaluate_credential(
            credential_type="custom",
            destination="api.custom.com",
            path="/"
        )
        assert decision.effect == "allow"

    def test_add_hmac_approval(self, engine):
        """Test adding HMAC-based approval."""
        # Initially should require approval
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.specific.com",
            path="/",
            credential_hmac="uniquehmac123"
        )
        assert decision.effect == "prompt"

        # Add HMAC-specific approval
        engine.add_credential_approval(
            destination="api.specific.com",
            cred_id="hmac:uniquehmac123"
        )

        # Should now be allowed with correct HMAC
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.specific.com",
            path="/",
            credential_hmac="uniquehmac123"
        )
        assert decision.effect == "allow"

        # Different HMAC should still require approval
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.specific.com",
            path="/",
            credential_hmac="differenthmac"
        )
        assert decision.effect == "prompt"


class TestBudgetTracking:
    """Tests for request budget/rate limiting."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with budget config."""
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test policy"

permissions:
  - action: network:request
    resource: "api.test.com/*"
    effect: budget
    budget: 60  # 1 per second - reasonable for burst testing
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
        # First request should always be allowed
        decision = engine.evaluate_request(
            host="api.test.com",
            path="/endpoint",
            method="GET"
        )
        assert decision.effect == "allow"

    def test_budget_exceeded_blocks(self, engine):
        """Test requests exceeding budget are eventually blocked."""
        # Keep making requests until blocked
        allowed_count = 0
        for _ in range(100):  # Try up to 100 requests
            decision = engine.evaluate_request(
                host="api.test.com",
                path="/endpoint",
                method="GET"
            )
            if decision.effect == "allow":
                allowed_count += 1
            else:
                break

        # Should have been blocked at some point
        assert decision.effect == "budget_exceeded", f"Expected budget_exceeded after {allowed_count} requests"
        # GCRA allows some burst, so we should have gotten at least 1 through
        assert allowed_count >= 1, "Should allow at least 1 request"


class TestAddonConfiguration:
    """Tests for addon enable/disable via policy."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create PolicyEngine with addon config."""
        from policy_engine import PolicyEngine

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
""")

        engine = PolicyEngine(baseline_path=baseline)
        return engine

    def test_addon_enabled_default(self, engine):
        """Test default addon enabled state."""
        assert engine.is_addon_enabled("credential_guard", domain="api.openai.com")
        assert not engine.is_addon_enabled("pattern_scanner", domain="api.openai.com")

    def test_addon_bypassed_for_domain(self, engine):
        """Test addon bypass for specific domain."""
        assert not engine.is_addon_enabled("network_guard", domain="db.internal")
        assert engine.is_addon_enabled("credential_guard", domain="db.internal")  # required


class TestGatewayCondition:
    """Tests for gateway-specific Condition fields."""

    @pytest.fixture
    def make_condition(self):
        from policy_engine import Condition
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


class TestRiskyRouteEvaluation:
    """Tests for PolicyEngine.evaluate_risky_route()."""

    @pytest.fixture
    def engine(self, tmp_path):
        from policy_engine import PolicyEngine

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
            service="gmail", agent="boris", account="agent",
            tactics=["collection"], enables=[], irreversible=False,
        )
        assert decision.effect == "allow"

    def test_exfiltration_requires_approval(self, engine):
        decision = engine.evaluate_risky_route(
            service="gmail", agent="boris", account="agent",
            tactics=["exfiltration", "persistence"], enables=[], irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_irreversible_denied_for_operator(self, engine):
        decision = engine.evaluate_risky_route(
            service="gmail", agent="boris", account="operator",
            tactics=["impact"], enables=[], irreversible=True,
        )
        assert decision.effect == "deny"

    def test_agent_specific_allow(self, engine):
        decision = engine.evaluate_risky_route(
            service="github", agent="boris", account="agent",
            tactics=["privilege_escalation"], enables=[], irreversible=False,
        )
        assert decision.effect == "allow"

    def test_agent_specific_no_match_other_agent(self, engine):
        """Different agent doesn't match boris-specific rule, falls through."""
        decision = engine.evaluate_risky_route(
            service="github", agent="alice", account="agent",
            tactics=["privilege_escalation"], enables=[], irreversible=False,
        )
        # No matching rule → default fail-safe (prompt)
        assert decision.effect == "prompt"

    def test_default_failsafe_prompt(self, engine):
        """No matching risk appetite rule → require approval."""
        decision = engine.evaluate_risky_route(
            service="unknown", agent="unknown", account="custom",
            tactics=["lateral_movement"], enables=[], irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_no_risk_appetite_rules_failsafe(self, tmp_path):
        """Engine with no gateway:risky_route permissions defaults to prompt."""
        from policy_engine import PolicyEngine

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
            service="gmail", agent="boris", account="agent",
            tactics=["collection"], enables=[], irreversible=False,
        )
        assert decision.effect == "prompt"


class TestCapabilityCondition:
    """Tests for capability condition matching on Condition model."""

    @pytest.fixture
    def make_condition(self):
        from policy_engine import Condition
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


class TestGatewayRequestEvaluation:
    """Tests for evaluate_gateway_request()."""

    @pytest.fixture
    def engine(self, tmp_path):
        from policy_engine import PolicyEngine

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
            service="minifuse", capability="reader",
            agent="claude", method="GET", path="/v1/feeds",
        )
        assert decision.effect == "allow"

    def test_deny_on_no_match(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse", capability="reader",
            agent="claude", method="DELETE", path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_deny_wrong_capability(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse", capability="admin",
            agent="claude", method="GET", path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_deny_wrong_agent(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse", capability="reader",
            agent="unknown-agent", method="GET", path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_resolved_contract_path(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse", capability="category_manager",
            agent="claude", method="GET", path="/v1/categories/137/feeds",
        )
        assert decision.effect == "allow"

    def test_wildcard_path_match(self, engine):
        decision = engine.evaluate_gateway_request(
            service="minifuse", capability="reader",
            agent="claude", method="GET", path="/v1/feeds/42",
        )
        assert decision.effect == "allow"

    def test_operator_deny_override(self, engine):
        """Explicit deny for a specific agent overrides defaults."""
        decision = engine.evaluate_gateway_request(
            service="minifuse", capability="reader",
            agent="blocked-agent", method="GET", path="/v1/feeds",
        )
        assert decision.effect == "deny"

    def test_default_deny_no_permissions(self, tmp_path):
        """Engine with no gateway:request permissions denies everything."""
        from policy_engine import PolicyEngine

        baseline = tmp_path / "empty.yaml"
        baseline.write_text("""
metadata:
  version: "1.0"
permissions: []
""")
        engine = PolicyEngine(baseline_path=baseline)
        decision = engine.evaluate_gateway_request(
            service="any", capability="any",
            agent="any", method="GET", path="/anything",
        )
        assert decision.effect == "deny"
