"""
Tests for PolicyEngine mutation methods — update_host_rate, add_host_allowance, add_host_bypass.
"""


import pytest

SAMPLE_TOML = """\
[metadata]
version = "2.0"
description = "Test policy"

[hosts]
"api.openai.com" = {allow = ["openai:*"], rate = 3000}
"api.anthropic.com" = {allow = ["anthropic:*"], rate = 1000}

[hosts."*"]
unknown_creds = "prompt"
rate = 600
"""

SAMPLE_YAML = """\
metadata:
  version: "1.0"
  description: "Test policy"

permissions:
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["openai:*"]

  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 3000
    tier: explicit

  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit

budgets:
  network:request: 12000

required: []
addons: {}
"""


class TestUpdateHostRate:
    """Tests for PolicyEngine.update_host_rate()."""

    @pytest.fixture
    def engine_toml(self, tmp_path):
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.toml"
        baseline.write_text(SAMPLE_TOML)
        return PolicyEngine(baseline_path=baseline)

    @pytest.fixture
    def engine_yaml(self, tmp_path):
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text(SAMPLE_YAML)
        return PolicyEngine(baseline_path=baseline)

    def test_update_existing_rate(self, engine_toml):
        result = engine_toml.update_host_rate("api.openai.com", 6000)
        assert result["status"] == "updated"
        assert result["host"] == "api.openai.com"
        assert result["new_rate"] == 6000
        # Old rate should be captured (from budget permission compiled from TOML)

    def test_create_new_rate(self, engine_yaml):
        result = engine_yaml.update_host_rate("api.newhost.com", 500)
        assert result["status"] == "updated"
        assert result["host"] == "api.newhost.com"
        assert result["new_rate"] == 500
        assert result["old_rate"] is None  # didn't exist before

    def test_rate_persists_to_toml(self, engine_toml, tmp_path):
        engine_toml.update_host_rate("api.openai.com", 9000)

        # Reload and check
        from toml_roundtrip import load_roundtrip
        doc = load_roundtrip(tmp_path / "policy.toml")
        assert doc["hosts"]["api.openai.com"]["rate"] == 9000

    def test_invalid_rate_rejected(self, engine_toml):
        with pytest.raises(ValueError, match="rate must be >= 1"):
            engine_toml.update_host_rate("api.openai.com", 0)

    def test_negative_rate_rejected(self, engine_toml):
        with pytest.raises(ValueError, match="rate must be >= 1"):
            engine_toml.update_host_rate("api.openai.com", -1)

    def test_toml_comments_preserved(self, tmp_path):
        from policy_engine import PolicyEngine

        policy_text = """\
# Main policy file
[metadata]
version = "2.0"

# Host configurations
[hosts]
# OpenAI API
"api.openai.com" = {allow = ["openai:*"], rate = 3000}

[hosts."*"]
unknown_creds = "prompt"
rate = 600
"""
        baseline = tmp_path / "policy.toml"
        baseline.write_text(policy_text)
        engine = PolicyEngine(baseline_path=baseline)
        engine.update_host_rate("api.openai.com", 5000)

        saved = baseline.read_text()
        assert "# Main policy file" in saved
        assert "# OpenAI API" in saved


class TestAddHostAllowance:
    """Tests for PolicyEngine.add_host_allowance()."""

    @pytest.fixture
    def engine(self, tmp_path):
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.toml"
        baseline.write_text(SAMPLE_TOML)
        return PolicyEngine(baseline_path=baseline)

    def test_add_host_without_rate(self, engine):
        result = engine.add_host_allowance("cdn.example.com")
        assert result["status"] == "added"
        assert result["host"] == "cdn.example.com"
        assert result["rate"] is None

    def test_add_host_with_rate(self, engine):
        result = engine.add_host_allowance("cdn.example.com", rate=1200)
        assert result["status"] == "added"
        assert result["host"] == "cdn.example.com"
        assert result["rate"] == 1200

    def test_host_persists_to_toml(self, engine, tmp_path):
        engine.add_host_allowance("cdn.example.com", rate=800)

        from toml_roundtrip import load_roundtrip
        doc = load_roundtrip(tmp_path / "policy.toml")
        assert "cdn.example.com" in doc["hosts"]
        assert doc["hosts"]["cdn.example.com"]["rate"] == 800

    def test_allows_requests_after_adding(self, engine):
        # After adding a host allowance, evaluate_request should allow it
        engine.add_host_allowance("cdn.example.com")
        decision = engine.evaluate_request(
            host="cdn.example.com",
            path="/asset.js",
            method="GET",
        )
        assert decision.effect == "allow"

    def test_add_host_allowance_agent_scoped(self, engine):
        """Passing agent= writes a condition with agent field on the permission."""
        result = engine.add_host_allowance("internal.dev", agent="boris")
        assert result["status"] == "added"
        assert result["agent"] == "boris"

        # Find the permission that was created
        from policy_engine import Condition

        baseline = engine._loader._baseline
        matching = [
            p for p in baseline.permissions
            if p.resource == "internal.dev/*"
            and p.action == "network:request"
            and p.effect == "allow"
        ]
        assert len(matching) == 1
        assert matching[0].condition is not None
        assert matching[0].condition == Condition(agent="boris")


class TestAddHostBypass:
    """Tests for PolicyEngine.add_host_bypass()."""

    @pytest.fixture
    def engine(self, tmp_path):
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.toml"
        baseline.write_text(SAMPLE_TOML)
        return PolicyEngine(baseline_path=baseline)

    def test_add_bypass(self, engine):
        result = engine.add_host_bypass("api.openai.com", "pattern-scanner")
        assert result["status"] == "updated"
        assert result["host"] == "api.openai.com"
        assert "pattern-scanner" in result["bypass"]

    def test_add_bypass_persists(self, engine, tmp_path):
        engine.add_host_bypass("api.openai.com", "pattern-scanner")

        from toml_roundtrip import load_roundtrip
        doc = load_roundtrip(tmp_path / "policy.toml")
        assert doc["hosts"]["api.openai.com"]["bypass"] == ["pattern-scanner"]

    def test_no_duplicate_bypass(self, engine):
        engine.add_host_bypass("api.openai.com", "pattern-scanner")
        result = engine.add_host_bypass("api.openai.com", "pattern-scanner")
        assert result["status"] == "unchanged"
        assert result["bypass"].count("pattern-scanner") == 1

    def test_append_to_existing_bypass(self, tmp_path):
        from policy_engine import PolicyEngine

        policy_text = """\
[metadata]
version = "2.0"

[hosts]
"internal.dev" = {bypass = ["credential-guard"], rate = 100}

[hosts."*"]
unknown_creds = "prompt"
rate = 600
"""
        baseline = tmp_path / "policy.toml"
        baseline.write_text(policy_text)
        engine = PolicyEngine(baseline_path=baseline)

        result = engine.add_host_bypass("internal.dev", "pattern-scanner")
        assert result["status"] == "updated"
        assert "credential-guard" in result["bypass"]
        assert "pattern-scanner" in result["bypass"]

    def test_requires_toml(self, tmp_path):
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text(SAMPLE_YAML)
        engine = PolicyEngine(baseline_path=baseline)

        with pytest.raises(ValueError, match="TOML"):
            engine.add_host_bypass("api.openai.com", "pattern-scanner")
