"""
Tests for the policy migrate command.

Tests YAML-to-TOML migration: field name conversion, structure,
and comment handling.
"""

import copy
import sys
from pathlib import Path

import pytest
import tomlkit
import yaml

# Ensure addons dir is on path for toml_normalize import
addons_dir = Path(__file__).parent.parent.parent / "addons"
if str(addons_dir) not in sys.path:
    sys.path.insert(0, str(addons_dir))


SAMPLE_YAML = """\
metadata:
  version: "2.0"
  description: "Test policy"

hosts:
  api.openai.com:
    credentials: [openai:*]
    rate_limit: 3000
  api.anthropic.com:
    credentials: [anthropic:*]
    rate_limit: 3000
  "*.internal":
    bypass: [pattern_scanner]
  "*":
    unknown_credentials: prompt
    rate_limit: 600

global_budget: 12000

credentials:
  openai:
    patterns:
      - 'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}'
    headers: [authorization, x-api-key]

required:
  - credential_guard
  - network_guard

gateway:
  risk_appetite:
    - account: agent
      tactics: [collection]
      decision: allow
"""


class TestDenormalize:
    """Test field name conversion from internal to TOML format."""

    def test_metadata_to_top_level(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert result["version"] == "2.0"
        assert result["description"] == "Test policy"
        assert "metadata" not in result

    def test_hosts_field_renaming(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert result["hosts"]["api.openai.com"]["allow"] == ["openai:*"]
        assert result["hosts"]["api.openai.com"]["rate"] == 3000
        assert "credentials" not in result["hosts"]["api.openai.com"]
        assert "rate_limit" not in result["hosts"]["api.openai.com"]

    def test_wildcard_host(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert result["hosts"]["*"]["unknown_creds"] == "prompt"
        assert result["hosts"]["*"]["rate"] == 600

    def test_credentials_to_credential(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert "credential" in result
        assert "credentials" not in result
        assert result["credential"]["openai"]["match"] == ['sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}']

    def test_global_budget_to_budget(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert result["budget"] == 12000
        assert "global_budget" not in result

    def test_risk_appetite_to_risk(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert "risk" in result
        assert result["risk"][0]["account"] == "agent"
        assert result["risk"][0]["decision"] == "allow"

    def test_bypass_passes_through(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        result = denormalize(raw)

        assert result["hosts"]["*.internal"]["bypass"] == ["pattern_scanner"]


class TestBuildTomlDocument:
    """Test building structured TOML documents."""

    def test_produces_valid_toml(self):
        from toml_normalize import denormalize

        raw = yaml.safe_load(SAMPLE_YAML)
        toml_data = denormalize(raw)
        content = tomlkit.dumps(toml_data)

        # Should be parseable
        parsed = tomlkit.parse(content)
        assert parsed["version"] == "2.0"
        assert "hosts" in parsed

    def test_full_round_trip(self):
        """YAML -> denormalize -> TOML -> normalize should match original."""
        from toml_normalize import denormalize, normalize

        raw = yaml.safe_load(SAMPLE_YAML)
        toml_data = denormalize(raw)
        content = tomlkit.dumps(toml_data)
        parsed = tomlkit.parse(content)
        plain = parsed.unwrap()
        back = normalize(plain)

        # Key fields should round-trip
        assert back["metadata"]["version"] == "2.0"
        assert back["global_budget"] == 12000
        assert back["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert back["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert back["hosts"]["*"]["unknown_credentials"] == "prompt"
        assert back["credentials"]["openai"]["patterns"] == ['sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}']
        assert back["required"] == ["credential_guard", "network_guard"]
        assert len(back["gateway"]["risk_appetite"]) == 1


class TestNormalize:
    """Tests for normalize() — TOML field names to internal field names."""

    def test_normalize_budget_to_global_budget(self):
        """Top-level 'budget' becomes 'global_budget'."""
        from toml_normalize import normalize

        result = normalize({"budget": 12000})
        assert result["global_budget"] == 12000
        assert "budget" not in result

    def test_normalize_credential_to_credentials_with_patterns(self):
        """Singular 'credential' becomes plural 'credentials', .match -> .patterns."""
        from toml_normalize import normalize

        result = normalize({
            "credential": {
                "openai": {"match": ["sk-.*"], "headers": ["authorization"]},
            }
        })
        assert "credentials" in result
        assert "credential" not in result
        assert result["credentials"]["openai"]["patterns"] == ["sk-.*"]
        assert result["credentials"]["openai"]["headers"] == ["authorization"]

    def test_normalize_host_rate_to_rate_limit(self):
        """Per-host 'rate' becomes 'rate_limit'."""
        from toml_normalize import normalize

        result = normalize({
            "hosts": {"api.openai.com": {"rate": 3000, "allow": ["openai:*"]}}
        })
        assert result["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert "rate" not in result["hosts"]["api.openai.com"]
        assert "allow" not in result["hosts"]["api.openai.com"]

    def test_normalize_collision_budget_and_global_budget_raises(self):
        """Raises ValueError when both 'budget' and 'global_budget' are present."""
        from toml_normalize import normalize

        with pytest.raises(ValueError, match="budget.*global_budget"):
            normalize({"budget": 100, "global_budget": 200})

    def test_normalize_non_dict_hosts_raises(self):
        """Raises ValueError when 'hosts' is not a dict."""
        from toml_normalize import normalize

        with pytest.raises(ValueError, match="Expected dict.*hosts"):
            normalize({"hosts": ["not", "a", "dict"]})

    def test_normalize_agents_hosts_renamed(self):
        """Agent-scoped hosts get the same field renames as top-level hosts."""
        from toml_normalize import normalize

        result = normalize({
            "agents": {
                "boris": {
                    "hosts": {
                        "api.openai.com": {"rate": 500, "allow": ["openai:*"]}
                    }
                }
            }
        })
        agent_host = result["agents"]["boris"]["hosts"]["api.openai.com"]
        assert agent_host["rate_limit"] == 500
        assert agent_host["credentials"] == ["openai:*"]

    def test_normalize_does_not_mutate_input(self):
        """normalize() must not modify the caller's input dict."""
        from toml_normalize import normalize

        original = {
            "budget": 12000,
            "hosts": {"api.openai.com": {"rate": 3000, "allow": ["openai:*"]}},
        }
        frozen = copy.deepcopy(original)
        normalize(original)
        assert original == frozen

    def test_normalize_empty_input(self):
        """normalize({}) returns an empty dict."""
        from toml_normalize import normalize

        result = normalize({})
        assert result == {}
