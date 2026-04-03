"""
Tests for the policy migrate command.

Tests YAML-to-TOML migration: field name conversion, structure,
and comment handling.
"""

import sys
from pathlib import Path

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

        assert result["hosts"]["*"]["on_unknown"] == "prompt"
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
