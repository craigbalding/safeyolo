"""
Tests for toml_normalize.py - Bidirectional field name mapping.

Tests normalize/denormalize round-trip, all field mappings, unknown key passthrough.
"""

import pytest


@pytest.fixture
def normalize():
    from toml_normalize import normalize
    return normalize


@pytest.fixture
def denormalize():
    from toml_normalize import denormalize
    return denormalize


class TestNormalize:
    """Test TOML -> internal field name conversion."""

    def test_version_and_description_to_metadata(self, normalize):
        """Top-level version/description -> metadata dict."""
        result = normalize({"version": "2.0", "description": "test"})
        assert result["metadata"] == {"version": "2.0", "description": "test"}
        assert "version" not in result
        assert "description" not in result

    def test_budget_to_global_budget(self, normalize):
        """budget -> global_budget."""
        result = normalize({"budget": 12000})
        assert result["global_budget"] == 12000
        assert "budget" not in result

    def test_hosts_allow_to_credentials(self, normalize):
        """hosts.X.allow -> hosts.X.credentials."""
        result = normalize({
            "hosts": {
                "api.openai.com": {"allow": ["openai:*"], "rate": 3000}
            }
        })
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert result["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert "allow" not in result["hosts"]["api.openai.com"]
        assert "rate" not in result["hosts"]["api.openai.com"]

    def test_hosts_unknown_creds_to_unknown_credentials(self, normalize):
        """hosts.X.unknown_creds -> hosts.X.unknown_credentials."""
        result = normalize({
            "hosts": {"*": {"unknown_creds": "prompt", "rate": 600}}
        })
        assert result["hosts"]["*"]["unknown_credentials"] == "prompt"
        assert result["hosts"]["*"]["rate_limit"] == 600

    def test_credential_singular_to_credentials_plural(self, normalize):
        """credential (singular) -> credentials (plural)."""
        result = normalize({
            "credential": {
                "openai": {"match": ["sk-..."], "headers": ["authorization"]}
            }
        })
        assert "credentials" in result
        assert "credential" not in result
        assert result["credentials"]["openai"]["patterns"] == ["sk-..."]
        assert result["credentials"]["openai"]["headers"] == ["authorization"]

    def test_risk_to_gateway_risk_appetite(self, normalize):
        """risk (top-level list) -> gateway.risk_appetite."""
        result = normalize({
            "risk": [
                {"account": "agent", "tactics": ["collection"], "decision": "allow"}
            ]
        })
        assert "gateway" in result
        assert result["gateway"]["risk_appetite"] == [
            {"account": "agent", "tactics": ["collection"], "decision": "allow"}
        ]
        assert "risk" not in result

    def test_unknown_keys_pass_through(self, normalize):
        """Unknown keys pass through unchanged."""
        result = normalize({
            "required": ["credential_guard"],
            "scan_patterns": [],
            "custom_key": "custom_value",
        })
        assert result["required"] == ["credential_guard"]
        assert result["scan_patterns"] == []
        assert result["custom_key"] == "custom_value"

    def test_hosts_bypass_passes_through(self, normalize):
        """bypass field passes through unchanged."""
        result = normalize({
            "hosts": {"*.internal": {"bypass": ["pattern_scanner"]}}
        })
        assert result["hosts"]["*.internal"]["bypass"] == ["pattern_scanner"]

    def test_non_dict_host_config_passes_through(self, normalize):
        """Non-dict host config passes through."""
        result = normalize({"hosts": {"example.com": None}})
        assert result["hosts"]["example.com"] is None

    def test_empty_input(self, normalize):
        """Empty dict produces empty dict."""
        result = normalize({})
        assert result == {}

    def test_full_policy(self, normalize):
        """Full TOML-style policy normalizes correctly."""
        toml_style = {
            "version": "2.0",
            "description": "test policy",
            "budget": 12000,
            "hosts": {
                "api.openai.com": {"allow": ["openai:*"], "rate": 3000},
                "*.internal": {"bypass": ["pattern_scanner"]},
                "*": {"unknown_creds": "prompt", "rate": 600},
            },
            "credential": {
                "openai": {"match": ["sk-..."], "headers": ["authorization"]},
            },
            "risk": [
                {"account": "agent", "tactics": ["collection"], "decision": "allow"},
            ],
            "required": ["credential_guard"],
        }
        result = normalize(toml_style)

        # metadata
        assert result["metadata"]["version"] == "2.0"
        # global budget
        assert result["global_budget"] == 12000
        # hosts
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert result["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert result["hosts"]["*"]["unknown_credentials"] == "prompt"
        # credentials
        assert result["credentials"]["openai"]["patterns"] == ["sk-..."]
        # gateway
        assert len(result["gateway"]["risk_appetite"]) == 1
        # required
        assert result["required"] == ["credential_guard"]


class TestDenormalize:
    """Test internal -> TOML field name conversion."""

    def test_metadata_to_top_level(self, denormalize):
        """metadata.version/description -> top-level."""
        result = denormalize({"metadata": {"version": "2.0", "description": "test"}})
        assert result["version"] == "2.0"
        assert result["description"] == "test"
        assert "metadata" not in result

    def test_global_budget_to_budget(self, denormalize):
        """global_budget -> budget."""
        result = denormalize({"global_budget": 12000})
        assert result["budget"] == 12000
        assert "global_budget" not in result

    def test_hosts_credentials_to_allow(self, denormalize):
        """hosts.X.credentials -> hosts.X.allow."""
        result = denormalize({
            "hosts": {"api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000}}
        })
        assert result["hosts"]["api.openai.com"]["allow"] == ["openai:*"]
        assert result["hosts"]["api.openai.com"]["rate"] == 3000

    def test_credentials_plural_to_singular(self, denormalize):
        """credentials -> credential, patterns -> match."""
        result = denormalize({
            "credentials": {"openai": {"patterns": ["sk-..."], "headers": ["auth"]}}
        })
        assert result["credential"]["openai"]["match"] == ["sk-..."]
        assert result["credential"]["openai"]["headers"] == ["auth"]

    def test_gateway_risk_appetite_to_risk(self, denormalize):
        """gateway.risk_appetite -> risk."""
        result = denormalize({
            "gateway": {"risk_appetite": [{"decision": "allow"}]}
        })
        assert result["risk"] == [{"decision": "allow"}]

    def test_unknown_keys_pass_through(self, denormalize):
        """Unknown keys pass through."""
        result = denormalize({"required": ["x"], "custom": "val"})
        assert result["required"] == ["x"]
        assert result["custom"] == "val"


class TestRoundTrip:
    """Test normalize -> denormalize round-trip."""

    def test_normalize_then_denormalize(self, normalize, denormalize):
        """normalize(denormalize(x)) preserves semantics."""
        toml_style = {
            "version": "2.0",
            "budget": 12000,
            "hosts": {
                "api.openai.com": {"allow": ["openai:*"], "rate": 3000},
                "*": {"unknown_creds": "prompt", "rate": 600},
            },
            "credential": {
                "openai": {"match": ["sk-..."], "headers": ["auth"]},
            },
            "risk": [{"decision": "allow"}],
            "required": ["credential_guard"],
        }
        internal = normalize(toml_style)
        back = denormalize(internal)

        # Check key fields round-trip
        assert back["version"] == "2.0"
        assert back["budget"] == 12000
        assert back["hosts"]["api.openai.com"]["allow"] == ["openai:*"]
        assert back["hosts"]["api.openai.com"]["rate"] == 3000
        assert back["hosts"]["*"]["unknown_creds"] == "prompt"
        assert back["credential"]["openai"]["match"] == ["sk-..."]
        assert back["risk"] == [{"decision": "allow"}]
        assert back["required"] == ["credential_guard"]

    def test_denormalize_then_normalize(self, normalize, denormalize):
        """denormalize(normalize(x)) preserves semantics."""
        internal = {
            "metadata": {"version": "2.0"},
            "global_budget": 12000,
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
            },
            "credentials": {
                "openai": {"patterns": ["sk-..."]},
            },
            "gateway": {"risk_appetite": [{"decision": "allow"}]},
            "required": ["credential_guard"],
        }
        toml_style = denormalize(internal)
        back = normalize(toml_style)

        assert back["metadata"]["version"] == "2.0"
        assert back["global_budget"] == 12000
        assert back["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert back["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert back["credentials"]["openai"]["patterns"] == ["sk-..."]
        assert back["gateway"]["risk_appetite"] == [{"decision": "allow"}]
