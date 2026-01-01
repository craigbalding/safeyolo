"""
Tests for policy.py addon.

Tests wildcard matching, bypass lists, policy merging, and hot reload.
"""

import json
import pytest
import time
from pathlib import Path


class TestPatternMatching:
    """Tests for wildcard pattern matching."""

    @pytest.fixture
    def policy_engine(self):
        """Create fresh policy engine."""
        from addons.policy import PolicyEngine

        engine = PolicyEngine()
        return engine

    def test_exact_match(self, policy_engine):
        """Test exact domain matching."""
        assert policy_engine._matches_pattern("api.openai.com", "api.openai.com")
        assert not policy_engine._matches_pattern("api.openai.com", "api.anthropic.com")

    def test_wildcard_subdomain(self, policy_engine):
        """Test wildcard matching for subdomains."""
        assert policy_engine._matches_pattern("storage.googleapis.com", "*.googleapis.com")
        assert policy_engine._matches_pattern("auth.googleapis.com", "*.googleapis.com")
        assert not policy_engine._matches_pattern("googleapis.com.evil.com", "*.googleapis.com")

    def test_wildcard_prefix(self, policy_engine):
        """Test wildcard matching at start."""
        assert policy_engine._matches_pattern("admin-user", "admin-*")
        assert policy_engine._matches_pattern("admin-", "admin-*")
        assert not policy_engine._matches_pattern("user-admin", "admin-*")

    def test_wildcard_suffix(self, policy_engine):
        """Test wildcard matching at end."""
        assert policy_engine._matches_pattern("api.internal.corp", "*.internal.corp")
        assert policy_engine._matches_pattern("db.internal.corp", "*.internal.corp")

    def test_no_wildcard_partial(self, policy_engine):
        """Test that non-wildcard patterns don't match partially."""
        assert not policy_engine._matches_pattern("api.openai.com.evil.com", "api.openai.com")
        assert not policy_engine._matches_pattern("notapi.openai.com", "api.openai.com")


class TestAddonPolicy:
    """Tests for AddonPolicy dataclass."""

    def test_default_values(self):
        """Test AddonPolicy default values."""
        from addons.policy import AddonPolicy

        policy = AddonPolicy()
        assert policy.enabled is True
        assert policy.settings == {}

    def test_merge_policies(self):
        """Test merging two addon policies."""
        from addons.policy import AddonPolicy

        base = AddonPolicy(enabled=True, settings={"threshold": 0.5, "mode": "warn"})
        override = AddonPolicy(enabled=False, settings={"mode": "block"})

        merged = base.merge_with(override)

        assert merged.enabled is False  # Override takes precedence
        assert merged.settings["threshold"] == 0.5  # Base preserved
        assert merged.settings["mode"] == "block"  # Override takes precedence


class TestRequestPolicy:
    """Tests for RequestPolicy class."""

    def test_is_addon_enabled_default(self):
        """Test that unspecified addons are enabled by default."""
        from addons.policy import RequestPolicy

        policy = RequestPolicy()
        assert policy.is_addon_enabled("unknown-addon") is True

    def test_is_addon_enabled_explicit(self):
        """Test explicitly enabled/disabled addons."""
        from addons.policy import RequestPolicy, AddonPolicy

        policy = RequestPolicy(
            addons={
                "rate-limiter": AddonPolicy(enabled=True),
                "yara-scanner": AddonPolicy(enabled=False),
            }
        )

        assert policy.is_addon_enabled("rate-limiter") is True
        assert policy.is_addon_enabled("yara-scanner") is False

    def test_is_addon_enabled_bypassed(self):
        """Test that bypassed addons are disabled."""
        from addons.policy import RequestPolicy, AddonPolicy

        policy = RequestPolicy(
            addons={"rate-limiter": AddonPolicy(enabled=True)},
            bypassed_addons={"rate-limiter"},
        )

        # Even though explicitly enabled, bypass takes precedence
        assert policy.is_addon_enabled("rate-limiter") is False

    def test_get_addon_settings(self):
        """Test getting addon settings from policy."""
        from addons.policy import RequestPolicy, AddonPolicy

        policy = RequestPolicy(
            addons={
                "prompt-injection": AddonPolicy(
                    enabled=True, settings={"threshold": 0.7, "mode": "dual"}
                )
            }
        )

        settings = policy.get_addon_settings("prompt-injection")
        assert settings["threshold"] == 0.7
        assert settings["mode"] == "dual"

    def test_get_addon_settings_missing(self):
        """Test getting settings for addon without config returns empty dict."""
        from addons.policy import RequestPolicy

        policy = RequestPolicy()
        settings = policy.get_addon_settings("nonexistent")
        assert settings == {}


class TestPolicyParsing:
    """Tests for parsing policy config."""

    @pytest.fixture
    def policy_engine(self):
        """Create fresh policy engine."""
        from addons.policy import PolicyEngine

        engine = PolicyEngine()
        return engine

    def test_parse_defaults(self, policy_engine):
        """Test parsing default addon policies."""
        raw_policy = {
            "defaults": {
                "addons": {
                    "rate_limiter": {"enabled": True},
                    "credential_guard": {"enabled": True, "mode": "block"},
                }
            }
        }

        policy_engine._parse_policy(raw_policy)

        assert "rate_limiter" in policy_engine._defaults
        assert policy_engine._defaults["rate_limiter"].enabled is True
        assert policy_engine._defaults["credential_guard"].settings["mode"] == "block"

    def test_parse_domain_policies(self, policy_engine):
        """Test parsing domain-specific policies."""
        raw_policy = {
            "domains": {
                "api.openai.com": {
                    "addons": {"prompt_injection": {"enabled": True, "mode": "dual"}}
                },
                "*.internal": {"bypass": ["yara_scanner", "pattern_scanner"]},
            }
        }

        policy_engine._parse_policy(raw_policy)

        assert "api.openai.com" in policy_engine._domain_policies
        assert "*.internal" in policy_engine._domain_bypasses
        assert "yara_scanner" in policy_engine._domain_bypasses["*.internal"]

    def test_parse_client_policies(self, policy_engine):
        """Test parsing client-specific policies."""
        raw_policy = {
            "clients": {
                "admin-*": {"bypass": ["pattern_scanner"]},
                "ci-runner": {"addons": {"rate_limiter": {"enabled": False}}},
            }
        }

        policy_engine._parse_policy(raw_policy)

        assert "admin-*" in policy_engine._client_bypasses
        assert "ci-runner" in policy_engine._client_policies

    def test_parse_boolean_addon_config(self, policy_engine):
        """Test parsing shorthand boolean addon config."""
        raw_policy = {
            "defaults": {
                "addons": {
                    "yara_scanner": False,  # Shorthand for disabled
                    "rate_limiter": True,  # Shorthand for enabled
                }
            }
        }

        policy_engine._parse_policy(raw_policy)

        assert policy_engine._defaults["yara_scanner"].enabled is False
        assert policy_engine._defaults["rate_limiter"].enabled is True


class TestPolicyLookup:
    """Tests for policy lookup and merging."""

    @pytest.fixture
    def policy_engine(self):
        """Create policy engine with test config."""
        from addons.policy import PolicyEngine

        engine = PolicyEngine()
        engine._parse_policy({
            "defaults": {
                "addons": {
                    "rate_limiter": {"enabled": True, "rps": 1.0},
                    "credential_guard": {"enabled": True},
                }
            },
            "domains": {
                "api.openai.com": {
                    "addons": {"rate_limiter": {"rps": 10.0}}  # Override rate
                },
                "*.internal": {"bypass": ["yara_scanner"]},
            },
            "clients": {
                "admin-*": {"bypass": ["rate_limiter"]},
            },
        })
        return engine

    def test_lookup_defaults_only(self, policy_engine):
        """Test lookup for domain with no specific rules."""
        policy = policy_engine.get_request_policy(domain="unknown.com")

        assert policy.is_addon_enabled("rate_limiter") is True
        assert policy.is_addon_enabled("credential_guard") is True

    def test_lookup_domain_override(self, policy_engine):
        """Test that domain config overrides defaults."""
        policy = policy_engine.get_request_policy(domain="api.openai.com")

        settings = policy.get_addon_settings("rate_limiter")
        assert settings["rps"] == 10.0  # Domain override

    def test_lookup_domain_bypass(self, policy_engine):
        """Test domain bypass list."""
        policy = policy_engine.get_request_policy(domain="db.internal")

        assert policy.is_addon_enabled("yara_scanner") is False  # Bypassed
        assert policy.is_addon_enabled("rate_limiter") is True  # Not bypassed

    def test_lookup_client_bypass(self, policy_engine):
        """Test client bypass takes highest precedence."""
        policy = policy_engine.get_request_policy(
            domain="api.openai.com", client_id="admin-user"
        )

        # Admin client has rate_limiter bypassed
        assert policy.is_addon_enabled("rate_limiter") is False

    def test_lookup_caching(self, policy_engine):
        """Test that lookups are cached."""
        policy_engine.get_request_policy(domain="test.com")
        policy_engine.get_request_policy(domain="test.com")

        assert policy_engine.lookups_total == 2
        assert policy_engine.cache_hits == 1


class TestPolicyReload:
    """Tests for policy hot reload."""

    @pytest.fixture
    def policy_engine(self):
        """Create fresh policy engine."""
        from addons.policy import PolicyEngine

        engine = PolicyEngine()
        return engine

    def test_reload_from_json(self, policy_engine, tmp_path):
        """Test reloading policy from JSON file."""
        config_file = tmp_path / "policy.json"
        config_file.write_text(json.dumps({
            "defaults": {"addons": {"rate_limiter": {"enabled": True, "rps": 5.0}}}
        }))

        policy_engine.policy_path = config_file
        result = policy_engine._reload_policy()

        assert result is True
        assert "rate_limiter" in policy_engine._defaults
        assert policy_engine._defaults["rate_limiter"].settings["rps"] == 5.0

    def test_reload_clears_cache(self, policy_engine, tmp_path):
        """Test that reload clears the policy cache."""
        config_file = tmp_path / "policy.json"
        config_file.write_text(json.dumps({"defaults": {"addons": {}}}))

        policy_engine.policy_path = config_file
        policy_engine._reload_policy()

        # Populate cache
        policy_engine.get_request_policy(domain="test.com")
        assert len(policy_engine._cache) == 1

        # Reload should clear cache
        policy_engine._reload_policy()
        assert len(policy_engine._cache) == 0

    def test_reload_handles_missing_file(self, policy_engine, tmp_path):
        """Test reload handles missing file gracefully."""
        policy_engine.policy_path = tmp_path / "nonexistent.json"
        result = policy_engine._reload_policy()

        assert result is False

    def test_reload_handles_invalid_json(self, policy_engine, tmp_path):
        """Test reload handles invalid JSON gracefully."""
        config_file = tmp_path / "policy.json"
        config_file.write_text("not valid json {{{")

        policy_engine.policy_path = config_file
        result = policy_engine._reload_policy()

        assert result is False


class TestFlowMetadata:
    """Tests for policy attachment to flows."""

    @pytest.fixture
    def policy_engine(self):
        """Create policy engine with test config."""
        from addons.policy import PolicyEngine

        engine = PolicyEngine()
        engine._parse_policy({
            "defaults": {"addons": {"rate_limiter": {"enabled": True}}},
            "domains": {"api.openai.com": {"addons": {"rate_limiter": {"rps": 10.0}}}},
        })
        return engine

    def test_request_attaches_policy(self, policy_engine, make_flow):
        """Test that request hook attaches policy to flow."""
        flow = make_flow(url="https://api.openai.com/v1/chat")

        policy_engine.request(flow)

        assert "policy" in flow.metadata
        assert flow.metadata["policy_domain"] == "api.openai.com"

    def test_is_addon_enabled_with_flow(self, policy_engine, make_flow):
        """Test is_addon_enabled using flow metadata."""
        flow = make_flow(url="https://api.openai.com/v1/chat")
        policy_engine.request(flow)

        # Check using flow
        assert policy_engine.is_addon_enabled("rate_limiter", flow=flow) is True


class TestStats:
    """Tests for policy engine statistics."""

    def test_get_stats(self, tmp_path):
        """Test get_stats returns expected structure."""
        from addons.policy import PolicyEngine

        engine = PolicyEngine()
        config_file = tmp_path / "policy.json"
        config_file.write_text(json.dumps({
            "defaults": {"addons": {"test": {"enabled": True}}},
            "domains": {"a.com": {}, "b.com": {}},
        }))

        engine.policy_path = config_file
        engine._reload_policy()

        stats = engine.get_stats()

        assert stats["policy_file"] == str(config_file)
        assert "test" in stats["default_addons"]
        assert stats["domain_rules_count"] == 2
        assert "cache_hit_rate" in stats
