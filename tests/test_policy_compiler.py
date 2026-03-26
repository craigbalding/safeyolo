"""
Tests for policy_compiler.py - Host-centric to IAM policy compilation.
"""

import pytest


class TestIsHostCentric:
    """Tests for format detection."""

    def test_detects_hosts_key(self):
        from policy_compiler import is_host_centric

        assert is_host_centric({"hosts": {}})
        assert is_host_centric({"hosts": {"api.openai.com": {}}})

    def test_rejects_iam_format(self):
        from policy_compiler import is_host_centric

        assert not is_host_centric({"permissions": []})
        assert not is_host_centric({})


class TestCompileCredentials:
    """Tests for credential routing compilation."""

    def test_single_credential(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"]},
            }
        }
        result = compile_policy(raw)

        perms = result["permissions"]
        cred_perms = [p for p in perms if p["action"] == "credential:use"]
        assert len(cred_perms) == 1
        assert cred_perms[0]["resource"] == "api.openai.com/*"
        assert cred_perms[0]["effect"] == "allow"
        assert cred_perms[0]["condition"]["credential"] == ["openai:*"]

    def test_multiple_hosts(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"]},
                "api.anthropic.com": {"credentials": ["anthropic:*"]},
            }
        }
        result = compile_policy(raw)

        cred_perms = [p for p in result["permissions"] if p["action"] == "credential:use"]
        assert len(cred_perms) == 2

        resources = {p["resource"] for p in cred_perms}
        assert "api.openai.com/*" in resources
        assert "api.anthropic.com/*" in resources

    def test_string_credential_converted_to_list(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": "openai:*"},
            }
        }
        result = compile_policy(raw)
        cred_perm = [p for p in result["permissions"] if p["action"] == "credential:use"][0]
        assert cred_perm["condition"]["credential"] == ["openai:*"]


class TestCompileRateLimits:
    """Tests for rate limit compilation."""

    def test_single_rate_limit(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"rate_limit": 3000},
            }
        }
        result = compile_policy(raw)

        budget_perms = [p for p in result["permissions"] if p["effect"] == "budget"]
        assert len(budget_perms) == 1
        assert budget_perms[0]["resource"] == "api.openai.com/*"
        assert budget_perms[0]["budget"] == 3000

    def test_host_with_both_creds_and_limit(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
            }
        }
        result = compile_policy(raw)

        assert len(result["permissions"]) == 2
        actions = {p["action"] for p in result["permissions"]}
        assert "credential:use" in actions
        assert "network:request" in actions


class TestCompileWildcard:
    """Tests for wildcard host handling."""

    def test_unknown_credentials_prompt(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"unknown_credentials": "prompt", "rate_limit": 600},
            }
        }
        result = compile_policy(raw)

        cred_perms = [p for p in result["permissions"] if p["action"] == "credential:use"]
        assert len(cred_perms) == 1
        assert cred_perms[0]["resource"] == "*"
        assert cred_perms[0]["effect"] == "prompt"

        budget_perms = [p for p in result["permissions"] if p["effect"] == "budget"]
        assert len(budget_perms) == 1
        assert budget_perms[0]["resource"] == "*"
        assert budget_perms[0]["budget"] == 600

    def test_unknown_credentials_deny(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"unknown_credentials": "deny"},
            }
        }
        result = compile_policy(raw)

        cred_perms = [p for p in result["permissions"] if p["action"] == "credential:use"]
        assert cred_perms[0]["effect"] == "deny"


class TestCompileBypass:
    """Tests for domain bypass compilation."""

    def test_bypass_generates_domains(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "*.internal": {"bypass": ["pattern_scanner"]},
            }
        }
        result = compile_policy(raw)

        assert "domains" in result
        assert "*.internal" in result["domains"]
        assert result["domains"]["*.internal"]["bypass"] == ["pattern_scanner"]


class TestCompileRawRules:
    """Tests for IAM rule passthrough (escape hatch)."""

    def test_raw_rules_passed_through(self):
        from policy_compiler import compile_policy

        raw_rule = {
            "action": "credential:use",
            "resource": "api.openai.com/v1/chat/*",
            "effect": "allow",
            "condition": {"credential": ["hmac:abc123"]},
        }
        raw = {
            "hosts": {
                "api.openai.com": {
                    "credentials": ["openai:*"],
                    "rules": [raw_rule],
                },
            }
        }
        result = compile_policy(raw)

        # Should have credential perm + raw rule
        assert any(p["resource"] == "api.openai.com/v1/chat/*" for p in result["permissions"])


class TestCompileGlobalBudget:
    """Tests for global budget compilation."""

    def test_global_budget(self):
        from policy_compiler import compile_policy

        raw = {"hosts": {}, "global_budget": 12000}
        result = compile_policy(raw)

        assert result["budgets"] == {"network:request": 12000}

    def test_budgets_passthrough(self):
        from policy_compiler import compile_policy

        raw = {"hosts": {}, "budgets": {"network:request": 5000}}
        result = compile_policy(raw)

        assert result["budgets"] == {"network:request": 5000}


class TestCompileCredentialDetection:
    """Tests for credential detection rule compilation."""

    def test_explicit_allowed_hosts(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {},
            "credentials": {
                "openai": {
                    "patterns": ["sk-proj-.*"],
                    "headers": ["authorization"],
                    "allowed_hosts": ["api.openai.com"],
                }
            },
        }
        result = compile_policy(raw)

        rules = result["credential_rules"]
        assert len(rules) == 1
        assert rules[0]["name"] == "openai"
        assert rules[0]["allowed_hosts"] == ["api.openai.com"]
        assert rules[0]["header_names"] == ["authorization"]

    def test_auto_derived_allowed_hosts(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"]},
                "api.anthropic.com": {"credentials": ["anthropic:*"]},
            },
            "credentials": {
                "openai": {"patterns": ["sk-proj-.*"]},
                "anthropic": {"patterns": ["sk-ant-.*"]},
            },
        }
        result = compile_policy(raw)

        rules = {r["name"]: r for r in result["credential_rules"]}
        assert rules["openai"]["allowed_hosts"] == ["api.openai.com"]
        assert rules["anthropic"]["allowed_hosts"] == ["api.anthropic.com"]

    def test_multi_host_credential(self):
        """GitHub creds accepted at both github.com and api.github.com."""
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.github.com": {"credentials": ["github:*"]},
                "github.com": {"credentials": ["github:*"]},
            },
            "credentials": {
                "github": {"patterns": ["gh[ps]_.*"]},
            },
        }
        result = compile_policy(raw)

        rules = result["credential_rules"]
        github_rule = rules[0]
        assert set(github_rule["allowed_hosts"]) == {"api.github.com", "github.com"}


class TestCompilePassthrough:
    """Tests for sections that pass through unchanged."""

    def test_required_passthrough(self):
        from policy_compiler import compile_policy

        raw = {"hosts": {}, "required": ["credential_guard", "network_guard"]}
        result = compile_policy(raw)
        assert result["required"] == ["credential_guard", "network_guard"]

    def test_addons_passthrough(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {},
            "addons": {
                "credential_guard": {"enabled": True},
            },
        }
        result = compile_policy(raw)
        assert result["addons"]["credential_guard"]["enabled"] is True

    def test_scan_patterns_passthrough(self):
        from policy_compiler import compile_policy

        raw = {"hosts": {}, "scan_patterns": []}
        result = compile_policy(raw)
        assert result["scan_patterns"] == []


class TestFullPolicyCompilation:
    """End-to-end tests with realistic policy."""

    def test_realistic_policy(self):
        """Test compilation of a realistic baseline policy."""
        from policy_compiler import compile_policy

        raw = {
            "metadata": {"version": "2.0", "description": "Test"},
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
                "api.anthropic.com": {"credentials": ["anthropic:*"], "rate_limit": 3000},
                "api.github.com": {"credentials": ["github:*"], "rate_limit": 300},
                "github.com": {"credentials": ["github:*"]},
                "pypi.org": {"rate_limit": 1200},
                "*.internal": {"bypass": ["pattern_scanner"]},
                "*": {"unknown_credentials": "prompt", "rate_limit": 600},
            },
            "global_budget": 12000,
            "credentials": {
                "openai": {"patterns": ["sk-proj-.*"]},
                "anthropic": {"patterns": ["sk-ant-.*"]},
                "github": {"patterns": ["gh[ps]_.*"]},
            },
            "required": ["credential_guard", "network_guard"],
            "addons": {"credential_guard": {"enabled": True}},
            "scan_patterns": [],
        }

        result = compile_policy(raw)

        # Check structure
        assert "permissions" in result
        assert "budgets" in result
        assert "credential_rules" in result
        assert "domains" in result

        # Check credential permissions
        cred_perms = [p for p in result["permissions"] if p["action"] == "credential:use"]
        assert len(cred_perms) == 5  # openai, anthropic, github x2, wildcard prompt

        # Check budget permissions
        budget_perms = [p for p in result["permissions"] if p["effect"] == "budget"]
        assert len(budget_perms) == 5  # openai, anthropic, github, pypi, wildcard

        # Check domains
        assert "*.internal" in result["domains"]

    def test_compiled_policy_validates(self):
        """Compiled policy passes Pydantic UnifiedPolicy validation."""
        from policy_compiler import compile_policy
        from policy_engine import UnifiedPolicy

        raw = {
            "metadata": {"version": "2.0"},
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
                "*": {"unknown_credentials": "prompt", "rate_limit": 600},
            },
            "global_budget": 12000,
            "credentials": {
                "openai": {"patterns": ["sk-proj-.*"]},
            },
            "required": ["credential_guard"],
            "addons": {"credential_guard": {"enabled": True}},
            "scan_patterns": [],
        }

        compiled = compile_policy(raw)
        policy = UnifiedPolicy.model_validate(compiled)

        assert len(policy.permissions) == 4  # cred allow, cred prompt, budget x2
        assert len(policy.credential_rules) == 1
        assert policy.budgets["network:request"] == 12000

    def test_loaded_via_policy_loader(self, tmp_path):
        """Host-centric YAML loads correctly through PolicyLoader."""
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com:    { credentials: [openai:*], rate_limit: 3000 }
  api.anthropic.com: { credentials: [anthropic:*], rate_limit: 3000 }
  "*":               { unknown_credentials: prompt, rate_limit: 600 }

global_budget: 12000

credentials:
  openai:    { patterns: ["sk-proj-.*"] }
  anthropic: { patterns: ["sk-ant-.*"] }

required: [credential_guard, network_guard]
addons:
  credential_guard: { enabled: true }
  network_guard: { enabled: true }
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # Should have compiled to IAM permissions
        assert len(policy.permissions) > 0

        # Check credential routing works
        cred_perms = [
            p for p in policy.permissions
            if p.action == "credential:use" and "openai" in str(p.resource)
        ]
        assert len(cred_perms) == 1
        assert cred_perms[0].effect == "allow"

    def test_engine_evaluates_compiled_policy(self, tmp_path):
        """PolicyEngine correctly evaluates a compiled host-centric policy."""
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com:    { credentials: [openai:*], rate_limit: 3000 }
  api.anthropic.com: { credentials: [anthropic:*], rate_limit: 3000 }
  "*":               { unknown_credentials: prompt, rate_limit: 600 }

global_budget: 12000
required: [credential_guard]
addons:
  credential_guard: { enabled: true }
scan_patterns: []
""")

        engine = PolicyEngine(baseline_path=baseline)

        # Known credential to correct host → allow
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.openai.com",
            path="/v1/chat/completions",
        )
        assert decision.effect == "allow"

        # Known credential to wrong host → prompt
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.anthropic.com",
            path="/v1/messages",
        )
        assert decision.effect == "prompt"

        # Unknown credential → prompt
        decision = engine.evaluate_credential(
            credential_type="unknown",
            destination="api.example.com",
            path="/",
        )
        assert decision.effect == "prompt"

        # Rate limiting works
        decision = engine.evaluate_request(
            host="api.openai.com",
            path="/v1/chat/completions",
        )
        assert decision.effect == "allow"

    def test_bypass_works_via_compiled_policy(self, tmp_path):
        """Domain bypass compiles correctly and is evaluated."""
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  "*.internal": { bypass: [pattern_scanner] }

required: [credential_guard]
addons:
  credential_guard: { enabled: true }
  pattern_scanner: { enabled: true }
scan_patterns: []
""")

        engine = PolicyEngine(baseline_path=baseline)

        # pattern_scanner bypassed for internal domains
        assert not engine.is_addon_enabled("pattern_scanner", domain="db.internal")

        # pattern_scanner active for external domains
        assert engine.is_addon_enabled("pattern_scanner", domain="api.openai.com")

        # credential_guard active for internal (required)
        assert engine.is_addon_enabled("credential_guard", domain="db.internal")


class TestCompileGateway:
    """Tests for services/agents gateway compilation."""

    def test_compile_gateway_with_agents(self):
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "research-agent": {
                    "services": {
                        "gmail": {"role": "readonly", "token": "gmail-cred"},
                        "slack": {"role": "poster", "token": "slack-cred"},
                    },
                },
            },
        }
        gateway = compile_gateway(raw)
        assert "token_map" in gateway
        assert "agent_env" in gateway
        assert len(gateway["token_map"]) == 2
        assert "research-agent" in gateway["agent_env"]
        assert "gmail" in gateway["agent_env"]["research-agent"]
        assert "slack" in gateway["agent_env"]["research-agent"]

    def test_compile_gateway_token_format(self):
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "agent-1": {
                    "services": {"minifuse": {"role": "reader", "token": "mf-key"}},
                },
            },
        }
        gateway = compile_gateway(raw)
        token = list(gateway["token_map"].keys())[0]
        assert token.startswith("sgw_")
        assert len(token) == 4 + 64

    def test_compile_gateway_token_binding(self):
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "my-agent": {
                    "services": {"gmail": {"capability": "search_headers", "token": "gmail-cred", "account": "operator"}},
                },
            },
        }
        gateway = compile_gateway(raw)
        binding = list(gateway["token_map"].values())[0]
        assert binding["agent"] == "my-agent"
        assert binding["service"] == "gmail"
        assert binding["capability"] == "search_headers"
        assert binding["token"] == "gmail-cred"
        assert binding["account"] == "operator"

    def test_compile_gateway_role_compat(self):
        """Legacy role field is accepted as capability."""
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "my-agent": {
                    "services": {"gmail": {"role": "readonly", "token": "gmail-cred"}},
                },
            },
        }
        gateway = compile_gateway(raw)
        binding = list(gateway["token_map"].values())[0]
        assert binding["capability"] == "readonly"
        assert binding["account"] == "agent"  # default

    def test_compile_gateway_multiple_agents(self):
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "a1": {"services": {"gmail": {"role": "readonly", "token": "g"}}},
                "a2": {"services": {
                    "slack": {"role": "poster", "token": "s"},
                    "minifuse": {"role": "reader", "token": "m"},
                }},
            },
        }
        gateway = compile_gateway(raw)
        assert len(gateway["token_map"]) == 3
        assert "a1" in gateway["agent_env"]
        assert "a2" in gateway["agent_env"]

    def test_compile_gateway_empty_agents(self):
        from policy_compiler import compile_gateway

        gateway = compile_gateway({"agents": {}})
        assert gateway["token_map"] == {}
        assert gateway["agent_env"] == {}
        assert gateway["host_map"] == {}

    def test_compile_gateway_no_agents(self):
        from policy_compiler import compile_gateway

        gateway = compile_gateway({})
        assert gateway["token_map"] == {}
        assert gateway["agent_env"] == {}
        assert gateway["host_map"] == {}

    def test_mint_gateway_token_uniqueness(self):
        from policy_compiler import mint_gateway_token

        tokens = {mint_gateway_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_compile_policy_with_agents_section(self):
        """compile_policy stores gateway config in result['gateway']."""
        from policy_compiler import compile_policy

        raw = {
            "hosts": {"*": {"unknown_credentials": "prompt", "rate_limit": 600}},
            "agents": {
                "test-agent": {
                    "services": {"gmail": {"role": "readonly", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)
        assert "gateway" in result
        assert len(result["gateway"]["token_map"]) == 1

    def test_legacy_string_format(self):
        """Legacy format: minifuse: reader (no token) still compiles."""
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "agent": {"services": {"minifuse": "reader"}},
            },
        }
        gateway = compile_gateway(raw)
        binding = list(gateway["token_map"].values())[0]
        assert binding["capability"] == "reader"
        assert binding["token"] == ""

    def test_host_map_extraction(self):
        """Policy hosts with service: key produce host_map in gateway result."""
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.minifuse.io": {"service": "minifuse", "rate_limit": 300},
                "gmail.googleapis.com": {"service": "gmail", "credentials": ["google:*"]},
                "pypi.org": {"rate_limit": 1200},  # no service key
            },
            "agents": {
                "test-agent": {
                    "services": {"minifuse": {"role": "reader", "token": "mf"}},
                },
            },
        }
        result = compile_policy(raw)
        host_map = result["gateway"]["host_map"]
        assert host_map["api.minifuse.io"] == "minifuse"
        assert host_map["gmail.googleapis.com"] == "gmail"
        assert "pypi.org" not in host_map

    def test_host_map_empty_without_service(self):
        """Hosts without service: key produce empty host_map."""
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
                "pypi.org": {"rate_limit": 1200},
            },
            "agents": {
                "agent": {
                    "services": {"gmail": {"role": "readonly", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)
        assert result["gateway"]["host_map"] == {}

    def test_host_map_passed_through_compile_gateway(self):
        """compile_gateway includes host_map when passed explicitly."""
        from policy_compiler import compile_gateway

        host_map = {"api.minifuse.io": "minifuse"}
        raw = {
            "agents": {
                "agent": {
                    "services": {"minifuse": {"role": "reader", "token": "mf"}},
                },
            },
        }
        gateway = compile_gateway(raw, host_map=host_map)
        assert gateway["host_map"] == {"api.minifuse.io": "minifuse"}

    def test_host_map_without_agents(self):
        """host_map stored in gateway even when no agents section exists."""
        from policy_compiler import compile_policy

        raw = {
            "hosts": {
                "api.minifuse.io": {"service": "minifuse"},
            },
        }
        result = compile_policy(raw)
        assert result["gateway"]["host_map"] == {"api.minifuse.io": "minifuse"}


class TestNoneAndEdgeCases:
    """Tests for edge cases and defensive handling."""

    def test_empty_hosts(self):
        from policy_compiler import compile_policy

        result = compile_policy({"hosts": {}})
        assert result["permissions"] == []

    def test_host_with_none_config(self):
        from policy_compiler import compile_policy

        result = compile_policy({"hosts": {"api.test.com": None}})
        assert result["permissions"] == []

    def test_host_with_empty_config(self):
        from policy_compiler import compile_policy

        result = compile_policy({"hosts": {"api.test.com": {}}})
        assert result["permissions"] == []

    def test_metadata_passthrough(self):
        from policy_compiler import compile_policy

        raw = {"hosts": {}, "metadata": {"version": "2.0", "description": "Test"}}
        result = compile_policy(raw)
        assert result["metadata"]["version"] == "2.0"


class TestAddonFileSplit:
    """Tests for loading addons.yaml as a sibling file."""

    def test_addons_merged_from_sibling_file(self, tmp_path):
        """Addons from sibling file are merged into policy."""
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com: { credentials: [openai:*], rate_limit: 3000 }
  "*":            { unknown_credentials: prompt, rate_limit: 600 }
required: [credential_guard]
scan_patterns: []
""")

        addons = tmp_path / "addons.yaml"
        addons.write_text("""
addons:
  credential_guard:
    enabled: true
    detection_level: paranoid
  pattern_scanner:
    enabled: true
""")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # Addons should be loaded from sibling file
        assert "credential_guard" in policy.addons
        assert "pattern_scanner" in policy.addons

    def test_baseline_addons_override_sibling(self, tmp_path):
        """Addons in policy.yaml take precedence over addons.yaml."""
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  "*": { unknown_credentials: prompt, rate_limit: 600 }
required: []
scan_patterns: []
addons:
  credential_guard:
    enabled: false
""")

        addons = tmp_path / "addons.yaml"
        addons.write_text("""
addons:
  credential_guard:
    enabled: true
    detection_level: paranoid
  pattern_scanner:
    enabled: true
""")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # policy.yaml overrides: credential_guard disabled
        assert not policy.addons["credential_guard"].enabled
        # pattern_scanner from addons.yaml still merged in
        assert "pattern_scanner" in policy.addons

    def test_works_without_addons_file(self, tmp_path):
        """Policy loads fine when no addons.yaml sibling exists."""
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com: { credentials: [openai:*], rate_limit: 3000 }
  "*":            { unknown_credentials: prompt, rate_limit: 600 }
required: [credential_guard]
addons:
  credential_guard: { enabled: true }
scan_patterns: []
""")

        # No addons.yaml file — should still work
        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        assert len(policy.permissions) > 0
        assert "credential_guard" in policy.addons

    def test_engine_uses_split_files(self, tmp_path):
        """PolicyEngine works correctly with split baseline + addons."""
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com: { credentials: [openai:*], rate_limit: 3000 }
  "*.internal":   { bypass: [pattern_scanner] }
  "*":            { unknown_credentials: prompt, rate_limit: 600 }
required: [credential_guard]
scan_patterns: []
""")

        addons = tmp_path / "addons.yaml"
        addons.write_text("""
addons:
  credential_guard: { enabled: true }
  pattern_scanner: { enabled: true }
""")

        engine = PolicyEngine(baseline_path=baseline)

        # Credential evaluation works
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.openai.com",
            path="/v1/chat",
        )
        assert decision.effect == "allow"

        # Addon config from addons.yaml is respected
        assert engine.is_addon_enabled("pattern_scanner", domain="api.openai.com")
        assert not engine.is_addon_enabled("pattern_scanner", domain="db.internal")

    def test_non_addons_keys_merged_as_defaults(self, tmp_path):
        """Non-addons keys in addons.yaml merge as defaults."""
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  "*": { unknown_credentials: prompt, rate_limit: 600 }
scan_patterns: []
""")

        addons = tmp_path / "addons.yaml"
        addons.write_text("""
addons:
  credential_guard: { enabled: true }
required:
  - credential_guard
  - network_guard
""")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # 'required' not in baseline, so addons.yaml provides it
        assert "credential_guard" in policy.required
        assert "network_guard" in policy.required

    def test_baseline_required_not_overridden(self, tmp_path):
        """Keys already in policy.yaml are not overridden by addons.yaml."""
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  "*": { unknown_credentials: prompt, rate_limit: 600 }
required: [credential_guard]
scan_patterns: []
""")

        addons = tmp_path / "addons.yaml"
        addons.write_text("""
addons:
  credential_guard: { enabled: true }
required:
  - credential_guard
  - network_guard
  - circuit_breaker
""")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # policy.yaml wins for non-addons keys
        assert policy.required == ["credential_guard"]

    def test_agents_merged_from_sibling_file(self, tmp_path):
        """agents.yaml content is merged into policy under 'agents' key."""
        import yaml
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  api.openai.com: { credentials: [openai:*], rate_limit: 3000 }
  "*":            { unknown_credentials: prompt, rate_limit: 600 }
required: [credential_guard]
addons:
  credential_guard: { enabled: true }
scan_patterns: []
""")

        agents = tmp_path / "agents.yaml"
        agents.write_text(yaml.dump({
            "boris": {
                "template": "claude-code",
                "folder": "/tmp/proj",
                "services": {
                    "gmail": {"role": "readonly", "token": "g"},
                },
            },
        }))

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # Policy should have compiled with agents section (gateway)
        assert len(policy.permissions) > 0
        assert hasattr(policy, "gateway")
        assert len(policy.gateway.get("token_map", {})) == 1

    def test_agents_yaml_change_triggers_reload(self, tmp_path):
        """Modifying agents.yaml triggers a baseline reload."""
        import yaml
        from policy_loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  "*": { unknown_credentials: prompt, rate_limit: 600 }
required: []
addons:
  credential_guard: { enabled: true }
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)

        # No agents.yaml yet — gateway should be empty
        assert loader.baseline.gateway.get("token_map", {}) == {}

        # Create agents.yaml
        agents = tmp_path / "agents.yaml"
        agents.write_text(yaml.dump({
            "boris": {
                "services": {
                    "gmail": {"role": "readonly", "token": "g"},
                },
            },
        }))

        # Simulate watcher: force reload since agents.yaml now exists
        loader._load_baseline()

        assert len(loader.baseline.gateway.get("token_map", {})) == 1

    def test_actual_config_files_load(self):
        """The real config/policy.yaml + config/addons.yaml load correctly."""
        from pathlib import Path

        from policy_loader import PolicyLoader

        baseline = Path(__file__).parent.parent / "config" / "policy.yaml"
        if not baseline.exists():
            pytest.skip("config/policy.yaml not found")

        loader = PolicyLoader(baseline_path=baseline)
        policy = loader.baseline

        # Should have permissions from hosts compilation
        assert len(policy.permissions) > 0
        # Should have addons from addons.yaml
        assert "credential_guard" in policy.addons


class TestCompileRiskAppetite:
    """Tests for gateway.risk_appetite compilation."""

    def test_risk_appetite_compiles_to_permissions(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"tactics": ["collection"], "account": "agent", "decision": "allow"},
                    {"tactics": ["exfiltration"], "decision": "require_approval"},
                    {"irreversible": True, "decision": "deny"},
                ],
            },
        }
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert len(gateway_perms) == 3

        # Check decision mapping
        assert gateway_perms[0]["effect"] == "allow"
        assert gateway_perms[0]["condition"]["tactics"] == ["collection"]
        assert gateway_perms[0]["condition"]["account"] == "agent"

        assert gateway_perms[1]["effect"] == "prompt"
        assert gateway_perms[1]["condition"]["tactics"] == ["exfiltration"]

        assert gateway_perms[2]["effect"] == "deny"
        assert gateway_perms[2]["condition"]["irreversible"] is True

    def test_risk_appetite_agent_and_service(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"agent": "boris", "service": "github", "tactics": ["privilege_escalation"], "decision": "allow"},
                ],
            },
        }
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert len(gateway_perms) == 1
        cond = gateway_perms[0]["condition"]
        assert cond["agent"] == "boris"
        assert cond["service"] == "github"

    def test_risk_appetite_default_decision(self):
        from policy_compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"tactics": ["impact"]},  # no decision → default require_approval
                ],
            },
        }
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert gateway_perms[0]["effect"] == "prompt"

    def test_risk_appetite_validates_in_engine(self, tmp_path):
        """Compiled risk appetite loads into PolicyEngine and evaluates."""
        from policy_engine import PolicyEngine

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
hosts:
  "*": { unknown_credentials: prompt, rate_limit: 600 }

gateway:
  risk_appetite:
    - tactics: [collection]
      account: agent
      decision: allow
    - tactics: [exfiltration]
      decision: require_approval

required: []
addons: {}
scan_patterns: []
""")

        engine = PolicyEngine(baseline_path=baseline)
        # collection for agent → allow
        decision = engine.evaluate_risky_route(
            service="gmail", agent="boris", account="agent",
            tactics=["collection"], enables=[], irreversible=False,
        )
        assert decision.effect == "allow"

        # exfiltration → prompt
        decision = engine.evaluate_risky_route(
            service="gmail", agent="boris", account="agent",
            tactics=["exfiltration"], enables=[], irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_no_risk_appetite_section(self):
        """No gateway.risk_appetite produces no gateway permissions."""
        from policy_compiler import compile_policy

        raw = {"hosts": {"*": {"rate_limit": 600}}}
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert gateway_perms == []


class TestCompileCapabilityRoutes:
    """Tests for capability route → gateway:request permission compilation."""

    def _make_service_dir(self, tmp_path, service_yaml):
        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "minifuse.yaml").write_text(service_yaml)
        # Init registry so compiler can look up services
        from service_loader import ServiceRegistry
        import service_loader
        registry = ServiceRegistry(svc_dir)
        registry.load()
        service_loader._registry = registry
        return svc_dir

    def test_compile_raw_routes_no_contract(self, tmp_path):
        """Capability without contract emits raw routes as gateway:request."""
        from policy_compiler import compile_gateway

        svc_dir = self._make_service_dir(tmp_path, """
schema_version: 1
name: minifuse
auth:
  type: api_key
  header: X-API-Key
capabilities:
  reader:
    description: "Read-only access"
    routes:
      - methods: [GET]
        path: "/v1/feeds"
      - methods: [GET]
        path: "/v1/entries"
""")
        raw = {
            "agents": {
                "claude": {
                    "services": {"minifuse": {"capability": "reader", "token": "mf-key"}},
                },
            },
        }
        permissions = []
        compile_gateway(raw, services_dir=svc_dir, permissions=permissions)

        gw_perms = [p for p in permissions if p["action"] == "gateway:request"]
        assert len(gw_perms) == 2
        resources = {p["resource"] for p in gw_perms}
        assert "minifuse:/v1/feeds" in resources
        assert "minifuse:/v1/entries" in resources
        # Verify condition
        for p in gw_perms:
            assert p["condition"]["agent"] == "claude"
            assert p["condition"]["capability"] == "reader"
            assert p["condition"]["method"] == ["GET"]

    def test_compile_resolved_operations_with_binding(self, tmp_path):
        """Capability with contract + binding resolves operations."""
        from policy_compiler import compile_gateway

        svc_dir = self._make_service_dir(tmp_path, """
schema_version: 1
name: minifuse
auth:
  type: api_key
  header: X-API-Key
capabilities:
  category_manager:
    description: "Manage one category"
    routes:
      - methods: [GET, POST]
        path: "/v1/categories/*/feeds"
    contract:
      template: category_scope
      bindings:
        approved_category_id:
          source: agent
          type: integer
      operations:
        - name: list_feeds
          request:
            method: GET
            path: /v1/categories/{id}/feeds
            transport:
              require_no_body: true
            path_params:
              id:
                equals_var: approved_category_id
            query:
              deny_unknown: true
        - name: create_feed
          request:
            method: POST
            path: /v1/feeds
            body:
              deny_unknown: true
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
""")
        raw = {
            "agents": {
                "claude": {
                    "services": {"minifuse": {"capability": "category_manager", "token": "mf-key"}},
                    "contract_bindings": [
                        {
                            "service": "minifuse",
                            "capability": "category_manager",
                            "template": "category_scope",
                            "bound_values": {"approved_category_id": 137},
                            "grantable_operations": ["list_feeds", "create_feed"],
                        }
                    ],
                },
            },
        }
        permissions = []
        compile_gateway(raw, services_dir=svc_dir, permissions=permissions)

        gw_perms = [p for p in permissions if p["action"] == "gateway:request"]
        assert len(gw_perms) == 2
        resources = {p["resource"] for p in gw_perms}
        # list_feeds: /v1/categories/{id}/feeds → /v1/categories/137/feeds
        assert "minifuse:/v1/categories/137/feeds" in resources
        # create_feed: /v1/feeds (no path params to resolve)
        assert "minifuse:/v1/feeds" in resources

    def test_skip_unbound_contracted_capability(self, tmp_path):
        """Capability with contract but no binding → no permissions emitted."""
        from policy_compiler import compile_gateway

        svc_dir = self._make_service_dir(tmp_path, """
schema_version: 1
name: minifuse
auth:
  type: api_key
  header: X-API-Key
capabilities:
  category_manager:
    description: "Manage one category"
    routes:
      - methods: [GET]
        path: "/v1/categories/*/feeds"
    contract:
      template: category_scope
      bindings:
        approved_category_id:
          source: agent
          type: integer
      operations:
        - name: list_feeds
          request:
            method: GET
            path: /v1/categories/{id}/feeds
            path_params:
              id:
                equals_var: approved_category_id
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
""")
        raw = {
            "agents": {
                "claude": {
                    "services": {"minifuse": {"capability": "category_manager", "token": "mf-key"}},
                    # No contract_bindings → unbound
                },
            },
        }
        permissions = []
        compile_gateway(raw, services_dir=svc_dir, permissions=permissions)

        gw_perms = [p for p in permissions if p["action"] == "gateway:request"]
        assert len(gw_perms) == 0

    def test_service_not_found_graceful(self, tmp_path):
        """Unknown service → warning, no permissions, no crash."""
        from policy_compiler import compile_gateway

        svc_dir = tmp_path / "services"
        svc_dir.mkdir()
        raw = {
            "agents": {
                "claude": {
                    "services": {"nonexistent": {"capability": "reader", "token": "x"}},
                },
            },
        }
        permissions = []
        compile_gateway(raw, services_dir=svc_dir, permissions=permissions)
        assert permissions == []

    def test_no_services_dir_graceful(self):
        """No services_dir → no-op, no crash."""
        from policy_compiler import compile_gateway

        raw = {
            "agents": {
                "claude": {
                    "services": {"minifuse": {"capability": "reader", "token": "x"}},
                },
            },
        }
        permissions = []
        compile_gateway(raw, services_dir=None, permissions=permissions)
        assert permissions == []

    def test_compile_policy_includes_gateway_request_permissions(self, tmp_path):
        """Full compile_policy flow includes gateway:request permissions."""
        from policy_compiler import compile_policy

        svc_dir = self._make_service_dir(tmp_path, """
schema_version: 1
name: minifuse
auth:
  type: api_key
  header: X-API-Key
capabilities:
  reader:
    description: "Read-only"
    routes:
      - methods: [GET]
        path: "/v1/feeds"
""")
        raw = {
            "hosts": {"api.minifuse.io": {"service": "minifuse"}},
            "agents": {
                "claude": {
                    "services": {"minifuse": {"capability": "reader", "token": "mf-key"}},
                },
            },
        }
        result = compile_policy(raw)
        gw_perms = [p for p in result["permissions"] if p["action"] == "gateway:request"]
        assert len(gw_perms) == 1
        assert gw_perms[0]["resource"] == "minifuse:/v1/feeds"
