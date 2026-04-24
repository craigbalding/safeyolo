"""
Tests for policy_compiler.py - Host-centric to IAM policy compilation.

Organised by contract area:
- TestIsHostCentric: format detection
- TestCompileCredentials: per-host credential routing
- TestCompileRateLimits: per-host rate limit budget rules
- TestCompileEgress: per-host egress deny/prompt (B1 fix)
- TestCompileWildcard: wildcard host handling
- TestCompileBypass: domain bypass compilation
- TestCompileRawRules: IAM rule passthrough
- TestCompileGlobalBudget: global_budget and budgets passthrough
- TestCompileCredentialDetection: credential detection rule compilation
- TestCompilePassthrough: sections that pass through unchanged
- TestCompileDomains: domains merge direction
- TestCompileAgentHosts: per-agent host entries
- TestCompileRiskAppetite: gateway.risk_appetite rules
- TestCompileGateway: services/agents gateway compilation
- TestCompileCapabilityRoutes: capability route permissions
- TestDecompileApproval: decompile_approval for saving approvals
- TestCompileErrors: fail-closed error paths (B2-B5)
- TestFullPolicyCompilation: end-to-end integration tests
"""

import pytest


class TestIsHostCentric:
    """Tests for format detection."""

    def test_detects_hosts_key(self):
        from safeyolo.policy.compiler import is_host_centric

        assert is_host_centric({"hosts": {}}) is True

    def test_detects_hosts_with_entries(self):
        from safeyolo.policy.compiler import is_host_centric

        assert is_host_centric({"hosts": {"api.openai.com": {}}}) is True

    def test_rejects_iam_format(self):
        from safeyolo.policy.compiler import is_host_centric

        assert is_host_centric({"permissions": []}) is False

    def test_rejects_empty_dict(self):
        from safeyolo.policy.compiler import is_host_centric

        assert is_host_centric({}) is False


class TestCompileCredentials:
    """Tests for credential routing compilation."""

    def test_single_credential(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"]},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "credential:use",
                "resource": "api.openai.com/*",
                "effect": "allow",
                "tier": "explicit",
                "condition": {"credential": ["openai:*"]},
            }
        ]

    def test_multiple_hosts(self):
        from safeyolo.policy.compiler import compile_policy

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
        assert resources == {"api.openai.com/*", "api.anthropic.com/*"}

    def test_string_credential_converted_to_list(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": "openai:*"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"][0]["condition"]["credential"] == ["openai:*"]


class TestCompileRateLimits:
    """Tests for rate limit compilation."""

    def test_single_rate_limit(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"rate_limit": 3000},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "network:request",
                "resource": "api.openai.com/*",
                "effect": "budget",
                "budget": 3000,
                "tier": "explicit",
            }
        ]

    def test_host_with_both_creds_and_limit(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
            }
        }
        result = compile_policy(raw)

        assert len(result["permissions"]) == 2
        actions = [p["action"] for p in result["permissions"]]
        assert actions == ["credential:use", "network:request"]


class TestCompileEgress:
    """Tests for per-host egress control (B1 fix: prompt was silently ignored)."""

    def test_per_host_egress_prompt(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "evil.com": {"egress": "prompt"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "network:request",
                "resource": "evil.com/*",
                "effect": "prompt",
                "tier": "explicit",
            }
        ]

    def test_per_host_egress_deny(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "evil.com": {"egress": "deny"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "network:request",
                "resource": "evil.com/*",
                "effect": "deny",
                "tier": "explicit",
            }
        ]

    def test_per_host_egress_allow_generates_no_permission(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "safe.com": {"egress": "allow"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == []

    def test_per_host_egress_absent_generates_no_permission(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "safe.com": {},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == []

    def test_per_host_egress_with_credentials_and_rate_limit(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.example.com": {
                    "credentials": ["example:*"],
                    "egress": "prompt",
                    "rate_limit": 500,
                },
            }
        }
        result = compile_policy(raw)

        assert len(result["permissions"]) == 3
        effects = [p["effect"] for p in result["permissions"]]
        assert effects == ["allow", "prompt", "budget"]


class TestCompileWildcard:
    """Tests for wildcard host handling."""

    def test_unknown_credentials_prompt(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"unknown_credentials": "prompt", "rate_limit": 600},
            }
        }
        result = compile_policy(raw)

        assert len(result["permissions"]) == 2
        assert result["permissions"][0] == {
            "action": "credential:use",
            "resource": "*",
            "effect": "prompt",
            "tier": "explicit",
        }
        assert result["permissions"][1] == {
            "action": "network:request",
            "resource": "*",
            "effect": "budget",
            "budget": 600,
            "tier": "explicit",
        }

    def test_unknown_credentials_deny(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"unknown_credentials": "deny"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "credential:use",
                "resource": "*",
                "effect": "deny",
                "tier": "explicit",
            }
        ]

    def test_wildcard_egress_prompt(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"egress": "prompt"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "network:request",
                "resource": "*",
                "effect": "prompt",
                "tier": "explicit",
            }
        ]

    def test_wildcard_egress_deny(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"egress": "deny"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "network:request",
                "resource": "*",
                "effect": "deny",
                "tier": "explicit",
            }
        ]

    def test_wildcard_egress_allow_generates_no_permission(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"egress": "allow"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == []

    def test_wildcard_credentials_fallback_for_unknown_credentials(self):
        """When unknown_credentials is absent, credentials key is used."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"credentials": "prompt"},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "credential:use",
                "resource": "*",
                "effect": "prompt",
                "tier": "explicit",
            }
        ]

    def test_wildcard_rate_limit(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"rate_limit": 600},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [
            {
                "action": "network:request",
                "resource": "*",
                "effect": "budget",
                "budget": 600,
                "tier": "explicit",
            }
        ]

    def test_wildcard_raw_rules_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw_rule = {
            "action": "network:request",
            "resource": "*",
            "effect": "deny",
        }
        raw = {
            "hosts": {
                "*": {"rules": [raw_rule]},
            }
        }
        result = compile_policy(raw)

        assert result["permissions"] == [raw_rule]


class TestCompileBypass:
    """Tests for domain bypass compilation."""

    def test_bypass_generates_domains(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*.internal": {"bypass": ["pattern_scanner"]},
            }
        }
        result = compile_policy(raw)

        assert result["domains"] == {"*.internal": {"bypass": ["pattern_scanner"]}}


class TestCompileRawRules:
    """Tests for IAM rule passthrough (escape hatch)."""

    def test_raw_rules_passed_through(self):
        from safeyolo.policy.compiler import compile_policy

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

        assert len(result["permissions"]) == 2
        assert result["permissions"][1] == raw_rule


class TestCompileGlobalBudget:
    """Tests for global budget compilation."""

    def test_global_budget(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "global_budget": 12000}
        result = compile_policy(raw)

        assert result["budgets"] == {"network:request": 12000}

    def test_budgets_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "budgets": {"network:request": 5000}}
        result = compile_policy(raw)

        assert result["budgets"] == {"network:request": 5000}

    def test_global_budget_takes_precedence_over_budgets(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "global_budget": 12000, "budgets": {"network:request": 5000}}
        result = compile_policy(raw)

        assert result["budgets"] == {"network:request": 12000}


class TestCompileCredentialDetection:
    """Tests for credential detection rule compilation."""

    def test_explicit_allowed_hosts(self):
        from safeyolo.policy.compiler import compile_policy

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

        assert result["credential_rules"] == [
            {
                "name": "openai",
                "patterns": ["sk-proj-.*"],
                "header_names": ["authorization"],
                "allowed_hosts": ["api.openai.com"],
            }
        ]

    def test_auto_derived_allowed_hosts(self):
        from safeyolo.policy.compiler import compile_policy

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
        from safeyolo.policy.compiler import compile_policy

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
        assert rules[0]["name"] == "github"
        assert set(rules[0]["allowed_hosts"]) == {"api.github.com", "github.com"}

    def test_suggested_url_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "credentials": {
                "openai": {
                    "patterns": ["sk-proj-.*"],
                    "suggested_url": "https://platform.openai.com/api-keys",
                }
            },
        }
        result = compile_policy(raw)

        assert result["credential_rules"][0]["suggested_url"] == "https://platform.openai.com/api-keys"

    def test_credential_rules_passthrough_when_no_credentials_section(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "credential_rules": [
                {"name": "openai", "patterns": ["sk-proj-.*"], "allowed_hosts": ["api.openai.com"]}
            ],
        }
        result = compile_policy(raw)

        assert result["credential_rules"] == [
            {"name": "openai", "patterns": ["sk-proj-.*"], "allowed_hosts": ["api.openai.com"]}
        ]

    def test_wildcard_host_excluded_from_auto_derived(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*": {"unknown_credentials": "prompt"},
                "api.openai.com": {"credentials": ["openai:*"]},
            },
            "credentials": {
                "openai": {"patterns": ["sk-proj-.*"]},
            },
        }
        result = compile_policy(raw)

        assert result["credential_rules"][0]["allowed_hosts"] == ["api.openai.com"]


class TestCompilePassthrough:
    """Tests for sections that pass through unchanged."""

    def test_required_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "required": ["credential_guard", "network_guard"]}
        result = compile_policy(raw)
        assert result["required"] == ["credential_guard", "network_guard"]

    def test_addons_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "addons": {
                "credential_guard": {"enabled": True},
            },
        }
        result = compile_policy(raw)
        assert result["addons"] == {"credential_guard": {"enabled": True}}

    def test_scan_patterns_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "scan_patterns": []}
        result = compile_policy(raw)
        assert result["scan_patterns"] == []

    def test_clients_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "clients": {"my-client": {"allowed": True}}}
        result = compile_policy(raw)
        assert result["clients"] == {"my-client": {"allowed": True}}


class TestCompileDomains:
    """Tests for domains merge direction."""

    def test_compiled_domains_override_explicit_on_conflict(self):
        """Compiled bypass overrides explicit domains for same host."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*.internal": {"bypass": ["pattern_scanner"]},
            },
            "domains": {
                "*.internal": {"bypass": ["credential_guard"]},
                "*.external": {"bypass": ["network_guard"]},
            },
        }
        result = compile_policy(raw)

        # Compiled bypass wins for *.internal
        assert result["domains"]["*.internal"]["bypass"] == ["pattern_scanner"]
        # Explicit domain for *.external is preserved
        assert result["domains"]["*.external"]["bypass"] == ["network_guard"]

    def test_explicit_domains_passthrough_when_no_compiled_domains(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"]},
            },
            "domains": {
                "*.internal": {"bypass": ["pattern_scanner"]},
            },
        }
        result = compile_policy(raw)

        assert result["domains"] == {"*.internal": {"bypass": ["pattern_scanner"]}}

    def test_per_host_addons_key_generates_domains(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.example.com": {
                    "addons": {"credential_guard": {"detection_level": "paranoid"}},
                },
            }
        }
        result = compile_policy(raw)

        assert result["domains"] == {
            "api.example.com": {
                "addons": {"credential_guard": {"detection_level": "paranoid"}},
            }
        }


class TestCompileAgentHosts:
    """Tests for per-agent host entries with agent condition."""

    def test_agent_credential_routing(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "hosts": {
                        "api.openai.com": {"credentials": ["openai:*"]},
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        cred_perms = [p for p in result["permissions"] if p["action"] == "credential:use"]
        assert len(cred_perms) == 1
        assert cred_perms[0] == {
            "action": "credential:use",
            "resource": "api.openai.com/*",
            "effect": "allow",
            "tier": "explicit",
            "condition": {"credential": ["openai:*"], "agent": "boris"},
        }

    def test_agent_rate_limit(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "hosts": {
                        "api.openai.com": {"rate_limit": 500},
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        budget_perms = [p for p in result["permissions"] if p["effect"] == "budget"]
        assert len(budget_perms) == 1
        assert budget_perms[0] == {
            "action": "network:request",
            "resource": "api.openai.com/*",
            "effect": "budget",
            "budget": 500,
            "tier": "explicit",
            "condition": {"agent": "boris"},
        }

    def test_agent_egress_deny(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "hosts": {
                        "evil.com": {"egress": "deny"},
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        egress_perms = [
            p for p in result["permissions"]
            if p["action"] == "network:request" and p.get("effect") == "deny"
        ]
        assert len(egress_perms) == 1
        assert egress_perms[0] == {
            "action": "network:request",
            "resource": "evil.com/*",
            "effect": "deny",
            "tier": "explicit",
            "condition": {"agent": "boris"},
        }

    def test_agent_egress_prompt(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "hosts": {
                        "suspicious.com": {"egress": "prompt"},
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        egress_perms = [
            p for p in result["permissions"]
            if p["action"] == "network:request" and p.get("effect") == "prompt"
        ]
        assert len(egress_perms) == 1
        assert egress_perms[0] == {
            "action": "network:request",
            "resource": "suspicious.com/*",
            "effect": "prompt",
            "tier": "explicit",
            "condition": {"agent": "boris"},
        }

    def test_agent_default_egress_deny(self):
        """Agent-level egress: deny generates wildcard deny with agent condition."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "egress": "deny",
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        egress_perms = [
            p for p in result["permissions"]
            if p["action"] == "network:request" and p.get("effect") == "deny"
        ]
        assert len(egress_perms) == 1
        assert egress_perms[0] == {
            "action": "network:request",
            "resource": "*",
            "effect": "deny",
            "tier": "explicit",
            "condition": {"agent": "boris"},
        }

    def test_agent_default_egress_prompt(self):
        """Agent-level egress: prompt generates wildcard prompt with agent condition."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "egress": "prompt",
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        egress_perms = [
            p for p in result["permissions"]
            if p["action"] == "network:request" and p.get("effect") == "prompt"
        ]
        assert len(egress_perms) == 1
        assert egress_perms[0] == {
            "action": "network:request",
            "resource": "*",
            "effect": "prompt",
            "tier": "explicit",
            "condition": {"agent": "boris"},
        }

    def test_agent_bypass_mutates_domains_dict(self):
        """Agent bypass writes to the domains dict passed by compile_policy.

        Note: this is a known ordering issue -- _compile_agent_hosts runs AFTER
        the domains-merge check, so agent bypass domains are NOT written to the
        result unless a top-level host also generated a domains entry. This test
        documents the current behaviour.
        """
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "*.corp": {"bypass": ["network_guard"]},  # triggers domains merge
            },
            "agents": {
                "boris": {
                    "hosts": {
                        "*.internal": {"bypass": ["pattern_scanner"]},
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        # Top-level host bypass is present
        assert result["domains"]["*.corp"] == {"bypass": ["network_guard"]}
        # Agent bypass is NOT in result due to ordering (domains merge already ran)
        assert "*.internal" not in result.get("domains", {})

    def test_agent_none_config_treated_as_empty(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "hosts": {
                        "api.openai.com": None,
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        # None config = no permissions from that host entry
        agent_perms = [p for p in result["permissions"] if p.get("condition", {}).get("agent") == "boris"]
        # Only permissions would be from services/gateway, not from agent hosts
        host_perms = [
            p for p in agent_perms
            if p["action"] in ("credential:use", "network:request") and p.get("resource") == "api.openai.com/*"
        ]
        assert host_perms == []

    def test_agent_non_dict_config_skipped(self):
        """Non-dict agent config is silently skipped (B6: low severity)."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": "not-a-dict",
            },
        }
        # No crash, no permissions from this agent
        result = compile_policy(raw)
        assert result["permissions"] == []

    def test_agent_string_credential_converted_to_list(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "boris": {
                    "hosts": {
                        "api.openai.com": {"credentials": "openai:*"},
                    },
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
        }
        result = compile_policy(raw)

        cred_perms = [p for p in result["permissions"] if p["action"] == "credential:use"]
        assert len(cred_perms) == 1
        assert cred_perms[0]["condition"]["credential"] == ["openai:*"]


class TestCompileRiskAppetite:
    """Tests for gateway.risk_appetite compilation."""

    def test_risk_appetite_compiles_to_permissions(self):
        from safeyolo.policy.compiler import compile_policy

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

        assert gateway_perms[0] == {
            "action": "gateway:risky_route",
            "resource": "*",
            "effect": "allow",
            "tier": "explicit",
            "condition": {"tactics": ["collection"], "account": "agent"},
        }
        assert gateway_perms[1] == {
            "action": "gateway:risky_route",
            "resource": "*",
            "effect": "prompt",
            "tier": "explicit",
            "condition": {"tactics": ["exfiltration"]},
        }
        assert gateway_perms[2] == {
            "action": "gateway:risky_route",
            "resource": "*",
            "effect": "deny",
            "tier": "explicit",
            "condition": {"irreversible": True},
        }

    def test_risk_appetite_agent_and_service(self):
        from safeyolo.policy.compiler import compile_policy

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
        assert gateway_perms[0]["condition"] == {
            "agent": "boris",
            "service": "github",
            "tactics": ["privilege_escalation"],
        }

    def test_risk_appetite_default_decision(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"tactics": ["impact"]},  # no decision -> default require_approval
                ],
            },
        }
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert gateway_perms[0]["effect"] == "prompt"

    def test_risk_appetite_enables_condition(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"enables": ["data_access"], "decision": "allow"},
                ],
            },
        }
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert gateway_perms[0]["condition"] == {"enables": ["data_access"]}

    def test_risk_appetite_no_condition_fields(self):
        """Rule with only decision produces no condition key."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"decision": "deny"},
                ],
            },
        }
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert gateway_perms[0] == {
            "action": "gateway:risky_route",
            "resource": "*",
            "effect": "deny",
            "tier": "explicit",
        }
        assert "condition" not in gateway_perms[0]

    def test_risk_appetite_validates_in_engine(self, tmp_path):
        """Compiled risk appetite loads into PolicyEngine and evaluates."""
        from safeyolo.policy.engine import PolicyEngine

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
        # collection for agent -> allow
        decision = engine.evaluate_risky_route(
            service="gmail",
            agent="boris",
            account="agent",
            tactics=["collection"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "allow"

        # exfiltration -> prompt
        decision = engine.evaluate_risky_route(
            service="gmail",
            agent="boris",
            account="agent",
            tactics=["exfiltration"],
            enables=[],
            irreversible=False,
        )
        assert decision.effect == "prompt"

    def test_no_risk_appetite_section(self):
        """No gateway.risk_appetite produces no gateway permissions."""
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {"*": {"rate_limit": 600}}}
        result = compile_policy(raw)
        gateway_perms = [p for p in result["permissions"] if p["action"] == "gateway:risky_route"]
        assert gateway_perms == []


class TestCompileGateway:
    """Tests for services/agents gateway compilation."""

    def test_compile_gateway_with_agents(self):
        from safeyolo.policy.compiler import compile_gateway

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
        assert len(gateway["token_map"]) == 2
        assert "research-agent" in gateway["agent_env"]
        assert len(gateway["agent_env"]["research-agent"]) == 2
        assert "gmail" in gateway["agent_env"]["research-agent"]
        assert "slack" in gateway["agent_env"]["research-agent"]

    def test_compile_gateway_token_format(self):
        from safeyolo.policy.compiler import compile_gateway

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
        from safeyolo.policy.compiler import compile_gateway

        raw = {
            "agents": {
                "my-agent": {
                    "services": {
                        "gmail": {"capability": "search_headers", "token": "gmail-cred", "account": "operator"}
                    },
                },
            },
        }
        gateway = compile_gateway(raw)
        binding = list(gateway["token_map"].values())[0]
        assert binding == {
            "agent": "my-agent",
            "service": "gmail",
            "capability": "search_headers",
            "token": "gmail-cred",
            "account": "operator",
        }

    def test_compile_gateway_role_compat(self):
        """Legacy role field is accepted as capability."""
        from safeyolo.policy.compiler import compile_gateway

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
        from safeyolo.policy.compiler import compile_gateway

        raw = {
            "agents": {
                "a1": {"services": {"gmail": {"role": "readonly", "token": "g"}}},
                "a2": {
                    "services": {
                        "slack": {"role": "poster", "token": "s"},
                        "minifuse": {"role": "reader", "token": "m"},
                    }
                },
            },
        }
        gateway = compile_gateway(raw)
        assert len(gateway["token_map"]) == 3
        assert set(gateway["agent_env"].keys()) == {"a1", "a2"}

    def test_compile_gateway_empty_agents(self):
        from safeyolo.policy.compiler import compile_gateway

        gateway = compile_gateway({"agents": {}})
        assert gateway == {"token_map": {}, "agent_env": {}, "host_map": {}}

    def test_compile_gateway_no_agents(self):
        from safeyolo.policy.compiler import compile_gateway

        gateway = compile_gateway({})
        assert gateway == {"token_map": {}, "agent_env": {}, "host_map": {}}

    def test_mint_gateway_token_uniqueness(self):
        from safeyolo.policy.compiler import mint_gateway_token

        tokens = {mint_gateway_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_compile_policy_with_agents_section(self):
        """compile_policy stores gateway config in result['gateway']."""
        from safeyolo.policy.compiler import compile_policy

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
        from safeyolo.policy.compiler import compile_gateway

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
        from safeyolo.policy.compiler import compile_policy

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
        from safeyolo.policy.compiler import compile_policy

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
        from safeyolo.policy.compiler import compile_gateway

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
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.minifuse.io": {"service": "minifuse"},
            },
        }
        result = compile_policy(raw)
        assert result["gateway"] == {"token_map": {}, "agent_env": {}, "host_map": {"api.minifuse.io": "minifuse"}}

    def test_grant_ttl_seconds_passthrough(self):
        """gateway.grant_ttl_seconds is passed through to result."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "agents": {
                "test-agent": {
                    "services": {"gmail": {"capability": "reader", "token": "g"}},
                },
            },
            "gateway": {
                "grant_ttl_seconds": 3600,
            },
        }
        result = compile_policy(raw)
        assert result["gateway"]["grant_ttl_seconds"] == 3600

    def test_grant_ttl_seconds_without_agents(self):
        """gateway.grant_ttl_seconds works even without agents."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "grant_ttl_seconds": 7200,
            },
        }
        result = compile_policy(raw)
        assert result["gateway"]["grant_ttl_seconds"] == 7200


class TestDecompileApproval:
    """Tests for decompile_approval — creating host-centric entries for approvals."""

    def test_single_credential(self):
        from safeyolo.policy.compiler import decompile_approval

        result = decompile_approval("api.example.com", ["hmac:a1b2c3"])
        assert result == {"credentials": ["hmac:a1b2c3"]}

    def test_multiple_credentials(self):
        from safeyolo.policy.compiler import decompile_approval

        result = decompile_approval("api.example.com", ["hmac:a1b2c3", "openai:x9y8z7"])
        assert result == {"credentials": ["hmac:a1b2c3", "openai:x9y8z7"]}

    def test_empty_credentials(self):
        from safeyolo.policy.compiler import decompile_approval

        result = decompile_approval("api.example.com", [])
        assert result == {"credentials": []}

    def test_destination_not_included_in_result(self):
        """Destination is the key, not part of the value dict."""
        from safeyolo.policy.compiler import decompile_approval

        result = decompile_approval("api.example.com", ["hmac:abc"])
        assert "destination" not in result
        assert list(result.keys()) == ["credentials"]


class TestCompileErrors:
    """Fail-closed error paths for malformed input."""

    def test_non_dict_host_config_raises_valueerror(self):
        """B3: Non-dict host config (e.g. bare int) raises ValueError."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": 3000,
            }
        }
        with pytest.raises(ValueError, match="Host 'api.openai.com' config must be a dict"):
            compile_policy(raw)

    def test_non_dict_host_config_string_raises_valueerror(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": "allow",
            }
        }
        with pytest.raises(ValueError, match="got str"):
            compile_policy(raw)

    def test_non_dict_host_config_list_raises_valueerror(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {
                "api.openai.com": ["openai:*"],
            }
        }
        with pytest.raises(ValueError, match="got list"):
            compile_policy(raw)

    def test_non_dict_credential_config_raises_valueerror(self):
        """B4: Non-dict credential config raises ValueError."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "credentials": {
                "openai": "sk-proj-.*",
            },
        }
        with pytest.raises(ValueError, match="Credential 'openai' config must be a dict"):
            compile_policy(raw)

    def test_non_dict_credential_config_list_raises_valueerror(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "credentials": {
                "openai": ["sk-proj-.*"],
            },
        }
        with pytest.raises(ValueError, match="got list"):
            compile_policy(raw)

    def test_credential_without_patterns_raises_valueerror(self):
        """B2: Missing patterns field raises ValueError."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "credentials": {
                "openai": {
                    "headers": ["authorization"],
                    "allowed_hosts": ["api.openai.com"],
                },
            },
        }
        with pytest.raises(ValueError, match="Credential 'openai' has no 'patterns' field"):
            compile_policy(raw)

    def test_unknown_risk_appetite_decision_raises_valueerror(self):
        """B5: Unknown decision value raises ValueError (was fallback to 'prompt')."""
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"tactics": ["collection"], "decision": "denp"},  # typo
                ],
            },
        }
        with pytest.raises(ValueError, match="unknown decision 'denp'"):
            compile_policy(raw)

    def test_unknown_risk_appetite_decision_message_lists_valid_values(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {
            "hosts": {},
            "gateway": {
                "risk_appetite": [
                    {"decision": "block"},
                ],
            },
        }
        with pytest.raises(ValueError, match="allow, require_approval, deny"):
            compile_policy(raw)


class TestNoneAndEdgeCases:
    """Tests for edge cases and defensive handling."""

    def test_empty_hosts(self):
        from safeyolo.policy.compiler import compile_policy

        result = compile_policy({"hosts": {}})
        assert result["permissions"] == []

    def test_host_with_none_config(self):
        from safeyolo.policy.compiler import compile_policy

        result = compile_policy({"hosts": {"api.test.com": None}})
        assert result["permissions"] == []

    def test_host_with_empty_config(self):
        from safeyolo.policy.compiler import compile_policy

        result = compile_policy({"hosts": {"api.test.com": {}}})
        assert result["permissions"] == []

    def test_metadata_passthrough(self):
        from safeyolo.policy.compiler import compile_policy

        raw = {"hosts": {}, "metadata": {"version": "2.0", "description": "Test"}}
        result = compile_policy(raw)
        assert result["metadata"] == {"version": "2.0", "description": "Test"}


class TestFullPolicyCompilation:
    """End-to-end tests with realistic policy."""

    def test_realistic_policy(self):
        """Test compilation of a realistic baseline policy."""
        from safeyolo.policy.compiler import compile_policy

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
        assert result["domains"] == {"*.internal": {"bypass": ["pattern_scanner"]}}

    def test_compiled_policy_validates(self):
        """Compiled policy passes Pydantic UnifiedPolicy validation."""
        from safeyolo.policy.compiler import compile_policy
        from safeyolo.policy.engine import UnifiedPolicy

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
        from safeyolo.policy.loader import PolicyLoader

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
        assert len(policy.permissions) == 6  # 2 cred allow + 1 cred prompt + 2 host budget + 1 wildcard budget

        # Check credential routing works
        cred_perms = [p for p in policy.permissions if p.action == "credential:use" and "openai" in str(p.resource)]
        assert len(cred_perms) == 1
        assert cred_perms[0].effect == "allow"

    def test_engine_evaluates_compiled_policy(self, tmp_path):
        """PolicyEngine correctly evaluates a compiled host-centric policy."""
        from safeyolo.policy.engine import PolicyEngine

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

        # Known credential to correct host -> allow
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.openai.com",
            path="/v1/chat/completions",
        )
        assert decision.effect == "allow"

        # Known credential to wrong host -> prompt
        decision = engine.evaluate_credential(
            credential_type="openai",
            destination="api.anthropic.com",
            path="/v1/messages",
        )
        assert decision.effect == "prompt"

        # Unknown credential -> prompt
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
        from safeyolo.policy.engine import PolicyEngine

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


class TestCompileCapabilityRoutes:
    """Tests for capability route -> gateway:request permission compilation."""

    def _make_service_dir(self, tmp_path, service_yaml):
        svc_dir = tmp_path / "services"
        svc_dir.mkdir(exist_ok=True)
        (svc_dir / "minifuse.yaml").write_text(service_yaml)
        # Init registry so compiler can look up services
        import safeyolo.core.service_loader as service_loader
        from safeyolo.core.service_loader import ServiceRegistry

        registry = ServiceRegistry(svc_dir)
        registry.load()
        service_loader._registry = registry
        return svc_dir

    def test_compile_raw_routes_no_contract(self, tmp_path):
        """Capability without contract emits raw routes as gateway:request."""
        from safeyolo.policy.compiler import compile_gateway

        svc_dir = self._make_service_dir(
            tmp_path,
            """
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
""",
        )
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
        assert resources == {"minifuse:/v1/feeds", "minifuse:/v1/entries"}
        assert gw_perms[0]["condition"]["agent"] == "claude"
        assert gw_perms[0]["condition"]["capability"] == "reader"
        assert gw_perms[0]["condition"]["method"] == ["GET"]

    def test_compile_resolved_operations_with_binding(self, tmp_path):
        """Capability with contract + binding resolves operations."""
        from safeyolo.policy.compiler import compile_gateway

        svc_dir = self._make_service_dir(
            tmp_path,
            """
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
""",
        )
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
        # list_feeds: /v1/categories/{id}/feeds -> /v1/categories/137/feeds
        assert "minifuse:/v1/categories/137/feeds" in resources
        # create_feed: /v1/feeds (no path params to resolve)
        assert "minifuse:/v1/feeds" in resources

    def test_skip_unbound_contracted_capability(self, tmp_path):
        """Capability with contract but no binding -> no permissions emitted."""
        from safeyolo.policy.compiler import compile_gateway

        svc_dir = self._make_service_dir(
            tmp_path,
            """
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
""",
        )
        raw = {
            "agents": {
                "claude": {
                    "services": {"minifuse": {"capability": "category_manager", "token": "mf-key"}},
                    # No contract_bindings -> unbound
                },
            },
        }
        permissions = []
        compile_gateway(raw, services_dir=svc_dir, permissions=permissions)

        gw_perms = [p for p in permissions if p["action"] == "gateway:request"]
        assert gw_perms == []

    def test_service_not_found_graceful(self, tmp_path):
        """Unknown service -> warning, no permissions, no crash."""
        from safeyolo.policy.compiler import compile_gateway

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
        """No services_dir -> no-op, no crash."""
        from safeyolo.policy.compiler import compile_gateway

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
        from safeyolo.policy.compiler import compile_policy

        self._make_service_dir(
            tmp_path,
            """
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
""",
        )
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
