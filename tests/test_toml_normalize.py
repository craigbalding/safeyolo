"""Tests for toml_normalize — bidirectional field name mapping.

Each test maps to a specific contract item. Tests state expected outcomes
directly (full-dict equality where possible) — no recomputation of
production logic inside test bodies.
"""

import copy

import pytest


@pytest.fixture
def normalize():
    from safeyolo.policy.toml_normalize import normalize

    return normalize


@pytest.fixture
def denormalize():
    from safeyolo.policy.toml_normalize import denormalize

    return denormalize


# =========================================================================
# normalize() — happy path per contract item
# =========================================================================


class TestNormalizeMetadata:
    def test_version_and_description_move_to_metadata(self, normalize):
        result = normalize({"version": "2.0", "description": "test"})
        assert result == {"metadata": {"version": "2.0", "description": "test"}}

    def test_version_only(self, normalize):
        result = normalize({"version": "2.0"})
        assert result == {"metadata": {"version": "2.0"}}

    def test_description_only(self, normalize):
        result = normalize({"description": "hello"})
        assert result == {"metadata": {"description": "hello"}}

    def test_neither_produces_no_metadata_key(self, normalize):
        result = normalize({"required": []})
        assert "metadata" not in result


class TestNormalizeBudget:
    def test_budget_becomes_global_budget(self, normalize):
        result = normalize({"budget": 12000})
        assert result == {"global_budget": 12000}

    def test_original_budget_key_removed(self, normalize):
        result = normalize({"budget": 12000})
        assert "budget" not in result


class TestNormalizeHosts:
    def test_allow_becomes_credentials(self, normalize):
        result = normalize({"hosts": {"api.openai.com": {"allow": ["openai:*"]}}})
        assert result == {"hosts": {"api.openai.com": {"credentials": ["openai:*"]}}}

    def test_rate_becomes_rate_limit(self, normalize):
        result = normalize({"hosts": {"api.openai.com": {"rate": 3000}}})
        assert result == {"hosts": {"api.openai.com": {"rate_limit": 3000}}}

    def test_unknown_creds_becomes_unknown_credentials(self, normalize):
        result = normalize({"hosts": {"*": {"unknown_creds": "prompt"}}})
        assert result == {"hosts": {"*": {"unknown_credentials": "prompt"}}}

    def test_multiple_renames_same_host(self, normalize):
        result = normalize(
            {"hosts": {"api.openai.com": {"allow": ["openai:*"], "rate": 3000}}}
        )
        assert result == {
            "hosts": {
                "api.openai.com": {
                    "credentials": ["openai:*"],
                    "rate_limit": 3000,
                }
            }
        }

    def test_bypass_passes_through(self, normalize):
        result = normalize({"hosts": {"*.internal": {"bypass": ["pattern_scanner"]}}})
        assert result == {"hosts": {"*.internal": {"bypass": ["pattern_scanner"]}}}

    def test_egress_passes_through(self, normalize):
        result = normalize({"hosts": {"*": {"egress": "prompt"}}})
        assert result == {"hosts": {"*": {"egress": "prompt"}}}

    def test_non_dict_host_config_passes_through(self, normalize):
        result = normalize({"hosts": {"example.com": None}})
        assert result == {"hosts": {"example.com": None}}

    def test_host_with_no_renamable_fields(self, normalize):
        result = normalize({"hosts": {"example.com": {"custom": "value"}}})
        assert result == {"hosts": {"example.com": {"custom": "value"}}}


class TestNormalizeCredentials:
    def test_credential_singular_becomes_credentials_plural(self, normalize):
        result = normalize({"credential": {"openai": {"match": ["sk-..."]}}})
        assert result == {"credentials": {"openai": {"patterns": ["sk-..."]}}}

    def test_other_credential_fields_pass_through(self, normalize):
        result = normalize(
            {
                "credential": {
                    "openai": {"match": ["sk-..."], "headers": ["authorization"]}
                }
            }
        )
        assert result == {
            "credentials": {
                "openai": {"patterns": ["sk-..."], "headers": ["authorization"]}
            }
        }


class TestNormalizeRisk:
    def test_risk_list_becomes_gateway_risk_appetite(self, normalize):
        result = normalize({"risk": [{"decision": "allow"}]})
        assert result == {"gateway": {"risk_appetite": [{"decision": "allow"}]}}


class TestNormalizeAgentHosts:
    def test_agent_host_rename(self, normalize):
        result = normalize(
            {"agents": {"boris": {"hosts": {"api.stripe.com": {"allow": ["stripe:*"], "rate": 600}}}}}
        )
        assert result["agents"]["boris"]["hosts"]["api.stripe.com"] == {
            "credentials": ["stripe:*"],
            "rate_limit": 600,
        }

    def test_agent_without_hosts_section_left_alone(self, normalize):
        result = normalize({"agents": {"boris": {"template": "claude-code"}}})
        assert result["agents"]["boris"] == {"template": "claude-code"}

    def test_non_dict_agent_config_left_alone(self, normalize):
        result = normalize({"agents": {"boris": None}})
        assert result["agents"]["boris"] is None


class TestNormalizePassThrough:
    def test_unknown_keys_copied(self, normalize):
        result = normalize({"required": ["credential_guard"], "custom": "value"})
        assert result == {"required": ["credential_guard"], "custom": "value"}

    def test_empty_input_produces_empty_output(self, normalize):
        assert normalize({}) == {}


# =========================================================================
# normalize() — errors (fail-closed, transparent)
# =========================================================================


class TestNormalizeErrors:
    def test_both_budget_and_global_budget_raises(self, normalize):
        with pytest.raises(ValueError, match="budget.*global_budget"):
            normalize({"budget": 1, "global_budget": 2})

    def test_both_credential_and_credentials_raises(self, normalize):
        with pytest.raises(ValueError, match="credential.*credentials"):
            normalize({"credential": {}, "credentials": {}})

    def test_both_top_level_risk_and_gateway_risk_appetite_raises(self, normalize):
        """top-level risk and gateway.risk_appetite are two reps of the same field."""
        with pytest.raises(ValueError, match="risk.*gateway.risk_appetite"):
            normalize({"risk": [{"decision": "allow"}], "gateway": {"risk_appetite": [{"decision": "deny"}]}})

    def test_top_level_risk_with_gateway_other_fields_ok(self, normalize):
        """gateway dict without risk_appetite can coexist with top-level risk."""
        result = normalize(
            {"risk": [{"decision": "allow"}], "gateway": {"grant_ttl_seconds": 3600}}
        )
        assert result == {
            "gateway": {
                "risk_appetite": [{"decision": "allow"}],
                "grant_ttl_seconds": 3600,
            }
        }

    def test_non_dict_hosts_raises(self, normalize):
        with pytest.raises(ValueError, match="hosts"):
            normalize({"hosts": "not a dict"})

    def test_non_dict_credential_raises(self, normalize):
        with pytest.raises(ValueError, match="credential"):
            normalize({"credential": "not a dict"})

    def test_non_dict_agents_raises(self, normalize):
        with pytest.raises(ValueError, match="agents"):
            normalize({"agents": "not a dict"})

    def test_non_list_risk_raises(self, normalize):
        with pytest.raises(ValueError, match="risk"):
            normalize({"risk": "not a list"})


# =========================================================================
# normalize() — input immutability (fail-closed purity promise)
# =========================================================================


class TestNormalizeInputImmutability:
    def test_normalize_does_not_mutate_input(self, normalize):
        input_doc = {
            "version": "2.0",
            "budget": 12000,
            "hosts": {"api.openai.com": {"allow": ["openai:*"], "rate": 3000}},
            "credential": {"openai": {"match": ["sk-..."]}},
            "risk": [{"decision": "allow"}],
            "agents": {"boris": {"hosts": {"api.stripe.com": {"allow": ["stripe:*"]}}}},
            "required": ["credential_guard"],
        }
        snapshot = copy.deepcopy(input_doc)
        normalize(input_doc)
        assert input_doc == snapshot

    def test_mutating_output_host_value_does_not_affect_input(self, normalize):
        input_doc = {"hosts": {"api.openai.com": {"allow": ["openai:*"]}}}
        result = normalize(input_doc)
        result["hosts"]["api.openai.com"]["credentials"].append("another:*")
        assert input_doc["hosts"]["api.openai.com"]["allow"] == ["openai:*"]

    def test_mutating_output_agent_host_does_not_affect_input(self, normalize):
        input_doc = {
            "agents": {
                "boris": {"hosts": {"api.stripe.com": {"allow": ["stripe:*"]}}}
            }
        }
        result = normalize(input_doc)
        result["agents"]["boris"]["hosts"]["api.stripe.com"]["credentials"] = ["changed"]
        assert input_doc["agents"]["boris"]["hosts"]["api.stripe.com"]["allow"] == [
            "stripe:*"
        ]


# =========================================================================
# denormalize() — happy path per contract item
# =========================================================================


class TestDenormalizeMetadata:
    def test_metadata_version_to_top_level(self, denormalize):
        result = denormalize({"metadata": {"version": "2.0"}})
        assert result == {"version": "2.0"}

    def test_metadata_description_to_top_level(self, denormalize):
        result = denormalize({"metadata": {"description": "hello"}})
        assert result == {"description": "hello"}

    def test_metadata_both_fields(self, denormalize):
        result = denormalize({"metadata": {"version": "2.0", "description": "hello"}})
        assert result == {"version": "2.0", "description": "hello"}


class TestDenormalizeBudget:
    def test_global_budget_to_budget(self, denormalize):
        result = denormalize({"global_budget": 12000})
        assert result == {"budget": 12000}


class TestDenormalizeHosts:
    def test_credentials_to_allow(self, denormalize):
        result = denormalize({"hosts": {"x.com": {"credentials": ["openai:*"]}}})
        assert result == {"hosts": {"x.com": {"allow": ["openai:*"]}}}

    def test_rate_limit_to_rate(self, denormalize):
        result = denormalize({"hosts": {"x.com": {"rate_limit": 100}}})
        assert result == {"hosts": {"x.com": {"rate": 100}}}

    def test_unknown_credentials_to_unknown_creds(self, denormalize):
        result = denormalize({"hosts": {"*": {"unknown_credentials": "prompt"}}})
        assert result == {"hosts": {"*": {"unknown_creds": "prompt"}}}

    def test_non_dict_host_config_passes_through(self, denormalize):
        result = denormalize({"hosts": {"x.com": None}})
        assert result == {"hosts": {"x.com": None}}


class TestDenormalizeCredentials:
    def test_credentials_to_credential(self, denormalize):
        result = denormalize({"credentials": {"openai": {"patterns": ["sk-..."]}}})
        assert result == {"credential": {"openai": {"match": ["sk-..."]}}}


class TestDenormalizeGateway:
    def test_risk_appetite_to_top_level_risk(self, denormalize):
        result = denormalize({"gateway": {"risk_appetite": [{"decision": "allow"}]}})
        assert result == {"risk": [{"decision": "allow"}]}

    def test_gateway_extra_fields_preserved(self, denormalize):
        """Non-risk_appetite fields in gateway must survive denormalize."""
        result = denormalize(
            {
                "gateway": {
                    "risk_appetite": [{"decision": "allow"}],
                    "grant_ttl_seconds": 3600,
                }
            }
        )
        assert result == {
            "risk": [{"decision": "allow"}],
            "gateway": {"grant_ttl_seconds": 3600},
        }

    def test_gateway_without_risk_appetite_preserved(self, denormalize):
        result = denormalize({"gateway": {"grant_ttl_seconds": 3600}})
        assert result == {"gateway": {"grant_ttl_seconds": 3600}}


class TestDenormalizeAgentHosts:
    def test_agent_host_rename(self, denormalize):
        result = denormalize(
            {"agents": {"boris": {"hosts": {"api.stripe.com": {"credentials": ["stripe:*"]}}}}}
        )
        assert result["agents"]["boris"]["hosts"]["api.stripe.com"] == {
            "allow": ["stripe:*"]
        }


class TestDenormalizePassThrough:
    def test_unknown_keys_copied(self, denormalize):
        result = denormalize({"required": ["x"], "custom": "val"})
        assert result == {"required": ["x"], "custom": "val"}

    def test_empty_input(self, denormalize):
        assert denormalize({}) == {}


# =========================================================================
# denormalize() — errors (fail-closed, transparent)
# =========================================================================


class TestDenormalizeErrors:
    def test_both_global_budget_and_budget_raises(self, denormalize):
        with pytest.raises(ValueError, match="global_budget.*budget"):
            denormalize({"global_budget": 1, "budget": 2})

    def test_both_credentials_and_credential_raises(self, denormalize):
        with pytest.raises(ValueError, match="credentials.*credential"):
            denormalize({"credentials": {}, "credential": {}})

    def test_non_dict_metadata_raises(self, denormalize):
        with pytest.raises(ValueError, match="metadata"):
            denormalize({"metadata": "not a dict"})

    def test_non_dict_hosts_raises(self, denormalize):
        with pytest.raises(ValueError, match="hosts"):
            denormalize({"hosts": "not a dict"})

    def test_non_dict_credentials_raises(self, denormalize):
        with pytest.raises(ValueError, match="credentials"):
            denormalize({"credentials": "not a dict"})

    def test_non_dict_agents_raises(self, denormalize):
        with pytest.raises(ValueError, match="agents"):
            denormalize({"agents": "not a dict"})

    def test_non_dict_gateway_raises(self, denormalize):
        with pytest.raises(ValueError, match="gateway"):
            denormalize({"gateway": "not a dict"})


# =========================================================================
# denormalize() — input immutability
# =========================================================================


class TestDenormalizeInputImmutability:
    def test_denormalize_does_not_mutate_input(self, denormalize):
        input_doc = {
            "metadata": {"version": "2.0"},
            "global_budget": 12000,
            "hosts": {"api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000}},
            "credentials": {"openai": {"patterns": ["sk-..."]}},
            "gateway": {"risk_appetite": [{"decision": "allow"}], "grant_ttl_seconds": 3600},
            "agents": {
                "boris": {"hosts": {"api.stripe.com": {"credentials": ["stripe:*"]}}}
            },
            "required": ["credential_guard"],
        }
        snapshot = copy.deepcopy(input_doc)
        denormalize(input_doc)
        assert input_doc == snapshot

    def test_mutating_output_does_not_affect_input(self, denormalize):
        input_doc = {"hosts": {"x.com": {"credentials": ["openai:*"]}}}
        result = denormalize(input_doc)
        result["hosts"]["x.com"]["allow"].append("another:*")
        assert input_doc["hosts"]["x.com"]["credentials"] == ["openai:*"]


# =========================================================================
# Round-trip (full equality)
# =========================================================================


class TestRoundTrip:
    def test_minimal_toml_roundtrip(self, normalize, denormalize):
        """A minimal TOML doc round-trips to itself exactly."""
        toml = {"version": "2.0", "budget": 12000}
        assert denormalize(normalize(toml)) == toml

    def test_full_toml_roundtrip(self, normalize, denormalize):
        """A full TOML policy round-trips to itself exactly."""
        toml = {
            "version": "2.0",
            "description": "test policy",
            "budget": 12000,
            "required": ["credential_guard"],
            "hosts": {
                "api.openai.com": {"allow": ["openai:*"], "rate": 3000},
                "*.internal": {"bypass": ["pattern_scanner"]},
                "*": {"unknown_creds": "prompt", "rate": 600},
            },
            "credential": {
                "openai": {"match": ["sk-..."], "headers": ["authorization"]},
            },
            "risk": [
                {"account": "agent", "tactics": ["collection"], "decision": "allow"}
            ],
        }
        assert denormalize(normalize(toml)) == toml

    def test_minimal_internal_roundtrip(self, normalize, denormalize):
        """A minimal internal doc round-trips to itself exactly."""
        internal = {"metadata": {"version": "2.0"}, "global_budget": 12000}
        assert normalize(denormalize(internal)) == internal

    def test_gateway_with_extra_fields_roundtrip(self, normalize, denormalize):
        """denormalize(normalize(...)) must preserve gateway.* fields beyond risk_appetite.

        This test locks in bug B3's fix — the pre-fix denormalize silently
        dropped every non-risk_appetite gateway field via the skip list.
        """
        internal = {
            "gateway": {
                "risk_appetite": [{"decision": "allow"}],
                "grant_ttl_seconds": 3600,
            }
        }
        back = normalize(denormalize(internal))
        assert back == internal
