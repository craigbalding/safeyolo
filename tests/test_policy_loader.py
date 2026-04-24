"""
Tests for policy_loader.py - Policy file loading, hot reload, and permission indexing.

Contract:
  - specificity_score: wildcard '*' scores 0, longer patterns score higher,
    wildcards reduce score, conditions add 5 as tiebreaker
  - _is_exact_resource: matches 'host/*' but not '*.glob/*', 'svc:path/*', deep paths, bare host
  - _is_simple_permission: explicit tier, no condition, non-budget effect
  - _build_permission_index: partitions into simple_sets / exact_dict / pattern_list
  - PolicyLoader loads YAML, JSON, and TOML (the primary production format)
  - Host-centric TOML is compiled, simple permissions are pre-extracted into sets
  - set_baseline re-merges pre-extracted simple permissions (B1 fix)
  - Expired hosts are pruned; malformed expires warns and keeps host (B2/B4 fix)
  - addons.yaml is merged as defaults (policy.yaml wins on conflict)
  - Task policy extends baseline; clear removes it
  - get_merged_index: task entries override baseline for exact/patterns, union for simple_sets
  - Reload failure preserves the previous baseline (fail-closed)
  - File watcher detects changes and auto-reloads
  - Audit events are emitted on success and failure
"""

import json
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

# ---------------------------------------------------------------------------
# Specificity score
# ---------------------------------------------------------------------------

class TestSpecificityScore:
    """Tests for _specificity_score: ordering heuristic for permission matching."""

    def test_wildcard_only_scores_zero(self):
        from safeyolo.policy.loader import _specificity_score

        assert _specificity_score("*") == 0

    def test_exact_host_scores_by_length(self):
        from safeyolo.policy.loader import _specificity_score

        # "api.example.com" = 15 chars * 10 = 150
        assert _specificity_score("api.example.com") == 150

    def test_longer_pattern_scores_higher_than_shorter(self):
        from safeyolo.policy.loader import _specificity_score

        assert _specificity_score("api.example.com") > _specificity_score("api.com")

    def test_single_wildcard_reduces_score(self):
        from safeyolo.policy.loader import _specificity_score

        # "*.example.com" has a wildcard, "api.example.com" does not
        exact = _specificity_score("api.example.com")
        glob = _specificity_score("*.example.com")
        assert exact > glob

    def test_more_wildcards_reduce_score_further(self):
        from safeyolo.policy.loader import _specificity_score

        one_wild = _specificity_score("*.example.com")
        two_wild = _specificity_score("*.*")
        assert one_wild > two_wild

    def test_condition_adds_five_point_tiebreaker(self):
        from safeyolo.policy.loader import _specificity_score

        without = _specificity_score("api.example.com", has_condition=False)
        with_cond = _specificity_score("api.example.com", has_condition=True)
        assert with_cond == without + 5


# ---------------------------------------------------------------------------
# Permission indexing helpers
# ---------------------------------------------------------------------------

class TestIsExactResource:
    """Tests for _is_exact_resource: identifies 'host/*' patterns for O(1) lookup."""

    def test_simple_host_slash_star(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("api.openai.com/*") is True

    def test_wildcard_host_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("*.googleapis.com/*") is False

    def test_bare_wildcard_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("*") is False

    def test_no_trailing_slash_star_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("api.openai.com") is False

    def test_service_colon_path_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("minifuse:/v1/feeds/*") is False

    def test_deep_path_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("api.example.com/v1/*") is False

    def test_question_mark_in_host_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("api?.example.com/*") is False

    def test_bracket_glob_in_host_is_not_exact(self):
        from safeyolo.policy.loader import _is_exact_resource

        assert _is_exact_resource("[abc].example.com/*") is False


class TestIsSimplePermission:
    """Tests for _is_simple_permission: identifies permissions reducible to set entries."""

    def test_explicit_allow_no_condition(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _is_simple_permission

        perm = Permission(action="network:request", resource="api.example.com/*", effect="allow", tier="explicit")
        assert _is_simple_permission(perm) is True

    def test_explicit_deny_no_condition(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _is_simple_permission

        perm = Permission(action="network:request", resource="evil.com/*", effect="deny", tier="explicit")
        assert _is_simple_permission(perm) is True

    def test_budget_effect_is_not_simple(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _is_simple_permission

        perm = Permission(action="network:request", resource="api.example.com/*", effect="budget", budget=3000, tier="explicit")
        assert _is_simple_permission(perm) is False

    def test_with_condition_is_not_simple(self):
        from safeyolo.policy.engine import Condition, Permission
        from safeyolo.policy.loader import _is_simple_permission

        perm = Permission(
            action="credential:use",
            resource="api.openai.com/*",
            effect="allow",
            tier="explicit",
            condition=Condition(credential=["openai:*"]),
        )
        assert _is_simple_permission(perm) is False

    def test_inferred_tier_is_not_simple(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _is_simple_permission

        perm = Permission(action="network:request", resource="api.example.com/*", effect="allow", tier="inferred")
        assert _is_simple_permission(perm) is False


class TestBuildPermissionIndex:
    """Tests for _build_permission_index: partitions permissions into three tiers."""

    def test_simple_allow_goes_to_simple_sets(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _build_permission_index

        perm = Permission(action="network:request", resource="api.example.com/*", effect="allow", tier="explicit")
        simple, exact, patterns = _build_permission_index([perm])

        assert simple == {("network:request", "allow"): {"api.example.com/*"}}
        assert exact == {}
        assert patterns == []

    def test_conditioned_exact_goes_to_exact_dict(self):
        from safeyolo.policy.engine import Condition, Permission
        from safeyolo.policy.loader import _build_permission_index

        perm = Permission(
            action="credential:use",
            resource="api.openai.com/*",
            effect="allow",
            tier="explicit",
            condition=Condition(credential=["openai:*"]),
        )
        simple, exact, patterns = _build_permission_index([perm])

        assert simple == {}
        assert ("credential:use", "api.openai.com/*") in exact
        assert len(exact[("credential:use", "api.openai.com/*")]) == 1
        assert patterns == []

    def test_wildcard_resource_goes_to_patterns(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _build_permission_index

        perm = Permission(action="network:request", resource="*.example.com/*", effect="allow", tier="explicit")
        simple, exact, patterns = _build_permission_index([perm])

        assert simple == {}
        assert exact == {}
        assert len(patterns) == 1
        assert patterns[0].resource == "*.example.com/*"

    def test_budget_exact_goes_to_exact_dict(self):
        from safeyolo.policy.engine import Permission
        from safeyolo.policy.loader import _build_permission_index

        perm = Permission(action="network:request", resource="api.openai.com/*", effect="budget", budget=3000, tier="explicit")
        simple, exact, patterns = _build_permission_index([perm])

        assert simple == {}
        assert ("network:request", "api.openai.com/*") in exact
        assert patterns == []

    def test_mixed_permissions_are_partitioned_correctly(self):
        from safeyolo.policy.engine import Condition, Permission
        from safeyolo.policy.loader import _build_permission_index

        perms = [
            Permission(action="network:request", resource="evil.com/*", effect="deny", tier="explicit"),
            Permission(action="credential:use", resource="api.openai.com/*", effect="allow", condition=Condition(credential=["openai:*"])),
            Permission(action="network:request", resource="*", effect="deny"),
        ]
        simple, exact, patterns = _build_permission_index(perms)

        assert simple == {("network:request", "deny"): {"evil.com/*"}}
        assert ("credential:use", "api.openai.com/*") in exact
        assert len(patterns) == 1
        assert patterns[0].resource == "*"


# ---------------------------------------------------------------------------
# PolicyLoader basics
# ---------------------------------------------------------------------------

class TestPolicyLoaderConstruction:
    """Tests for PolicyLoader construction and empty-state properties."""

    def test_no_path_creates_empty_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        assert len(loader.baseline.permissions) == 0

    def test_task_policy_initially_none(self):
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        assert loader.task_policy is None

    def test_task_policy_path_initially_none(self):
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        assert loader.task_policy_path is None

    def test_baseline_path_property_reflects_init(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")
            loader = PolicyLoader(baseline_path=path)
            assert loader.baseline_path == path

    def test_baseline_path_none_when_no_path(self):
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        assert loader.baseline_path is None


# ---------------------------------------------------------------------------
# File loading: YAML, JSON, TOML
# ---------------------------------------------------------------------------

class TestYAMLLoading:
    """Tests for YAML file loading."""

    def test_loads_yaml_with_permissions(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].resource == "api.example.com/*"
            assert loader.baseline.permissions[0].effect == "allow"

    def test_loads_empty_yaml(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 0

    def test_loads_yml_extension(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1


class TestJSONLoading:
    """Tests for JSON file loading."""

    def test_loads_json_policy(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "baseline.json"
            path.write_text(json.dumps({
                "permissions": [
                    {"action": "network:request", "resource": "api.example.com/*", "effect": "allow"}
                ]
            }))
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].resource == "api.example.com/*"


class TestTOMLLoading:
    """Tests for TOML file loading -- the PRIMARY production format."""

    def test_loads_host_centric_toml(self):
        """TOML with hosts section is compiled into IAM permissions.

        Hosts with rate= get network:request budget (not simple allow).
        Hosts with allow= get credential:use with condition (exact_dict).
        Only egress=deny hosts land in simple_sets.
        """
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text("""
version = "2.0"

[hosts]
"api.openai.com" = { allow = ["openai:*"], rate = 3000 }
"evil.com" = { egress = "deny" }
"*" = { egress = "allow", unknown_creds = "prompt", rate = 600 }
""")
            loader = PolicyLoader(baseline_path=path)

            # Should have compiled permissions
            assert len(loader.baseline.permissions) > 0

            # Hosts with rate compile to budget (exact_dict), not simple allow.
            # credential:use with condition goes to exact_dict.
            assert ("credential:use", "api.openai.com/*") in loader._baseline_exact

            # Only egress=deny produces simple entries
            assert ("network:request", "deny") in loader._baseline_simple
            assert "evil.com/*" in loader._baseline_simple[("network:request", "deny")]

    def test_toml_host_deny_entries_in_simple_sets(self):
        """Host deny entries (e.g. from blocklists) go into simple_sets for O(1) lookup."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text("""
version = "2.0"

[hosts]
"evil.com" = { egress = "deny" }
"malware.net" = { egress = "deny" }
"*" = { egress = "allow", rate = 600 }
""")
            loader = PolicyLoader(baseline_path=path)

            simple = loader._baseline_simple
            deny_key = ("network:request", "deny")
            assert deny_key in simple
            assert "evil.com/*" in simple[deny_key]
            assert "malware.net/*" in simple[deny_key]

    def test_toml_metadata_preserved(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text("""
version = "2.0"
description = "Test policy"

[hosts]
"*" = { egress = "allow", rate = 600 }
""")
            loader = PolicyLoader(baseline_path=path)
            assert loader.baseline.metadata.version == "2.0"
            assert loader.baseline.metadata.description == "Test policy"


# ---------------------------------------------------------------------------
# set_baseline preserves pre-extracted simple permissions (B1 fix)
# ---------------------------------------------------------------------------

class TestSetBaselinePreservesSimplePermissions:
    """B1 fix: set_baseline() must re-merge pre-extracted simple permissions."""

    def test_set_baseline_preserves_blocklist_denies(self):
        """After set_baseline with a modified policy, the bulk deny entries
        from the original TOML load must still be present."""
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text("""
version = "2.0"

[hosts]
"evil.com" = { egress = "deny" }
"malware.net" = { egress = "deny" }
"*" = { egress = "allow", rate = 600 }
""")
            loader = PolicyLoader(baseline_path=path)

            # Verify deny entries exist after initial load
            deny_key = ("network:request", "deny")
            assert deny_key in loader._baseline_simple
            assert "evil.com/*" in loader._baseline_simple[deny_key]
            assert "malware.net/*" in loader._baseline_simple[deny_key]

            # Now simulate an incremental mutation (e.g., approve_credential)
            # by calling set_baseline with a modified policy that only has
            # the non-simple permissions (as would happen in production).
            new_policy = UnifiedPolicy(permissions=[
                Permission(action="network:request", resource="new-host.com/*", effect="allow"),
            ])
            loader.set_baseline(new_policy)

            # The pre-extracted deny entries must survive the set_baseline
            assert deny_key in loader._baseline_simple
            assert "evil.com/*" in loader._baseline_simple[deny_key]
            assert "malware.net/*" in loader._baseline_simple[deny_key]

            # The new permission should also be indexed
            allow_key = ("network:request", "allow")
            assert allow_key in loader._baseline_simple
            assert "new-host.com/*" in loader._baseline_simple[allow_key]

    def test_set_baseline_without_prior_load_works(self):
        """set_baseline on a fresh loader (no _pre_extracted_simple) must not error."""
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        policy = UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="api.example.com/*", effect="allow"),
        ])
        loader.set_baseline(policy)

        assert ("network:request", "allow") in loader._baseline_simple
        assert "api.example.com/*" in loader._baseline_simple[("network:request", "allow")]


# ---------------------------------------------------------------------------
# Expired host pruning
# ---------------------------------------------------------------------------

class TestExpiredHostPruning:
    """Tests for _prune_expired_hosts: removes time-limited host entries."""

    def test_expired_host_is_removed(self):
        """An expired deny entry should be pruned and not appear in the index."""
        from safeyolo.policy.loader import PolicyLoader

        yesterday = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(f"""
version = "2.0"

[hosts]
"temp.example.com" = {{ egress = "deny", expires = "{yesterday}" }}
"permanent.example.com" = {{ egress = "deny" }}
"*" = {{ egress = "allow", rate = 600 }}
""")
            loader = PolicyLoader(baseline_path=path)

            deny_key = ("network:request", "deny")
            deny_set = loader._baseline_simple.get(deny_key, set())
            # permanent should survive; temp should be pruned
            assert "permanent.example.com/*" in deny_set
            assert "temp.example.com/*" not in deny_set

    def test_non_expired_host_is_preserved(self):
        """A deny entry whose expires is in the future should remain."""
        from safeyolo.policy.loader import PolicyLoader

        tomorrow = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(f"""
version = "2.0"

[hosts]
"temp.example.com" = {{ egress = "deny", expires = "{tomorrow}" }}
"*" = {{ egress = "allow", rate = 600 }}
""")
            loader = PolicyLoader(baseline_path=path)

            deny_key = ("network:request", "deny")
            deny_set = loader._baseline_simple.get(deny_key, set())
            assert "temp.example.com/*" in deny_set

    def test_unparseable_expires_string_warns_and_keeps_host(self, caplog):
        """B2 fix: malformed expires string logs warning naming the host."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
hosts:
  bad-date.example.com:
    egress: deny
    expires: "next tuesday"
  "*":
    egress: allow
    rate_limit: 600
""")
            with caplog.at_level("WARNING", logger="safeyolo.policy-loader"):
                loader = PolicyLoader(baseline_path=path)

            # Host should be kept (not pruned) -- it's a deny, so it's in simple_sets
            deny_key = ("network:request", "deny")
            deny_set = loader._baseline_simple.get(deny_key, set())
            assert "bad-date.example.com/*" in deny_set

            # Warning should mention the host name
            assert any("bad-date.example.com" in r.message for r in caplog.records)
            assert any("unparseable" in r.message.lower() for r in caplog.records)

    def test_non_datetime_expires_warns_and_keeps_host(self, caplog):
        """B4 fix: non-string non-datetime expires (e.g. integer) logs warning."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            # Use JSON since YAML/TOML would parse 20260405 as an integer.
            # Use egress=deny so the host lands in simple_sets for assertion.
            path = Path(tmpdir) / "baseline.json"
            path.write_text(json.dumps({
                "hosts": {
                    "int-expires.example.com": {"egress": "deny", "expires": 20260405},
                    "*": {"egress": "allow", "rate_limit": 600},
                }
            }))
            with caplog.at_level("WARNING", logger="safeyolo.policy-loader"):
                loader = PolicyLoader(baseline_path=path)

            # Host should be kept (not pruned)
            deny_key = ("network:request", "deny")
            deny_set = loader._baseline_simple.get(deny_key, set())
            assert "int-expires.example.com/*" in deny_set

            # Warning should mention the type
            assert any("int" in r.message for r in caplog.records)

    def test_host_without_expires_is_not_pruned(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text("""
version = "2.0"

[hosts]
"permanent.example.com" = { egress = "deny" }
"*" = { egress = "allow", rate = 600 }
""")
            loader = PolicyLoader(baseline_path=path)

            deny_key = ("network:request", "deny")
            deny_set = loader._baseline_simple.get(deny_key, set())
            assert "permanent.example.com/*" in deny_set

    def test_expired_host_removed_from_toml_on_disk(self):
        """Pruned hosts should also be removed from the TOML file."""
        import tomlkit

        from safeyolo.policy.loader import PolicyLoader

        yesterday = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(f"""
version = "2.0"

[hosts]
"temp.example.com" = {{ egress = "deny", expires = "{yesterday}" }}
"permanent.example.com" = {{ egress = "deny" }}
"*" = {{ egress = "allow", rate = 600 }}
""")
            PolicyLoader(baseline_path=path)

            # Read back the TOML and verify temp.example.com is gone
            doc = tomlkit.parse(path.read_text())
            hosts = doc.get("hosts", {})
            assert "temp.example.com" not in hosts
            assert "permanent.example.com" in hosts


# ---------------------------------------------------------------------------
# Addons.yaml merging
# ---------------------------------------------------------------------------

class TestAddonsMerging:
    """Tests for _merge_addons: sibling addons.yaml merges as defaults."""

    def test_addons_yaml_provides_defaults(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")
            addons_path = Path(tmpdir) / "addons.yaml"
            addons_path.write_text("""
required:
  - credential_guard
  - network_guard
""")
            loader = PolicyLoader(baseline_path=policy_path)

            # required should come from addons.yaml
            assert "credential_guard" in loader.baseline.required
            assert "network_guard" in loader.baseline.required

    def test_policy_yaml_overrides_addons_yaml(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text("""
permissions: []
required:
  - custom_addon
""")
            addons_path = Path(tmpdir) / "addons.yaml"
            addons_path.write_text("""
required:
  - credential_guard
""")
            loader = PolicyLoader(baseline_path=policy_path)

            # policy.yaml's required should win (not replaced by addons.yaml)
            assert loader.baseline.required == ["custom_addon"]

    def test_addons_section_deep_merged(self):
        """The 'addons' key gets deep-merged: addons.yaml provides defaults,
        policy.yaml keys override."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text("""
permissions: []
addons:
  credential_guard:
    enabled: false
""")
            addons_path = Path(tmpdir) / "addons.yaml"
            addons_path.write_text("""
addons:
  credential_guard:
    enabled: true
  network_guard:
    enabled: true
""")
            loader = PolicyLoader(baseline_path=policy_path)

            # credential_guard.enabled should come from policy (false, not true)
            assert loader.baseline.addons["credential_guard"].enabled is False
            # network_guard should come from addons.yaml
            assert loader.baseline.addons["network_guard"].enabled is True

    def test_no_addons_yaml_is_fine(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text("permissions: []")
            # No addons.yaml

            loader = PolicyLoader(baseline_path=policy_path)
            assert len(loader.baseline.permissions) == 0


# ---------------------------------------------------------------------------
# Task policy management
# ---------------------------------------------------------------------------

class TestTaskPolicy:
    """Tests for task policy loading, clearing, and path tracking."""

    def test_loads_task_policy(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "policy.yaml"
            baseline.write_text("permissions: []")
            task = Path(tmpdir) / "task.yaml"
            task.write_text("""
permissions:
  - action: "credential:use"
    resource: "openai:*"
    effect: allow
""")
            loader = PolicyLoader(baseline_path=baseline)
            result = loader.load_task_policy(task)

            assert result is True
            assert loader.task_policy is not None
            assert len(loader.task_policy.permissions) == 1
            assert loader.task_policy.permissions[0].action == "credential:use"

    def test_task_policy_path_tracked(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "policy.yaml"
            baseline.write_text("permissions: []")
            task = Path(tmpdir) / "task.yaml"
            task.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            assert loader.task_policy_path is None

            loader.load_task_policy(task)
            assert loader.task_policy_path == task

    def test_clear_task_policy(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "policy.yaml"
            baseline.write_text("permissions: []")
            task = Path(tmpdir) / "task.yaml"
            task.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            loader.load_task_policy(task)
            assert loader.task_policy is not None

            loader.clear_task_policy()
            assert loader.task_policy is None
            assert loader.task_policy_path is None

    def test_task_policy_failure_returns_false(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "policy.yaml"
            baseline.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            result = loader.load_task_policy(Path("/nonexistent/task.yaml"))
            assert result is False
            assert loader.task_policy is None

    def test_set_task_policy_directly(self):
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        policy = UnifiedPolicy(permissions=[
            Permission(action="credential:use", resource="openai:*", effect="allow"),
        ])
        loader.set_task_policy(policy)

        assert loader.task_policy is not None
        assert len(loader.task_policy.permissions) == 1


# ---------------------------------------------------------------------------
# Permission sorting
# ---------------------------------------------------------------------------

class TestPermissionSorting:
    """Tests that permissions are sorted most-specific first."""

    def test_most_specific_permission_first(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "*"
    effect: deny
  - action: "network:request"
    resource: "*.example.com/*"
    effect: allow
  - action: "network:request"
    resource: "api.example.com/v1/*"
    effect: allow
""")
            loader = PolicyLoader(baseline_path=path)

            resources = [p.resource for p in loader.baseline.permissions]
            assert resources[0] == "api.example.com/v1/*"
            assert resources[1] == "*.example.com/*"
            assert resources[2] == "*"


# ---------------------------------------------------------------------------
# Merged index semantics
# ---------------------------------------------------------------------------

class TestMergedIndex:
    """Tests for get_merged_index: merging task + baseline permission indexes."""

    def test_no_task_returns_baseline_directly(self):
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        loader.set_baseline(UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="api.example.com/*", effect="allow"),
        ]))

        simple, exact, patterns = loader.get_merged_index()

        assert ("network:request", "allow") in simple
        assert "api.example.com/*" in simple[("network:request", "allow")]

    def test_simple_sets_are_unioned(self):
        """Both baseline and task deny entries must appear in merged simple_sets."""
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        loader.set_baseline(UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="evil.com/*", effect="deny"),
        ]))
        loader.set_task_policy(UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="malware.net/*", effect="deny"),
        ]))

        simple, _, _ = loader.get_merged_index()
        deny_set = simple[("network:request", "deny")]
        assert "evil.com/*" in deny_set
        assert "malware.net/*" in deny_set

    def test_exact_dict_task_overrides_baseline(self):
        """For exact dict entries, task takes priority over baseline."""
        from safeyolo.policy.engine import Condition, Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        baseline_perm = Permission(
            action="credential:use",
            resource="api.openai.com/*",
            effect="allow",
            condition=Condition(credential=["openai:*"]),
        )
        task_perm = Permission(
            action="credential:use",
            resource="api.openai.com/*",
            effect="deny",
            condition=Condition(credential=["openai:*"]),
        )

        loader = PolicyLoader()
        loader.set_baseline(UnifiedPolicy(permissions=[baseline_perm]))
        loader.set_task_policy(UnifiedPolicy(permissions=[task_perm]))

        _, exact, _ = loader.get_merged_index()
        key = ("credential:use", "api.openai.com/*")
        assert key in exact
        # Task permission should replace baseline for this key
        assert len(exact[key]) == 1
        assert exact[key][0].effect == "deny"

    def test_patterns_task_before_baseline(self):
        """Pattern list: task patterns come first (higher priority)."""
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        baseline_perm = Permission(action="network:request", resource="*.example.com/*", effect="allow")
        task_perm = Permission(action="network:request", resource="*.taskdomain.com/*", effect="deny")

        loader = PolicyLoader()
        loader.set_baseline(UnifiedPolicy(permissions=[baseline_perm]))
        loader.set_task_policy(UnifiedPolicy(permissions=[task_perm]))

        _, _, patterns = loader.get_merged_index()
        pattern_resources = [p.resource for p in patterns]
        assert pattern_resources == ["*.taskdomain.com/*", "*.example.com/*"]


# ---------------------------------------------------------------------------
# Reload and fail-closed
# ---------------------------------------------------------------------------

class TestReload:
    """Tests for reload() and fail-closed semantics."""

    def test_reload_picks_up_file_changes(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 0

            path.write_text("""
permissions:
  - action: "network:request"
    resource: "new.example.com/*"
    effect: allow
""")
            result = loader.reload()
            assert result is True
            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].resource == "new.example.com/*"

    def test_reload_failure_preserves_previous_baseline(self):
        """Fail-closed: if reload fails, the old baseline stays active."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1

            # Corrupt the file
            path.write_text("permissions:\n  - invalid_field: oops")

            result = loader.reload()
            assert result is False
            # Previous baseline preserved
            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].resource == "api.example.com/*"

    def test_reload_deleted_file_preserves_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "keep-me.example.com/*"
    effect: allow
""")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 1

            path.unlink()
            result = loader.reload()
            assert result is False
            # Previous baseline preserved
            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].resource == "keep-me.example.com/*"

    def test_reload_reloads_both_baseline_and_task(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "policy.yaml"
            baseline.write_text("permissions: []")
            task = Path(tmpdir) / "task.yaml"
            task.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=baseline)
            loader.load_task_policy(task)

            baseline.write_text("""
permissions:
  - action: "network:request"
    resource: "new.example.com/*"
    effect: allow
""")
            task.write_text("""
permissions:
  - action: "credential:use"
    resource: "openai:*"
    effect: allow
""")
            result = loader.reload()
            assert result is True
            assert len(loader.baseline.permissions) == 1
            assert len(loader.task_policy.permissions) == 1


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

class TestReloadCallbacks:
    """Tests for on_reload and add_reload_callback."""

    def test_on_reload_called_on_initial_load(self):
        from safeyolo.policy.loader import PolicyLoader

        callback = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")
            PolicyLoader(baseline_path=path, on_reload=callback)

        assert callback.call_count == 1

    def test_add_reload_callback_called_on_reload(self):
        from safeyolo.policy.loader import PolicyLoader

        callback = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")
            loader = PolicyLoader(baseline_path=path)

            loader.add_reload_callback(callback)
            loader.reload()

        assert callback.call_count == 1

    def test_callback_exception_does_not_break_load(self):
        from safeyolo.policy.loader import PolicyLoader

        def bad_callback():
            raise RuntimeError("callback exploded")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")
            # Should not raise even though callback throws
            loader = PolicyLoader(baseline_path=path, on_reload=bad_callback)
            assert len(loader.baseline.permissions) == 0


# ---------------------------------------------------------------------------
# File watcher
# ---------------------------------------------------------------------------

class TestFileWatcher:
    """Tests for start_watcher / stop_watcher."""

    def test_start_creates_running_thread_stop_terminates_it(self):
        """Observable behaviour: after start, watcher detects changes.
        After stop, internal thread is cleaned up."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            loader.start_watcher()

            # Watcher thread should be alive
            assert loader._watcher_thread is not None
            assert loader._watcher_thread.is_alive()

            loader.stop_watcher()
            assert loader._watcher_thread is None

    def test_double_start_is_idempotent(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            loader.start_watcher()
            thread1 = loader._watcher_thread

            # Second start should be a no-op
            loader.start_watcher()
            assert loader._watcher_thread is thread1

            loader.stop_watcher()

    def test_watcher_detects_baseline_change(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            loader.start_watcher()

            assert len(loader.baseline.permissions) == 0

            # Modify file with enough mtime gap
            time.sleep(0.1)
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "api.example.com/*"
    effect: allow
""")

            # Wait for watcher to detect (poll interval is 2s)
            time.sleep(2.5)
            loader.stop_watcher()

            assert len(loader.baseline.permissions) == 1
            assert loader.baseline.permissions[0].resource == "api.example.com/*"

    def test_watcher_handles_disappearing_file(self):
        """Watcher should not crash if the file is deleted."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")

            loader = PolicyLoader(baseline_path=path)
            loader.start_watcher()

            path.unlink()
            time.sleep(2.5)

            # Should not have crashed
            loader.stop_watcher()
            assert loader.baseline is not None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for graceful error handling on bad inputs."""

    def test_missing_file_creates_empty_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader(baseline_path=Path("/nonexistent/policy.yaml"))
        assert len(loader.baseline.permissions) == 0

    def test_invalid_yaml_creates_empty_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("not: valid: yaml: {{{")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 0

    def test_invalid_policy_structure_creates_empty_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - invalid_field: "should fail validation"
""")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 0

    def test_permission_denied_creates_empty_baseline(self):
        import os

        from safeyolo.policy.loader import PolicyLoader

        assert os.geteuid() != 0, "Container running as root - security risk"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - action: "network:request"
    resource: "*"
    effect: allow
""")
            os.chmod(path, 0o000)
            try:
                loader = PolicyLoader(baseline_path=path)
                assert len(loader.baseline.permissions) == 0
            finally:
                os.chmod(path, 0o644)

    def test_directory_as_policy_file_creates_empty_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir) / "not_a_file"
            policy_dir.mkdir()
            loader = PolicyLoader(baseline_path=policy_dir)
            assert len(loader.baseline.permissions) == 0

    def test_binary_file_creates_empty_baseline(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_bytes(b"\x00\x01\x02\x03\x04\x05\xff\xfe")
            loader = PolicyLoader(baseline_path=path)
            assert len(loader.baseline.permissions) == 0

    def test_symlink_loop_creates_empty_baseline(self):
        import os

        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            link1 = Path(tmpdir) / "link1.yaml"
            link2 = Path(tmpdir) / "link2.yaml"
            os.symlink(link2, link1)
            os.symlink(link1, link2)

            loader = PolicyLoader(baseline_path=link1)
            assert len(loader.baseline.permissions) == 0


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

class TestAuditEvents:
    """Tests that audit events are emitted on policy load success and failure."""

    def test_successful_load_emits_policy_reload_event(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("permissions: []")

            with patch("safeyolo.policy.loader.write_event") as mock_write:
                PolicyLoader(baseline_path=path)

            # Should have emitted ops.policy_reload
            event_names = [call.args[0] for call in mock_write.call_args_list]
            assert "ops.policy_reload" in event_names

    def test_missing_file_emits_policy_error_event(self):
        from safeyolo.policy.loader import PolicyLoader

        with patch("safeyolo.policy.loader.write_event") as mock_write:
            PolicyLoader(baseline_path=Path("/nonexistent/policy.yaml"))

        event_names = [call.args[0] for call in mock_write.call_args_list]
        assert "ops.policy_error" in event_names

    def test_validation_failure_emits_policy_error_event(self):
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
permissions:
  - invalid_field: "should fail"
""")
            with patch("safeyolo.policy.loader.write_event") as mock_write:
                PolicyLoader(baseline_path=path)

        event_names = [call.args[0] for call in mock_write.call_args_list]
        assert "ops.policy_error" in event_names


# ---------------------------------------------------------------------------
# Direct set_baseline / set_task_policy
# ---------------------------------------------------------------------------

class TestDirectSet:
    """Tests for set_baseline and set_task_policy (API-driven updates)."""

    def test_set_baseline_sorts_permissions(self):
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        policy = UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="*", effect="deny"),
            Permission(action="network:request", resource="api.example.com/v1/*", effect="allow"),
        ])
        loader.set_baseline(policy)

        # Most specific first
        assert loader.baseline.permissions[0].resource == "api.example.com/v1/*"
        assert loader.baseline.permissions[1].resource == "*"

    def test_set_baseline_builds_permission_index(self):
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        policy = UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="api.example.com/*", effect="allow"),
        ])
        loader.set_baseline(policy)

        simple, exact, patterns = loader.get_merged_index()
        assert ("network:request", "allow") in simple
        assert "api.example.com/*" in simple[("network:request", "allow")]

    def test_set_task_policy_sorts_and_indexes(self):
        from safeyolo.policy.engine import Permission, UnifiedPolicy
        from safeyolo.policy.loader import PolicyLoader

        loader = PolicyLoader()
        policy = UnifiedPolicy(permissions=[
            Permission(action="network:request", resource="*", effect="deny"),
            Permission(action="network:request", resource="api.example.com/*", effect="allow"),
        ])
        loader.set_task_policy(policy)

        assert loader.task_policy.permissions[0].resource == "api.example.com/*"
        assert loader.task_policy.permissions[1].resource == "*"


# ---------------------------------------------------------------------------
# Host-centric compilation pipeline (integration)
# ---------------------------------------------------------------------------

class TestHostCentricCompilation:
    """Tests for the full host-centric pipeline: TOML -> compile -> index."""

    def test_host_centric_yaml_compiles_to_permissions(self):
        """Host-centric YAML with credentials + rate_limit compiles to
        credential:use (with condition, in exact_dict) and
        network:request budget (in exact_dict)."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"
            path.write_text("""
hosts:
  api.openai.com:
    credentials:
      - "openai:*"
    rate_limit: 3000
  evil.com:
    egress: deny
  "*":
    egress: allow
    unknown_credentials: prompt
    rate_limit: 600
""")
            loader = PolicyLoader(baseline_path=path)

            # Should have compiled permissions
            assert len(loader.baseline.permissions) > 0

            # credential:use with condition goes to exact_dict
            assert ("credential:use", "api.openai.com/*") in loader._baseline_exact

            # egress=deny produces simple deny entry
            deny_key = ("network:request", "deny")
            assert "evil.com/*" in loader._baseline_simple.get(deny_key, set())

    def test_host_centric_toml_with_required_and_credential_rules(self):
        """Full TOML policy with required addons and credential rules."""
        from safeyolo.policy.loader import PolicyLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text("""
version = "2.0"
description = "Test full TOML"

required = ["credential_guard", "network_guard"]

[hosts]
"api.openai.com" = { allow = ["openai:*"], rate = 3000 }
"*" = { egress = "allow", unknown_creds = "prompt", rate = 600 }

[credential.openai]
match = ['sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}']
headers = ["authorization"]
""")
            loader = PolicyLoader(baseline_path=path)

            assert loader.baseline.metadata.version == "2.0"
            assert "credential_guard" in loader.baseline.required
            assert "network_guard" in loader.baseline.required
            assert len(loader.baseline.permissions) > 0
            assert len(loader.baseline.credential_rules) == 1
            assert loader.baseline.credential_rules[0].name == "openai"


# ---------------------------------------------------------------------------
# _extract_simple_permissions
# ---------------------------------------------------------------------------

class TestExtractSimplePermissions:
    """Tests for _extract_simple_permissions: pre-Pydantic set extraction."""

    def test_simple_deny_extracted(self):
        from safeyolo.policy.loader import _extract_simple_permissions

        perms = [
            {"action": "network:request", "resource": "evil.com/*", "effect": "deny", "tier": "explicit"},
            {"action": "network:request", "resource": "malware.net/*", "effect": "deny", "tier": "explicit"},
        ]
        remaining, simple = _extract_simple_permissions(perms)

        assert remaining == []
        assert simple == {("network:request", "deny"): {"evil.com/*", "malware.net/*"}}

    def test_budget_not_extracted(self):
        from safeyolo.policy.loader import _extract_simple_permissions

        perms = [
            {"action": "network:request", "resource": "api.openai.com/*", "effect": "budget", "budget": 3000},
        ]
        remaining, simple = _extract_simple_permissions(perms)

        assert len(remaining) == 1
        assert simple == {}

    def test_conditioned_not_extracted(self):
        from safeyolo.policy.loader import _extract_simple_permissions

        perms = [
            {"action": "credential:use", "resource": "api.openai.com/*", "effect": "allow",
             "condition": {"credential": ["openai:*"]}},
        ]
        remaining, simple = _extract_simple_permissions(perms)

        assert len(remaining) == 1
        assert simple == {}

    def test_wildcard_resource_not_extracted(self):
        from safeyolo.policy.loader import _extract_simple_permissions

        perms = [
            {"action": "network:request", "resource": "*.example.com/*", "effect": "allow"},
        ]
        remaining, simple = _extract_simple_permissions(perms)

        assert len(remaining) == 1
        assert simple == {}

    def test_default_effect_is_allow(self):
        """When effect is omitted, it defaults to 'allow'."""
        from safeyolo.policy.loader import _extract_simple_permissions

        perms = [
            {"action": "network:request", "resource": "api.example.com/*"},
        ]
        remaining, simple = _extract_simple_permissions(perms)

        assert remaining == []
        assert ("network:request", "allow") in simple
        assert "api.example.com/*" in simple[("network:request", "allow")]

    def test_mixed_permissions_partitioned(self):
        from safeyolo.policy.loader import _extract_simple_permissions

        perms = [
            {"action": "network:request", "resource": "evil.com/*", "effect": "deny", "tier": "explicit"},
            {"action": "credential:use", "resource": "api.openai.com/*", "effect": "allow",
             "condition": {"credential": ["openai:*"]}},
            {"action": "network:request", "resource": "*", "effect": "deny"},
        ]
        remaining, simple = _extract_simple_permissions(perms)

        # Only the first is extractable; the second has condition, third has wildcard resource
        assert len(remaining) == 2
        assert simple == {("network:request", "deny"): {"evil.com/*"}}


# ---------------------------------------------------------------------------
# _is_simple_permission_dict
# ---------------------------------------------------------------------------

class TestIsSimplePermissionDict:
    """Tests for _is_simple_permission_dict: raw dict version of _is_simple_permission."""

    def test_simple_deny_dict(self):
        from safeyolo.policy.loader import _is_simple_permission_dict

        p = {"action": "network:request", "resource": "evil.com/*", "effect": "deny", "tier": "explicit"}
        assert _is_simple_permission_dict(p) is True

    def test_budget_dict_not_simple(self):
        from safeyolo.policy.loader import _is_simple_permission_dict

        p = {"action": "network:request", "resource": "api.openai.com/*", "effect": "budget", "budget": 3000}
        assert _is_simple_permission_dict(p) is False

    def test_conditioned_dict_not_simple(self):
        from safeyolo.policy.loader import _is_simple_permission_dict

        p = {"action": "credential:use", "resource": "api.openai.com/*", "effect": "allow",
             "condition": {"credential": ["openai:*"]}}
        assert _is_simple_permission_dict(p) is False

    def test_wildcard_resource_not_simple(self):
        from safeyolo.policy.loader import _is_simple_permission_dict

        p = {"action": "network:request", "resource": "*.example.com/*", "effect": "allow"}
        assert _is_simple_permission_dict(p) is False

    def test_inferred_tier_not_simple(self):
        from safeyolo.policy.loader import _is_simple_permission_dict

        p = {"action": "network:request", "resource": "api.example.com/*", "effect": "allow", "tier": "inferred"}
        assert _is_simple_permission_dict(p) is False
