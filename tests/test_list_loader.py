"""Tests for list_loader — named list loading and policy expansion.

Each test maps to a specific contract item. Tests state expected outcomes
directly — no recomputation of production logic inside test bodies.
"""

import pytest

# =========================================================================
# load_list() — plain format
# =========================================================================


class TestLoadListPlainFormat:
    def test_returns_entries_in_file_order(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("pypi.org\nfiles.pythonhosted.org\nregistry.npmjs.org\n")
        assert load_list(f) == ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]

    def test_strips_comment_lines(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("# Python\npypi.org\n# JS\nregistry.npmjs.org\n")
        assert load_list(f) == ["pypi.org", "registry.npmjs.org"]

    def test_strips_blank_lines(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("pypi.org\n\n\nregistry.npmjs.org\n")
        assert load_list(f) == ["pypi.org", "registry.npmjs.org"]

    def test_strips_leading_and_trailing_whitespace(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("  pypi.org  \n\tregistry.npmjs.org\t\n")
        assert load_list(f) == ["pypi.org", "registry.npmjs.org"]

    def test_empty_file_returns_empty_list(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "empty.txt"
        f.write_text("")
        assert load_list(f) == []

    def test_comments_only_file_returns_empty_list(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "comments.txt"
        f.write_text("# only a comment\n# and another\n")
        assert load_list(f) == []


# =========================================================================
# load_list() — hosts-file format (IP prefix stripping)
# =========================================================================


class TestLoadListHostsFileFormat:
    def test_strips_0_0_0_0_prefix(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("0.0.0.0 ads.example.com\n")
        assert load_list(f) == ["ads.example.com"]

    def test_strips_127_0_0_1_prefix(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("127.0.0.1 ads.example.com\n")
        assert load_list(f) == ["ads.example.com"]

    def test_strips_255_255_255_255_prefix(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("255.255.255.255 broadcast.example.com\n")
        assert load_list(f) == ["broadcast.example.com"]

    def test_strips_ipv6_loopback_prefix(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("::1 ip6.example.com\n")
        assert load_list(f) == ["ip6.example.com"]

    def test_strips_ipv6_multicast_prefix(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("ff02::1 multicast.example.com\n")
        assert load_list(f) == ["multicast.example.com"]

    def test_strips_ipv6_link_local_prefix(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("fe80::1 link.example.com\n")
        assert load_list(f) == ["link.example.com"]

    def test_mixed_plain_and_hosts_file_format_in_same_file(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("plain.example.com\n0.0.0.0 ads.example.com\n# comment\n127.0.0.1 tracker.example.com\n")
        assert load_list(f) == ["plain.example.com", "ads.example.com", "tracker.example.com"]


# =========================================================================
# load_list() — non-domain filtering
# =========================================================================


class TestLoadListFiltering:
    def test_skips_entry_without_dot(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("valid.com\nip6-allnodes\nanother.org\n")
        assert load_list(f) == ["valid.com", "another.org"]

    def test_skips_localhost(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("127.0.0.1 localhost\nvalid.com\n")
        assert load_list(f) == ["valid.com"]

    def test_skips_localhost_localdomain(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("127.0.0.1 localhost.localdomain\nvalid.com\n")
        assert load_list(f) == ["valid.com"]

    def test_skips_broadcasthost(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("255.255.255.255 broadcasthost\nvalid.com\n")
        assert load_list(f) == ["valid.com"]

    def test_skips_zero_zero_zero_zero_as_entry(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text("0.0.0.0 0.0.0.0\nvalid.com\n")
        assert load_list(f) == ["valid.com"]


# =========================================================================
# load_list() — deduplication
# =========================================================================


class TestLoadListDeduplication:
    def test_duplicate_entry_kept_only_once(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("a.com\nb.com\na.com\n")
        assert load_list(f) == ["a.com", "b.com"]

    def test_dedup_preserves_first_occurrence_order(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("z.com\na.com\nz.com\nb.com\na.com\n")
        assert load_list(f) == ["z.com", "a.com", "b.com"]


# =========================================================================
# load_list() — errors
# =========================================================================


class TestLoadListErrors:
    def test_missing_file_raises_file_not_found_error(self, tmp_path):
        from safeyolo.policy.list_loader import load_list

        with pytest.raises(FileNotFoundError):
            load_list(tmp_path / "nonexistent.txt")


# =========================================================================
# expand_lists() — happy path
# =========================================================================


class TestExpandListsBasic:
    def _write_list(self, tmp_path, name, entries):
        f = tmp_path / name
        f.write_text("\n".join(entries) + "\n")
        return f

    def test_dollar_reference_is_replaced_with_individual_host_entries(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["pypi.org", "registry.npmjs.org"])
        raw = {
            "lists": {"pkg": "pkg.txt"},
            "hosts": {"$pkg": {"rate_limit": 1200}},
        }
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {
            "pypi.org": {"rate_limit": 1200},
            "registry.npmjs.org": {"rate_limit": 1200},
        }

    def test_dollar_reference_key_removed_after_expansion(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["pypi.org"])
        raw = {"lists": {"pkg": "pkg.txt"}, "hosts": {"$pkg": {}}}
        result = expand_lists(raw, tmp_path)
        assert "$pkg" not in result["hosts"]

    def test_explicit_host_takes_priority_over_list_entry(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["pypi.org", "registry.npmjs.org"])
        raw = {
            "lists": {"pkg": "pkg.txt"},
            "hosts": {
                "$pkg": {"rate_limit": 1200},
                "pypi.org": {"rate_limit": 9999},  # explicit override
            },
        }
        result = expand_lists(raw, tmp_path)
        assert result["hosts"]["pypi.org"] == {"rate_limit": 9999}
        assert result["hosts"]["registry.npmjs.org"] == {"rate_limit": 1200}

    def test_multiple_list_references_expanded_independently(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["pypi.org"])
        self._write_list(tmp_path, "bad.txt", ["evil.com"])
        raw = {
            "lists": {"pkg": "pkg.txt", "bad": "bad.txt"},
            "hosts": {
                "$pkg": {"rate_limit": 1200},
                "$bad": {"egress": "deny"},
            },
        }
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {
            "pypi.org": {"rate_limit": 1200},
            "evil.com": {"egress": "deny"},
        }

    def test_empty_list_file_produces_no_host_entries(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "empty.txt", [])
        raw = {"lists": {"empty": "empty.txt"}, "hosts": {"$empty": {"egress": "deny"}}}
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {}

    def test_dollar_reference_with_none_config_uses_empty_dict(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "bad.txt", ["evil.com"])
        raw = {"lists": {"bad": "bad.txt"}, "hosts": {"$bad": None}}
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {"evil.com": {}}


# =========================================================================
# expand_lists() — config independence (bug fix: config dict is copied)
# =========================================================================


class TestExpandListsConfigIndependence:
    def _write_list(self, tmp_path, name, entries):
        f = tmp_path / name
        f.write_text("\n".join(entries) + "\n")
        return f

    def test_mutating_one_expanded_config_does_not_affect_others(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["one.com", "two.com", "three.com"])
        raw = {"lists": {"pkg": "pkg.txt"}, "hosts": {"$pkg": {"rate": 100}}}
        result = expand_lists(raw, tmp_path)

        # Mutate one entry's config
        result["hosts"]["one.com"]["rate"] = 9999

        # Other entries are unaffected
        assert result["hosts"]["two.com"] == {"rate": 100}
        assert result["hosts"]["three.com"] == {"rate": 100}


# =========================================================================
# expand_lists() — path resolution
# =========================================================================


class TestExpandListsPathResolution:
    def _write_list(self, path, entries):
        path.write_text("\n".join(entries) + "\n")

    def test_relative_path_resolved_against_base_dir(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        subdir = tmp_path / "lists"
        subdir.mkdir()
        self._write_list(subdir / "pkg.txt", ["pypi.org"])
        raw = {"lists": {"pkg": "lists/pkg.txt"}, "hosts": {"$pkg": {}}}
        result = expand_lists(raw, tmp_path)
        assert "pypi.org" in result["hosts"]

    def test_absolute_path_used_as_is(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        list_file = elsewhere / "pkg.txt"
        self._write_list(list_file, ["pypi.org"])
        raw = {"lists": {"pkg": str(list_file)}, "hosts": {"$pkg": {}}}
        # base_dir is unrelated — absolute path ignores it
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        result = expand_lists(raw, other_dir)
        assert "pypi.org" in result["hosts"]


# =========================================================================
# expand_lists() — errors (fail-closed)
# =========================================================================


class TestExpandListsErrors:
    def _write_list(self, tmp_path, name, entries):
        f = tmp_path / name
        f.write_text("\n".join(entries) + "\n")
        return f

    def test_undefined_dollar_reference_raises_value_error(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {
            "lists": {"good": "good.txt"},
            "hosts": {"$typo_name": {"egress": "deny"}},
        }
        with pytest.raises(ValueError, match=r"Undefined list reference '\$typo_name'"):
            expand_lists(raw, tmp_path)

    def test_undefined_ref_error_lists_defined_names(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {
            "lists": {"alpha": "a.txt", "beta": "b.txt"},
            "hosts": {"$typo": {}},
        }
        with pytest.raises(ValueError, match=r"Defined lists: alpha, beta"):
            expand_lists(raw, tmp_path)

    def test_empty_lists_section_error_lists_none(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {"lists": {"a": "a.txt"}, "hosts": {"$typo": {}}}
        with pytest.raises(ValueError, match=r"Defined lists: a"):
            expand_lists(raw, tmp_path)

    def test_missing_file_raises_value_error(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {
            "lists": {"bad": "nonexistent.txt"},
            "hosts": {"$bad": {"egress": "deny"}},
        }
        with pytest.raises(ValueError, match=r"List file not found.*nonexistent\.txt.*\$bad"):
            expand_lists(raw, tmp_path)


# =========================================================================
# expand_lists() — no-op cases
# =========================================================================


class TestExpandListsNoOp:
    def test_no_lists_section_returns_raw_unchanged(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {"hosts": {"example.com": {"rate_limit": 100}}}
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {"example.com": {"rate_limit": 100}}

    def test_empty_lists_section_returns_raw_unchanged(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {"lists": {}, "hosts": {"example.com": {}}}
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {"example.com": {}}

    def test_lists_section_not_a_dict_is_noop(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {"lists": "not-a-dict", "hosts": {"example.com": {}}}
        result = expand_lists(raw, tmp_path)
        assert result["hosts"] == {"example.com": {}}

    def test_no_hosts_section_returns_raw_unchanged(self, tmp_path):
        from safeyolo.policy.list_loader import expand_lists

        raw = {"lists": {"pkg": "pkg.txt"}}
        result = expand_lists(raw, tmp_path)
        assert result == {"lists": {"pkg": "pkg.txt"}}


# =========================================================================
# Integration with PolicyLoader — happy path
# =========================================================================


class TestListIntegrationHappyPath:
    def test_valid_list_reference_produces_budget_permissions(self, tmp_path):
        from safeyolo.policy.loader import PolicyLoader

        lists_dir = tmp_path / "lists"
        lists_dir.mkdir()
        (lists_dir / "pkg.txt").write_text("pypi.org\nregistry.npmjs.org\n")

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
lists:
  pkg: lists/pkg.txt
hosts:
  "$pkg": {rate_limit: 1200}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)

        resources = {p.resource for p in loader.baseline.permissions}
        assert "pypi.org/*" in resources
        assert "registry.npmjs.org/*" in resources

    def test_deny_list_reference_produces_deny_entries_in_simple_sets(self, tmp_path):
        from safeyolo.policy.loader import PolicyLoader

        lists_dir = tmp_path / "lists"
        lists_dir.mkdir()
        (lists_dir / "bad.txt").write_text("evil.com\nmalware.org\n")

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
lists:
  bad: lists/bad.txt
hosts:
  "$bad": {egress: deny}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)
        simple_sets, _, _ = loader.get_merged_index()
        deny_resources = simple_sets.get(("network:request", "deny"), set())
        assert "evil.com/*" in deny_resources
        assert "malware.org/*" in deny_resources


# =========================================================================
# Integration with PolicyLoader — failure and recovery
# =========================================================================


class TestListIntegrationFailureAndRecovery:
    def test_undefined_list_reference_causes_load_to_fail(self, tmp_path):
        from safeyolo.policy.loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
lists:
  good: good.txt
hosts:
  "$typo": {egress: deny}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)
        # Policy load failed → baseline is the default empty UnifiedPolicy
        assert loader.baseline.permissions == []

    def test_missing_list_file_causes_load_to_fail(self, tmp_path):
        from safeyolo.policy.loader import PolicyLoader

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
lists:
  bad: lists/nonexistent.txt
hosts:
  "$bad": {egress: deny}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)
        assert loader.baseline.permissions == []

    def test_reload_with_broken_policy_keeps_previous_baseline(self, tmp_path):
        """Hot-reload fail-safe: if a reloaded policy is broken, keep the old one."""
        from safeyolo.policy.loader import PolicyLoader

        lists_dir = tmp_path / "lists"
        lists_dir.mkdir()
        (lists_dir / "pkg.txt").write_text("pypi.org\n")

        baseline = tmp_path / "policy.yaml"
        baseline.write_text("""
lists:
  pkg: lists/pkg.txt
hosts:
  "$pkg": {rate_limit: 1200}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")

        loader = PolicyLoader(baseline_path=baseline)
        original_resources = {p.resource for p in loader.baseline.permissions}
        assert "pypi.org/*" in original_resources

        # Break the policy (undefined reference)
        baseline.write_text("""
lists:
  pkg: lists/pkg.txt
hosts:
  "$typo": {egress: deny}
  "*": {unknown_credentials: prompt, rate_limit: 600}
required: []
addons:
  credential_guard: {enabled: true}
scan_patterns: []
""")
        # Reload — should fail, but keep the old baseline
        reload_ok = loader._load_baseline()
        assert reload_ok is False
        # Old baseline still in effect
        resources = {p.resource for p in loader.baseline.permissions}
        assert "pypi.org/*" in resources
