"""Tests for list_loader — named list loading and policy expansion."""

import pytest

# =========================================================================
# load_list()
# =========================================================================


class TestLoadList:
    def test_basic_entries(self, tmp_path):
        from list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("pypi.org\nfiles.pythonhosted.org\nregistry.npmjs.org\n")
        assert load_list(f) == ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]

    def test_comments_and_blanks_stripped(self, tmp_path):
        from list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("# Python\npypi.org\n\n# JS\nregistry.npmjs.org\n\n")
        assert load_list(f) == ["pypi.org", "registry.npmjs.org"]

    def test_whitespace_trimmed(self, tmp_path):
        from list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("  pypi.org  \n\tregistry.npmjs.org\t\n")
        assert load_list(f) == ["pypi.org", "registry.npmjs.org"]

    def test_hosts_file_format(self, tmp_path):
        from list_loader import load_list

        f = tmp_path / "hosts"
        f.write_text(
            "# Steven Black hosts\n"
            "127.0.0.1 localhost\n"
            "127.0.0.1 localhost.localdomain\n"
            "::1 localhost\n"
            "0.0.0.0 0.0.0.0\n"
            "0.0.0.0 evil.com\n"
            "0.0.0.0 malware.org\n"
            "0.0.0.0 evil.com\n"  # duplicate
        )
        result = load_list(f)
        assert result == ["evil.com", "malware.org"]

    def test_entries_without_dot_skipped(self, tmp_path):
        from list_loader import load_list

        f = tmp_path / "hosts.txt"
        f.write_text("valid.com\nip6-allnodes\nanother.org\n")
        assert load_list(f) == ["valid.com", "another.org"]

    def test_empty_file(self, tmp_path):
        from list_loader import load_list

        f = tmp_path / "empty.txt"
        f.write_text("# only comments\n\n")
        assert load_list(f) == []

    def test_missing_file_raises(self, tmp_path):
        from list_loader import load_list

        with pytest.raises(FileNotFoundError):
            load_list(tmp_path / "nonexistent.txt")


# =========================================================================
# expand_lists()
# =========================================================================


class TestExpandLists:
    def _write_list(self, tmp_path, name, entries):
        f = tmp_path / name
        f.write_text("\n".join(entries) + "\n")
        return f

    def test_expands_dollar_reference(self, tmp_path):
        from list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["pypi.org", "registry.npmjs.org"])
        raw = {
            "lists": {"pkg": "pkg.txt"},
            "hosts": {
                "$pkg": {"rate_limit": 1200},
                "api.openai.com": {"rate_limit": 3000},
            },
        }
        result = expand_lists(raw, tmp_path)
        assert "$pkg" not in result["hosts"]
        assert result["hosts"]["pypi.org"] == {"rate_limit": 1200}
        assert result["hosts"]["registry.npmjs.org"] == {"rate_limit": 1200}
        assert result["hosts"]["api.openai.com"] == {"rate_limit": 3000}

    def test_config_preserved_on_each_entry(self, tmp_path):
        from list_loader import expand_lists

        self._write_list(tmp_path, "bad.txt", ["evil.com", "malware.org"])
        raw = {
            "lists": {"bad": "bad.txt"},
            "hosts": {"$bad": {"egress": "deny"}},
        }
        result = expand_lists(raw, tmp_path)
        assert result["hosts"]["evil.com"] == {"egress": "deny"}
        assert result["hosts"]["malware.org"] == {"egress": "deny"}

    def test_explicit_host_not_overwritten(self, tmp_path):
        from list_loader import expand_lists

        self._write_list(tmp_path, "pkg.txt", ["pypi.org", "registry.npmjs.org"])
        raw = {
            "lists": {"pkg": "pkg.txt"},
            "hosts": {
                "$pkg": {"rate_limit": 1200},
                "pypi.org": {"rate_limit": 9999},
            },
        }
        result = expand_lists(raw, tmp_path)
        assert result["hosts"]["pypi.org"] == {"rate_limit": 9999}
        assert result["hosts"]["registry.npmjs.org"] == {"rate_limit": 1200}

    def test_multiple_lists(self, tmp_path):
        from list_loader import expand_lists

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
        assert result["hosts"]["pypi.org"] == {"rate_limit": 1200}
        assert result["hosts"]["evil.com"] == {"egress": "deny"}

    def test_undefined_list_skipped(self, tmp_path):
        from list_loader import expand_lists

        raw = {
            "lists": {},
            "hosts": {"$undefined": {"rate_limit": 100}},
        }
        result = expand_lists(raw, tmp_path)
        # $undefined stays since it wasn't found in lists
        assert "$undefined" in result["hosts"]

    def test_missing_file_keeps_reference(self, tmp_path):
        from list_loader import expand_lists

        raw = {
            "lists": {"bad": "nonexistent.txt"},
            "hosts": {"$bad": {"egress": "deny"}},
        }
        result = expand_lists(raw, tmp_path)
        # $bad stays — file not found, entry not expanded
        assert "$bad" in result["hosts"]

    def test_relative_path_resolved(self, tmp_path):
        from list_loader import expand_lists

        subdir = tmp_path / "lists"
        subdir.mkdir()
        self._write_list(subdir, "pkg.txt", ["pypi.org"])
        raw = {
            "lists": {"pkg": "lists/pkg.txt"},
            "hosts": {"$pkg": {"rate_limit": 1200}},
        }
        result = expand_lists(raw, tmp_path)
        assert result["hosts"]["pypi.org"] == {"rate_limit": 1200}

    def test_no_lists_section_noop(self, tmp_path):
        from list_loader import expand_lists

        raw = {"hosts": {"example.com": {"rate_limit": 100}}}
        result = expand_lists(raw, tmp_path)
        assert result["hosts"]["example.com"] == {"rate_limit": 100}


# =========================================================================
# Integration with PolicyLoader
# =========================================================================


class TestListIntegration:
    def test_policy_with_list_loads_and_compiles(self, tmp_path):
        from policy_loader import PolicyLoader

        # Write list file
        lists_dir = tmp_path / "lists"
        lists_dir.mkdir()
        (lists_dir / "pkg.txt").write_text("pypi.org\nregistry.npmjs.org\n")

        # Write policy
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
        policy = loader.baseline

        resources = {p.resource for p in policy.permissions}
        assert "pypi.org/*" in resources
        assert "registry.npmjs.org/*" in resources

    def test_expanded_hosts_get_correct_permissions(self, tmp_path):
        from policy_loader import PolicyLoader

        lists_dir = tmp_path / "lists"
        lists_dir.mkdir()
        (lists_dir / "bad.txt").write_text("evil.com\n")

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

        # Simple deny permissions are extracted into sets (not Permission objects)
        simple_sets, _, _ = loader.get_merged_index()
        deny_resources = simple_sets.get(("network:request", "deny"), set())
        assert "evil.com/*" in deny_resources
