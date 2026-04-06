"""Tests for mount path protection logic.

Contract for is_path_protected(host_path, protected_paths):
- Returns the matching protected path string if host_path is exactly a protected path
  or is a subdirectory of a protected path.
- Returns None if host_path does not fall under any protected path.
- Resolves paths via Path.resolve() before comparison, so relative paths and
  trailing slashes are normalised.
"""


from safeyolo.commands.mount import is_path_protected


class TestIsPathProtectedExactMatch:
    """Exact match: path IS a protected path."""

    def test_exact_match_returns_protected_path(self, tmp_path):
        protected = str(tmp_path / "secrets")
        result = is_path_protected(protected, [protected])
        assert result == protected

    def test_exact_match_with_trailing_slash(self, tmp_path):
        """Trailing slash on input is normalised away by resolve()."""
        protected = str(tmp_path / "secrets")
        result = is_path_protected(protected + "/", [protected])
        assert result == protected


class TestIsPathProtectedSubdirectory:
    """Subdirectory match: path is under a protected path."""

    def test_child_dir_matches(self, tmp_path):
        protected = str(tmp_path / "secrets")
        child = str(tmp_path / "secrets" / "keys")
        result = is_path_protected(child, [protected])
        assert result == protected

    def test_deeply_nested_child_matches(self, tmp_path):
        protected = str(tmp_path / "data")
        nested = str(tmp_path / "data" / "a" / "b" / "c")
        result = is_path_protected(nested, [protected])
        assert result == protected


class TestIsPathProtectedNonMatch:
    """Non-match cases: path not under any protected path."""

    def test_unrelated_path_returns_none(self, tmp_path):
        protected = str(tmp_path / "secrets")
        unrelated = str(tmp_path / "public")
        result = is_path_protected(unrelated, [protected])
        assert result is None

    def test_sibling_with_shared_prefix_does_not_match(self, tmp_path):
        """/app does not match /app2 -- prefix matching is not string matching."""
        protected = str(tmp_path / "app")
        sibling = str(tmp_path / "app2")
        result = is_path_protected(sibling, [protected])
        assert result is None


class TestIsPathProtectedEdgeCases:
    """Edge cases for protected path checking."""

    def test_root_as_protected_matches_everything(self):
        """If '/' is protected, every absolute path matches."""
        result = is_path_protected("/usr/local/bin", ["/"])
        assert result == "/"

    def test_empty_protected_list_returns_none(self, tmp_path):
        result = is_path_protected(str(tmp_path / "anything"), [])
        assert result is None

    def test_multiple_protected_paths_first_match_wins(self, tmp_path):
        """When multiple protected paths match, the first one in list order wins."""
        parent = str(tmp_path / "data")
        child = str(tmp_path / "data" / "secrets")
        target = str(tmp_path / "data" / "secrets" / "key.pem")
        result = is_path_protected(target, [parent, child])
        assert result == parent

    def test_relative_path_resolved_against_cwd(self, monkeypatch, tmp_path):
        """Relative paths are resolved to absolute before comparison."""
        # Create a dir structure and chdir into it
        base = tmp_path / "workspace"
        base.mkdir()
        monkeypatch.chdir(base)
        # Protect the resolved absolute path
        protected = str(base / "secrets")
        result = is_path_protected("secrets/key.pem", [protected])
        assert result == protected
