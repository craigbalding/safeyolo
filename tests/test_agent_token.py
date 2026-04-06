"""Tests for pdp/tokens.py - agent token read utility."""

from pdp.tokens import read_active_token


class TestReadActiveToken:
    def test_missing_file_returns_none(self, tmp_path):
        path = tmp_path / "nonexistent"
        assert read_active_token(path) is None

    def test_reads_token_from_file(self, tmp_path):
        path = tmp_path / "agent_token"
        path.write_text("my-token-string")
        assert read_active_token(path) == "my-token-string"

    def test_strips_whitespace(self, tmp_path):
        path = tmp_path / "agent_token"
        path.write_text("  my-token  \n")
        assert read_active_token(path) == "my-token"

    def test_empty_file_returns_none(self, tmp_path):
        path = tmp_path / "agent_token"
        path.write_text("")
        assert read_active_token(path) is None

    def test_unreadable_file_returns_none(self, tmp_path):
        """OSError (e.g. permission denied) returns None, not an exception."""
        # Use a directory path — read_text() on a directory raises IsADirectoryError (an OSError)
        path = tmp_path / "is_a_directory"
        path.mkdir()
        assert read_active_token(path) is None
