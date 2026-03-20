"""Tests for safeyolo token commands."""

import pytest
from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.commands.token import _parse_ttl


@pytest.fixture
def cli_runner():
    return CliRunner()


class TestParseTtl:
    def test_hours(self):
        assert _parse_ttl("1h") == 3600

    def test_days(self):
        assert _parse_ttl("7d") == 604800

    def test_minutes(self):
        assert _parse_ttl("30m") == 1800

    def test_seconds(self):
        assert _parse_ttl("3600") == 3600

    def test_invalid(self):
        with pytest.raises(ValueError):
            _parse_ttl("abc")


class TestTokenCreate:
    def test_create_requires_admin_token(self, cli_runner, tmp_config_dir):
        """Without admin token, create should fail."""
        result = cli_runner.invoke(app, ["token", "create"])
        assert result.exit_code != 0
        assert "No admin token" in result.output

    def test_create_with_admin_token(self, cli_runner, tmp_config_dir):
        """With admin token, create should succeed."""
        # Write admin token
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        result = cli_runner.invoke(app, ["token", "create"])
        assert result.exit_code == 0
        assert "Token created" in result.output

        # Verify active token file was written
        active_path = tmp_config_dir / "data" / "readonly_token"
        assert active_path.exists()
        token_str = active_path.read_text()
        assert "." in token_str

    def test_create_replaces_existing(self, cli_runner, tmp_config_dir):
        """Creating a new token replaces the old one."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        # Create first token
        cli_runner.invoke(app, ["token", "create"])
        active_path = tmp_config_dir / "data" / "readonly_token"
        first_token = active_path.read_text()

        # Create second token
        cli_runner.invoke(app, ["token", "create"])
        second_token = active_path.read_text()

        # Different tokens
        assert first_token != second_token

    def test_create_with_custom_ttl(self, cli_runner, tmp_config_dir):
        """Custom TTL works."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        result = cli_runner.invoke(app, ["token", "create", "--ttl", "4h"])
        assert result.exit_code == 0
        assert "Token created" in result.output


class TestTokenShow:
    def test_show_no_token(self, cli_runner, tmp_config_dir):
        result = cli_runner.invoke(app, ["token", "show"])
        assert result.exit_code == 0
        assert "No active token" in result.output

    def test_show_with_token(self, cli_runner, tmp_config_dir):
        """Show displays active token info."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        # Create a token first
        cli_runner.invoke(app, ["token", "create"])

        result = cli_runner.invoke(app, ["token", "show"])
        assert result.exit_code == 0
        assert "active" in result.output.lower()


class TestTokenRevoke:
    def test_revoke_no_token(self, cli_runner, tmp_config_dir):
        result = cli_runner.invoke(app, ["token", "revoke"])
        assert result.exit_code == 0
        assert "No active token" in result.output

    def test_revoke_deletes_file(self, cli_runner, tmp_config_dir):
        """Revoke deletes the token file."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        # Create a token
        cli_runner.invoke(app, ["token", "create"])

        # Verify file exists
        active_path = tmp_config_dir / "data" / "readonly_token"
        assert active_path.exists()

        # Revoke
        result = cli_runner.invoke(app, ["token", "revoke"])
        assert result.exit_code == 0
        assert "revoked" in result.output.lower()

        # Verify file is gone
        assert not active_path.exists()
