"""Tests for safeyolo token commands."""


import pytest
from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.commands.token import _load_tokens, _parse_ttl


@pytest.fixture
def cli_runner():
    return CliRunner()


class TestParseTtl:
    def test_hours(self):
        assert _parse_ttl("24h") == 86400

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

        # Verify token registry was created
        tokens = _load_tokens()
        assert len(tokens) == 1
        assert tokens[0]["status"] == "active"

        # Verify active token file was written
        active_path = tmp_config_dir / "data" / "readonly_token"
        assert active_path.exists()
        token_str = active_path.read_text()
        assert "." in token_str

    def test_create_with_custom_ttl(self, cli_runner, tmp_config_dir):
        """Custom TTL is stored in registry."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        result = cli_runner.invoke(app, ["token", "create", "--ttl", "7d"])
        assert result.exit_code == 0

        tokens = _load_tokens()
        assert tokens[0]["ttl"] == "7d"


class TestTokenList:
    def test_list_empty(self, cli_runner, tmp_config_dir):
        result = cli_runner.invoke(app, ["token", "list"])
        assert result.exit_code == 0
        assert "No tokens found" in result.output

    def test_list_with_tokens(self, cli_runner, tmp_config_dir):
        """List shows existing tokens."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        # Create a token first
        cli_runner.invoke(app, ["token", "create"])

        result = cli_runner.invoke(app, ["token", "list"])
        assert result.exit_code == 0
        assert "active" in result.output


class TestTokenRevoke:
    def test_revoke_requires_jti_or_all(self, cli_runner, tmp_config_dir):
        result = cli_runner.invoke(app, ["token", "revoke"])
        assert result.exit_code != 0

    def test_revoke_all(self, cli_runner, tmp_config_dir):
        """Revoke --all marks all tokens as revoked."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        # Create tokens
        cli_runner.invoke(app, ["token", "create"])
        cli_runner.invoke(app, ["token", "create"])

        result = cli_runner.invoke(app, ["token", "revoke", "--all"])
        assert result.exit_code == 0
        assert "Revoked 2 token(s)" in result.output

        # Verify all revoked
        tokens = _load_tokens()
        assert all(t["status"] == "revoked" for t in tokens)

        # Verify active token file was removed
        active_path = tmp_config_dir / "data" / "readonly_token"
        assert not active_path.exists()

    def test_revoke_specific_jti(self, cli_runner, tmp_config_dir):
        """Revoke specific token by JTI."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")

        # Create a token
        cli_runner.invoke(app, ["token", "create"])
        tokens = _load_tokens()
        jti = tokens[0]["jti"]

        result = cli_runner.invoke(app, ["token", "revoke", jti])
        assert result.exit_code == 0
        assert "Revoked 1 token(s)" in result.output

    def test_revoke_nonexistent(self, cli_runner, tmp_config_dir):
        """Revoking nonexistent JTI shows message."""
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("test-admin-token")
        cli_runner.invoke(app, ["token", "create"])

        result = cli_runner.invoke(app, ["token", "revoke", "nonexistent"])
        assert "not found" in result.output
