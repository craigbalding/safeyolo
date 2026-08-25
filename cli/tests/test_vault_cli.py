"""Tests for vault key management.

Contract for _get_or_create_key():
- If the key file exists, reads it, strips whitespace, and returns the string.
- If the key file does not exist, generates a new key via secrets.token_urlsafe(32),
  writes it to the key path, sets 0o600 permissions, and returns the key string.
- Creates parent directories if they don't exist.
- The generated key is a URL-safe base64 string (43 chars from 32 random bytes).
- Idempotent: calling twice returns the same key (reads from file on second call).

Contract for `safeyolo vault add`:
- Exactly one of --token, --token-file, --token-env may be given; more is an error.
- --token-file reads and strips the file contents; missing file is an error.
- --token-env reads the named env var; unset/empty is an error.
- With no source flag, prompts securely (unchanged).
"""


import pytest
from typer.testing import CliRunner

from safeyolo.commands.vault import _get_or_create_key, vault_app


class TestGetOrCreateKeyCreation:
    """Key creation when no key file exists."""

    def test_creates_key_file_and_returns_string(self, tmp_path, monkeypatch):
        key_path = tmp_path / "data" / "vault.key"
        monkeypatch.setattr("safeyolo.commands.vault._get_key_path", lambda: key_path)

        key = _get_or_create_key()

        assert isinstance(key, str)
        assert len(key) > 0
        assert key_path.exists()
        assert key_path.read_text() == key

    def test_key_file_has_0600_permissions(self, tmp_path, monkeypatch):
        key_path = tmp_path / "data" / "vault.key"
        monkeypatch.setattr("safeyolo.commands.vault._get_key_path", lambda: key_path)

        _get_or_create_key()

        file_mode = key_path.stat().st_mode & 0o777
        assert file_mode == 0o600

    def test_creates_parent_directories(self, tmp_path, monkeypatch):
        key_path = tmp_path / "deep" / "nested" / "vault.key"
        monkeypatch.setattr("safeyolo.commands.vault._get_key_path", lambda: key_path)

        _get_or_create_key()

        assert key_path.exists()
        assert (tmp_path / "deep" / "nested").is_dir()

    def test_generated_key_is_43_char_urlsafe_base64(self, tmp_path, monkeypatch):
        """secrets.token_urlsafe(32) produces 43 characters of URL-safe base64."""
        key_path = tmp_path / "data" / "vault.key"
        monkeypatch.setattr("safeyolo.commands.vault._get_key_path", lambda: key_path)

        key = _get_or_create_key()

        # token_urlsafe(32) encodes 32 bytes as base64 without padding = 43 chars
        assert len(key) == 43
        # Only URL-safe characters
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert set(key).issubset(allowed)


class TestGetOrCreateKeyIdempotent:
    """Reading existing key file (idempotent behaviour)."""

    def test_returns_existing_key_without_overwriting(self, tmp_path, monkeypatch):
        key_path = tmp_path / "data" / "vault.key"
        key_path.parent.mkdir(parents=True)
        existing_key = "my-existing-key-value-here"
        key_path.write_text(existing_key)

        monkeypatch.setattr("safeyolo.commands.vault._get_key_path", lambda: key_path)

        result = _get_or_create_key()

        assert result == existing_key
        # File content unchanged
        assert key_path.read_text() == existing_key


class _StubCredential:
    def __init__(self, name, type, value, **kwargs):
        self.name = name
        self.type = type
        self.value = value


class _StubVault:
    def __init__(self):
        self.stored: list[_StubCredential] = []

    def store(self, cred):
        self.stored.append(cred)


@pytest.fixture
def stub_vault(monkeypatch):
    """Replace _load_vault so `vault add` exercises input plumbing without touching disk/crypto."""
    v = _StubVault()
    monkeypatch.setattr("safeyolo.commands.vault._load_vault", lambda: (v, _StubCredential))
    return v


class TestVaultAddTokenSources:
    """`vault add` accepts one of --token / --token-file / --token-env."""

    def test_inline_token_stored(self, stub_vault):
        result = CliRunner().invoke(
            vault_app,
            ["add", "cred1", "--type", "bearer", "--token", "secret-abc"],
        )
        assert result.exit_code == 0, result.output
        assert [(c.name, c.type, c.value) for c in stub_vault.stored] == [("cred1", "bearer", "secret-abc")]

    def test_token_file_reads_and_strips(self, tmp_path, stub_vault):
        tok = tmp_path / "hb.tok"
        tok.write_text("  file-value\n")

        result = CliRunner().invoke(
            vault_app,
            ["add", "cred2", "--type", "bearer", "--token-file", str(tok)],
        )
        assert result.exit_code == 0, result.output
        assert stub_vault.stored[0].value == "file-value"

    def test_token_file_missing_errors(self, tmp_path, stub_vault):
        result = CliRunner().invoke(
            vault_app,
            ["add", "cred3", "--type", "bearer", "--token-file", str(tmp_path / "nope")],
        )
        assert result.exit_code != 0
        assert "File not found" in result.output
        assert stub_vault.stored == []

    def test_token_env_reads_named_var(self, monkeypatch, stub_vault):
        monkeypatch.setenv("HB_TOKEN", "env-value")

        result = CliRunner().invoke(
            vault_app,
            ["add", "cred4", "--type", "bearer", "--token-env", "HB_TOKEN"],
        )
        assert result.exit_code == 0, result.output
        assert stub_vault.stored[0].value == "env-value"

    def test_token_env_unset_errors(self, monkeypatch, stub_vault):
        monkeypatch.delenv("HB_TOKEN", raising=False)

        result = CliRunner().invoke(
            vault_app,
            ["add", "cred5", "--type", "bearer", "--token-env", "HB_TOKEN"],
        )
        assert result.exit_code != 0
        assert "HB_TOKEN" in result.output
        assert stub_vault.stored == []

    def test_multiple_sources_rejected(self, tmp_path, stub_vault):
        tok = tmp_path / "hb.tok"
        tok.write_text("file")

        result = CliRunner().invoke(
            vault_app,
            [
                "add",
                "cred6",
                "--type",
                "bearer",
                "--token",
                "inline",
                "--token-file",
                str(tok),
            ],
        )
        assert result.exit_code != 0
        assert "at most one" in result.output
        assert stub_vault.stored == []
