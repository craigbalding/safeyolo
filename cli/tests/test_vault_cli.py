"""Tests for vault key management.

Contract for _get_or_create_key():
- If the key file exists, reads it, strips whitespace, and returns the string.
- If the key file does not exist, generates a new key via secrets.token_urlsafe(32),
  writes it to the key path, sets 0o600 permissions, and returns the key string.
- Creates parent directories if they don't exist.
- The generated key is a URL-safe base64 string (43 chars from 32 random bytes).
- Idempotent: calling twice returns the same key (reads from file on second call).
"""


from safeyolo.commands.vault import _get_or_create_key


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
