"""Tests for addons/vault.py — Encrypted credential store."""

import threading

import pytest

from safeyolo.core.vault import Vault, VaultCredential


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.yaml.enc"


@pytest.fixture
def vault(vault_path):
    v = Vault(vault_path)
    v.unlock("test-passphrase")
    return v


class TestVaultCredential:
    def test_to_dict_minimal(self):
        cred = VaultCredential(name="test", type="bearer", value="tok123")
        d = cred.to_dict()
        assert d == {"name": "test", "type": "bearer", "value": "tok123"}

    def test_to_dict_full(self):
        cred = VaultCredential(
            name="gmail", type="oauth2", value="ya29.xxx",
            refresh_token="1//rt", token_url="https://oauth2.googleapis.com/token",
            client_id="cid", client_secret="csec", expires_at="2025-01-01T00:00:00+00:00",
        )
        d = cred.to_dict()
        assert d["refresh_token"] == "1//rt"
        assert d["token_url"] == "https://oauth2.googleapis.com/token"

    def test_from_dict_roundtrip(self):
        original = VaultCredential(
            name="test", type="api_key", value="key123",
            refresh_token="rt", token_url="https://example.com/token",
        )
        d = original.to_dict()
        restored = VaultCredential.from_dict(d)
        assert restored.name == original.name
        assert restored.type == original.type
        assert restored.value == original.value
        assert restored.refresh_token == original.refresh_token

    def test_is_expired_no_expiry(self):
        cred = VaultCredential(name="test", type="bearer", value="tok")
        assert not cred.is_expired()

    def test_is_expired_past(self):
        cred = VaultCredential(name="test", type="oauth2", value="tok",
                               expires_at="2020-01-01T00:00:00+00:00")
        assert cred.is_expired()

    def test_is_expired_future(self):
        cred = VaultCredential(name="test", type="oauth2", value="tok",
                               expires_at="2099-01-01T00:00:00+00:00")
        assert not cred.is_expired()


    def test_is_expired_malformed_date_returns_true(self):
        """Malformed expires_at is treated as expired (fail-closed)."""
        cred = VaultCredential(name="test", type="oauth2", value="tok",
                               expires_at="not-a-date")
        assert cred.is_expired() is True


class TestVault:
    def test_unlock_creates_new_vault(self, vault_path):
        v = Vault(vault_path)
        v.unlock("my-pass")
        assert vault_path.exists()
        assert v.list_names() == []

    def test_store_and_get(self, vault):
        cred = VaultCredential(name="test-key", type="api_key", value="sk-12345")
        vault.store(cred)
        retrieved = vault.get("test-key")
        assert retrieved is not None
        assert retrieved.value == "sk-12345"
        assert retrieved.type == "api_key"

    def test_get_missing_returns_none(self, vault):
        assert vault.get("nonexistent") is None

    def test_list_names(self, vault):
        vault.store(VaultCredential(name="a", type="bearer", value="v1"))
        vault.store(VaultCredential(name="b", type="api_key", value="v2"))
        names = vault.list_names()
        assert sorted(names) == ["a", "b"]

    def test_remove(self, vault):
        vault.store(VaultCredential(name="temp", type="bearer", value="v"))
        assert vault.remove("temp") is True
        assert vault.get("temp") is None

    def test_remove_nonexistent(self, vault):
        assert vault.remove("nope") is False

    def test_persist_across_instances(self, vault_path):
        # Store in first instance
        v1 = Vault(vault_path)
        v1.unlock("secret")
        v1.store(VaultCredential(name="persist", type="bearer", value="tok"))

        # Load in second instance
        v2 = Vault(vault_path)
        v2.unlock("secret")
        cred = v2.get("persist")
        assert cred is not None
        assert cred.value == "tok"

    def test_wrong_passphrase(self, vault_path):
        v1 = Vault(vault_path)
        v1.unlock("correct-pass")
        v1.store(VaultCredential(name="x", type="bearer", value="y"))

        v2 = Vault(vault_path)
        with pytest.raises(ValueError, match="Wrong passphrase"):
            v2.unlock("wrong-pass")

    def test_thread_safety(self, vault):
        """Concurrent store/get operations should not corrupt state."""
        errors = []

        def worker(n):
            try:
                for i in range(20):
                    name = f"thread-{n}-{i}"
                    vault.store(VaultCredential(name=name, type="bearer", value=f"val-{n}-{i}"))
                    cred = vault.get(name)
                    if cred is None or cred.value != f"val-{n}-{i}":
                        errors.append(f"Mismatch: {name}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread safety errors: {errors}"

    def test_vault_file_permissions(self, vault_path):
        v = Vault(vault_path)
        v.unlock("pass")
        v.store(VaultCredential(name="x", type="bearer", value="y"))
        # File should be 0600
        mode = vault_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_hot_reload_detects_change(self, vault_path):
        """External modification to vault file triggers _has_changes()."""
        v1 = Vault(vault_path)
        v1.unlock("pass")
        v1.store(VaultCredential(name="original", type="api_key", value="key1"))
        assert not v1._has_changes()

        # Simulate external update (e.g. CLI `safeyolo vault add`)
        v2 = Vault(vault_path)
        v2.unlock("pass")
        v2.store(VaultCredential(name="original", type="api_key", value="key1"))
        v2.store(VaultCredential(name="added", type="api_key", value="key2"))

        assert v1._has_changes()
        v1._reload()
        assert not v1._has_changes()
        assert v1.get("added") is not None
        assert v1.get("added").value == "key2"

    def test_save_without_unlock_raises(self, vault_path):
        """Calling save() on a vault that was never unlocked raises RuntimeError."""
        v = Vault(vault_path)
        with pytest.raises(RuntimeError, match="Vault not unlocked"):
            v.save()

    def test_list_names_returns_only_names(self, vault):
        """list_names() returns credential names, never values or other fields."""
        vault.store(VaultCredential(name="alpha", type="api_key", value="secret-a"))
        vault.store(VaultCredential(name="beta", type="bearer", value="secret-b"))

        names = vault.list_names()
        assert sorted(names) == ["alpha", "beta"]
        # Ensure values are NOT in the list
        for name in names:
            assert "secret" not in name


class TestVaultSingleton:
    """Tests for init_vault / get_vault module-level singleton."""

    def test_init_vault_and_get_vault_singleton(self, tmp_path):
        """init_vault creates and returns vault; get_vault returns same instance."""
        import safeyolo.core.vault as vault_mod

        path = tmp_path / "singleton.yaml.enc"
        old_vault = vault_mod._vault

        try:
            v = vault_mod.init_vault(path, "pass123")
            assert v is not None
            assert vault_mod.get_vault() is v
            assert path.exists()
        finally:
            vault_mod._vault = old_vault

    def test_get_vault_before_init_returns_none(self):
        """get_vault returns None when init_vault has not been called."""
        import safeyolo.core.vault as vault_mod

        old_vault = vault_mod._vault
        try:
            vault_mod._vault = None
            assert vault_mod.get_vault() is None
        finally:
            vault_mod._vault = old_vault
