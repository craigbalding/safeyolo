"""
vault.py - Encrypted credential store for Service Gateway

Fernet-encrypted YAML vault, unlocked at startup with a passphrase.
Key derivation: PBKDF2HMAC(passphrase) -> Fernet key.

Thread-safe via RLock on all access. Module singleton via get_vault()/init_vault().

Usage:
    from safeyolo.core.vault import init_vault, get_vault

    init_vault(Path("/safeyolo/data/vault.yaml.enc"), "my-passphrase")
    vault = get_vault()
    vault.store(VaultCredential(name="gmail", type="oauth2", value="ya29.xxx"))
    cred = vault.get("gmail")
"""

import base64
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

log = logging.getLogger("safeyolo.vault")

# PBKDF2 parameters
_KDF_ITERATIONS = 480_000
_KDF_SALT_LEN = 16


@dataclass
class VaultCredential:
    """A credential stored in the vault."""
    name: str
    type: str  # oauth2, api_key, bearer
    value: str
    refresh_token: str | None = None
    token_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    expires_at: str | None = None  # ISO 8601

    def is_expired(self) -> bool:
        """Check if credential is expired (for OAuth2 tokens)."""
        if not self.expires_at:
            return False
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            return datetime.now(UTC) >= expiry
        except ValueError:
            # Unparseable expiry date — treat as expired (fail-closed).
            # A credential with a corrupt expiry should force a refresh
            # rather than being silently treated as valid forever.
            return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for YAML storage."""
        d: dict[str, Any] = {"name": self.name, "type": self.type, "value": self.value}
        if self.refresh_token:
            d["refresh_token"] = self.refresh_token
        if self.token_url:
            d["token_url"] = self.token_url
        if self.client_id:
            d["client_id"] = self.client_id
        if self.client_secret:
            d["client_secret"] = self.client_secret
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VaultCredential":
        """Deserialize from dict."""
        return cls(
            name=d["name"],
            type=d["type"],
            value=d["value"],
            refresh_token=d.get("refresh_token"),
            token_url=d.get("token_url"),
            client_id=d.get("client_id"),
            client_secret=d.get("client_secret"),
            expires_at=d.get("expires_at"),
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive Fernet key from passphrase using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


class Vault:
    """Encrypted credential store.

    Credentials are stored in a Fernet-encrypted YAML file.
    All operations are thread-safe via RLock.
    """

    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.RLock()
        self._credentials: dict[str, VaultCredential] = {}
        self._fernet: Fernet | None = None
        self._salt: bytes | None = None
        self._last_mtime: float = 0.0
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()

    def unlock(self, passphrase: str) -> None:
        """Unlock the vault with a passphrase.

        If the vault file exists, decrypts and loads credentials.
        If not, initializes an empty vault with a new salt.

        Raises:
            ValueError: If passphrase is wrong (decryption fails)
        """
        with self._lock:
            if self._path.exists():
                raw = self._path.read_bytes()
                # First 16 bytes are salt
                self._salt = raw[:_KDF_SALT_LEN]
                key = _derive_key(passphrase, self._salt)
                self._fernet = Fernet(key)
                try:
                    plaintext = self._fernet.decrypt(raw[_KDF_SALT_LEN:])
                except InvalidToken:
                    self._fernet = None
                    self._salt = None
                    raise ValueError("Wrong passphrase or corrupted vault")
                data = yaml.safe_load(plaintext.decode()) or {}
                self._credentials = {}
                for cred_dict in data.get("credentials", []):
                    cred = VaultCredential.from_dict(cred_dict)
                    self._credentials[cred.name] = cred
                self._last_mtime = self._path.stat().st_mtime
                log.info(f"Vault unlocked: {len(self._credentials)} credentials loaded")
            else:
                import os
                self._salt = os.urandom(_KDF_SALT_LEN)
                key = _derive_key(passphrase, self._salt)
                self._fernet = Fernet(key)
                self._credentials = {}
                self.save()
                log.info("Vault created (empty)")

    def get(self, name: str) -> VaultCredential | None:
        """Get a credential by name. Returns None if not found."""
        with self._lock:
            return self._credentials.get(name)

    def store(self, cred: VaultCredential) -> None:
        """Store or update a credential, then persist to disk."""
        with self._lock:
            self._credentials[cred.name] = cred
            self.save()
            log.info(f"Stored credential: {cred.name} (type={cred.type})")

    def remove(self, name: str) -> bool:
        """Remove a credential by name. Returns True if removed."""
        with self._lock:
            if name in self._credentials:
                del self._credentials[name]
                self.save()
                log.info(f"Removed credential: {name}")
                return True
            return False

    def save(self) -> None:
        """Encrypt and persist vault to disk."""
        with self._lock:
            if not self._fernet or self._salt is None:
                raise RuntimeError("Vault not unlocked")

            data = {
                "credentials": [c.to_dict() for c in self._credentials.values()]
            }
            plaintext = yaml.dump(data, default_flow_style=False).encode()
            encrypted = self._fernet.encrypt(plaintext)

            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Write atomically via temp file
            tmp = self._path.with_suffix(".tmp")
            tmp.write_bytes(self._salt + encrypted)
            tmp.rename(self._path)
            # Restrict permissions
            self._path.chmod(0o600)
            self._last_mtime = self._path.stat().st_mtime

    def _has_changes(self) -> bool:
        """Check if vault file has been modified since last load."""
        if not self._path.exists():
            return False
        return self._path.stat().st_mtime != self._last_mtime

    def start_watcher(self) -> None:
        """Start background file watcher for vault changes."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    if self._has_changes():
                        log.info("Vault file changed, reloading...")
                        self._reload()
                except Exception as e:
                    log.warning(f"Vault watcher error: {type(e).__name__}: {e}")
                self._watcher_stop.wait(timeout=2.0)

        self._watcher_thread = threading.Thread(
            target=watch_loop, daemon=True, name="vault-watcher"
        )
        self._watcher_thread.start()
        log.info("Started vault file watcher")

    def stop_watcher(self) -> None:
        """Stop file watcher."""
        if self._watcher_thread:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
            self._watcher_stop.clear()

    def _reload(self) -> None:
        """Re-read and decrypt the vault file using the existing key."""
        with self._lock:
            if not self._fernet or self._salt is None:
                return
            try:
                raw = self._path.read_bytes()
                plaintext = self._fernet.decrypt(raw[_KDF_SALT_LEN:])
                data = yaml.safe_load(plaintext.decode()) or {}
                self._credentials = {}
                for cred_dict in data.get("credentials", []):
                    cred = VaultCredential.from_dict(cred_dict)
                    self._credentials[cred.name] = cred
                self._last_mtime = self._path.stat().st_mtime
                log.info(f"Vault reloaded: {len(self._credentials)} credentials")
            except InvalidToken:
                log.error("Vault reload failed: passphrase/key mismatch (vault may have been re-encrypted)")
            except Exception as e:
                log.warning(f"Vault reload failed: {type(e).__name__}: {e}")

    def list_names(self) -> list[str]:
        """List credential names (never values)."""
        with self._lock:
            return list(self._credentials.keys())

    def refresh_oauth2(self, name: str) -> bool:
        """Refresh an OAuth2 token if near expiry.

        Returns True if refresh succeeded, False otherwise.
        """
        with self._lock:
            cred = self._credentials.get(name)
            if not cred:
                return False
            if cred.type != "oauth2":
                return False
            if not cred.refresh_token or not cred.token_url:
                return False
            if not cred.is_expired():
                return False

        # Do HTTP call outside lock to avoid blocking
        try:
            import httpx
            response = httpx.post(
                cred.token_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": cred.refresh_token,
                    "client_id": cred.client_id or "",
                    "client_secret": cred.client_secret or "",
                },
                timeout=10.0,
            )
            response.raise_for_status()
            token_data = response.json()
        except Exception as e:
            log.error(f"OAuth2 refresh failed for {name}: {type(e).__name__}: {e}")
            return False

        with self._lock:
            cred = self._credentials.get(name)
            if not cred:
                return False
            cred.value = token_data["access_token"]
            if "refresh_token" in token_data:
                cred.refresh_token = token_data["refresh_token"]
            if "expires_in" in token_data:
                from datetime import timedelta
                expires_at = datetime.now(UTC) + timedelta(seconds=token_data["expires_in"])
                cred.expires_at = expires_at.isoformat()
            self.save()
            log.info(f"OAuth2 token refreshed for {name}")
            return True


# Module singleton
_vault: Vault | None = None
_vault_lock = threading.Lock()


def init_vault(path: Path, passphrase: str) -> Vault:
    """Initialize and unlock the module-level vault singleton."""
    global _vault
    with _vault_lock:
        _vault = Vault(path)
        _vault.unlock(passphrase)
        return _vault


def get_vault() -> Vault | None:
    """Get the module-level vault singleton. Returns None if not initialized."""
    return _vault
