"""macOS Keychain storage for Command Centre Admin API credentials."""

from __future__ import annotations

from typing import Protocol

KEYCHAIN_SERVICE = "io.safeyolo.command-centre"


class CredentialStoreError(RuntimeError):
    pass


class Keychain(Protocol):
    def set_password(self, service: str, username: str, password: str) -> None: ...

    def get_password(self, service: str, username: str) -> str | None: ...

    def delete_password(self, service: str, username: str) -> None: ...


def _keychain() -> Keychain:
    try:
        from keyring.backends.macOS import Keyring
    except ImportError as exc:
        raise CredentialStoreError("macOS Keychain support is unavailable") from exc
    return Keyring()


def store_token(instance_id: str, token: str) -> None:
    """Add or replace an instance's Admin API token in macOS Keychain."""
    try:
        _keychain().set_password(KEYCHAIN_SERVICE, instance_id, token)
    except Exception as exc:
        raise CredentialStoreError(f"Could not store the Admin API token: {exc}") from exc


def load_token(instance_id: str) -> str | None:
    """Return an instance token, or ``None`` when it isn't stored."""
    try:
        return _keychain().get_password(KEYCHAIN_SERVICE, instance_id)
    except Exception as exc:
        raise CredentialStoreError(f"Could not read the Admin API token: {exc}") from exc


def delete_token(instance_id: str) -> None:
    """Remove an instance token from macOS Keychain."""
    try:
        _keychain().delete_password(KEYCHAIN_SERVICE, instance_id)
    except Exception as exc:
        try:
            from keyring.errors import PasswordDeleteError
        except ImportError:
            pass
        else:
            if isinstance(exc, PasswordDeleteError):
                return
        raise CredentialStoreError(f"Could not delete the Admin API token: {exc}") from exc
