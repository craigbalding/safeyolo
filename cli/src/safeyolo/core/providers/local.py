"""
providers/local.py - Local Fernet-encrypted vault as a CredentialProvider.

Wraps the existing `safeyolo.core.vault.Vault` singleton without altering its
behaviour. Accepts references in two forms:

    - Bare name (`github-pat`) — the historical format used in policy.toml.
    - `local://<name>` — explicit form, useful when a project mixes providers.

Preserves the OAuth2 refresh path by delegating to `Vault.refresh_oauth2()`.
"""

from __future__ import annotations

import logging

from safeyolo.core.credential_provider import (
    CredentialNotFound,
    ResolveFailed,
    ResolvedCredential,
    strip_scheme,
)
from safeyolo.core.utils import sanitize_for_log
from safeyolo.core.vault import get_vault

log = logging.getLogger("safeyolo.credential-provider.local")


class LocalVaultProvider:
    scheme = "local"

    def _name(self, ref: str) -> str:
        return strip_scheme(ref)

    def resolve(self, ref: str) -> ResolvedCredential:
        name = self._name(ref)
        vault = get_vault()
        if vault is None:
            raise ResolveFailed("Local vault is not loaded")
        cred = vault.get(name)
        if cred is None:
            raise CredentialNotFound(
                f"Local vault has no credential named '{sanitize_for_log(name)}'"
            )
        return ResolvedCredential(
            value=cred.value,
            type=cred.type,
            expires_at=cred.expires_at,
        )

    def refresh(self, ref: str) -> ResolvedCredential | None:
        name = self._name(ref)
        vault = get_vault()
        if vault is None:
            return None
        if not vault.refresh_oauth2(name):
            return None
        cred = vault.get(name)
        if cred is None:
            return None
        return ResolvedCredential(
            value=cred.value,
            type=cred.type,
            expires_at=cred.expires_at,
        )
