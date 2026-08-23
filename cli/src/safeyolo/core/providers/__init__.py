"""
providers - concrete CredentialProvider implementations for the Service Gateway.

Providers register themselves at import time via `register_provider()`. Import
`safeyolo.core.providers` once at startup to make all built-in providers
available to `resolve_credential()`.
"""

from safeyolo.core.credential_provider import register_provider
from safeyolo.core.providers.local import LocalVaultProvider
from safeyolo.core.providers.onepassword import OnePasswordProvider


def register_builtin_providers() -> None:
    """Idempotently register the built-in providers.

    Safe to call from multiple init paths; `register_provider()` is idempotent.
    """
    register_provider(LocalVaultProvider())
    register_provider(OnePasswordProvider())


register_builtin_providers()
