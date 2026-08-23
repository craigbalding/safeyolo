"""
credential_provider.py - Provider-neutral credential resolution for the Service Gateway.

The Service Gateway holds no secrets of its own; it looks up a *reference* attached
to a TokenBinding and asks the appropriate CredentialProvider to resolve it into a
concrete credential value. Resolution happens only after policy + approval have
cleared, and the resolved value is injected into the intercepted upstream request
without being persisted, logged, or returned to the agent.

Reference grammar (kept intentionally trivial for the first two providers):

    - Bare name              → local vault credential of that name
    - "local://<name>"       → explicit local vault form
    - "op://vault/item/field" → 1Password reference resolved via `op read`
    - Anything else (unknown URI scheme) → fails closed with UnknownScheme

New providers register themselves by scheme; there is no on-disk provider config yet.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from safeyolo.core.utils import sanitize_for_log

log = logging.getLogger("safeyolo.credential-provider")


class CredentialProviderError(Exception):
    """Base for provider errors. Message must never contain secret material."""

    code: str = "PROVIDER_ERROR"


class UnknownScheme(CredentialProviderError):
    """Credential reference used an unrecognised URI scheme — fail closed."""

    code = "PROVIDER_UNKNOWN"


class CredentialNotFound(CredentialProviderError):
    """Provider knows the scheme but has no credential at that reference."""

    code = "CREDENTIAL_NOT_FOUND"


class ResolveFailed(CredentialProviderError):
    """Provider tried to resolve and failed for a runtime reason (timeout, auth, …)."""

    code = "PROVIDER_RESOLVE_FAILED"


@dataclass
class ResolvedCredential:
    """A credential value returned by a provider, ready for injection.

    `type` mirrors the vault credential schema ("bearer" | "api_key" | "basic" |
    "oauth2") so downstream code can decide whether OAuth2 refresh is applicable.
    External-vault providers typically return "bearer".
    """

    value: str
    type: str = "bearer"
    expires_at: str | None = None  # ISO 8601; only OAuth2 credentials set this

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        from datetime import UTC, datetime

        try:
            return datetime.now(UTC) >= datetime.fromisoformat(self.expires_at)
        except ValueError:
            # Corrupt expiry → treat as expired (fail closed).
            return True


@runtime_checkable
class CredentialProvider(Protocol):
    """A backend that can resolve a credential reference into a concrete value."""

    scheme: str  # URI scheme this provider handles (e.g. "local", "op")

    def resolve(self, ref: str) -> ResolvedCredential: ...

    def refresh(self, ref: str) -> ResolvedCredential | None:
        """Optional. Return a fresh credential if the provider supports refresh.

        Providers that cannot refresh (e.g. `op read`) should return None so the
        gateway skips the OAuth2 refresh path silently.
        """
        ...


# ---------------------------------------------------------------------------
# Registry + dispatch
# ---------------------------------------------------------------------------

_providers: dict[str, CredentialProvider] = {}
_providers_lock = threading.RLock()


def register_provider(provider: CredentialProvider) -> None:
    """Register a provider under its `scheme`. Idempotent — later calls overwrite."""
    with _providers_lock:
        _providers[provider.scheme] = provider
        log.info("Registered credential provider: %s", provider.scheme)


def get_provider(scheme: str) -> CredentialProvider | None:
    with _providers_lock:
        return _providers.get(scheme)


def _split_ref(ref: str) -> tuple[str, str]:
    """Return (scheme, rest). Bare names → ('local', ref)."""
    if not ref:
        # Empty ref is treated as local-lookup-of-empty-name; the local provider
        # will fail closed with CredentialNotFound. We do NOT special-case empty
        # here because the compiler already warns on empty tokens.
        return ("local", ref)
    # A scheme must contain "://" and use only [a-z0-9+-.] before it.
    marker = ref.find("://")
    if marker <= 0:
        return ("local", ref)
    scheme = ref[:marker]
    rest = ref[marker + 3 :]
    if not scheme.replace("-", "").replace("+", "").replace(".", "").isalnum():
        return ("local", ref)  # Not a valid URI scheme; treat as opaque local name.
    return (scheme.lower(), rest)


def resolve_credential(ref: str) -> ResolvedCredential:
    """Resolve `ref` through the registered provider for its scheme.

    Raises:
        UnknownScheme: scheme has no registered provider — fail closed.
        CredentialNotFound: provider recognises the scheme but the ref is missing.
        ResolveFailed: transient/runtime resolution failure (never carries secret).
    """
    scheme, _rest = _split_ref(ref)
    provider = get_provider(scheme)
    if provider is None:
        raise UnknownScheme(
            f"No provider registered for scheme '{sanitize_for_log(scheme)}'"
        )
    # Pass the full ref: providers decide whether they want the prefix stripped.
    return provider.resolve(ref)


def refresh_credential(ref: str) -> ResolvedCredential | None:
    """Ask the provider for `ref` to refresh in place, if it supports refresh."""
    scheme, _rest = _split_ref(ref)
    provider = get_provider(scheme)
    if provider is None:
        return None
    refresh = getattr(provider, "refresh", None)
    if refresh is None:
        return None
    try:
        return refresh(ref)
    except CredentialProviderError:
        return None


def strip_scheme(ref: str) -> str:
    """Return the ref with any recognised scheme prefix removed.

    Convenience for providers that want the bare name after the scheme.
    """
    scheme, rest = _split_ref(ref)
    if scheme == "local" and not ref.startswith("local://"):
        return ref  # Bare name — no prefix to strip.
    return rest


def _reset_for_tests() -> None:
    """Clear the registry. Test-only."""
    with _providers_lock:
        _providers.clear()
