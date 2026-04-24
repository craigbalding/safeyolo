"""Process-wide cache for PolicyClient.get_sensor_config().

Before: each request/response hook calling `get_policy_client().
get_sensor_config()` hit the PDP — either an in-process dict-lookup
with lock overhead or (when the PDP runs out-of-process) an HTTP
roundtrip. Multiple addons do this per flow, so a typical request
triggers 3-5 such calls.

After: addons call `config_cache.get()`. A module-level singleton
holds the last-fetched dict; the first access populates it, subsequent
accesses are a lock-free read of the cached reference.

Invalidation:
  - LocalPolicyClient: the cache registers `invalidate` as a reload
    callback on the client; when the policy file changes, the next
    `get()` re-fetches. No TTL — changes are caught instantly.
  - HTTPClient: no reload signal exists (the client can't observe
    remote policy changes). Falls back to a TTL that the next `get()`
    after expiry treats as an implicit invalidation. Default 30 s;
    override via `SAFEYOLO_CONFIG_CACHE_TTL_S`.

Fall-through behaviour: when the PDP isn't configured yet (startup
race) `get()` returns `{}` — same shape as the HTTP client's timeout
fallback, so callers need no extra handling.
"""
from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger("safeyolo.config-cache")

# Default TTL in seconds, applied only when the active PolicyClient
# has no reload-callback signal (today: HTTPClient). Kept short —
# operators can restart the proxy for immediate cutover, and 30 s
# bounds how long stale config can serve traffic after a remote
# policy change.
_DEFAULT_HTTP_TTL_S = 30.0


class _ConfigCache:
    def __init__(self) -> None:
        self._config: dict | None = None
        self._lock = threading.Lock()
        self._callback_registered = False
        self._fetched_at: float | None = None
        # None = no TTL (reload-driven invalidation only). Set to a
        # positive float for HTTP-client fallback staleness bounding.
        self._ttl_s: float | None = None

    def get(self) -> dict:
        """Return cached sensor_config, fetching on first call.

        The cache is invalidated on policy reload (LocalPolicyClient)
        or on TTL expiry (HTTPClient fallback), so the slow path only
        fires after the first access per process, after each policy
        change, and — for HTTP deployments — at most once per TTL.
        """
        # Fast path: lock-free read of the cached reference. `dict`
        # assignment is atomic under the GIL, so a concurrent writer
        # either leaves the old reference or installs the new one —
        # never a torn value.
        cfg = self._config
        if cfg is not None and not self._expired():
            return cfg
        return self._fetch_and_cache()

    def _fetch_and_cache(self) -> dict:
        try:
            return self._fetch_raising()
        except Exception as exc:  # noqa: BLE001 — silent fallback is the contract
            log.warning("config_cache fetch failed: %s: %s", type(exc).__name__, exc)
            return {}

    def get_or_raise(self) -> dict:
        """Return cached sensor_config; propagate fetch errors to caller.

        Used by addons that need to distinguish "PDP not configured
        yet" from "PDP returned an error" and log at different levels
        (e.g. credential_guard.first-load vs subsequent-load). The
        caching behaviour is the same as `get()` — only the first call
        and calls after `invalidate()` can raise; hits on a populated
        cache are error-free.

        Raises:
            RuntimeError: PolicyClient not configured
            Exception: whatever `client.get_sensor_config()` raises
        """
        cfg = self._config
        if cfg is not None and not self._expired():
            return cfg
        return self._fetch_raising()

    def _expired(self) -> bool:
        """True if a TTL is set and the cached entry is past it."""
        if self._ttl_s is None or self._fetched_at is None:
            return False
        return (time.monotonic() - self._fetched_at) > self._ttl_s

    def _fetch_raising(self) -> dict:
        from pdp import get_policy_client, is_policy_client_configured
        if not is_policy_client_configured():
            raise RuntimeError("PolicyClient not configured")
        client = get_policy_client()
        new_config = client.get_sensor_config()
        with self._lock:
            self._config = new_config
            self._fetched_at = time.monotonic()
            self._ensure_reload_or_ttl(client)
        return new_config

    def _ensure_reload_or_ttl(self, client) -> None:
        """Register reload callback, or fall back to TTL, once.

        LocalPolicyClient has `add_reload_callback`, so cache
        invalidation is signal-driven and the TTL stays `None`
        (infinite). HTTPClient has no such signal — we set a
        TTL so the cache eventually refreshes even without an
        explicit invalidation. The `hasattr` check mirrors the
        pattern already used in service_gateway.py.
        """
        if self._callback_registered:
            return
        if hasattr(client, "add_reload_callback"):
            client.add_reload_callback(self.invalidate)
        else:
            try:
                self._ttl_s = float(
                    os.environ.get("SAFEYOLO_CONFIG_CACHE_TTL_S",
                                   str(_DEFAULT_HTTP_TTL_S))
                )
            except ValueError:
                self._ttl_s = _DEFAULT_HTTP_TTL_S
            log.info(
                "config_cache: TTL fallback (%.1fs) — PolicyClient has no reload signal",
                self._ttl_s,
            )
        self._callback_registered = True

    def invalidate(self) -> None:
        """Drop the cached config.

        Wired to PolicyClient reload callbacks. Next `get()` re-fetches.
        Safe to call from any thread.
        """
        with self._lock:
            self._config = None
            self._fetched_at = None

    # ---- Convenience accessors -------------------------------------------
    # Keep callers from chaining `.get("...", [])` against the result dict.

    def credential_rules(self) -> list:
        return self.get().get("credential_rules", [])

    def scan_patterns(self) -> list:
        return self.get().get("scan_patterns", [])

    def policy_hash(self) -> str:
        return self.get().get("policy_hash", "")

    def addon_section(self, addon: str) -> dict:
        """Return `config["addons"][<addon>]`, or `{}` if absent."""
        return self.get().get("addons", {}).get(addon, {})


_cache = _ConfigCache()


# Module-level convenience so callers can just `from config_cache import get`.
def get() -> dict:
    return _cache.get()


def get_or_raise() -> dict:
    return _cache.get_or_raise()


def invalidate() -> None:
    _cache.invalidate()


def credential_rules() -> list:
    return _cache.credential_rules()


def scan_patterns() -> list:
    return _cache.scan_patterns()


def policy_hash() -> str:
    return _cache.policy_hash()


def addon_section(addon: str) -> dict:
    return _cache.addon_section(addon)


# This module is pure infrastructure — not a mitmproxy addon. The empty
# `addons` list makes the intent explicit for anyone tempted to wire it
# up with `-s`.
addons: list = []
