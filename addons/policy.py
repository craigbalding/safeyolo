"""
policy.py - Native mitmproxy addon for unified policy configuration

Provides domain-specific and client-specific addon policies with hot reload.
Other addons check policy before acting.

Usage:
    mitmdump -s addons/policy.py --set policy_file=/path/to/policy.yaml

Policy file format (YAML):
    defaults:
      addons:
        pattern_scanner: { enabled: true, block_on_match: true }
        rate_limiter: { enabled: true }

    domains:
      "api.openai.com":
        addons:
          prompt_injection: { enabled: true, mode: dual }

      "*.internal.corp":
        bypass: [yara_scanner, pattern_scanner]

    clients:
      "admin-*":
        bypass: [pattern_scanner]
"""

import fnmatch
import json
import logging
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.policy")

# Try to import yaml, fall back to JSON-only if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None


@dataclass
class AddonPolicy:
    """Policy settings for a single addon."""
    enabled: bool = True
    settings: dict[str, Any] = field(default_factory=dict)

    def merge_with(self, other: "AddonPolicy") -> "AddonPolicy":
        """Merge with another policy (other takes precedence)."""
        merged_settings = {**self.settings, **other.settings}
        return AddonPolicy(
            enabled=other.enabled,
            settings=merged_settings,
        )


@dataclass
class RequestPolicy:
    """Complete policy for a specific request."""
    addons: dict[str, AddonPolicy] = field(default_factory=dict)
    bypassed_addons: set[str] = field(default_factory=set)

    def is_addon_enabled(self, addon_name: str) -> bool:
        """Check if addon is enabled and not bypassed."""
        if addon_name in self.bypassed_addons:
            return False
        addon_policy = self.addons.get(addon_name)
        if addon_policy is None:
            return True  # Default to enabled if not specified
        return addon_policy.enabled

    def get_addon_settings(self, addon_name: str) -> dict[str, Any]:
        """Get settings for an addon."""
        addon_policy = self.addons.get(addon_name)
        if addon_policy is None:
            return {}
        return addon_policy.settings


class PolicyEngine:
    """
    Native mitmproxy addon for unified policy configuration.

    Loads policy from YAML/JSON file and provides domain/client-specific
    addon configuration. Supports hot reload via SIGHUP or file watching.

    Other addons access policy via flow.metadata["policy"] or by
    calling get_request_policy() directly.
    """

    name = "policy"

    def __init__(self):
        self.policy_path: Optional[Path] = None
        self.watch_for_changes: bool = False

        # Policy data
        self._raw_policy: dict = {}
        self._defaults: dict[str, AddonPolicy] = {}
        self._domain_policies: dict[str, dict[str, AddonPolicy]] = {}
        self._domain_bypasses: dict[str, set[str]] = {}
        self._client_policies: dict[str, dict[str, AddonPolicy]] = {}
        self._client_bypasses: dict[str, set[str]] = {}

        # Thread safety
        self._lock = threading.RLock()
        self._last_load_time: float = 0
        self._last_mtime: float = 0

        # File watcher
        self._watcher_thread: Optional[threading.Thread] = None
        self._watcher_stop = threading.Event()

        # Stats
        self.lookups_total = 0
        self.cache_hits = 0

        # Simple cache
        self._cache: dict[tuple, RequestPolicy] = {}
        self._cache_max_size = 1000

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="policy_file",
            typespec=Optional[str],
            default=None,
            help="Path to policy YAML/JSON file",
        )
        loader.add_option(
            name="policy_watch",
            typespec=bool,
            default=True,
            help="Watch policy file for changes",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "policy_file" in updates:
            path = ctx.options.policy_file
            if path:
                self.policy_path = Path(path)
                self._reload_policy()

        if "policy_watch" in updates:
            self.watch_for_changes = ctx.options.policy_watch
            if self.watch_for_changes and self.policy_path:
                self._start_watcher()
            else:
                self._stop_watcher()

        # Setup SIGHUP handler
        self._setup_signal_handler()

    def _setup_signal_handler(self):
        """Setup SIGHUP handler for hot reload."""
        try:
            signal.signal(signal.SIGHUP, self._handle_sighup)
        except (ValueError, OSError):
            pass  # Not main thread or not supported

    def _handle_sighup(self, signum, frame):
        """Handle SIGHUP signal."""
        log.info("Received SIGHUP, reloading policy...")
        self._reload_policy()

    def _start_watcher(self):
        """Start background thread to watch for file changes."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    if self.policy_path and self.policy_path.exists():
                        mtime = self.policy_path.stat().st_mtime
                        if mtime > self._last_mtime:
                            log.info("Policy file changed, reloading...")
                            self._reload_policy()
                except Exception as e:
                    log.warning(f"Error checking policy file: {type(e).__name__}: {e}")

                self._watcher_stop.wait(timeout=5.0)

        self._watcher_thread = threading.Thread(target=watch_loop, daemon=True)
        self._watcher_thread.start()
        log.info(f"Started policy file watcher for {self.policy_path}")

    def _stop_watcher(self):
        """Stop the file watcher thread."""
        if self._watcher_thread:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
            self._watcher_stop.clear()

    def _reload_policy(self) -> bool:
        """Reload policy from file."""
        if not self.policy_path:
            return False

        if not self.policy_path.exists():
            log.warning(f"Policy file not found: {self.policy_path}")
            return False

        try:
            with open(self.policy_path) as f:
                content = f.read()

            # Parse based on extension
            if self.policy_path.suffix in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    log.error("PyYAML not installed, cannot load YAML policy")
                    return False
                raw_policy = yaml.safe_load(content) or {}
            else:
                raw_policy = json.loads(content)

            with self._lock:
                self._parse_policy(raw_policy)
                self._raw_policy = raw_policy
                self._last_load_time = time.time()
                self._last_mtime = self.policy_path.stat().st_mtime
                self._cache.clear()

            log.info(
                f"Policy reloaded: {len(self._defaults)} defaults, "
                f"{len(self._domain_policies)} domain rules, "
                f"{len(self._client_policies)} client rules"
            )
            return True

        except Exception as e:
            log.error(f"Failed to load policy: {type(e).__name__}: {e}")
            return False

    def _parse_policy(self, raw: dict):
        """Parse raw config into policy structures."""
        # Parse defaults
        self._defaults = {}
        defaults_raw = raw.get("defaults", {}).get("addons", {})
        for addon_name, settings in defaults_raw.items():
            self._defaults[addon_name] = self._parse_addon_policy(settings)

        # Parse domain policies
        self._domain_policies = {}
        self._domain_bypasses = {}
        for domain_pattern, domain_config in raw.get("domains", {}).items():
            addons = {}
            for addon_name, settings in domain_config.get("addons", {}).items():
                addons[addon_name] = self._parse_addon_policy(settings)
            self._domain_policies[domain_pattern] = addons

            bypasses = set(domain_config.get("bypass", []))
            if bypasses:
                self._domain_bypasses[domain_pattern] = bypasses

        # Parse client policies
        self._client_policies = {}
        self._client_bypasses = {}
        for client_pattern, client_config in raw.get("clients", {}).items():
            addons = {}
            for addon_name, settings in client_config.get("addons", {}).items():
                addons[addon_name] = self._parse_addon_policy(settings)
            self._client_policies[client_pattern] = addons

            bypasses = set(client_config.get("bypass", []))
            if bypasses:
                self._client_bypasses[client_pattern] = bypasses

    def _parse_addon_policy(self, settings) -> AddonPolicy:
        """Parse addon settings into AddonPolicy."""
        if isinstance(settings, bool):
            return AddonPolicy(enabled=settings)

        settings = dict(settings)  # Copy to avoid mutation
        enabled = settings.pop("enabled", True)
        return AddonPolicy(enabled=enabled, settings=settings)

    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """Check if value matches pattern (supports wildcards)."""
        if value == pattern:
            return True
        return fnmatch.fnmatch(value, pattern)

    def get_request_policy(
        self,
        domain: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> RequestPolicy:
        """
        Get complete policy for a request.

        Merges defaults -> domain rules -> client rules (later takes precedence).
        """
        self.lookups_total += 1

        # Check cache
        cache_key = (domain, client_id)
        if cache_key in self._cache:
            self.cache_hits += 1
            return self._cache[cache_key]

        with self._lock:
            policy = RequestPolicy()

            # Start with defaults
            for addon_name, addon_policy in self._defaults.items():
                policy.addons[addon_name] = AddonPolicy(
                    enabled=addon_policy.enabled,
                    settings=dict(addon_policy.settings),
                )

            # Apply domain-specific policies
            if domain:
                for pattern, domain_addons in self._domain_policies.items():
                    if self._matches_pattern(domain, pattern):
                        for addon_name, addon_policy in domain_addons.items():
                            if addon_name in policy.addons:
                                policy.addons[addon_name] = policy.addons[addon_name].merge_with(addon_policy)
                            else:
                                policy.addons[addon_name] = addon_policy

                for pattern, bypasses in self._domain_bypasses.items():
                    if self._matches_pattern(domain, pattern):
                        policy.bypassed_addons.update(bypasses)

            # Apply client-specific policies (highest precedence)
            if client_id:
                for pattern, client_addons in self._client_policies.items():
                    if self._matches_pattern(client_id, pattern):
                        for addon_name, addon_policy in client_addons.items():
                            if addon_name in policy.addons:
                                policy.addons[addon_name] = policy.addons[addon_name].merge_with(addon_policy)
                            else:
                                policy.addons[addon_name] = addon_policy

                for pattern, bypasses in self._client_bypasses.items():
                    if self._matches_pattern(client_id, pattern):
                        policy.bypassed_addons.update(bypasses)

            # Cache result
            if len(self._cache) < self._cache_max_size:
                self._cache[cache_key] = policy

            return policy

    def request(self, flow: http.HTTPFlow):
        """Attach policy to flow for other addons to use."""
        domain = flow.request.host

        # Extract client ID from header if present
        client_id = flow.request.headers.get("X-Client-ID")

        policy = self.get_request_policy(domain, client_id)
        flow.metadata["policy"] = policy
        flow.metadata["policy_domain"] = domain
        flow.metadata["policy_client"] = client_id

    def is_addon_enabled(
        self,
        addon_name: str,
        flow: Optional[http.HTTPFlow] = None,
        domain: Optional[str] = None,
    ) -> bool:
        """
        Check if an addon is enabled for the given context.

        Other addons call this to check if they should process a request.
        """
        if flow and "policy" in flow.metadata:
            policy = flow.metadata["policy"]
        else:
            policy = self.get_request_policy(domain)

        return policy.is_addon_enabled(addon_name)

    def get_addon_settings(
        self,
        addon_name: str,
        flow: Optional[http.HTTPFlow] = None,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get settings for an addon from policy."""
        if flow and "policy" in flow.metadata:
            policy = flow.metadata["policy"]
        else:
            policy = self.get_request_policy(domain)

        return policy.get_addon_settings(addon_name)

    def done(self):
        """Cleanup on shutdown."""
        self._stop_watcher()

    def get_stats(self) -> dict:
        """Get policy engine statistics."""
        with self._lock:
            return {
                "policy_file": str(self.policy_path) if self.policy_path else None,
                "last_load_time": self._last_load_time,
                "watching": self._watcher_thread is not None,
                "default_addons": list(self._defaults.keys()),
                "domain_rules_count": len(self._domain_policies),
                "client_rules_count": len(self._client_policies),
                "lookups_total": self.lookups_total,
                "cache_hits": self.cache_hits,
                "cache_size": len(self._cache),
                "cache_hit_rate": self.cache_hits / max(1, self.lookups_total),
            }


# Global instance for other addons to access
_policy_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> Optional[PolicyEngine]:
    """Get the policy engine instance."""
    return _policy_engine


# mitmproxy addon instance
policy_engine = PolicyEngine()
_policy_engine = policy_engine
addons = [policy_engine]
