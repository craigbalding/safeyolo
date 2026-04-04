"""
policy_loader.py - Policy file loading, watching, and hot reload

Handles:
- Loading baseline and task policies from YAML/JSON
- Host-centric policy compilation (hosts: → permissions:)
- File watching with auto-reload
- Thread-safe policy access

Usage:
    loader = PolicyLoader(baseline_path)
    loader.start_watcher()

    policy = loader.baseline  # Current baseline policy
    loader.load_task_policy(task_path)  # Load task policy
"""

import json
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from policy_engine import UnifiedPolicy

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

from datetime import UTC

from policy_compiler import compile_policy, is_host_centric
from utils import sanitize_for_log, write_event

from audit_schema import EventKind, Severity

log = logging.getLogger("safeyolo.policy-loader")


def _specificity_score(pattern: str) -> int:
    """Calculate specificity score for permission ordering.

    More specific patterns (fewer wildcards, longer) score higher.
    """
    score = len(pattern) * 10
    if "*" in pattern:
        score -= pattern.count("*") * 50
    if pattern == "*":
        score = 0
    return score


def _is_exact_resource(resource: str) -> bool:
    """Check if a permission resource is an exact host/* pattern.

    Exact: "api.openai.com/*" (host + single trailing /*)
    Pattern: "*.googleapis.com/*", "*", "minifuse:/v1/feeds/*", "/v1/**"

    Only matches the host/* format used by network:request and credential:use
    evaluations (e.g., "api.openai.com/*"). Resources with deeper paths or
    service:path formats are treated as patterns even if they end with /*.
    """
    if not resource.endswith("/*"):
        return False
    prefix = resource[:-2]  # strip trailing /*
    # Must be a simple host (no slashes, no colons, no glob chars in prefix)
    if "/" in prefix or ":" in prefix:
        return False
    return "*" not in prefix and "?" not in prefix and "[" not in prefix


def _is_simple_permission(perm) -> bool:
    """Check if a permission is simple enough to reduce to a set entry.

    Simple: explicit tier, no condition, effect is deny/prompt/allow (not budget).
    These are the bulk of expanded list permissions (e.g., 92k blocklist denies).
    """
    return (
        perm.tier == "explicit"
        and perm.condition is None
        and perm.effect != "budget"
    )


def _build_permission_index(permissions):
    """Partition sorted permissions into three tiers for lookup.

    Args:
        permissions: Pre-sorted list of Permission objects

    Returns:
        (simple_sets, exact_dict, pattern_list) where:
        - simple_sets: {(action, effect): set(resource, ...)} for O(1) set lookup
          (no condition, no budget — just check membership)
        - exact_dict: {(action, resource): [Permission, ...]} for O(1) dict lookup
          (has conditions or budget — need full Permission check)
        - pattern_list: [Permission, ...] for linear scan (wildcards/globs only)
    """
    simple: dict[tuple[str, str], set[str]] = {}
    exact: dict[tuple[str, str], list] = {}
    patterns = []

    for perm in permissions:
        if _is_exact_resource(perm.resource):
            if _is_simple_permission(perm):
                # Reduce to set membership — no Permission object needed
                set_key = (perm.action, perm.effect)
                simple.setdefault(set_key, set()).add(perm.resource)
            else:
                # Keep full Permission for condition/budget checking
                key = (perm.action, perm.resource)
                exact.setdefault(key, []).append(perm)
        else:
            patterns.append(perm)

    return simple, exact, patterns


def _is_simple_permission_dict(p: dict) -> bool:
    """Check if a raw permission dict is simple enough for set extraction.

    Simple: exact host/*, explicit tier, no condition, no budget.
    """
    resource = p.get("resource", "")
    if not _is_exact_resource(resource):
        return False
    if p.get("condition"):
        return False
    if p.get("effect") == "budget":
        return False
    if p.get("tier", "explicit") != "explicit":
        return False
    return True


def _extract_simple_permissions(
    permissions: list[dict],
) -> tuple[list[dict], dict[tuple[str, str], set[str]]]:
    """Extract simple permissions from the raw list before Pydantic validation.

    Returns:
        (remaining, simple_sets) where:
        - remaining: permission dicts that need full Pydantic validation
        - simple_sets: {(action, effect): set(resource)} extracted entries
    """
    remaining = []
    simple: dict[tuple[str, str], set[str]] = {}
    for p in permissions:
        if _is_simple_permission_dict(p):
            key = (p["action"], p.get("effect", "allow"))
            simple.setdefault(key, set()).add(p["resource"])
        else:
            remaining.append(p)
    return remaining, simple


class PolicyLoader:
    """
    Loads and watches policy files with hot reload support.

    Thread-safe access to baseline and task policies.
    """

    def __init__(
        self,
        baseline_path: Path | None = None,
        on_reload: Callable[[], None] | None = None,
        services_dir: Path | None = None,
    ):
        """
        Initialize policy loader.

        Args:
            baseline_path: Path to baseline policy file
            on_reload: Optional callback when policies are reloaded
            services_dir: Path to service definitions directory (for capability route compilation)
        """
        # Import here to avoid circular imports
        from policy_engine import UnifiedPolicy

        self._UnifiedPolicy = UnifiedPolicy

        self._baseline_path = baseline_path
        self._services_dir = services_dir
        self._on_reload_callbacks: list[Callable[[], None]] = []
        if on_reload:
            self._on_reload_callbacks.append(on_reload)

        # Policies
        self._baseline: UnifiedPolicy = UnifiedPolicy()
        self._task_policy: UnifiedPolicy | None = None
        self._task_policy_path: Path | None = None

        # Permission indexes (built after sorting, used for O(1) lookup)
        self._baseline_simple: dict[tuple[str, str], set[str]] = {}
        self._baseline_exact: dict[tuple[str, str], list] = {}
        self._baseline_patterns: list = []
        self._task_simple: dict[tuple[str, str], set[str]] = {}
        self._task_exact: dict[tuple[str, str], list] = {}
        self._task_patterns: list = []

        # Thread safety
        self._lock = threading.RLock()
        self._last_baseline_mtime: float = 0
        self._last_addons_mtime: float = 0
        self._last_lists_mtime: float = 0
        self._last_services_mtime: float = 0
        self._last_task_mtime: float = 0

        # File watcher
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()

        # Load baseline if path provided
        if baseline_path:
            self._load_baseline()

    def _load_file(self, path: Path) -> dict | None:
        """Load YAML, TOML, or JSON file, return None on error."""
        if not path.exists():
            log.warning(f"Policy file not found: {path}")
            return None

        try:
            if path.suffix == ".toml":
                from toml_roundtrip import load_as_internal

                return load_as_internal(path)
            elif path.suffix in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    log.error("PyYAML not installed, cannot load YAML policy")
                    return None
                content = path.read_text()
                return yaml.safe_load(content) or {}
            else:
                content = path.read_text()
                return json.loads(content)
        except Exception as e:
            log.error(f"Failed to load {path}: {type(e).__name__}: {e}")
            return None

    def _addons_path(self) -> Path | None:
        """Get path to sibling addons.yaml (if it exists)."""
        if not self._baseline_path:
            return None
        addons_path = self._baseline_path.parent / "addons.yaml"
        if addons_path.exists():
            return addons_path
        return None

    def _merge_addons(self, raw: dict) -> dict:
        """Merge sibling addons.yaml into the policy dict.

        Keys from addons.yaml are merged as defaults — anything already
        in policy.yaml takes precedence.
        """
        addons_path = self._addons_path()
        if not addons_path:
            return raw

        addons_raw = self._load_file(addons_path)
        if addons_raw is None:
            return raw

        # Merge each top-level key from addons.yaml as a default
        for key, value in addons_raw.items():
            if key not in raw:
                raw[key] = value
            elif key == "addons" and isinstance(raw[key], dict) and isinstance(value, dict):
                # Deep merge: addons.yaml provides defaults, policy.yaml overrides
                merged = dict(value)
                merged.update(raw[key])
                raw[key] = merged

        log.info(f"Merged addon config from {addons_path}")
        return raw

    def _lists_max_mtime(self) -> float:
        """Get the max mtime across all list files referenced in policy."""
        if not self._baseline_path:
            return 0
        try:
            raw = self._load_file(self._baseline_path)
            if not raw:
                return 0
            lists_config = raw.get("lists", {})
            if not isinstance(lists_config, dict):
                return 0
        except (OSError, ValueError):
            return 0

        base_dir = self._baseline_path.parent
        max_mtime = 0.0
        for list_path_str in lists_config.values():
            if not isinstance(list_path_str, str):
                continue
            p = Path(list_path_str)
            if not p.is_absolute():
                p = base_dir / p
            try:
                mt = p.stat().st_mtime
                if mt > max_mtime:
                    max_mtime = mt
            except OSError:
                pass
        return max_mtime

    def _services_max_mtime(self) -> float:
        """Get the max mtime across all YAML files in the services directory."""
        if not self._services_dir or not self._services_dir.is_dir():
            return 0
        max_mtime = 0.0
        for p in self._services_dir.glob("*.yaml"):
            try:
                mt = p.stat().st_mtime
                if mt > max_mtime:
                    max_mtime = mt
            except OSError:
                pass  # Skip files that vanish between glob and stat
        return max_mtime

    def _prune_expired_hosts(self, raw: dict) -> dict:
        """Remove host entries with expired `expires` fields.

        Also removes the expired entries from the TOML file on disk.
        """
        from datetime import datetime

        now = datetime.now(UTC)
        hosts = raw.get("hosts", {})
        expired = []

        for host, config in hosts.items():
            if not isinstance(config, dict):
                continue
            expires = config.get("expires")
            if expires is None:
                continue
            # Parse if string, otherwise assume datetime
            if isinstance(expires, str):
                try:
                    expires = datetime.fromisoformat(expires)
                except (ValueError, TypeError):
                    continue
            if hasattr(expires, "tzinfo") and expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= now:
                expired.append(host)

        if not expired:
            return raw

        for host in expired:
            del hosts[host]
            log.info("Pruned expired host entry: %s", sanitize_for_log(host))

        # Remove from TOML file on disk
        if self._baseline_path and self._baseline_path.suffix == ".toml":
            try:
                from toml_roundtrip import load_roundtrip, save_roundtrip

                doc = load_roundtrip(self._baseline_path)
                toml_hosts = doc.get("hosts")
                if toml_hosts:
                    changed = False
                    for host in expired:
                        if host in toml_hosts:
                            del toml_hosts[host]
                            changed = True
                    if changed:
                        save_roundtrip(self._baseline_path, doc)
                        log.info("Removed %d expired host(s) from policy.toml", len(expired))
            except OSError as e:
                log.warning("Failed to prune expired hosts from TOML: %s", e)

        return raw

    def _load_baseline(self) -> bool:
        """Load baseline policy from file.

        If a sibling addons.yaml exists, its contents are merged as defaults
        before compilation and validation.
        """
        if not self._baseline_path:
            return False

        raw = self._load_file(self._baseline_path)
        if raw is None:
            write_event(
                "ops.policy_error",
                kind=EventKind.OPS,
                severity=Severity.HIGH,
                summary="Baseline policy file not found or invalid",
                addon="policy-loader",
                details={"policy_type": "baseline", "error": "File not found or invalid"},
            )
            return False

        try:
            # Prune expired host entries before compilation
            if "hosts" in raw:
                raw = self._prune_expired_hosts(raw)

            # Merge sibling addons.yaml if present
            raw = self._merge_addons(raw)

            # Expand $list references in hosts section
            if "lists" in raw and "hosts" in raw:
                from list_loader import expand_lists

                raw = expand_lists(raw, self._baseline_path.parent)

            # Compile host-centric format → IAM format if needed
            pre_simple = {}
            if is_host_centric(raw):
                raw = compile_policy(raw)
                # Extract simple permissions into sets BEFORE Pydantic validation
                # to avoid creating 92k+ Permission objects for bulk list entries.
                # Only for host-centric (compiled) policies — IAM-format policies
                # keep all permissions as-is since they're hand-authored.
                raw["permissions"], pre_simple = _extract_simple_permissions(raw["permissions"])

            with self._lock:
                self._baseline = self._UnifiedPolicy.model_validate(raw)
                self._last_baseline_mtime = self._baseline_path.stat().st_mtime
                addons_path = self._addons_path()
                if addons_path:
                    self._last_addons_mtime = addons_path.stat().st_mtime
                self._last_lists_mtime = self._lists_max_mtime()
                if self._services_dir:
                    self._last_services_mtime = self._services_max_mtime()

                # Sort permissions by specificity (most specific first)
                self._baseline.permissions.sort(key=lambda p: _specificity_score(p.resource), reverse=True)

                # Build permission index for O(1) exact-host lookup
                self._baseline_simple, self._baseline_exact, self._baseline_patterns = (
                    _build_permission_index(self._baseline.permissions)
                )
                # Merge pre-extracted simple sets into the index
                for key, resources in pre_simple.items():
                    self._baseline_simple.setdefault(key, set()).update(resources)

            log.info(
                f"Loaded baseline policy: {len(self._baseline.permissions)} permissions "
                f"({len(self._baseline_exact)} indexed, {len(self._baseline_patterns)} patterns), "
                f"{len(self._baseline.required)} required addons"
            )
            write_event(
                "ops.policy_reload",
                kind=EventKind.OPS,
                severity=Severity.MEDIUM,
                summary=f"Baseline policy reloaded: {len(self._baseline.permissions)} permissions",
                addon="policy-loader",
                details={"policy_type": "baseline", "permissions_count": len(self._baseline.permissions)},
            )

            for cb in self._on_reload_callbacks:
                try:
                    cb()
                except Exception as e:
                    log.warning("Reload callback error: %s", e)

            return True

        except Exception as e:
            log.error(f"Failed to validate baseline policy: {type(e).__name__}: {e}")
            write_event(
                "ops.policy_error",
                kind=EventKind.OPS,
                severity=Severity.HIGH,
                summary=f"Baseline policy validation failed: {type(e).__name__}",
                addon="policy-loader",
                details={"policy_type": "baseline", "error": str(e)},
            )
            return False

    def load_task_policy(self, path: Path) -> bool:
        """Load task policy (extends baseline)."""
        return self._load_task_policy(path)

    def _load_task_policy(self, path: Path) -> bool:
        """Internal task policy loader."""
        raw = self._load_file(path)
        if raw is None:
            return False

        try:
            with self._lock:
                self._task_policy = self._UnifiedPolicy.model_validate(raw)
                self._task_policy_path = path
                self._last_task_mtime = path.stat().st_mtime

                # Sort permissions
                self._task_policy.permissions.sort(key=lambda p: _specificity_score(p.resource), reverse=True)
                self._task_simple, self._task_exact, self._task_patterns = (
                    _build_permission_index(self._task_policy.permissions)
                )

            log.info(f"Loaded task policy: {len(self._task_policy.permissions)} permissions")
            write_event(
                "ops.policy_reload",
                kind=EventKind.OPS,
                severity=Severity.MEDIUM,
                summary=f"Task policy reloaded: {len(self._task_policy.permissions)} permissions",
                addon="policy-loader",
                details={
                    "policy_type": "task",
                    "task_id": self._task_policy.metadata.task_id,
                    "permissions_count": len(self._task_policy.permissions),
                },
            )

            for cb in self._on_reload_callbacks:
                try:
                    cb()
                except Exception as e:
                    log.warning("Reload callback error: %s", e)

            return True

        except Exception as e:
            log.error(f"Failed to load task policy: {type(e).__name__}: {e}")
            return False

    def clear_task_policy(self) -> None:
        """Clear active task policy."""
        with self._lock:
            self._task_policy = None
            self._task_policy_path = None
            log.info("Cleared task policy")

    def add_reload_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to run after policy reloads."""
        self._on_reload_callbacks.append(callback)

    def start_watcher(self) -> None:
        """Start background file watcher."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    # Check baseline
                    reload_baseline = False
                    if self._baseline_path and self._baseline_path.exists():
                        mtime = self._baseline_path.stat().st_mtime
                        if mtime > self._last_baseline_mtime:
                            reload_baseline = True

                    # Check addons.yaml (triggers baseline reload since it merges in)
                    addons_path = self._addons_path()
                    if addons_path:
                        mtime = addons_path.stat().st_mtime
                        if mtime > self._last_addons_mtime:
                            reload_baseline = True

                    # Check list files (triggers baseline reload since they expand into hosts)
                    lists_mtime = self._lists_max_mtime()
                    if lists_mtime > self._last_lists_mtime:
                        reload_baseline = True

                    # Check services dir (triggers baseline reload for capability routes)
                    if self._services_dir and self._services_dir.is_dir():
                        svc_mtime = self._services_max_mtime()
                        if svc_mtime > self._last_services_mtime:
                            reload_baseline = True

                    if reload_baseline:
                        log.info("Policy changed, reloading...")
                        self._load_baseline()

                    # Check task policy
                    if self._task_policy_path and self._task_policy_path.exists():
                        mtime = self._task_policy_path.stat().st_mtime
                        if mtime > self._last_task_mtime:
                            log.info("Task policy changed, reloading...")
                            self._load_task_policy(self._task_policy_path)

                except Exception as e:
                    log.warning(f"Policy watcher error: {type(e).__name__}: {e}")

                self._watcher_stop.wait(timeout=2.0)

        self._watcher_thread = threading.Thread(target=watch_loop, daemon=True, name="policy-watcher")
        self._watcher_thread.start()
        log.info("Started policy file watcher")

    def stop_watcher(self) -> None:
        """Stop file watcher."""
        if self._watcher_thread:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
            self._watcher_stop.clear()

    @property
    def baseline(self) -> "UnifiedPolicy":
        """Get current baseline policy."""
        with self._lock:
            return self._baseline

    @property
    def task_policy(self) -> Optional["UnifiedPolicy"]:
        """Get current task policy (if any)."""
        with self._lock:
            return self._task_policy

    def get_merged_index(self):
        """Get merged permission index (task + baseline).

        Task entries take priority over baseline for the same key.

        Returns:
            (simple_sets, exact_dict, pattern_list) — three-tier lookup:
            - simple_sets: {(action, effect): set(resource)} for set membership
            - exact_dict: {(action, resource): [Permission]} for condition checking
            - pattern_list: [Permission] for wildcard/glob scan
        """
        with self._lock:
            if not self._task_policy:
                return self._baseline_simple, self._baseline_exact, self._baseline_patterns

            # Merge simple sets: union (both baseline and task denies apply)
            merged_simple = {}
            for key, resources in self._baseline_simple.items():
                merged_simple[key] = set(resources)
            for key, resources in self._task_simple.items():
                merged_simple.setdefault(key, set()).update(resources)

            # Merge exact: task takes priority
            merged_exact = dict(self._baseline_exact)
            merged_exact.update(self._task_exact)

            # Patterns: task first (higher priority), then baseline
            merged_patterns = self._task_patterns + self._baseline_patterns

            return merged_simple, merged_exact, merged_patterns

    @property
    def baseline_path(self) -> Path | None:
        """Get baseline policy path."""
        return self._baseline_path

    @property
    def task_policy_path(self) -> Path | None:
        """Get task policy path."""
        return self._task_policy_path

    def set_baseline(self, policy: "UnifiedPolicy") -> None:
        """Set baseline policy directly (for updates via API)."""
        with self._lock:
            self._baseline = policy
            self._baseline.permissions.sort(key=lambda p: _specificity_score(p.resource), reverse=True)
            self._baseline_simple, self._baseline_exact, self._baseline_patterns = (
                _build_permission_index(self._baseline.permissions)
            )

    def set_task_policy(self, policy: "UnifiedPolicy") -> None:
        """Set task policy directly (for updates via API)."""
        with self._lock:
            self._task_policy = policy
            self._task_policy.permissions.sort(key=lambda p: _specificity_score(p.resource), reverse=True)
            self._task_simple, self._task_exact, self._task_patterns = (
                _build_permission_index(self._task_policy.permissions)
            )

    def reload(self) -> bool:
        """Force reload of all policies."""
        success = True
        if self._baseline_path:
            success = self._load_baseline() and success
        if self._task_policy_path:
            success = self._load_task_policy(self._task_policy_path) and success
        return success
