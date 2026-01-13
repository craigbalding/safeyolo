"""
policy_loader.py - Policy file loading, watching, and hot reload

Handles:
- Loading baseline and task policies from YAML/JSON
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

from utils import write_event

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


class PolicyLoader:
    """
    Loads and watches policy files with hot reload support.

    Thread-safe access to baseline and task policies.
    """

    def __init__(
        self,
        baseline_path: Path | None = None,
        on_reload: Callable[[], None] | None = None,
    ):
        """
        Initialize policy loader.

        Args:
            baseline_path: Path to baseline policy file
            on_reload: Optional callback when policies are reloaded
        """
        # Import here to avoid circular imports
        from policy_engine import UnifiedPolicy
        self._UnifiedPolicy = UnifiedPolicy

        self._baseline_path = baseline_path
        self._on_reload = on_reload

        # Policies
        self._baseline: UnifiedPolicy = UnifiedPolicy()
        self._task_policy: UnifiedPolicy | None = None
        self._task_policy_path: Path | None = None

        # Thread safety
        self._lock = threading.RLock()
        self._last_baseline_mtime: float = 0
        self._last_task_mtime: float = 0

        # File watcher
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()

        # Load baseline if path provided
        if baseline_path:
            self._load_baseline()

    def _load_file(self, path: Path) -> dict | None:
        """Load YAML or JSON file, return None on error."""
        if not path.exists():
            log.warning(f"Policy file not found: {path}")
            return None

        try:
            content = path.read_text()
            if path.suffix in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    log.error("PyYAML not installed, cannot load YAML policy")
                    return None
                return yaml.safe_load(content) or {}
            else:
                return json.loads(content)
        except Exception as e:
            log.error(f"Failed to load {path}: {type(e).__name__}: {e}")
            return None

    def _load_baseline(self) -> bool:
        """Load baseline policy from file."""
        if not self._baseline_path:
            return False

        raw = self._load_file(self._baseline_path)
        if raw is None:
            write_event(
                "ops.policy_error",
                addon="policy-loader",
                policy_type="baseline",
                error="File not found or invalid",
            )
            return False

        try:
            with self._lock:
                self._baseline = self._UnifiedPolicy.model_validate(raw)
                self._last_baseline_mtime = self._baseline_path.stat().st_mtime

                # Sort permissions by specificity (most specific first)
                self._baseline.permissions.sort(
                    key=lambda p: _specificity_score(p.resource), reverse=True
                )

            log.info(
                f"Loaded baseline policy: {len(self._baseline.permissions)} permissions, "
                f"{len(self._baseline.required)} required addons"
            )
            write_event(
                "ops.policy_reload",
                addon="policy-loader",
                policy_type="baseline",
                permissions_count=len(self._baseline.permissions),
            )

            if self._on_reload:
                self._on_reload()

            return True

        except Exception as e:
            log.error(f"Failed to validate baseline policy: {type(e).__name__}: {e}")
            write_event(
                "ops.policy_error",
                addon="policy-loader",
                policy_type="baseline",
                error=str(e),
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
                self._task_policy.permissions.sort(
                    key=lambda p: _specificity_score(p.resource), reverse=True
                )

            log.info(
                f"Loaded task policy: {len(self._task_policy.permissions)} permissions"
            )
            write_event(
                "ops.policy_reload",
                addon="policy-loader",
                policy_type="task",
                task_id=self._task_policy.metadata.task_id,
                permissions_count=len(self._task_policy.permissions),
            )

            if self._on_reload:
                self._on_reload()

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

    def start_watcher(self) -> None:
        """Start background file watcher."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    # Check baseline
                    if self._baseline_path and self._baseline_path.exists():
                        mtime = self._baseline_path.stat().st_mtime
                        if mtime > self._last_baseline_mtime:
                            log.info("Baseline policy changed, reloading...")
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

        self._watcher_thread = threading.Thread(
            target=watch_loop, daemon=True, name="policy-watcher"
        )
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
            self._baseline.permissions.sort(
                key=lambda p: _specificity_score(p.resource), reverse=True
            )

    def set_task_policy(self, policy: "UnifiedPolicy") -> None:
        """Set task policy directly (for updates via API)."""
        with self._lock:
            self._task_policy = policy
            self._task_policy.permissions.sort(
                key=lambda p: _specificity_score(p.resource), reverse=True
            )

    def reload(self) -> bool:
        """Force reload of all policies."""
        success = True
        if self._baseline_path:
            success = self._load_baseline() and success
        if self._task_policy_path:
            success = self._load_task_policy(self._task_policy_path) and success
        return success
