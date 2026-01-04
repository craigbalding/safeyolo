"""
policy_engine.py - Unified IAM-inspired policy engine for SafeYolo

Provides layered policy evaluation with:
- Baseline policy (always active)
- Task policy (optional, extends baseline)
- Budget tracking with GCRA algorithm
- Hot reload via file watching

Policy schema uses IAM-style action/resource/effect vocabulary.

Usage:
    from policy_engine import get_policy_engine, PolicyDecision

    engine = get_policy_engine()
    decision = engine.evaluate_credential("openai", "api.openai.com", "/v1/chat")
    if decision.effect == "allow":
        # proceed
    elif decision.effect == "prompt":
        # require human approval
"""

import fnmatch
import json
import logging
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

try:
    from .utils import write_event
except ImportError:
    from utils import write_event

log = logging.getLogger("safeyolo.policy-engine")


# =============================================================================
# Pydantic Models
# =============================================================================

class PolicyMetadata(BaseModel):
    """Policy file metadata."""
    version: str = "1.0"
    task_id: Optional[str] = None
    description: Optional[str] = None
    created: Optional[str] = None
    approved: Optional[str] = None
    brief_hash: Optional[str] = None
    policy_hash: Optional[str] = None


class Condition(BaseModel):
    """Optional conditions for permission matching."""
    # For credential:use - what credentials can access this destination
    credential: Optional[str | list[str]] = None  # e.g., ["openai:*", "hmac:a1b2c3"]
    # For network:request
    method: Optional[str | list[str]] = None
    path_prefix: Optional[str] = None
    content_type: Optional[str] = None

    def matches(self, context: dict[str, Any]) -> bool:
        """Check if all specified conditions match the context."""
        if self.credential is not None:
            ctx_cred = context.get("credential_type", "")
            ctx_hmac = context.get("credential_hmac", "")
            credentials = [self.credential] if isinstance(self.credential, str) else self.credential

            # Check if any credential pattern matches (type or hmac)
            matched = False
            for cred_pattern in credentials:
                if cred_pattern.startswith("hmac:"):
                    # Exact HMAC match
                    if ctx_hmac and cred_pattern == f"hmac:{ctx_hmac}":
                        matched = True
                        break
                else:
                    # Type pattern match (e.g., "openai:*")
                    if _matches_pattern(f"{ctx_cred}:x", cred_pattern):
                        matched = True
                        break
            if not matched:
                return False

        if self.method is not None:
            ctx_method = context.get("method", "").upper()
            methods = [self.method] if isinstance(self.method, str) else self.method
            if ctx_method not in [m.upper() for m in methods]:
                return False

        if self.path_prefix is not None:
            ctx_path = context.get("path", "")
            if not ctx_path.startswith(self.path_prefix):
                return False

        if self.content_type is not None:
            ctx_ct = context.get("content_type", "")
            if self.content_type not in ctx_ct:
                return False

        return True


class Permission(BaseModel):
    """IAM-style permission rule.

    For credential:use:
      - resource = destination pattern (e.g., "api.openai.com/*")
      - condition.credential = allowed credential types/HMACs (e.g., ["openai:*"])

    For network:request:
      - resource = destination pattern (e.g., "api.openai.com/*")
      - effect = budget means rate limiting
    """
    action: Literal["credential:use", "network:request", "file:read", "file:write", "subprocess:exec"]
    resource: str  # glob pattern for destination: "api.openai.com/*", "*.example.com/*"
    effect: Literal["allow", "deny", "prompt", "budget"] = "allow"
    budget: Optional[int] = None  # Required if effect=budget (requests per minute)
    tier: Literal["explicit", "inferred"] = "explicit"
    condition: Optional[Condition] = None

    @model_validator(mode="after")
    def validate_budget_required(self):
        """Ensure budget is set when effect is 'budget'."""
        if self.effect == "budget" and self.budget is None:
            raise ValueError("budget must be set when effect is 'budget'")
        return self


class AddonConfig(BaseModel):
    """Configuration for a single addon."""
    enabled: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"  # Allow extra fields as settings


class DomainOverride(BaseModel):
    """Domain or client-specific policy override."""
    bypass: list[str] = Field(default_factory=list)
    addons: dict[str, AddonConfig] = Field(default_factory=dict)


class UnifiedPolicy(BaseModel):
    """Complete policy document."""
    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    permissions: list[Permission] = Field(default_factory=list)
    budgets: dict[str, int] = Field(default_factory=dict)  # Global budget caps
    required: list[str] = Field(default_factory=list)  # Addons that cannot be disabled
    addons: dict[str, AddonConfig] = Field(default_factory=dict)
    domains: dict[str, DomainOverride] = Field(default_factory=dict)
    clients: dict[str, DomainOverride] = Field(default_factory=dict)


# =============================================================================
# Decision Types
# =============================================================================

@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    effect: Literal["allow", "deny", "prompt", "budget_exceeded"]
    permission: Optional[Permission] = None  # Matched permission (if any)
    reason: str = ""
    budget_remaining: Optional[int] = None


@dataclass
class BudgetState:
    """GCRA-based budget tracking for a resource."""
    tat: float = 0.0  # Theoretical Arrival Time in milliseconds
    last_check: float = 0.0


# =============================================================================
# Helper Functions
# =============================================================================

def _matches_pattern(value: str, pattern: str) -> bool:
    """Check if value matches pattern (supports glob wildcards)."""
    value = value.lower()
    pattern = pattern.lower()

    # Exact match
    if value == pattern:
        return True

    # Wildcard domain patterns: *.example.com
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return value.endswith(suffix) or value == pattern[2:]

    # Glob patterns: api.stripe.com/*
    return fnmatch.fnmatch(value, pattern)


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


# =============================================================================
# GCRA Budget Tracker
# =============================================================================

class GCRABudgetTracker:
    """
    GCRA-based budget tracking with per-minute windows.

    Uses "virtual scheduling" - tracks TAT (Theoretical Arrival Time)
    for smooth rate limiting without thundering herd problems.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self._budgets: dict[str, BudgetState] = {}  # key -> state
        self._state_file = state_file
        self._lock = threading.RLock()
        self._snapshot_thread: Optional[threading.Thread] = None
        self._snapshot_stop = threading.Event()

        if self._state_file and self._state_file.exists():
            self._load_state()

        if self._state_file:
            self._start_snapshots()

    def check_and_consume(
        self,
        key: str,
        budget_per_minute: int,
        cost: int = 1,
    ) -> tuple[bool, int]:
        """
        Check if budget allows request and consume if so.

        Args:
            key: Budget key (e.g., "network:request:api.openai.com")
            budget_per_minute: Max requests per minute
            cost: Cost of this request (default 1)

        Returns:
            (allowed, remaining) tuple
        """
        with self._lock:
            now_ms = time.time() * 1000
            state = self._budgets.get(key)

            if state is None:
                state = BudgetState(tat=now_ms, last_check=now_ms)
                self._budgets[key] = state

            # GCRA calculation
            emission_interval_ms = 60000.0 / budget_per_minute  # ms between requests
            burst_capacity = max(1, budget_per_minute // 10)  # 10% burst
            burst_offset = emission_interval_ms * burst_capacity
            allow_at = state.tat - burst_offset

            if now_ms < allow_at:
                # Budget exceeded
                remaining = 0
                return False, remaining

            # Allowed - update TAT
            new_tat = max(state.tat, now_ms) + (emission_interval_ms * cost)
            state.tat = new_tat
            state.last_check = now_ms

            # Calculate remaining
            remaining = int((now_ms - (new_tat - burst_offset)) / emission_interval_ms)
            remaining = max(0, min(burst_capacity, remaining))

            return True, remaining

    def get_remaining(self, key: str, budget_per_minute: int) -> int:
        """Get remaining budget without consuming."""
        with self._lock:
            now_ms = time.time() * 1000
            state = self._budgets.get(key)

            if state is None:
                return budget_per_minute // 10  # Full burst capacity

            emission_interval_ms = 60000.0 / budget_per_minute
            burst_capacity = max(1, budget_per_minute // 10)
            burst_offset = emission_interval_ms * burst_capacity

            remaining = int((now_ms - (state.tat - burst_offset)) / emission_interval_ms)
            return max(0, min(burst_capacity, remaining))

    def reset(self, key: str) -> None:
        """Reset budget for a key."""
        with self._lock:
            self._budgets.pop(key, None)

    def reset_all(self) -> None:
        """Reset all budgets."""
        with self._lock:
            self._budgets.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get budget tracking statistics."""
        with self._lock:
            return {
                "tracked_keys": len(self._budgets),
                "keys": list(self._budgets.keys()),
            }

    def _load_state(self) -> None:
        """Load state from file."""
        try:
            with open(self._state_file) as f:
                data = json.load(f)

            for key, state_data in data.get("budgets", {}).items():
                self._budgets[key] = BudgetState(
                    tat=state_data.get("tat", 0.0),
                    last_check=state_data.get("last_check", 0.0),
                )

            log.info(f"Loaded {len(self._budgets)} budget states from {self._state_file}")
        except Exception as e:
            log.error(f"Failed to load budget state: {type(e).__name__}: {e}")
            self._budgets = {}

    def _save_state(self) -> None:
        """Save state to file (atomic write)."""
        if not self._state_file:
            return

        try:
            tmp_file = self._state_file.with_suffix(".tmp")

            with self._lock:
                data = {
                    "budgets": {
                        key: {"tat": state.tat, "last_check": state.last_check}
                        for key, state in self._budgets.items()
                    },
                    "saved_at": time.time(),
                }

            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_file, "w") as f:
                json.dump(data, f, indent=2)

            tmp_file.rename(self._state_file)
        except Exception as e:
            log.error(f"Failed to save budget state: {type(e).__name__}: {e}")

    def _start_snapshots(self) -> None:
        """Start background snapshot thread."""
        def snapshot_loop():
            while not self._snapshot_stop.is_set():
                self._save_state()
                self._snapshot_stop.wait(timeout=10.0)

        self._snapshot_thread = threading.Thread(
            target=snapshot_loop, daemon=True, name="policy-budget-snapshot"
        )
        self._snapshot_thread.start()
        log.info("Started policy budget state snapshots (10s interval)")

    def stop(self) -> None:
        """Stop snapshot thread and save final state."""
        if self._snapshot_thread:
            self._snapshot_stop.set()
            self._snapshot_thread.join(timeout=2.0)
            self._save_state()
            self._snapshot_thread = None
            self._snapshot_stop.clear()


# =============================================================================
# Policy Engine
# =============================================================================

class PolicyEngine:
    """
    Unified policy engine with layered evaluation.

    Layers:
    - Layer 0: Invariants (hardcoded in code)
    - Layer 1: Baseline (always active)
    - Layer 2: Task policy (optional, extends baseline)
    """

    def __init__(
        self,
        baseline_path: Optional[Path] = None,
        budget_state_path: Optional[Path] = None,
    ):
        self._baseline_path = baseline_path
        self._baseline: UnifiedPolicy = UnifiedPolicy()
        self._task_policy: Optional[UnifiedPolicy] = None
        self._task_policy_path: Optional[Path] = None

        # Budget tracking
        self._budget_tracker = GCRABudgetTracker(budget_state_path)

        # Thread safety
        self._lock = threading.RLock()
        self._last_baseline_mtime: float = 0
        self._last_task_mtime: float = 0

        # File watcher
        self._watcher_thread: Optional[threading.Thread] = None
        self._watcher_stop = threading.Event()

        # Stats
        self._evaluations = 0
        self._cache_hits = 0

        # Load baseline
        if baseline_path:
            self._load_baseline()
            self._start_watcher()

        # SIGHUP handler
        self._setup_signal_handler()

    def _setup_signal_handler(self) -> None:
        """Setup SIGHUP handler for hot reload."""
        try:
            signal.signal(signal.SIGHUP, self._handle_sighup)
        except (ValueError, OSError):
            pass  # Not main thread or not supported

    def _handle_sighup(self, signum, frame) -> None:
        """Handle SIGHUP signal."""
        log.info("Received SIGHUP, reloading policies...")
        self._load_baseline()
        if self._task_policy_path:
            self._load_task_policy(self._task_policy_path)

    def _load_baseline(self) -> bool:
        """Load baseline policy from file."""
        if not self._baseline_path or not self._baseline_path.exists():
            log.warning(f"Baseline policy not found: {self._baseline_path}")
            return False

        try:
            content = self._baseline_path.read_text()
            if self._baseline_path.suffix in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    log.error("PyYAML not installed, cannot load YAML policy")
                    return False
                raw = yaml.safe_load(content) or {}
            else:
                raw = json.loads(content)

            with self._lock:
                self._baseline = UnifiedPolicy.model_validate(raw)
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
                addon="policy-engine",
                policy_type="baseline",
                permissions_count=len(self._baseline.permissions),
            )
            return True

        except Exception as e:
            log.error(f"Failed to load baseline policy: {type(e).__name__}: {e}")
            write_event(
                "ops.policy_error",
                addon="policy-engine",
                policy_type="baseline",
                error=str(e),
            )
            return False

    def load_task_policy(self, path: Path) -> bool:
        """Load task policy (extends baseline)."""
        return self._load_task_policy(path)

    def _load_task_policy(self, path: Path) -> bool:
        """Internal task policy loader."""
        if not path.exists():
            log.warning(f"Task policy not found: {path}")
            return False

        try:
            content = path.read_text()
            if path.suffix in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    log.error("PyYAML not installed")
                    return False
                raw = yaml.safe_load(content) or {}
            else:
                raw = json.loads(content)

            with self._lock:
                self._task_policy = UnifiedPolicy.model_validate(raw)
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
                addon="policy-engine",
                policy_type="task",
                task_id=self._task_policy.metadata.task_id,
                permissions_count=len(self._task_policy.permissions),
            )
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

    def _start_watcher(self) -> None:
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

    def _stop_watcher(self) -> None:
        """Stop file watcher."""
        if self._watcher_thread:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
            self._watcher_stop.clear()

    # -------------------------------------------------------------------------
    # Permission Evaluation
    # -------------------------------------------------------------------------

    def _get_merged_permissions(self) -> list[Permission]:
        """Get merged permissions from baseline + task policy."""
        with self._lock:
            permissions = list(self._baseline.permissions)
            if self._task_policy:
                # Task permissions come first (higher priority)
                permissions = list(self._task_policy.permissions) + permissions
            return permissions

    def _find_matching_permission(
        self,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> Optional[Permission]:
        """Find first matching permission (most specific first)."""
        permissions = self._get_merged_permissions()

        for perm in permissions:
            if perm.action != action:
                continue

            if not _matches_pattern(resource, perm.resource):
                continue

            # Check tier - inferred permissions are inactive unless promoted
            if perm.tier == "inferred":
                continue

            # Check conditions
            if perm.condition and not perm.condition.matches(context):
                continue

            return perm

        return None

    def evaluate_credential(
        self,
        credential_type: str,
        destination: str,
        path: str = "/",
        credential_hmac: Optional[str] = None,
    ) -> PolicyDecision:
        """
        Evaluate credential usage permission (destination-first matching).

        The resource is the destination (host pattern). The condition.credential
        specifies what credential types or HMACs can access that destination.

        Args:
            credential_type: Type of credential (e.g., "openai", "anthropic", "unknown")
            destination: Target host
            path: Request path
            credential_hmac: Optional HMAC fingerprint for precise matching

        Returns:
            PolicyDecision with effect and details
        """
        self._evaluations += 1

        # Resource is now the destination pattern
        resource = f"{destination}/*"
        context = {
            "credential_type": credential_type,
            "credential_hmac": credential_hmac or "",
            "path": path,
        }

        # Find permission for this destination with matching credential condition
        permission = self._find_matching_permission("credential:use", resource, context)

        if permission is None:
            # Try wildcard destination match
            permission = self._find_matching_permission("credential:use", "*", context)

        if permission is None:
            # Default: require approval
            return PolicyDecision(
                effect="prompt",
                reason=f"No permission for '{credential_type}' credential to '{destination}'",
            )

        # Handle budget effect
        if permission.effect == "budget":
            budget_key = f"credential:use:{destination}:{credential_type}"
            allowed, remaining = self._budget_tracker.check_and_consume(
                budget_key, permission.budget
            )
            if not allowed:
                return PolicyDecision(
                    effect="budget_exceeded",
                    permission=permission,
                    reason=f"Budget exceeded for {credential_type} to {destination}",
                    budget_remaining=0,
                )
            return PolicyDecision(
                effect="allow",
                permission=permission,
                budget_remaining=remaining,
            )

        return PolicyDecision(
            effect=permission.effect,
            permission=permission,
        )

    def evaluate_request(
        self,
        host: str,
        path: str = "/",
        method: str = "GET",
    ) -> PolicyDecision:
        """
        Evaluate network request permission (for rate limiting).

        Args:
            host: Target host
            path: Request path
            method: HTTP method

        Returns:
            PolicyDecision with effect and details
        """
        self._evaluations += 1

        resource = f"{host}/*"
        context = {
            "destination": host,
            "path": path,
            "method": method,
        }

        # Try exact host match first
        permission = self._find_matching_permission("network:request", resource, context)

        if permission is None:
            # Try wildcard match
            permission = self._find_matching_permission("network:request", "*", context)

        if permission is None:
            # Default: allow (baseline should define catch-all)
            return PolicyDecision(effect="allow", reason="No matching permission, default allow")

        # Handle budget effect
        if permission.effect == "budget":
            budget_key = f"network:request:{host}"
            allowed, remaining = self._budget_tracker.check_and_consume(
                budget_key, permission.budget
            )

            # Also check global budget
            global_budget = self._get_global_budget("network:request")
            if global_budget:
                global_key = "network:request:__global__"
                global_allowed, global_remaining = self._budget_tracker.check_and_consume(
                    global_key, global_budget
                )
                if not global_allowed:
                    return PolicyDecision(
                        effect="budget_exceeded",
                        permission=permission,
                        reason=f"Global network budget exceeded",
                        budget_remaining=0,
                    )

            if not allowed:
                return PolicyDecision(
                    effect="budget_exceeded",
                    permission=permission,
                    reason=f"Rate limit exceeded for {host}",
                    budget_remaining=0,
                )

            return PolicyDecision(
                effect="allow",
                permission=permission,
                budget_remaining=remaining,
            )

        return PolicyDecision(
            effect=permission.effect,
            permission=permission,
        )

    def _get_global_budget(self, action: str) -> Optional[int]:
        """Get global budget cap for an action."""
        with self._lock:
            budget = self._baseline.budgets.get(action)
            if self._task_policy and action in self._task_policy.budgets:
                # Task policy can increase but not decrease global budget
                task_budget = self._task_policy.budgets[action]
                if budget is None or task_budget > budget:
                    budget = task_budget
            return budget

    def consume_budget(self, action: str, resource: str, cost: int = 1) -> tuple[bool, int]:
        """
        Consume budget for an action/resource.

        Used by rate_limiter addon after permission check.

        Args:
            action: Action type (e.g., "network:request")
            resource: Resource identifier (e.g., "api.openai.com")
            cost: Cost of operation

        Returns:
            (allowed, remaining) tuple
        """
        # Find matching permission to get budget
        permission = self._find_matching_permission(action, f"{resource}/*", {})
        if permission is None:
            permission = self._find_matching_permission(action, "*", {})

        if permission is None or permission.effect != "budget":
            return True, -1  # No budget constraint

        budget_key = f"{action}:{resource}"
        return self._budget_tracker.check_and_consume(budget_key, permission.budget, cost)

    # -------------------------------------------------------------------------
    # Addon Configuration
    # -------------------------------------------------------------------------

    def is_addon_enabled(
        self,
        addon_name: str,
        domain: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> bool:
        """
        Check if addon is enabled for the given context.

        Args:
            addon_name: Name of addon to check
            domain: Request domain (optional)
            client_id: Client identifier (optional)

        Returns:
            True if addon should process this request
        """
        with self._lock:
            # Check domain bypasses
            if domain:
                for pattern, override in self._baseline.domains.items():
                    if _matches_pattern(domain, pattern):
                        if addon_name in override.bypass:
                            return False
                if self._task_policy:
                    for pattern, override in self._task_policy.domains.items():
                        if _matches_pattern(domain, pattern):
                            if addon_name in override.bypass:
                                return False

            # Check client bypasses
            if client_id:
                for pattern, override in self._baseline.clients.items():
                    if _matches_pattern(client_id, pattern):
                        if addon_name in override.bypass:
                            # Check if required - cannot bypass required addons
                            if addon_name in self._baseline.required:
                                return True
                            return False

            # Check addon config
            config = self._get_addon_config(addon_name, domain)
            return config.enabled

    def _get_addon_config(
        self,
        addon_name: str,
        domain: Optional[str] = None,
    ) -> AddonConfig:
        """Get merged addon configuration."""
        with self._lock:
            # Start with baseline
            config = self._baseline.addons.get(addon_name, AddonConfig())

            # Merge domain-specific config
            if domain:
                for pattern, override in self._baseline.domains.items():
                    if _matches_pattern(domain, pattern):
                        if addon_name in override.addons:
                            domain_config = override.addons[addon_name]
                            config = AddonConfig(
                                enabled=domain_config.enabled,
                                settings={**config.settings, **domain_config.settings},
                            )

            # Merge task policy
            if self._task_policy:
                if addon_name in self._task_policy.addons:
                    task_config = self._task_policy.addons[addon_name]
                    # Task cannot disable required addons
                    if addon_name in self._baseline.required:
                        enabled = True
                    else:
                        enabled = task_config.enabled
                    config = AddonConfig(
                        enabled=enabled,
                        settings={**config.settings, **task_config.settings},
                    )

            return config

    def get_addon_settings(
        self,
        addon_name: str,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get settings for an addon."""
        config = self._get_addon_config(addon_name, domain)
        return config.settings

    # -------------------------------------------------------------------------
    # Policy Access
    # -------------------------------------------------------------------------

    @property
    def baseline_path(self) -> Optional[Path]:
        """Get baseline policy path."""
        return self._baseline_path

    def get_baseline(self) -> Optional[UnifiedPolicy]:
        """Get current baseline policy."""
        with self._lock:
            if not self._baseline.permissions:
                return None
            return self._baseline

    def get_task_policy(self, task_id: Optional[str] = None) -> Optional[UnifiedPolicy]:
        """Get current task policy (if any).

        Args:
            task_id: If provided, only return if task_id matches
        """
        with self._lock:
            if self._task_policy is None:
                return None
            if task_id and self._task_policy.metadata.task_id != task_id:
                return None
            return self._task_policy

    def get_stats(self) -> dict[str, Any]:
        """Get policy engine statistics."""
        with self._lock:
            return {
                "baseline_path": str(self._baseline_path) if self._baseline_path else None,
                "task_policy_path": str(self._task_policy_path) if self._task_policy_path else None,
                "baseline_permissions": len(self._baseline.permissions),
                "task_permissions": len(self._task_policy.permissions) if self._task_policy else 0,
                "required_addons": self._baseline.required,
                "evaluations": self._evaluations,
                "budget_stats": self._budget_tracker.get_stats(),
            }

    def get_budget_stats(self) -> dict[str, Any]:
        """Get current budget usage statistics."""
        with self._lock:
            stats = self._budget_tracker.get_stats()
            budget_usage = {}

            # Calculate remaining for each tracked key
            for key in stats.get("keys", []):
                # Parse key to extract action and resource
                parts = key.split(":", 2)
                if len(parts) >= 2:
                    action = f"{parts[0]}:{parts[1]}"
                    resource = parts[2] if len(parts) > 2 else "*"

                    # Find matching permission to get budget limit
                    permission = self._find_matching_permission(action, f"{resource}/*", {})
                    if permission is None:
                        permission = self._find_matching_permission(action, "*", {})

                    if permission and permission.budget:
                        remaining = self._budget_tracker.get_remaining(key, permission.budget)
                        budget_usage[key] = {
                            "budget_per_minute": permission.budget,
                            "remaining": remaining,
                            "resource": resource,
                        }

            return {
                "tracked_keys": stats.get("tracked_keys", 0),
                "budgets": budget_usage,
                "global_budgets": self._baseline.budgets,
            }

    def reset_budgets(self, resource: Optional[str] = None) -> dict[str, Any]:
        """Reset budget counters.

        Args:
            resource: If provided, reset only this resource. Otherwise reset all.

        Returns:
            Dict with status and reset count.
        """
        if resource:
            self._budget_tracker.reset(resource)
            log.info(f"Reset policy budget for: {resource}")
            write_event("admin.budget_reset", addon="policy-engine", resource=resource)
            return {"status": "reset", "resource": resource}
        else:
            self._budget_tracker.reset_all()
            log.info("Reset all policy budgets")
            write_event("admin.budget_reset", addon="policy-engine", resource="all")
            return {"status": "reset", "resource": "all"}

    # -------------------------------------------------------------------------
    # Policy Modification
    # -------------------------------------------------------------------------

    def add_credential_approval(
        self,
        destination: str,
        credential: str | list[str],
        tier: str = "explicit",
    ) -> dict[str, Any]:
        """Add credential permission to baseline policy (destination-first).

        Args:
            destination: Destination host pattern (e.g., "api.example.com", "*.example.com")
            credential: Credential type(s) or HMAC(s) to allow (e.g., "openai:*", "hmac:a1b2c3")
            tier: Permission tier ("explicit" or "inferred")

        Returns:
            Dict with status and permission count
        """
        if tier not in ("explicit", "inferred"):
            raise ValueError(f"tier must be 'explicit' or 'inferred', got '{tier}'")

        credentials = [credential] if isinstance(credential, str) else credential

        with self._lock:
            # Create new permission (destination-first)
            condition = Condition(credential=credentials)
            new_permission = Permission(
                action="credential:use",
                resource=f"{destination}/*",
                effect="allow",
                tier=tier,
                condition=condition,
            )

            # Add to baseline (at beginning for higher priority)
            self._baseline.permissions.insert(0, new_permission)

            # Re-sort by specificity
            self._baseline.permissions.sort(
                key=lambda p: _specificity_score(p.resource), reverse=True
            )

            # Save to file if path exists
            if self._baseline_path:
                self._save_baseline()

            log.info(f"Added credential approval: {destination} accepts {credentials}")
            write_event(
                "admin.credential_approval_added",
                addon="policy-engine",
                destination=destination,
                credential=credentials,
                tier=tier,
            )

            return {
                "status": "added",
                "permission_count": len(self._baseline.permissions),
            }

    def update_baseline(self, policy_data: dict[str, Any]) -> dict[str, Any]:
        """Update baseline policy from dict.

        Args:
            policy_data: Policy data to validate and apply

        Returns:
            Dict with status and permission count
        """
        try:
            new_policy = UnifiedPolicy.model_validate(policy_data)
        except Exception as e:
            raise ValueError(f"Invalid policy data: {e}")

        with self._lock:
            self._baseline = new_policy

            # Sort permissions by specificity
            self._baseline.permissions.sort(
                key=lambda p: _specificity_score(p.resource), reverse=True
            )

            # Save to file if path exists
            if self._baseline_path:
                self._save_baseline()

            log.info(f"Updated baseline policy: {len(self._baseline.permissions)} permissions")
            write_event(
                "ops.policy_update",
                addon="policy-engine",
                policy_type="baseline",
                permissions_count=len(self._baseline.permissions),
            )

            return {
                "status": "updated",
                "permission_count": len(self._baseline.permissions),
            }

    def set_task_policy(
        self,
        task_id: str,
        policy_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Set task policy from dict.

        Args:
            task_id: Task identifier
            policy_data: Policy data to validate and apply

        Returns:
            Dict with status and permission count
        """
        try:
            new_policy = UnifiedPolicy.model_validate(policy_data)
        except Exception as e:
            raise ValueError(f"Invalid policy data: {e}")

        # Set task_id in metadata
        new_policy.metadata.task_id = task_id

        with self._lock:
            self._task_policy = new_policy

            # Sort permissions by specificity
            self._task_policy.permissions.sort(
                key=lambda p: _specificity_score(p.resource), reverse=True
            )

            log.info(f"Set task policy '{task_id}': {len(self._task_policy.permissions)} permissions")
            write_event(
                "ops.policy_update",
                addon="policy-engine",
                policy_type="task",
                task_id=task_id,
                permissions_count=len(self._task_policy.permissions),
            )

            return {
                "status": "updated",
                "task_id": task_id,
                "permission_count": len(self._task_policy.permissions),
            }

    def _save_baseline(self) -> None:
        """Save baseline policy to file (atomic write)."""
        if not self._baseline_path:
            return

        try:
            import tempfile
            import shutil

            content = yaml.safe_dump(
                self._baseline.model_dump(exclude_none=True),
                default_flow_style=False,
                allow_unicode=True,
            )

            self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.yaml', dir=self._baseline_path.parent, delete=False
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            shutil.move(tmp_path, self._baseline_path)
            self._last_baseline_mtime = self._baseline_path.stat().st_mtime
            log.info(f"Saved baseline policy to {self._baseline_path}")

        except Exception as e:
            log.error(f"Failed to save baseline: {type(e).__name__}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def done(self) -> None:
        """Cleanup on shutdown."""
        self._stop_watcher()
        self._budget_tracker.stop()


# =============================================================================
# Global Instance
# =============================================================================

_policy_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> Optional[PolicyEngine]:
    """Get the global policy engine instance."""
    return _policy_engine


def init_policy_engine(
    baseline_path: Optional[Path] = None,
    budget_state_path: Optional[Path] = None,
) -> PolicyEngine:
    """Initialize the global policy engine."""
    global _policy_engine

    if baseline_path is None:
        # Default paths
        baseline_path = Path("/app/config/baseline.yaml")
        if not baseline_path.exists():
            baseline_path = Path.home() / ".safeyolo" / "baseline.yaml"

    if budget_state_path is None:
        budget_state_path = Path("/app/data/policy_budget_state.json")
        if not budget_state_path.parent.exists():
            budget_state_path = Path.home() / ".safeyolo" / "data" / "policy_budget_state.json"

    _policy_engine = PolicyEngine(baseline_path, budget_state_path)
    return _policy_engine


# =============================================================================
# Mitmproxy Addon Interface
# =============================================================================

class PolicyEngineAddon:
    """Mitmproxy addon wrapper for PolicyEngine."""

    name = "policy-engine"

    def __init__(self):
        self.engine: Optional[PolicyEngine] = None

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="policy_baseline",
            typespec=Optional[str],
            default=None,
            help="Path to baseline policy YAML file",
        )
        loader.add_option(
            name="policy_budget_state",
            typespec=Optional[str],
            default=None,
            help="Path to budget state JSON file",
        )

    def configure(self, updates):
        """Handle option changes."""
        from mitmproxy import ctx

        if "policy_baseline" in updates or self.engine is None:
            baseline_path = ctx.options.policy_baseline
            budget_path = ctx.options.policy_budget_state

            self.engine = init_policy_engine(
                baseline_path=Path(baseline_path) if baseline_path else None,
                budget_state_path=Path(budget_path) if budget_path else None,
            )

    def request(self, flow):
        """Attach policy info to flow for other addons."""
        if self.engine:
            flow.metadata["policy_engine"] = self.engine

    def done(self):
        """Cleanup on shutdown."""
        if self.engine:
            self.engine.done()

    def get_stats(self) -> dict:
        """Get engine statistics."""
        if self.engine:
            return self.engine.get_stats()
        return {}


# Mitmproxy addon instance
policy_engine_addon = PolicyEngineAddon()
addons = [policy_engine_addon]
