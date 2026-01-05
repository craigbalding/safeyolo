"""
policy_engine.py - Unified IAM-inspired policy engine for SafeYolo

Provides layered policy evaluation with:
- Baseline policy (always active)
- Task policy (optional, extends baseline)
- Budget tracking with GCRA algorithm
- Hot reload via file watching (delegated to PolicyLoader)

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
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, Field, model_validator

try:
    from .utils import write_event, matches_host_pattern, matches_resource_pattern
    from .budget_tracker import GCRABudgetTracker
    from .policy_loader import PolicyLoader
except ImportError:
    from utils import write_event, matches_host_pattern, matches_resource_pattern
    from budget_tracker import GCRABudgetTracker
    from policy_loader import PolicyLoader

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

    def _matches_credential(self, context: dict[str, Any]) -> bool:
        """Check if credential condition matches."""
        if self.credential is None:
            return True

        ctx_cred = context.get("credential_type", "")
        ctx_hmac = context.get("credential_hmac", "")
        credentials = [self.credential] if isinstance(self.credential, str) else self.credential

        for cred_pattern in credentials:
            if cred_pattern.startswith("hmac:"):
                if ctx_hmac and cred_pattern == f"hmac:{ctx_hmac}":
                    return True
            elif _matches_pattern(f"{ctx_cred}:x", cred_pattern):
                return True
        return False

    def _matches_method(self, context: dict[str, Any]) -> bool:
        """Check if method condition matches."""
        if self.method is None:
            return True

        ctx_method = context.get("method", "").upper()
        methods = [self.method] if isinstance(self.method, str) else self.method
        return ctx_method in [m.upper() for m in methods]

    def _matches_path_prefix(self, context: dict[str, Any]) -> bool:
        """Check if path_prefix condition matches."""
        if self.path_prefix is None:
            return True

        ctx_path = context.get("path", "")
        return ctx_path.startswith(self.path_prefix)

    def _matches_content_type(self, context: dict[str, Any]) -> bool:
        """Check if content_type condition matches."""
        if self.content_type is None:
            return True

        ctx_ct = context.get("content_type", "")
        return self.content_type in ctx_ct

    def matches(self, context: dict[str, Any]) -> bool:
        """Check if all specified conditions match the context."""
        return (
            self._matches_credential(context) and
            self._matches_method(context) and
            self._matches_path_prefix(context) and
            self._matches_content_type(context)
        )


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
# Policy Engine
# =============================================================================

class PolicyEngine:
    """
    Unified policy engine with layered evaluation.

    Layers:
    - Layer 0: Invariants (hardcoded in code)
    - Layer 1: Baseline (always active)
    - Layer 2: Task policy (optional, extends baseline)

    File loading and watching is delegated to PolicyLoader.
    """

    def __init__(
        self,
        baseline_path: Optional[Path] = None,
        budget_state_path: Optional[Path] = None,
    ):
        # Budget tracking
        self._budget_tracker = GCRABudgetTracker(budget_state_path)

        # Policy loader handles file loading, watching, SIGHUP
        self._loader = PolicyLoader(baseline_path)
        if baseline_path:
            self._loader.start_watcher()

        # Thread safety for engine-specific state
        self._lock = threading.RLock()

        # Stats
        self._evaluations = 0

    # -------------------------------------------------------------------------
    # Policy Access (delegated to loader)
    # -------------------------------------------------------------------------

    @property
    def baseline_path(self) -> Optional[Path]:
        """Get baseline policy path."""
        return self._loader.baseline_path

    def get_baseline(self) -> Optional[UnifiedPolicy]:
        """Get current baseline policy."""
        baseline = self._loader.baseline
        if not baseline.permissions:
            return None
        return baseline

    def get_task_policy(self, task_id: Optional[str] = None) -> Optional[UnifiedPolicy]:
        """Get current task policy (if any).

        Args:
            task_id: If provided, only return if task_id matches
        """
        task = self._loader.task_policy
        if task is None:
            return None
        if task_id and task.metadata.task_id != task_id:
            return None
        return task

    def load_task_policy(self, path: Path) -> bool:
        """Load task policy (extends baseline)."""
        return self._loader.load_task_policy(path)

    def clear_task_policy(self) -> None:
        """Clear active task policy."""
        self._loader.clear_task_policy()

    # -------------------------------------------------------------------------
    # Permission Evaluation
    # -------------------------------------------------------------------------

    def _get_merged_permissions(self) -> list[Permission]:
        """Get merged permissions from baseline + task policy."""
        permissions = list(self._loader.baseline.permissions)
        task = self._loader.task_policy
        if task:
            # Task permissions come first (higher priority)
            permissions = list(task.permissions) + permissions
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

            if not matches_resource_pattern(resource, perm.resource):
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
                global_allowed, _ = self._budget_tracker.check_and_consume(
                    global_key, global_budget
                )
                if not global_allowed:
                    return PolicyDecision(
                        effect="budget_exceeded",
                        permission=permission,
                        reason="Global network budget exceeded",
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
        baseline = self._loader.baseline
        task = self._loader.task_policy

        budget = baseline.budgets.get(action)
        if task and action in task.budgets:
            # Task policy can increase but not decrease global budget
            task_budget = task.budgets[action]
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
        baseline = self._loader.baseline
        task = self._loader.task_policy

        # Check domain bypasses
        if domain:
            for pattern, override in baseline.domains.items():
                if matches_host_pattern(domain, pattern):
                    if addon_name in override.bypass:
                        return False
            if task:
                for pattern, override in task.domains.items():
                    if matches_host_pattern(domain, pattern):
                        if addon_name in override.bypass:
                            return False

        # Check client bypasses
        if client_id:
            for pattern, override in baseline.clients.items():
                if _matches_pattern(client_id, pattern):
                    if addon_name in override.bypass:
                        # Check if required - cannot bypass required addons
                        if addon_name in baseline.required:
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
        baseline = self._loader.baseline
        task = self._loader.task_policy

        # Start with baseline
        config = baseline.addons.get(addon_name, AddonConfig())

        # Merge domain-specific config
        if domain:
            for pattern, override in baseline.domains.items():
                if matches_host_pattern(domain, pattern):
                    if addon_name in override.addons:
                        domain_config = override.addons[addon_name]
                        config = AddonConfig(
                            enabled=domain_config.enabled,
                            settings={**config.settings, **domain_config.settings},
                        )

        # Merge task policy
        if task:
            if addon_name in task.addons:
                task_config = task.addons[addon_name]
                # Task cannot disable required addons
                if addon_name in baseline.required:
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
    # Stats & Budget Access
    # -------------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Get policy engine statistics."""
        baseline = self._loader.baseline
        task = self._loader.task_policy

        return {
            "baseline_path": str(self._loader.baseline_path) if self._loader.baseline_path else None,
            "task_policy_path": str(self._loader.task_policy_path) if self._loader.task_policy_path else None,
            "baseline_permissions": len(baseline.permissions),
            "task_permissions": len(task.permissions) if task else 0,
            "required_addons": baseline.required,
            "evaluations": self._evaluations,
            "budget_stats": self._budget_tracker.get_stats(),
        }

    def get_budget_stats(self) -> dict[str, Any]:
        """Get current budget usage statistics."""
        baseline = self._loader.baseline
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
            "global_budgets": baseline.budgets,
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
        baseline = self._loader.baseline
        baseline.permissions.insert(0, new_permission)

        # Re-sort and update
        self._loader.set_baseline(baseline)

        # Save to file if path exists
        if self._loader.baseline_path:
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
            "permission_count": len(baseline.permissions),
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

        self._loader.set_baseline(new_policy)

        # Save to file if path exists
        if self._loader.baseline_path:
            self._save_baseline()

        log.info(f"Updated baseline policy: {len(new_policy.permissions)} permissions")
        write_event(
            "ops.policy_update",
            addon="policy-engine",
            policy_type="baseline",
            permissions_count=len(new_policy.permissions),
        )

        return {
            "status": "updated",
            "permission_count": len(new_policy.permissions),
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

        self._loader.set_task_policy(new_policy)

        log.info(f"Set task policy '{task_id}': {len(new_policy.permissions)} permissions")
        write_event(
            "ops.policy_update",
            addon="policy-engine",
            policy_type="task",
            task_id=task_id,
            permissions_count=len(new_policy.permissions),
        )

        return {
            "status": "updated",
            "task_id": task_id,
            "permission_count": len(new_policy.permissions),
        }

    def _save_baseline(self) -> None:
        """Save baseline policy to file (atomic write)."""
        baseline_path = self._loader.baseline_path
        if not baseline_path:
            return

        try:
            import tempfile
            import shutil

            baseline = self._loader.baseline
            content = yaml.safe_dump(
                baseline.model_dump(exclude_none=True),
                default_flow_style=False,
                allow_unicode=True,
            )

            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.yaml', dir=baseline_path.parent, delete=False
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            shutil.move(tmp_path, baseline_path)
            log.info(f"Saved baseline policy to {baseline_path}")

        except Exception as e:
            log.error(f"Failed to save baseline: {type(e).__name__}: {e}")
            raise

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def done(self) -> None:
        """Cleanup on shutdown."""
        self._loader.stop_watcher()
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
