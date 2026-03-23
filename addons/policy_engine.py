"""
policy_engine.py - Policy engine and PolicyClient configurator for SafeYolo

This module provides:
1. PolicyEngine class - layered policy evaluation (baseline + task policies)
2. PolicyClientConfigurator addon - configures global PolicyClient singleton

PolicyEngine features:
- Baseline policy (always active)
- Task policy (optional, extends baseline)
- Budget tracking with GCRA algorithm
- Hot reload via file watching (delegated to PolicyLoader)

Policy schema uses IAM-style action/resource/effect vocabulary.

Usage (via PolicyClient - recommended):
    from pdp import get_policy_client, create_http_event

    client = get_policy_client()  # Configured by PolicyClientConfigurator addon
    decision = client.evaluate(http_event)
    if decision.effect == Effect.ALLOW:
        # proceed
    else:
        # block with decision.immediate_response

The PolicyClientConfigurator addon configures the PolicyClient singleton
using mitmproxy options (--set policy_file=/path/to/policy.yaml).
It must be loaded BEFORE any addon that calls get_policy_client().
"""

import fnmatch
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from budget_tracker import GCRABudgetTracker
from policy_loader import PolicyLoader
from pydantic import BaseModel, Field, model_validator
from utils import matches_host_pattern, matches_resource_pattern, sanitize_for_log, write_event

from audit_schema import EventKind, Severity

log = logging.getLogger("safeyolo.policy-engine")


# =============================================================================
# Pydantic Models
# =============================================================================


class PolicyMetadata(BaseModel):
    """Policy file metadata."""

    version: str = "1.0"
    task_id: str | None = None
    description: str | None = None
    created: str | None = None
    approved: str | None = None
    brief_hash: str | None = None
    policy_hash: str | None = None


class Condition(BaseModel):
    """Optional conditions for permission matching."""

    # For credential:use - what credentials can access this destination
    credential: str | list[str] | None = None  # e.g., ["openai:*", "hmac:a1b2c3"]
    # For network:request
    method: str | list[str] | None = None
    path_prefix: str | None = None
    content_type: str | None = None
    # For gateway:risky_route
    tactics: list[str] | None = None  # ANY-match against route tactics
    enables: list[str] | None = None  # ANY-match against route enables
    irreversible: bool | None = None  # exact match
    account: str | list[str] | None = None  # persona match
    agent: str | None = None  # glob match
    service: str | None = None  # glob match

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

    def _matches_tactics(self, context: dict[str, Any]) -> bool:
        """Check if any condition tactic is in the route's tactics (ANY-match)."""
        if self.tactics is None:
            return True
        ctx_tactics = context.get("tactics", [])
        return bool(set(self.tactics) & set(ctx_tactics))

    def _matches_enables(self, context: dict[str, Any]) -> bool:
        """Check if any condition enables is in the route's enables (ANY-match)."""
        if self.enables is None:
            return True
        ctx_enables = context.get("enables", [])
        return bool(set(self.enables) & set(ctx_enables))

    def _matches_irreversible(self, context: dict[str, Any]) -> bool:
        """Check if irreversible condition matches exactly."""
        if self.irreversible is None:
            return True
        return context.get("irreversible", False) == self.irreversible

    def _matches_account(self, context: dict[str, Any]) -> bool:
        """Check if account persona matches."""
        if self.account is None:
            return True
        ctx_account = context.get("account", "")
        accounts = [self.account] if isinstance(self.account, str) else self.account
        return ctx_account in accounts

    def _matches_agent(self, context: dict[str, Any]) -> bool:
        """Check if agent matches (glob)."""
        if self.agent is None:
            return True
        ctx_agent = context.get("agent", "")
        return fnmatch.fnmatch(ctx_agent, self.agent)

    def _matches_service(self, context: dict[str, Any]) -> bool:
        """Check if service matches (glob)."""
        if self.service is None:
            return True
        ctx_service = context.get("service", "")
        return fnmatch.fnmatch(ctx_service, self.service)

    def matches(self, context: dict[str, Any]) -> bool:
        """Check if all specified conditions match the context."""
        return (
            self._matches_credential(context)
            and self._matches_method(context)
            and self._matches_path_prefix(context)
            and self._matches_content_type(context)
            and self._matches_tactics(context)
            and self._matches_enables(context)
            and self._matches_irreversible(context)
            and self._matches_account(context)
            and self._matches_agent(context)
            and self._matches_service(context)
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

    action: Literal[
        "credential:use", "network:request", "file:read", "file:write", "subprocess:exec", "gateway:risky_route"
    ]
    resource: str  # glob pattern for destination: "api.openai.com/*", "*.example.com/*"
    effect: Literal["allow", "deny", "prompt", "budget"] = "allow"
    budget: int | None = None  # Required if effect=budget (requests per minute)
    tier: Literal["explicit", "inferred"] = "explicit"
    condition: Condition | None = None

    @model_validator(mode="after")
    def validate_budget_required(self):
        """Ensure budget is set when effect is 'budget'."""
        if self.effect == "budget" and self.budget is None:
            raise ValueError("budget must be set when effect is 'budget'")
        return self


class CredentialRule(BaseModel):
    """Credential detection and routing rule.

    Defines patterns for detecting credential types and where they can be routed.
    Used by credential_guard for detection and policy evaluation for routing.
    """

    name: str  # e.g., "openai", "anthropic", "github"
    patterns: list[str]  # Regex patterns for detection
    allowed_hosts: list[str]  # Where this credential can go
    header_names: list[str] = Field(default_factory=lambda: ["authorization", "x-api-key"])
    suggested_url: str = ""  # Hint for error messages


class ScanPattern(BaseModel):
    """Content scan pattern rule.

    Defines patterns for detecting sensitive content in URLs, headers, or bodies.
    Used by pattern_scanner to block or log matching content.
    """

    name: str
    pattern: str  # Regex pattern
    target: Literal["request", "response", "both"] = "both"
    scope: list[Literal["url", "headers", "body"]] = Field(default_factory=lambda: ["body"])
    action: Literal["block", "log"] = "log"
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    message: str = ""
    case_sensitive: bool = True


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
    """Complete policy document.

    Contains all security configuration for a baseline or task policy:
    - permissions: IAM-style access control rules
    - credential_rules: Credential detection patterns and allowed destinations
    - scan_patterns: Content scanning patterns for URLs/headers/bodies
    - budgets: Global rate limit caps
    - addons: Addon-specific configuration
    """

    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    permissions: list[Permission] = Field(default_factory=list)
    budgets: dict[str, int] = Field(default_factory=dict)  # Global budget caps
    required: list[str] = Field(default_factory=list)  # Addons that cannot be disabled

    # Credential detection and routing
    credential_rules: list[CredentialRule] = Field(default_factory=list)

    # Content scanning patterns
    scan_patterns: list[ScanPattern] = Field(default_factory=list)

    # Addon and domain configuration
    addons: dict[str, AddonConfig] = Field(default_factory=dict)
    domains: dict[str, DomainOverride] = Field(default_factory=dict)
    clients: dict[str, DomainOverride] = Field(default_factory=dict)

    # Service gateway: agent-to-service token bindings (compiled from agents: section)
    gateway: dict = Field(default_factory=dict)


# =============================================================================
# Decision Types
# =============================================================================


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""

    effect: Literal["allow", "deny", "prompt", "budget_exceeded"]
    permission: Permission | None = None  # Matched permission (if any)
    reason: str = ""
    budget_remaining: int | None = None


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
        baseline_path: Path | None = None,
        budget_state_path: Path | None = None,
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

    def add_reload_callback(self, callback) -> None:
        """Register a callback to run after policy reloads."""
        self._loader.add_reload_callback(callback)

    # -------------------------------------------------------------------------
    # Policy Access (delegated to loader)
    # -------------------------------------------------------------------------

    @property
    def baseline_path(self) -> Path | None:
        """Get baseline policy path."""
        return self._loader.baseline_path

    def get_baseline(self) -> UnifiedPolicy | None:
        """Get current baseline policy."""
        baseline = self._loader.baseline
        if not baseline.permissions:
            return None
        return baseline

    def get_task_policy(self, task_id: str | None = None) -> UnifiedPolicy | None:
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

    def get_credential_rules(self) -> list[CredentialRule]:
        """Get merged credential rules from baseline + task policy.

        Returns credential detection and routing rules. Task rules are
        appended to baseline (additive, not replacement).
        """
        rules = list(self._loader.baseline.credential_rules)
        task = self._loader.task_policy
        if task:
            rules.extend(task.credential_rules)
        return rules

    def get_scan_patterns(self) -> list[ScanPattern]:
        """Get merged scan patterns from baseline + task policy.

        Returns content scanning patterns. Task patterns are appended
        to baseline (additive, not replacement).
        """
        patterns = list(self._loader.baseline.scan_patterns)
        task = self._loader.task_policy
        if task:
            patterns.extend(task.scan_patterns)
        return patterns

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
    ) -> Permission | None:
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
        credential_hmac: str | None = None,
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
            allowed, remaining = self._budget_tracker.check_and_consume(budget_key, permission.budget)
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
            allowed, remaining = self._budget_tracker.check_and_consume(budget_key, permission.budget)

            # Also check global budget
            global_budget = self._get_global_budget("network:request")
            if global_budget:
                global_key = "network:request:__global__"
                global_allowed, _ = self._budget_tracker.check_and_consume(global_key, global_budget)
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

    def evaluate_risky_route(
        self,
        service: str,
        agent: str,
        account: str,
        tactics: list[str],
        enables: list[str],
        irreversible: bool,
        method: str = "GET",
        path: str = "/",
    ) -> PolicyDecision:
        """Evaluate a risky route against gateway risk appetite rules.

        Default (no matching rule) → effect="prompt" (fail safe — require approval).
        """
        self._evaluations += 1

        context = {
            "service": service,
            "agent": agent,
            "account": account,
            "tactics": tactics,
            "enables": enables,
            "irreversible": irreversible,
            "method": method,
            "path": path,
        }

        permission = self._find_matching_permission("gateway:risky_route", "*", context)

        if permission is None:
            # Default fail-safe: require approval
            return PolicyDecision(
                effect="prompt",
                reason="Risky route requires approval (no matching risk appetite rule)",
            )

        return PolicyDecision(
            effect=permission.effect,
            permission=permission,
            reason=f"Risk appetite rule matched: {permission.effect}",
        )

    def _get_global_budget(self, action: str) -> int | None:
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
        domain: str | None = None,
        client_id: str | None = None,
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

        # Check client bypasses and addon config
        if client_id:
            for pattern, override in baseline.clients.items():
                if _matches_pattern(client_id, pattern):
                    # Check bypass list
                    if addon_name in override.bypass:
                        # Check if required - cannot bypass required addons
                        if addon_name in baseline.required:
                            return True
                        return False
                    # Check client-specific addon config
                    if addon_name in override.addons:
                        client_config = override.addons[addon_name]
                        if not client_config.enabled:
                            # Check if required - cannot disable required addons
                            if addon_name in baseline.required:
                                return True
                            return False

        # Check addon config
        config = self._get_addon_config(addon_name, domain)
        return config.enabled

    def _get_addon_config(
        self,
        addon_name: str,
        domain: str | None = None,
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
        domain: str | None = None,
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

    def reset_budgets(self, resource: str | None = None) -> dict[str, Any]:
        """Reset budget counters.

        Args:
            resource: If provided, reset only this resource. Otherwise reset all.

        Returns:
            Dict with status and reset count.
        """
        if resource:
            self._budget_tracker.reset(resource)
            log.info(f"Reset policy budget for: {resource}")
            write_event(
                "admin.budget_reset",
                kind=EventKind.ADMIN,
                severity=Severity.MEDIUM,
                summary=f"Budget reset for {sanitize_for_log(resource)}",
                addon="policy-engine",
                details={"resource": resource},
            )
            return {"status": "reset", "resource": resource}
        else:
            self._budget_tracker.reset_all()
            log.info("Reset all policy budgets")
            write_event(
                "admin.budget_reset",
                kind=EventKind.ADMIN,
                severity=Severity.MEDIUM,
                summary="All budgets reset",
                addon="policy-engine",
                details={"resource": "all"},
            )
            return {"status": "reset", "resource": "all"}

    # -------------------------------------------------------------------------
    # Policy Modification
    # -------------------------------------------------------------------------

    def add_credential_approval(
        self,
        destination: str,
        cred_id: str | list[str],
        tier: str = "explicit",
    ) -> dict[str, Any]:
        """Add credential permission to baseline policy (destination-first).

        Args:
            destination: Destination host pattern (e.g., "api.example.com", "*.example.com")
            cred_id: Credential identifier(s) (e.g., "hmac:a1b2c3", "openai:*")
            tier: Permission tier ("explicit" or "inferred")

        Returns:
            Dict with status and permission count
        """
        if tier not in ("explicit", "inferred"):
            raise ValueError(f"tier must be 'explicit' or 'inferred', got '{tier}'")

        cred_ids = [cred_id] if isinstance(cred_id, str) else cred_id

        # Create new permission (destination-first)
        condition = Condition(credential=cred_ids)
        new_permission = Permission(
            action="credential:use",
            resource=f"{destination}/*",
            effect="allow",
            tier=tier,
            condition=condition,
        )

        # Add to baseline (at beginning for higher priority)
        with self._loader._lock:
            baseline = self._loader._baseline
            baseline.permissions.insert(0, new_permission)

        # Re-sort and update
        self._loader.set_baseline(baseline)

        # Save to file if path exists
        if self._loader.baseline_path:
            self._save_baseline_incremental(new_permission)

        log.info("Added credential approval: %s accepts %s", sanitize_for_log(destination), cred_ids)
        write_event(
            "admin.approval_added",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Credential approval added: {sanitize_for_log(destination)} accepts {cred_ids}",
            addon="policy-engine",
            details={"destination": destination, "cred_id": cred_ids, "tier": tier},
        )

        return {
            "status": "added",
            "permission_count": len(baseline.permissions),
        }

    def replace_baseline(self, policy_data: dict[str, Any]) -> dict[str, Any]:
        """Replace baseline policy from dict.

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
            self._save_baseline_full()

        log.info(f"Replaced baseline policy: {len(new_policy.permissions)} permissions")
        write_event(
            "ops.policy_update",
            kind=EventKind.OPS,
            severity=Severity.MEDIUM,
            summary=f"Baseline policy replaced: {len(new_policy.permissions)} permissions",
            addon="policy-engine",
            details={"policy_type": "baseline", "permissions_count": len(new_policy.permissions)},
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
            kind=EventKind.OPS,
            severity=Severity.MEDIUM,
            summary=f"Task policy '{sanitize_for_log(task_id)}' set: {len(new_policy.permissions)} permissions",
            addon="policy-engine",
            details={"policy_type": "task", "task_id": task_id, "permissions_count": len(new_policy.permissions)},
        )

        return {
            "status": "updated",
            "task_id": task_id,
            "permission_count": len(new_policy.permissions),
        }

    def _save_baseline_incremental(self, new_permission: Permission) -> None:
        """Save baseline with a new permission inserted, preserving comments.

        Handles both host-centric and IAM formats:
        - Host-centric: adds to the hosts section
        - IAM: inserts into the permissions list

        Falls back to full rewrite if the original file can't be loaded.

        Args:
            new_permission: The permission to insert at the top of the list
        """
        baseline_path = self._loader.baseline_path
        if not baseline_path:
            return

        try:
            from yaml_roundtrip import load_roundtrip, save_roundtrip

            if baseline_path.exists():
                data = load_roundtrip(baseline_path)

                if "hosts" in data:
                    # Host-centric format: add to hosts section
                    self._save_host_centric_approval(data, new_permission)
                else:
                    # IAM format: insert into permissions list
                    perm_dict = new_permission.model_dump(exclude_none=True)
                    if "permissions" in data:
                        data["permissions"].insert(0, perm_dict)
                    else:
                        data["permissions"] = [perm_dict]

                save_roundtrip(baseline_path, data)
                return
        except Exception as e:
            log.warning("Round-trip save failed, falling back to full rewrite: %s", e)

        # Fallback: full rewrite without comment preservation
        self._save_baseline_plain()

    def _save_host_centric_approval(self, data: dict, permission: Permission) -> None:
        """Insert a credential approval into the hosts section of a host-centric file.

        Extracts the host from the permission resource and adds/updates the
        credentials list in the hosts section.

        Args:
            data: Round-trip loaded YAML data (CommentedMap)
            permission: The credential:use permission to add
        """
        from ruamel.yaml.comments import CommentedMap, CommentedSeq

        # Extract host from resource pattern (e.g., "api.example.com/*" → "api.example.com")
        resource = permission.resource
        host = resource.rstrip("/*") if resource.endswith("/*") else resource

        hosts = data.get("hosts")
        if hosts is None:
            hosts = CommentedMap()
            data["hosts"] = hosts

        # Get or create host entry
        if host in hosts and isinstance(hosts[host], dict):
            host_config = hosts[host]
        else:
            host_config = CommentedMap()
            hosts[host] = host_config

        # Extract credential IDs from the permission condition
        cred_ids = []
        if permission.condition and permission.condition.credential:
            creds = permission.condition.credential
            if isinstance(creds, str):
                cred_ids = [creds]
            else:
                cred_ids = list(creds)

        # Add to existing credentials or create new list
        existing = host_config.get("credentials")
        if existing is None:
            new_creds = CommentedSeq(cred_ids)
            host_config["credentials"] = new_creds
        else:
            for cred in cred_ids:
                if cred not in existing:
                    existing.append(cred)

    def _save_baseline_full(self) -> None:
        """Save full baseline policy, preserving comments where possible.

        If the original file exists, loads it with ruamel.yaml and merges the
        current policy data into it, preserving section banners and comments
        on unchanged keys. Falls back to plain dump if round-trip fails.
        """
        baseline_path = self._loader.baseline_path
        if not baseline_path:
            return

        try:
            from yaml_roundtrip import load_roundtrip, merge_into_roundtrip, save_roundtrip

            if baseline_path.exists():
                original = load_roundtrip(baseline_path)
                baseline = self._loader.baseline
                new_data = baseline.model_dump(exclude_none=True)
                merge_into_roundtrip(original, new_data)
                save_roundtrip(baseline_path, original)
                return
        except Exception as e:
            log.warning("Round-trip save failed, falling back to full rewrite: %s", e)

        # Fallback: full rewrite without comment preservation
        self._save_baseline_plain()

    def _save_baseline_plain(self) -> None:
        """Save baseline policy as plain YAML (no comment preservation).

        Used as fallback when the original file doesn't exist or ruamel.yaml
        round-trip fails.
        """
        baseline_path = self._loader.baseline_path
        if not baseline_path:
            return

        try:
            import shutil
            import tempfile

            baseline = self._loader.baseline
            content = yaml.safe_dump(
                baseline.model_dump(exclude_none=True),
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )

            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", dir=baseline_path.parent, delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            shutil.move(tmp_path, baseline_path)
            log.info(f"Saved baseline policy (plain) to {baseline_path}")

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
# Mitmproxy Addon Interface - PolicyClient Configurator
# =============================================================================
#
# This addon configures the global PolicyClient singleton.
# It must load BEFORE any addon that calls get_policy_client().
#
# Design:
# - Registers mitmproxy options for policy paths
# - Calls configure_policy_client() on startup/reconfigure
# - Does NOT own a PolicyEngine instance (PDPCore does via LocalPolicyClient)
#
# This is the ONLY place PolicyClient should be configured in mitmproxy mode.
# =============================================================================


class PolicyClientConfigurator:
    """
    Mitmproxy addon that configures the global PolicyClient.

    Must be loaded first in the addon chain. Other addons use get_policy_client()
    to get the configured client.
    """

    name = "policy-engine"  # Keep name for backwards compat with existing configs

    def __init__(self):
        self._configured_baseline: str | None = None
        self._configured_budget: str | None = None

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="policy_file",
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
        """Configure PolicyClient when options change."""
        from mitmproxy import ctx

        from pdp import PolicyClientConfig, configure_policy_client

        baseline_path = ctx.options.policy_file
        budget_path = ctx.options.policy_budget_state

        # Skip if nothing changed (smart reconfigure)
        if baseline_path == self._configured_baseline and budget_path == self._configured_budget:
            return

        # Build config with paths from mitmproxy options
        config = PolicyClientConfig(
            mode="local",
            baseline_path=Path(baseline_path) if baseline_path else None,
            budget_state_path=Path(budget_path) if budget_path else None,
        )

        configure_policy_client(config)

        self._configured_baseline = baseline_path
        self._configured_budget = budget_path

        log.info(
            "PolicyClient configured",
            extra={
                "baseline_path": baseline_path,
                "budget_state_path": budget_path,
            },
        )

    def done(self):
        """Cleanup on shutdown."""
        from pdp import reset_policy_client

        reset_policy_client()

    def get_stats(self) -> dict:
        """Get engine statistics via PolicyClient.get_stats()."""
        from pdp import get_policy_client, is_policy_client_configured

        if is_policy_client_configured():
            try:
                client = get_policy_client()
                return client.get_stats()
            except Exception:
                log.debug("Failed to get policy stats", exc_info=True)
        return {}


# Mitmproxy addon instance
policy_engine_addon = PolicyClientConfigurator()
addons = [policy_engine_addon]
