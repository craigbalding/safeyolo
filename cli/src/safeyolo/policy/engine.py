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
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from safeyolo.core.audit_schema import EventKind, Severity
from safeyolo.core.utils import matches_host_pattern, matches_resource_pattern, sanitize_for_log, write_event
from safeyolo.policy.budget_tracker import GCRABudgetTracker

# `PolicyLoader` is imported lazily inside `PolicyEngine.__init__` to
# avoid a module-level cycle: `loader.py` type-hints `UnifiedPolicy`
# (defined here) under `TYPE_CHECKING`, which CodeQL's
# `py/unsafe-cyclic-import` flags as a cycle even though there's no
# runtime edge. Keeping the runtime import at the call site eliminates
# both the lint complaint and any lingering import-order risk.

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
    capability: str | None = None  # glob match

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

    def _matches_capability(self, context: dict[str, Any]) -> bool:
        """Check if capability matches (glob)."""
        if self.capability is None:
            return True
        ctx_capability = context.get("capability", "")
        return fnmatch.fnmatch(ctx_capability, self.capability)

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
            and self._matches_capability(context)
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
        "credential:use",
        "network:request",
        "file:read",
        "file:write",
        "subprocess:exec",
        "gateway:risky_route",
        "gateway:request",
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

    # Summary of permissions extracted into simple sets (not in permissions list)
    # Format: {"network:request:deny": 92276, "network:request:allow": 5}
    simple_permissions: dict[str, int] = Field(default_factory=dict)


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
        services_dir: Path | None = None,
    ):
        # Budget tracking
        self._budget_tracker = GCRABudgetTracker(budget_state_path)

        # Policy loader handles file loading, watching, SIGHUP.
        # Lazy import — see module-level comment about the cycle.
        from safeyolo.policy.loader import PolicyLoader  # noqa: PLC0415
        self._loader = PolicyLoader(baseline_path, services_dir=services_dir)
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
        """Get current baseline policy.

        Returns the policy object if a baseline has been loaded (even if it
        has zero IAM permissions — a policy with only simple_permissions,
        credential_rules, or gateway config is still meaningful). Returns
        None only if no baseline path was configured.
        """
        if self._loader.baseline_path is None:
            return None
        return self._loader.baseline

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

    # Lightweight Permission stand-ins for simple set matches (no Pydantic overhead)
    _SIMPLE_DENY = Permission(action="network:request", resource="*", effect="deny")
    _SIMPLE_PROMPT = Permission(action="network:request", resource="*", effect="prompt")
    _SIMPLE_ALLOW = Permission(action="network:request", resource="*", effect="allow")
    _SIMPLE_EFFECT_MAP = {"deny": _SIMPLE_DENY, "prompt": _SIMPLE_PROMPT, "allow": _SIMPLE_ALLOW}

    def _find_matching_permission(
        self,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> Permission | None:
        """Find first matching permission using three-tier indexed lookup.

        When agent is in context, agent-scoped permissions are checked first
        across all tiers before falling through to unconditioned permissions.
        This ensures an agent's catch-all deny takes priority over proxy-wide
        explicit host entries.

        Tiers:
        1. Simple sets — O(1) set membership for bulk deny/allow/prompt
        2. Exact dict — O(1) dict lookup for host/* with conditions/budgets
        3. Pattern list — linear scan over wildcards/globs only
        """
        simple_sets, exact_dict, pattern_list = self._loader.get_merged_index()
        agent = context.get("agent")

        if agent:
            # Phase 1: agent-scoped permissions only (exact dict + patterns)
            result = self._check_exact_dict(exact_dict, action, resource, context, agent_only=True)
            if result:
                return result
            result = self._check_patterns(pattern_list, action, resource, context, agent_only=True)
            if result:
                return result

        # Phase 2: unconditioned permissions (simple sets + exact dict + patterns)
        # Simple sets have no conditions — always unconditioned
        for effect in ("deny", "prompt", "allow"):
            resources = simple_sets.get((action, effect))
            if resources and resource in resources:
                return self._SIMPLE_EFFECT_MAP.get(effect, self._SIMPLE_DENY)

        result = self._check_exact_dict(exact_dict, action, resource, context, agent_only=False)
        if result:
            return result
        return self._check_patterns(pattern_list, action, resource, context, agent_only=False)

    @staticmethod
    def _check_exact_dict(exact_dict, action, resource, context, *, agent_only):
        """Check exact dict tier, optionally filtering by agent condition."""
        candidates = exact_dict.get((action, resource))
        if not candidates:
            return None
        for perm in candidates:
            if perm.tier == "inferred":
                continue
            has_agent_cond = perm.condition and perm.condition.agent is not None
            if agent_only and not has_agent_cond:
                continue
            if not agent_only and has_agent_cond:
                continue
            if perm.condition and not perm.condition.matches(context):
                continue
            return perm
        return None

    @staticmethod
    def _check_patterns(pattern_list, action, resource, context, *, agent_only):
        """Check pattern list tier, optionally filtering by agent condition."""
        for perm in pattern_list:
            if perm.action != action:
                continue
            if not matches_resource_pattern(resource, perm.resource):
                continue
            if perm.tier == "inferred":
                continue
            has_agent_cond = perm.condition and perm.condition.agent is not None
            if agent_only and not has_agent_cond:
                continue
            if not agent_only and has_agent_cond:
                continue
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
        agent: str | None = None,
    ) -> PolicyDecision:
        """
        Evaluate network request permission.

        Agent-scoped permissions (with condition.agent) are checked first.
        Falls back to proxy-wide permissions if no agent match.

        Args:
            host: Target host
            path: Request path
            method: HTTP method
            agent: Agent name from service discovery (for per-agent policy)

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
        if agent:
            context["agent"] = agent

        # Try exact host match first
        permission = self._find_matching_permission("network:request", resource, context)

        if permission is None:
            # Try wildcard match
            permission = self._find_matching_permission("network:request", "*", context)

        if permission is None:
            # Default: deny. A security tool must fail closed when no
            # permission matches. If the operator wants default-allow, the
            # setup wizard adds an explicit `*` allow rule to the baseline.
            return PolicyDecision(effect="deny", reason="No matching permission (default deny)")

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

    def evaluate_gateway_request(
        self,
        service: str,
        capability: str,
        agent: str,
        method: str,
        path: str,
    ) -> PolicyDecision:
        """Evaluate a gateway request against compiled capability route permissions.

        Default (no matching rule) → effect="deny" (fail safe — unmatched route is forbidden).

        Args:
            service: Service name (e.g., "minifuse")
            capability: Capability name (e.g., "reader", "category_manager")
            agent: Agent name (e.g., "claude")
            method: HTTP method (e.g., "GET")
            path: Request path (e.g., "/v1/feeds")

        Returns:
            PolicyDecision with effect and details
        """
        self._evaluations += 1

        resource = f"{service}:{path}"
        context = {
            "service": service,
            "capability": capability,
            "agent": agent,
            "method": method,
        }

        permission = self._find_matching_permission("gateway:request", resource, context)

        if permission is None:
            # Default fail-safe: deny — an unmatched route is forbidden
            return PolicyDecision(
                effect="deny",
                reason=f"No gateway:request permission for {sanitize_for_log(agent)}/{sanitize_for_log(service)}/{sanitize_for_log(capability)} {sanitize_for_log(method)} {sanitize_for_log(path)}",
            )

        return PolicyDecision(
            effect=permission.effect,
            permission=permission,
            reason=f"Gateway request matched: {permission.effect}",
        )

    def _get_global_budget(self, action: str) -> int | None:
        """Get global budget cap for an action."""
        baseline = self._loader.baseline
        task = self._loader.task_policy

        budget = baseline.budgets.get(action)
        if task and action in task.budgets:
            # Task policy can restrict (lower) but not escalate (raise) the
            # global budget. The baseline is the security ceiling — a scoped,
            # less-trusted task context must not be able to raise rate limits.
            task_budget = task.budgets[action]
            if budget is None:
                budget = task_budget
            else:
                budget = min(budget, task_budget)
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

        # Check domain bypasses — but required addons cannot be bypassed
        if domain:
            for pattern, override in baseline.domains.items():
                if matches_host_pattern(domain, pattern):
                    if addon_name in override.bypass:
                        if addon_name in baseline.required:
                            return True  # Required addons resist domain bypass
                        return False
            if task:
                for pattern, override in task.domains.items():
                    if matches_host_pattern(domain, pattern):
                        if addon_name in override.bypass:
                            if addon_name in baseline.required:
                                return True
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

    def update_host_rate(self, host: str, rate: int) -> dict[str, Any]:
        """Update rate limit for a host in baseline policy.

        Args:
            host: Host pattern (e.g., "api.openai.com")
            rate: New rate limit (requests per minute)

        Returns:
            Dict with status, host, old_rate, new_rate
        """
        if rate < 1:
            raise ValueError("rate must be >= 1")

        with self._loader._lock:
            baseline = self._loader._baseline

            # Find existing budget permission for this host
            old_rate = None
            found = False
            for perm in baseline.permissions:
                if perm.action == "network:request" and perm.effect == "budget":
                    resource_host = perm.resource.rstrip("/*") if perm.resource.endswith("/*") else perm.resource
                    if resource_host == host:
                        old_rate = perm.budget
                        perm.budget = rate
                        found = True
                        break

            if not found:
                # Create new budget permission
                new_perm = Permission(
                    action="network:request",
                    resource=f"{host}/*",
                    effect="budget",
                    budget=rate,
                    tier="explicit",
                )
                baseline.permissions.append(new_perm)

        # Re-sort and update
        self._loader.set_baseline(baseline)

        # Persist to TOML if path exists
        if self._loader.baseline_path and self._loader.baseline_path.suffix == ".toml":
            try:
                from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip, update_host_field

                doc = load_roundtrip(self._loader.baseline_path)
                update_host_field(doc, host, "rate", rate)
                save_roundtrip(self._loader.baseline_path, doc)
            except Exception as e:
                log.warning("TOML round-trip save failed for host rate update: %s", e)

        log.info("Updated host rate: %s %s -> %s", sanitize_for_log(host), old_rate, rate)
        write_event(
            "admin.host_rate_updated",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Rate limit updated: {sanitize_for_log(host)} {old_rate} -> {rate}",
            addon="policy-engine",
            details={"host": host, "old_rate": old_rate, "new_rate": rate},
        )

        return {"status": "updated", "host": host, "old_rate": old_rate, "new_rate": rate}

    def add_host_allowance(
        self, host: str, rate: int | None = None, agent: str | None = None,
    ) -> dict[str, Any]:
        """Add a host to the allowed list in baseline policy.

        Upserts — removes any existing permission for the same host+agent
        before adding, so repeated calls don't accumulate duplicates.

        Args:
            host: Host pattern (e.g., "cdn.example.com")
            rate: Optional rate limit (requests per minute)
            agent: Optional agent name — writes to [agents.<name>.hosts] if set

        Returns:
            Dict with status, host, rate, agent
        """
        condition = Condition(agent=agent) if agent else None
        resource = f"{host}/*"

        with self._loader._lock:
            baseline = self._loader._baseline

            # Remove existing permissions for this host+agent before adding
            baseline.permissions = [
                p for p in baseline.permissions
                if not (p.action == "network:request" and p.resource == resource
                        and p.effect in ("allow", "budget")
                        and p.condition == condition)
            ]

            new_perm = Permission(
                action="network:request",
                resource=resource,
                effect="allow",
                tier="explicit",
                condition=condition,
            )
            baseline.permissions.insert(0, new_perm)

            if rate is not None:
                budget_perm = Permission(
                    action="network:request",
                    resource=resource,
                    effect="budget",
                    budget=rate,
                    tier="explicit",
                    condition=condition,
                )
                baseline.permissions.append(budget_perm)

        self._loader.set_baseline(baseline)

        # Persist to TOML
        if self._loader.baseline_path and self._loader.baseline_path.suffix == ".toml":
            try:
                from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip, upsert_host

                doc = load_roundtrip(self._loader.baseline_path)
                config: dict[str, Any] = {}
                if rate is not None:
                    config["rate"] = rate

                if agent:
                    self._write_agent_host(doc, agent, host, config)
                else:
                    upsert_host(doc, host, config)
                save_roundtrip(self._loader.baseline_path, doc)
            except (OSError, ValueError) as e:
                log.warning("TOML round-trip save failed for host allowance: %s", e)

        log.info("Added host allowance: %s (rate=%s, agent=%s)",
                 sanitize_for_log(host), sanitize_for_log(str(rate)), sanitize_for_log(str(agent)))
        write_event(
            "admin.host_allowed",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host allowed: {sanitize_for_log(host)} (rate={rate})",
            addon="policy-engine",
            details={"host": host, "rate": rate, "agent": agent},
        )

        return {"status": "added", "host": host, "rate": rate, "agent": agent}

    def add_host_denial(
        self, host: str, expires: str | None = None, agent: str | None = None,
    ) -> dict[str, Any]:
        """Deny egress to a host in baseline policy.

        Upserts — removes any existing deny permission for the same host+agent
        before adding, so repeated calls don't accumulate duplicates.

        Writes a host entry with egress = "deny" to policy.toml.
        Optionally includes an expires datetime for auto-cleanup.

        Args:
            host: Host pattern (e.g., "dodgy-site.com")
            expires: Optional ISO datetime string for auto-expiry
            agent: Optional agent name — writes to [agents.<name>.hosts] if set

        Returns:
            Dict with status, host, expires, agent
        """
        condition = Condition(agent=agent) if agent else None
        resource = f"{host}/*"

        with self._loader._lock:
            baseline = self._loader._baseline

            # Remove existing deny for this host+agent before adding
            baseline.permissions = [
                p for p in baseline.permissions
                if not (p.action == "network:request" and p.resource == resource
                        and p.effect == "deny" and p.condition == condition)
            ]

            new_perm = Permission(
                action="network:request",
                resource=resource,
                effect="deny",
                tier="explicit",
                condition=condition,
            )
            baseline.permissions.insert(0, new_perm)

        self._loader.set_baseline(baseline)

        # Persist to TOML
        if self._loader.baseline_path and self._loader.baseline_path.suffix == ".toml":
            try:
                from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip, upsert_host

                doc = load_roundtrip(self._loader.baseline_path)
                config: dict[str, Any] = {"egress": "deny"}
                if expires:
                    from datetime import datetime

                    config["expires"] = datetime.fromisoformat(expires)

                if agent:
                    self._write_agent_host(doc, agent, host, config)
                else:
                    upsert_host(doc, host, config)
                save_roundtrip(self._loader.baseline_path, doc)
            except (OSError, ValueError) as e:
                log.warning("TOML round-trip save failed for host denial: %s", e)

        log.info("Added host denial: %s (expires=%s, agent=%s)",
                 sanitize_for_log(host), sanitize_for_log(str(expires)), sanitize_for_log(str(agent)))
        write_event(
            "admin.host_denied",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host denied: {sanitize_for_log(host)} (expires={sanitize_for_log(str(expires))})",
            addon="policy-engine",
            details={"host": host, "expires": expires, "agent": agent},
        )

        return {"status": "denied", "host": host, "expires": expires, "agent": agent}

    @staticmethod
    def _write_agent_host(doc, agent_name: str, host: str, config: dict) -> None:
        """Write a host entry to [agents.<name>.hosts] in a TOMLDocument."""
        import tomlkit

        agents = doc.get("agents")
        if agents is None:
            agents = tomlkit.table()
            doc.add("agents", agents)
        agent_section = agents.get(agent_name)
        if agent_section is None:
            agent_section = tomlkit.table()
            agents.add(agent_name, agent_section)
        hosts = agent_section.get("hosts")
        if hosts is None:
            hosts = tomlkit.table()
            agent_section.add("hosts", hosts)

        it = tomlkit.inline_table()
        for k, v in config.items():
            it.append(k, v)
        hosts[host] = it

    def add_host_bypass(self, host: str, addon: str) -> dict[str, Any]:
        """Add an addon bypass for a host in baseline policy.

        Reads current bypass list from the TOML file, appends the addon,
        and persists. The bypass field is host-level config consumed by
        the policy compiler, not part of the IAM Permission model.

        Args:
            host: Host pattern (e.g., "internal.example.com")
            addon: Addon name to bypass (e.g., "pattern-scanner")

        Returns:
            Dict with status, host, bypass list
        """
        baseline_path = self._loader.baseline_path
        if not baseline_path or baseline_path.suffix != ".toml":
            raise ValueError("Host bypass requires a TOML policy file")

        try:
            from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip, update_host_field

            doc = load_roundtrip(baseline_path)

            # Read existing bypass list from TOML
            current_bypass: list[str] = []
            hosts = doc.get("hosts")
            if hosts and host in hosts:
                host_config = hosts[host]
                if isinstance(host_config, dict):
                    existing = host_config.get("bypass")
                    if existing:
                        current_bypass = list(existing)

            if addon in current_bypass:
                return {"status": "unchanged", "host": host, "bypass": current_bypass}

            updated_bypass = current_bypass + [addon]
            update_host_field(doc, host, "bypass", updated_bypass)
            save_roundtrip(baseline_path, doc)
        except Exception as e:
            log.warning("TOML round-trip save failed for host bypass: %s", e)
            raise

        # Reload from disk to pick up the change
        self._loader.reload()

        log.info("Added host bypass: %s bypass=%s", sanitize_for_log(host), updated_bypass)
        write_event(
            "admin.host_bypass_added",
            kind=EventKind.ADMIN,
            severity=Severity.MEDIUM,
            summary=f"Host bypass added: {sanitize_for_log(host)} bypass={addon}",
            addon="policy-engine",
            details={"host": host, "addon": addon, "bypass": updated_bypass},
        )

        return {"status": "updated", "host": host, "bypass": updated_bypass}

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

        # TOML branch: use tomlkit for round-trip editing
        if baseline_path.suffix == ".toml":
            try:
                from safeyolo.policy.toml_roundtrip import add_host_credential, load_roundtrip, save_roundtrip

                if baseline_path.exists():
                    doc = load_roundtrip(baseline_path)

                    # Extract host and cred_ids from the permission
                    resource = new_permission.resource
                    host = resource.rstrip("/*") if resource.endswith("/*") else resource
                    cred_ids = []
                    if new_permission.condition and new_permission.condition.credential:
                        creds = new_permission.condition.credential
                        cred_ids = [creds] if isinstance(creds, str) else list(creds)

                    add_host_credential(doc, host, cred_ids)
                    save_roundtrip(baseline_path, doc)
                    return
            except Exception as e:
                # Do NOT fall back to _save_baseline_plain — that silently
                # destroys all comments and formatting in the operator's TOML.
                # Let the in-memory state be the source of truth; the file
                # will be correct on the next full reload/save cycle.
                log.error(
                    "TOML round-trip save failed (in-memory state preserved, "
                    "file NOT overwritten): %s", e,
                )
                return

        # Non-TOML files: fall through to plain rewrite (no comment preservation).
        # YAML round-trip support was removed — TOML is the canonical format.
        self._save_baseline_plain()

    def _save_baseline_full(self) -> None:
        """Save full baseline policy. TOML uses tomlkit for comment preservation;
        other formats fall through to plain dump."""
        baseline_path = self._loader.baseline_path
        if not baseline_path:
            return

        # TOML branch: fresh document (no comment preservation for full replacement)
        if baseline_path.suffix == ".toml":
            try:
                import tomlkit

                from safeyolo.policy.toml_normalize import denormalize

                baseline = self._loader.baseline
                internal = baseline.model_dump(exclude_none=True)
                toml_data = denormalize(internal)
                content = tomlkit.dumps(toml_data)

                import shutil
                import tempfile

                baseline_path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".toml", dir=baseline_path.parent, delete=False
                ) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                shutil.move(tmp_path, baseline_path)
                log.info(f"Saved baseline policy (TOML full) to {baseline_path}")
                return
            except Exception as e:
                log.warning("TOML full save failed, falling back to plain: %s", e)
            self._save_baseline_plain()
            return

        # Non-TOML files: fall through to plain rewrite.
        self._save_baseline_plain()

    def _save_baseline_plain(self) -> None:
        """Save baseline policy as plain YAML/TOML (no comment preservation).

        Used as fallback when the original file doesn't exist or round-trip fails.
        """
        baseline_path = self._loader.baseline_path
        if not baseline_path:
            return

        try:
            import shutil
            import tempfile

            baseline = self._loader.baseline
            internal = baseline.model_dump(exclude_none=True)

            if baseline_path.suffix == ".toml":
                import tomlkit

                from safeyolo.policy.toml_normalize import denormalize

                content = tomlkit.dumps(denormalize(internal))
                suffix = ".toml"
            else:
                content = yaml.safe_dump(
                    internal,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                )
                suffix = ".yaml"

            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, dir=baseline_path.parent, delete=False) as tmp:
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
