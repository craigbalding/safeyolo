"""Policy data models shared by the engine and loader."""

import fnmatch
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from safeyolo.core.identifiers import validate_task_id


def _matches_pattern(value: str, pattern: str) -> bool:
    """Check if value matches a case-insensitive glob pattern."""
    value = value.lower()
    pattern = pattern.lower()

    if value == pattern:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return value.endswith(suffix) or value == pattern[2:]
    return fnmatch.fnmatch(value, pattern)


class PolicyMetadata(BaseModel):
    """Policy file metadata."""

    version: str = "1.0"
    task_id: str | None = None
    description: str | None = None
    created: str | None = None
    approved: str | None = None
    brief_hash: str | None = None
    policy_hash: str | None = None

    @field_validator("task_id")
    @classmethod
    def _validate_task_id(cls, value: str | None) -> str | None:
        return validate_task_id(value) if value is not None else None


class Condition(BaseModel):
    """Optional conditions for permission matching."""

    credential: str | list[str] | None = None
    method: str | list[str] | None = None
    path_prefix: str | None = None
    content_type: str | None = None
    tactics: list[str] | None = None
    enables: list[str] | None = None
    irreversible: bool | None = None
    account: str | list[str] | None = None
    agent: str | None = None
    service: str | None = None
    capability: str | None = None

    def _matches_credential(self, context: dict[str, Any]) -> bool:
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
        if self.method is None:
            return True
        ctx_method = context.get("method", "").upper()
        methods = [self.method] if isinstance(self.method, str) else self.method
        return ctx_method in [method.upper() for method in methods]

    def _matches_path_prefix(self, context: dict[str, Any]) -> bool:
        if self.path_prefix is None:
            return True
        return context.get("path", "").startswith(self.path_prefix)

    def _matches_content_type(self, context: dict[str, Any]) -> bool:
        if self.content_type is None:
            return True
        return self.content_type in context.get("content_type", "")

    def _matches_tactics(self, context: dict[str, Any]) -> bool:
        if self.tactics is None:
            return True
        return bool(set(self.tactics) & set(context.get("tactics", [])))

    def _matches_enables(self, context: dict[str, Any]) -> bool:
        if self.enables is None:
            return True
        return bool(set(self.enables) & set(context.get("enables", [])))

    def _matches_irreversible(self, context: dict[str, Any]) -> bool:
        if self.irreversible is None:
            return True
        return context.get("irreversible", False) == self.irreversible

    def _matches_account(self, context: dict[str, Any]) -> bool:
        if self.account is None:
            return True
        accounts = [self.account] if isinstance(self.account, str) else self.account
        return context.get("account", "") in accounts

    def _matches_agent(self, context: dict[str, Any]) -> bool:
        if self.agent is None:
            return True
        return fnmatch.fnmatch(context.get("agent", ""), self.agent)

    def _matches_service(self, context: dict[str, Any]) -> bool:
        if self.service is None:
            return True
        return fnmatch.fnmatch(context.get("service", ""), self.service)

    def _matches_capability(self, context: dict[str, Any]) -> bool:
        if self.capability is None:
            return True
        return fnmatch.fnmatch(context.get("capability", ""), self.capability)

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
    """IAM-style permission rule."""

    action: Literal[
        "credential:use",
        "network:request",
        "file:read",
        "file:write",
        "subprocess:exec",
        "gateway:risky_route",
        "gateway:request",
    ]
    resource: str
    effect: Literal["allow", "deny", "prompt", "budget"] = "allow"
    budget: int | None = None
    tier: Literal["explicit", "inferred"] = "explicit"
    condition: Condition | None = None

    @model_validator(mode="after")
    def validate_budget_required(self):
        if self.effect == "budget" and self.budget is None:
            raise ValueError("budget must be set when effect is 'budget'")
        return self


class CredentialRule(BaseModel):
    """Credential detection and routing rule."""

    name: str
    patterns: list[str]
    allowed_hosts: list[str]
    header_names: list[str] = Field(default_factory=lambda: ["authorization", "x-api-key"])
    suggested_url: str = ""


class ScanPattern(BaseModel):
    """Content scan pattern rule."""

    name: str
    pattern: str
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
        extra = "allow"


class DomainOverride(BaseModel):
    """Domain or client-specific policy override."""

    bypass: list[str] = Field(default_factory=list)
    addons: dict[str, AddonConfig] = Field(default_factory=dict)


class UnifiedPolicy(BaseModel):
    """Complete baseline or task policy document."""

    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    permissions: list[Permission] = Field(default_factory=list)
    budgets: dict[str, int] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)
    credential_rules: list[CredentialRule] = Field(default_factory=list)
    scan_patterns: list[ScanPattern] = Field(default_factory=list)
    addons: dict[str, AddonConfig] = Field(default_factory=dict)
    domains: dict[str, DomainOverride] = Field(default_factory=dict)
    clients: dict[str, DomainOverride] = Field(default_factory=dict)
    gateway: dict = Field(default_factory=dict)
    simple_permissions: dict[str, int] = Field(default_factory=dict)


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""

    effect: Literal["allow", "deny", "prompt", "budget_exceeded"]
    permission: Permission | None = None
    reason: str = ""
    budget_remaining: int | None = None


__all__ = [
    "AddonConfig",
    "Condition",
    "CredentialRule",
    "DomainOverride",
    "Permission",
    "PolicyDecision",
    "PolicyMetadata",
    "ScanPattern",
    "UnifiedPolicy",
    "_matches_pattern",
]
