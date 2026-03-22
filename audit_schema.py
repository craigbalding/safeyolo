"""
audit_schema.py - Shared audit event contract for SafeYolo

Defines the structured envelope that any PEP (Policy Enforcement Point) must
produce and that consumers (watch, alerting, relay) can rely on.

This is a leaf module: depends only on pydantic + stdlib.
Importable by addons, CLI, and any future PEP.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventKind(StrEnum):
    """Top-level event category."""
    SECURITY = "security"
    GATEWAY = "gateway"
    TRAFFIC = "traffic"
    OPS = "ops"
    ADMIN = "admin"
    AGENT = "agent"


class Severity(StrEnum):
    """Event severity for rendering and filtering."""
    CRITICAL = "critical"   # needs human action
    HIGH = "high"           # important
    MEDIUM = "medium"       # informational
    LOW = "low"             # noise


class Decision(StrEnum):
    """Security/gateway decision outcome."""
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    BUDGET_EXCEEDED = "budget_exceeded"
    LOG = "log"


class ApprovalRequest(BaseModel):
    """Approval metadata attached to events that need human action."""
    model_config = ConfigDict(extra="forbid")

    required: bool
    approval_type: str          # "credential", "network", "pattern"
    key: str                    # dedup identity (fingerprint, domain, rule)
    target: str                 # destination (host)
    scope_hint: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    """The audit event envelope - the shared contract."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event: str                              # taxonomy string e.g. "security.credential_guard"
    kind: EventKind                         # top-level category
    severity: Severity                      # for watch rendering
    summary: str                            # human-readable one-liner
    request_id: str | None = None           # correlation
    agent: str | None = None                # agent identity
    addon: str | None = None                # emitting addon
    decision: Decision | None = None        # only for security/gateway events
    host: str | None = None                 # always "host", never "domain"
    approval: ApprovalRequest | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    def to_jsonl(self) -> dict[str, Any]:
        """Serialize to a dict suitable for JSONL output."""
        return self.model_dump(mode="json", exclude_none=True)
