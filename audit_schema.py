"""
audit_schema.py - Shared audit event contract for SafeYolo

Defines the structured envelope that any PEP (Policy Enforcement Point) must
produce and that consumers (watch, alerting, agent API) can rely on.

This is a leaf module: depends only on pydantic + stdlib.
Importable by addons, CLI, and any future PEP.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Sanitization for safe rendering of user-controlled event fields.
# Copied from pdp/core.py — keep in sync.
_SAFE_CATEGORIES = frozenset(
    {
        "Lu",
        "Ll",
        "Lt",
        "Lm",
        "Lo",  # Letters
        "Nd",
        "Nl",
        "No",  # Numbers
        "Pc",
        "Pd",
        "Ps",
        "Pe",
        "Pi",
        "Pf",
        "Po",  # Punctuation
        "Sm",
        "Sc",
        "Sk",
        "So",  # Symbols
        "Zs",  # Space (not Zl/Zp line seps)
    }
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_BLOCKED_CODEPOINTS = frozenset(range(0x20)) | {0x7F, 0x2028, 0x2029}


def sanitize_for_log(value, max_len: int = 200) -> str:
    """Sanitize user-controlled values before logging to prevent log injection.

    Uses Unicode category whitelist plus explicit codepoint blocklist.
    Strips ANSI escapes and replaces unsafe chars with '?'.
    """
    if value is None:
        return ""
    text = _ANSI_ESCAPE_RE.sub("?", str(value))
    sanitized = "".join(
        c if (ord(c) not in _BLOCKED_CODEPOINTS and unicodedata.category(c) in _SAFE_CATEGORIES) else "?" for c in text
    )
    sanitized = re.sub(r"\?+", "?", sanitized)
    return sanitized[:max_len] + "..." if len(sanitized) > max_len else sanitized


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
