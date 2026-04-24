"""
audit_schema.py - Shared audit event contract for SafeYolo

Defines the structured envelope that any PEP (Policy Enforcement Point) must
produce and that consumers (watch, alerting, agent API) can rely on.

This is a leaf module: depends only on pydantic + stdlib. Importable by
addons, CLI, and any future PEP.

Canonical home of `sanitize_for_log` — `utils.py` and `pdp/core.py` import
from here rather than maintaining their own copies.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# =============================================================================
# Log sanitization (canonical implementation)
# =============================================================================

_SAFE_CATEGORIES = frozenset(
    {
        "Lu", "Ll", "Lt", "Lm", "Lo",                   # Letters
        "Nd", "Nl", "No",                                # Numbers
        "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",       # Punctuation
        "Sm", "Sc", "Sk", "So",                          # Symbols
        "Zs",                                            # Space (not Zl/Zp line seps)
    }
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_BLOCKED_CODEPOINTS = frozenset(range(0x20)) | {0x7F, 0x2028, 0x2029}


def sanitize_for_log(value, max_len: int = 200) -> str:
    """Sanitize user-controlled values before logging to prevent log injection.

    Uses Unicode category whitelist plus explicit codepoint blocklist.
    Strips ANSI escapes and replaces unsafe chars with '?'.

    - `None` returns the empty string.
    - Non-strings are coerced via `str()`.
    - Control characters (U+0000–U+001F, U+007F) and Unicode line/paragraph
      separators (U+2028, U+2029) are blocked.
    - ANSI CSI escape sequences are replaced with '?'.
    - Consecutive replacement '?' are collapsed into a single '?'.
    - Strings longer than `max_len` are truncated and suffixed with "...".
    """
    if value is None:
        return ""
    text = _ANSI_ESCAPE_RE.sub("?", str(value))
    sanitized = "".join(
        c if (ord(c) not in _BLOCKED_CODEPOINTS and unicodedata.category(c) in _SAFE_CATEGORIES)
        else "?"
        for c in text
    )
    sanitized = re.sub(r"\?+", "?", sanitized)
    return sanitized[:max_len] + "..." if len(sanitized) > max_len else sanitized


# =============================================================================
# Enums
# =============================================================================


class EventKind(StrEnum):
    """Top-level event category. The `event` field's prefix must match one of these."""
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
    """Security/gateway decision outcome. Note: SafeYolo uses DENY, never BLOCK."""
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    BUDGET_EXCEEDED = "budget_exceeded"
    LOG = "log"


class ApprovalType(StrEnum):
    """Types of human-approval an event may request.

    Extended from the original docstring-only enumeration ("credential",
    "network", "pattern") to match the real in-use set found across
    addons/agent_api, addons/network_guard, addons/credential_guard,
    and addons/service_gateway.
    """
    CREDENTIAL = "credential"
    NETWORK_EGRESS = "network_egress"
    GATEWAY_ROUTE = "gateway_route"
    SERVICE = "service"
    CONTRACT_BINDING = "contract_binding"


# =============================================================================
# Approval request
# =============================================================================


class ApprovalRequest(BaseModel):
    """Approval metadata attached to events that need human action."""
    model_config = ConfigDict(extra="forbid")

    required: bool
    approval_type: ApprovalType    # One of the ApprovalType enum values
    key: str                       # dedup identity (fingerprint, domain, rule)
    target: str                    # destination (host)
    scope_hint: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Audit event envelope
# =============================================================================

SCHEMA_VERSION = 1


class AuditEvent(BaseModel):
    """The audit event envelope - the shared contract."""
    model_config = ConfigDict(extra="forbid")

    schema_version: int = SCHEMA_VERSION
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event: str                              # taxonomy string e.g. "security.credential_guard"
    kind: EventKind                         # top-level category
    severity: Severity                      # for watch rendering
    summary: str = Field(..., min_length=1) # human-readable one-liner; must not be empty
    request_id: str | None = None           # correlation
    agent: str | None = None                # agent identity
    addon: str | None = None                # emitting addon
    decision: Decision | None = None        # only for security/gateway events
    host: str | None = None                 # always "host", never "domain"
    approval: ApprovalRequest | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, v: int) -> int:
        """Reject events declaring a schema_version this module does not support."""
        if v != SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {SCHEMA_VERSION}, got {v}. "
                f"Update audit_schema.py if a new version is intended."
            )
        return v

    @field_validator("ts")
    @classmethod
    def _validate_tz_aware(cls, v: datetime) -> datetime:
        """Audit timestamps must be timezone-aware.

        A naive datetime in a security audit log is forensically ambiguous —
        it could be local time, UTC, or container time with no way to tell.
        Reject at construction so the operator notices immediately.
        """
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "ts must be timezone-aware (e.g. datetime.now(UTC)); "
                "naive datetimes are rejected to prevent ambiguous audit timestamps"
            )
        return v

    @model_validator(mode="after")
    def _validate_event_matches_kind(self) -> AuditEvent:
        """The `event` string's prefix must match the `kind` enum value.

        Both fields encode the same category at different granularities; any
        disagreement is silent drift between producers and filters. This is
        the fail-closed alternative to the soft warn-only check that used to
        live in addons/utils.write_event.
        """
        expected_prefix = self.kind.value + "."
        if not self.event.startswith(expected_prefix):
            valid_kinds = ", ".join(k.value for k in EventKind)
            raise ValueError(
                f"event={self.event!r} does not match kind={self.kind.value!r} — "
                f"expected event to start with {expected_prefix!r}. "
                f"Valid kinds: {valid_kinds}"
            )
        return self

    def to_jsonl(self) -> dict[str, Any]:
        """Serialize to a dict suitable for JSONL output."""
        return self.model_dump(mode="json", exclude_none=True)


# =============================================================================
# Reader-side helper
# =============================================================================


class InvalidAuditEvent(ValueError):
    """Raised when a JSONL line cannot be parsed as a valid AuditEvent.

    The original exception is attached as `__cause__`. The raw dict is
    attached as the `raw` attribute for diagnostic logging.
    """

    def __init__(self, message: str, raw: Any):
        super().__init__(message)
        self.raw = raw


def parse_audit_event(raw: dict[str, Any]) -> AuditEvent:
    """Validate a dict (e.g. from `json.loads(line)`) as an AuditEvent.

    This is the reader-side counterpart to construction. Consumers that read
    JSONL audit lines should use this helper rather than treating the dict as
    opaque — the envelope schema is a two-way contract, and readers silently
    drifting from writers is a latent bug class.

    Args:
        raw: A dict parsed from a JSONL line.

    Returns:
        A validated AuditEvent.

    Raises:
        InvalidAuditEvent: if the dict is not a valid event.
    """
    if not isinstance(raw, dict):
        raise InvalidAuditEvent(
            f"expected dict, got {type(raw).__name__}", raw=raw
        )
    try:
        return AuditEvent.model_validate(raw)
    except Exception as exc:
        raise InvalidAuditEvent(
            f"failed to parse audit event: {exc}", raw=raw
        ) from exc
