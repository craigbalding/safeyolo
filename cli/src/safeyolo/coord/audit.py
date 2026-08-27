"""Typed, metadata-only audit events for the coordination kernel."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from safeyolo.core.audit_schema import AuditEvent, EventKind, Severity

from .identity import new_event_id

COORD_AUDIT_DESTINATION = "audit-jsonl"

_SUMMARIES = {
    "coord.schema_migrated": "Coord schema migration completed",
    "coord.migration_failed": "Coord schema migration rolled back",
    "coord.grant_changed": "Coord room grant changed",
    "coord.grant_revoked": "Coord room grant revoked",
    "coord.operation_conflict": "Coord operation ID conflict",
}

# This is deliberately an allow-list.  AuditEvent.details is generic, while
# coordination's contract is narrower: canonical prose stays in SQLite/NATS.
_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "actor",
        "content_hash",
        "error_class",
        "from_version",
        "object_id",
        "operation_id",
        "operation_type",
        "principal_id",
        "principal_kind",
        "request_hash",
        "revision",
        "room_id",
        "to_version",
        "transition",
    }
)


def build_coord_event(
    event_type: str,
    details: Mapping[str, Any],
    *,
    event_id: str | None = None,
) -> AuditEvent:
    """Build a validated coord event from generated operational metadata."""
    try:
        summary = _SUMMARIES[event_type]
    except KeyError as exc:
        raise ValueError(f"unsupported coord audit event {event_type!r}") from exc
    unknown = set(details) - _ALLOWED_DETAIL_KEYS
    if unknown:
        raise ValueError(
            "coord audit details contain prohibited/unknown keys: "
            + ", ".join(sorted(unknown))
        )
    return AuditEvent(
        event_id=event_id or new_event_id(),
        event=event_type,
        kind=EventKind.COORD,
        severity=(
            Severity.MEDIUM
            if event_type in {"coord.migration_failed", "coord.operation_conflict"}
            else Severity.LOW
        ),
        summary=summary,
        addon="coord",
        details=dict(details),
    )
