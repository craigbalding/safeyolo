"""Shared CLI audit event writer and log rotation helpers."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from safeyolo.core.audit_schema import sanitize_for_log

if TYPE_CHECKING:
    from safeyolo.core.audit_schema import ApprovalRequest, Decision, EventKind, Severity

__all__ = ["sanitize_for_log", "write_event"]

AUDIT_LOG_PATH = Path(os.environ.get("SAFEYOLO_LOG_PATH", "/app/logs/safeyolo.jsonl"))
SAFEYOLO_LOG_MAX_BYTES = int(os.environ.get("SAFEYOLO_LOG_MAX_MB", "50")) * 1_000_000
SAFEYOLO_LOG_BACKUPS = int(os.environ.get("SAFEYOLO_LOG_BACKUPS", "5"))

_log = logging.getLogger("safeyolo.utils")


def _rotate_jsonl_if_needed() -> None:
    """Rotate JSONL audit log if it exceeds max size."""
    if not AUDIT_LOG_PATH.exists():
        return
    try:
        if AUDIT_LOG_PATH.stat().st_size < SAFEYOLO_LOG_MAX_BYTES:
            return
    except OSError:
        return

    # Rotate: .5 -> delete, .4 -> .5, ... .1 -> .2, current -> .1
    for i in range(SAFEYOLO_LOG_BACKUPS, 0, -1):
        old_backup = AUDIT_LOG_PATH.with_suffix(f".jsonl.{i}")
        new_backup = AUDIT_LOG_PATH.with_suffix(f".jsonl.{i + 1}")
        if i == SAFEYOLO_LOG_BACKUPS and old_backup.exists():
            old_backup.unlink()
        elif old_backup.exists():
            old_backup.rename(new_backup)

    if AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.rename(AUDIT_LOG_PATH.with_suffix(".jsonl.1"))


def write_event(  # DOC: SECURITY.md, README.md
    event: str,
    *,
    kind: EventKind,
    severity: Severity,
    summary: str,
    decision: Decision | None = None,
    host: str | None = None,
    request_id: str | None = None,
    agent: str | None = None,
    evidence_owner: str | None = None,
    trusted_transport_identity: str | None = None,
    initiator: str | None = None,
    attribution_status: str | None = None,
    attribution_provenance: dict | None = None,
    addon: str | None = None,
    approval: ApprovalRequest | None = None,
    details: dict | None = None,
    confirm_append: bool = False,
) -> None:
    """
    Write a structured event to the central JSONL audit log.

    Constructs an AuditEvent, validates, and writes to AUDIT_LOG_PATH.

    Args:
        event: Event type using taxonomy (e.g., "security.credential_guard")
        kind: Top-level event category
        severity: Event severity for rendering
        summary: Human-readable one-liner
        decision: Security/gateway decision outcome
        host: Destination hostname
        request_id: Correlation ID from flow.metadata
        agent: Compatibility display alias for the evidence owner
        evidence_owner: Agent/query scope for the evidence
        trusted_transport_identity: Identity established by the transport
        initiator: Best-known traffic actor
        attribution_status: Attribution state independent of enforcement
        attribution_provenance: Bounded trusted source facts
        addon: Name of the addon emitting the event
        approval: Approval request metadata
        details: Addon-specific fields not in the spine
        confirm_append: Wait for append/close before claiming operator review;
            not a filesystem sync or crash-durability guarantee
    """
    from safeyolo.core.audit_schema import AuditEvent

    # Taxonomy is validated at schema level — AuditEvent rejects events whose
    # prefix does not match EventKind, so no separate prefix check is needed.

    try:
        audit_event = AuditEvent(
            event=event,
            kind=kind,
            severity=severity,
            summary=summary,
            decision=decision,
            host=host,
            request_id=request_id,
            agent=agent,
            evidence_owner=evidence_owner,
            trusted_transport_identity=trusted_transport_identity,
            initiator=initiator,
            attribution_status=attribution_status,
            attribution_provenance=attribution_provenance,
            addon=addon,
            approval=approval,
            details=details or {},
        )
        entry = audit_event.to_jsonl()
    except Exception as e:
        _log.error(f"Event validation failed for '{event}': {type(e).__name__}: {e}")
        if confirm_append:
            # An unvalidated fallback is not an operator-reviewable approval.
            raise
        # Fallback: write unvalidated entry so events are never silently lost
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            "kind": kind.value if hasattr(kind, "value") else str(kind),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "summary": summary,
        }

    # Ordinary events keep the non-blocking hook path. An approval that claims
    # operator review waits for the same writer's append/close acknowledgement.
    from safeyolo.core.audit_writer import put_event as _put_event
    if confirm_append:
        from safeyolo.core.audit_writer import put_event_confirmed

        put_event_confirmed(entry)
    else:
        _put_event(entry)
