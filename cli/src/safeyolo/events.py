"""Event logging for SafeYolo CLI.

Writes agent lifecycle events to the shared JSONL audit log,
matching the format used by the proxy addons.
"""

import json
import logging
import sys
from datetime import UTC, datetime

from .config import get_logs_dir
from .core.audit_schema import AuditEvent, EventKind, Severity  # noqa: F401 - re-exported

log = logging.getLogger("safeyolo.events")


def write_event(
    event: str,
    *,
    kind: EventKind,
    severity: Severity,
    summary: str,
    agent: str | None = None,
    addon: str | None = None,
    details: dict | None = None,
) -> None:
    """Write a structured event to the JSONL audit log.

    Args:
        event: Event type using taxonomy (e.g., "agent.started")
        kind: Top-level event category
        severity: Event severity
        summary: Human-readable one-liner
        agent: Agent identity
        addon: Emitting addon/component
        details: Additional fields
    """
    log_path = get_logs_dir(create=True) / "safeyolo.jsonl"
    try:
        audit_event = AuditEvent(
            event=event,
            kind=kind,
            severity=severity,
            summary=summary,
            agent=agent,
            addon=addon,
            details=details or {},
        )
        entry = audit_event.to_jsonl()
    except Exception as e:
        log.warning(f"Event validation failed: {type(e).__name__}: {e}")
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            "kind": kind.value if hasattr(kind, "value") else str(kind),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "summary": summary,
        }

    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[safeyolo] Event log write failed: {type(e).__name__}: {e}", file=sys.stderr)
