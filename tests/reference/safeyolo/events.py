"""Event logging for SafeYolo CLI.

Writes agent lifecycle events to the shared JSONL audit log,
matching the format used by the proxy addons.
"""

import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from .config import get_logs_dir
from .core.audit_schema import AuditEvent, EventKind, Severity  # noqa: F401 - re-exported

log = logging.getLogger("safeyolo.events")


def _missing_directories(path: Path) -> list[Path]:
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return missing


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_event_strict(event: AuditEvent) -> None:
    """Synchronously append a validated event or raise.

    Coordination's transactional outbox needs a positive acknowledgement
    before it can mark an edge delivered.  The legacy ``write_event`` helper
    deliberately swallows write failures, so it cannot provide that contract.
    """
    logs_dir = get_logs_dir()
    missing_directories = _missing_directories(logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "safeyolo.jsonl"
    with open(log_path, "a") as f:
        f.write(json.dumps(event.to_jsonl()) + "\n")
        f.flush()
        os.fsync(f.fileno())

    # The file sync persists its contents, but a newly-created file or parent
    # directory is not reachable after power loss until the corresponding
    # directory entries are durable too. Sync leaf-to-root; syncing logs_dir
    # on every low-volume coord append also closes the file-creation race.
    sync_directories = [logs_dir]
    sync_directories.extend(directory.parent for directory in missing_directories)
    for directory in dict.fromkeys(sync_directories):
        _fsync_directory(directory)


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
