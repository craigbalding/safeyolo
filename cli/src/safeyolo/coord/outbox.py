"""Transactional outbox and at-least-once coord event projection."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable

from safeyolo.core.audit_schema import AuditEvent
from safeyolo.events import append_event_strict

from .audit import COORD_AUDIT_DESTINATION, build_coord_event

log = logging.getLogger("safeyolo.coord.outbox")


def enqueue_coord_event(
    conn: sqlite3.Connection,
    event_type: str,
    details: dict,
    *,
    event_id: str | None = None,
) -> str:
    """Insert one logical event using the caller's current transaction."""
    event = build_coord_event(event_type, details, event_id=event_id)
    assert event.event_id is not None
    conn.execute(
        """INSERT OR IGNORE INTO coord_outbox
           (event_id, destination, event_type, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            event.event_id,
            COORD_AUDIT_DESTINATION,
            event_type,
            json.dumps(event.to_jsonl(), sort_keys=True, separators=(",", ":")),
            int(event.ts.timestamp() * 1000),
        ),
    )
    return event.event_id


def project_pending(
    *,
    limit: int = 100,
    _after_append: Callable[[str], None] | None = None,
) -> int:
    """Project pending coord audit edges to JSONL at least once.

    A DB write lock is held across append + delivered marking.  Concurrent
    projectors therefore serialize.  A process death after append rolls the
    delivery mark back, so the same stable event ID may be appended again.
    """
    from . import store

    delivered = 0
    for _ in range(max(0, limit)):
        with store.connect_unchecked() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT event_id, payload_json
                   FROM coord_outbox
                   WHERE destination = ? AND delivered_at IS NULL
                   ORDER BY created_at, event_id
                   LIMIT 1""",
                (COORD_AUDIT_DESTINATION,),
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                break
            try:
                event = AuditEvent.model_validate(json.loads(row["payload_json"]))
                append_event_strict(event)
                if _after_append is not None:
                    _after_append(row["event_id"])
                conn.execute(
                    """UPDATE coord_outbox
                       SET delivered_at = ?, attempt_count = attempt_count + 1,
                           last_error_class = NULL
                       WHERE event_id = ?""",
                    (store.now_ms(), row["event_id"]),
                )
                conn.execute("COMMIT")
                delivered += 1
            except Exception as exc:  # retry remains canonical in SQLite
                conn.execute(
                    """UPDATE coord_outbox
                       SET attempt_count = attempt_count + 1,
                           last_error_class = ?
                       WHERE event_id = ?""",
                    (type(exc).__name__, row["event_id"]),
                )
                conn.execute("COMMIT")
                log.warning(
                    "coord audit projection failed for %s: %s",
                    row["event_id"],
                    type(exc).__name__,
                )
                break
    return delivered
