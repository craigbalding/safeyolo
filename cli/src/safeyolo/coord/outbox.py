"""Transactional outbox and at-least-once coord event projection."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from collections.abc import Callable

from safeyolo.core.audit_schema import AuditEvent
from safeyolo.events import append_event_strict

from .audit import COORD_AUDIT_DESTINATION, build_coord_event

log = logging.getLogger("safeyolo.coord.outbox")

ATTENTION_HINT_DESTINATION = "attention-nats"


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


def _attention_hint_event_id(attention_id: str) -> str:
    material = f"coord.attention_hint\0{attention_id}".encode()
    return f"evt-{hashlib.sha256(material).hexdigest()[:32]}"


def enqueue_attention_hint(
    conn: sqlite3.Connection,
    *,
    attention_id: str,
    recipient_agent_id: str,
    feed_sequence: int,
) -> str:
    """Enqueue one metadata-only low-latency wake hint.

    The canonical edge is already in SQLite in the caller's transaction.
    NATS delivery is deliberately only a hint: a lost or duplicate publish
    cannot create or consume an attention edge.
    """
    event_id = _attention_hint_event_id(attention_id)
    payload_json = json.dumps(
        {
            "attention_id": attention_id,
            "recipient_agent_id": recipient_agent_id,
            "feed_sequence": feed_sequence,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    conn.execute(
        """INSERT OR IGNORE INTO coord_outbox
           (event_id, destination, event_type, payload_json, created_at)
           VALUES (?, ?, 'coord.attention_hint', ?, ?)""",
        (
            event_id,
            ATTENTION_HINT_DESTINATION,
            payload_json,
            time.time_ns() // 1_000_000,
        ),
    )
    existing = conn.execute(
        """SELECT destination, event_type, payload_json
           FROM coord_outbox WHERE event_id = ?""",
        (event_id,),
    ).fetchone()
    if (
        existing is None
        or existing["destination"] != ATTENTION_HINT_DESTINATION
        or existing["event_type"] != "coord.attention_hint"
        or existing["payload_json"] != payload_json
    ):
        raise RuntimeError("attention hint event ID collision")
    return event_id


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


async def project_attention_hints(
    *,
    limit: int = 100,
    _after_publish: Callable[[str], None] | None = None,
) -> int:
    """Publish pending attention hints at least once.

    Publication and SQLite delivery marking cannot be atomic. A concurrent
    projector or a process death after publish may therefore repeat the same
    hint. The recipient always re-reads the authoritative SQLite ledger and
    deduplicates by ``attention_id``.
    """
    from . import nats_client, store

    delivered = 0
    for _ in range(max(0, limit)):
        with store.connect() as conn:
            row = conn.execute(
                """SELECT event_id, payload_json
                   FROM coord_outbox
                   WHERE destination = ? AND delivered_at IS NULL
                   ORDER BY created_at, event_id
                   LIMIT 1""",
                (ATTENTION_HINT_DESTINATION,),
            ).fetchone()
        if row is None:
            break
        try:
            payload = json.loads(row["payload_json"])
            await nats_client.publish_attention_hint(
                payload["recipient_agent_id"],
                payload["attention_id"],
            )
            if _after_publish is not None:
                _after_publish(row["event_id"])
        except Exception as exc:
            with store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """UPDATE coord_outbox
                       SET attempt_count = attempt_count + 1,
                           last_error_class = ?
                       WHERE event_id = ? AND delivered_at IS NULL""",
                    (type(exc).__name__, row["event_id"]),
                )
                conn.execute("COMMIT")
            log.warning(
                "coord attention hint projection failed for %s: %s",
                row["event_id"],
                type(exc).__name__,
            )
            break
        with store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                """UPDATE coord_outbox
                   SET delivered_at = ?, attempt_count = attempt_count + 1,
                       last_error_class = NULL
                   WHERE event_id = ? AND delivered_at IS NULL""",
                (store.now_ms(), row["event_id"]),
            ).rowcount
            conn.execute("COMMIT")
        delivered += int(changed > 0)
    return delivered
