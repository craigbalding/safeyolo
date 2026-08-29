"""Canonical versioned operator brief state for coord rooms."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any

from . import attention, store
from .kernel import (
    LOCAL_OPERATOR_ID,
    LOCAL_OPERATOR_KIND,
    apply_revisioned_change,
    execute_mutation,
)

MAX_BRIEF_BYTES = 64 * 1024
MAX_HISTORY_PAGE = 200


class BriefRevisionNotFound(LookupError):
    """The requested immutable brief revision does not exist."""


def brief_object_id(room_id: str) -> str:
    """Return the stable canonical object ID for a room's one brief."""
    return f"brief-{room_id.removeprefix('rm-')}"


def _validate_markdown(markdown: str) -> bytes:
    if not isinstance(markdown, str) or not markdown.strip():
        raise ValueError("brief markdown must be a non-empty string")
    try:
        encoded = markdown.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("brief markdown must be valid UTF-8") from exc
    if len(encoded) > MAX_BRIEF_BYTES:
        raise ValueError(
            f"brief markdown exceeds {MAX_BRIEF_BYTES} UTF-8 bytes"
        )
    return encoded


def _validate_expected_revision(expected_revision: int) -> None:
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("expected_revision must be a non-negative integer")


def _public_current(room_id: str, row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {
            "room_id": room_id,
            "object_id": brief_object_id(room_id),
            "revision": 0,
            "markdown": None,
            "content_hash": None,
            "updated_at": None,
        }
    return {
        "room_id": room_id,
        "object_id": brief_object_id(room_id),
        "revision": int(row["revision"]),
        "markdown": row["markdown"],
        "content_hash": row["content_hash"],
        "updated_at": int(row["updated_at"]),
    }


def read_current(conn: sqlite3.Connection, room_id: str) -> dict[str, Any]:
    row = conn.execute(
        """SELECT revision, markdown, content_hash, updated_at
           FROM coord_briefs WHERE room_id = ?""",
        (room_id,),
    ).fetchone()
    return _public_current(room_id, row)


def read_revision(
    conn: sqlite3.Connection,
    room_id: str,
    revision: int,
) -> dict[str, Any]:
    if type(revision) is not int or revision <= 0:
        raise ValueError("revision must be a positive integer")
    row = conn.execute(
        """SELECT revision, markdown, content_hash, actor_kind, actor_id,
                  operation_id, created_at
           FROM coord_brief_revisions
           WHERE room_id = ? AND revision = ?""",
        (room_id, revision),
    ).fetchone()
    if row is None:
        raise BriefRevisionNotFound(revision)
    return {
        "room_id": room_id,
        "object_id": brief_object_id(room_id),
        "revision": int(row["revision"]),
        "markdown": row["markdown"],
        "content_hash": row["content_hash"],
        "actor_kind": row["actor_kind"],
        "actor_id": row["actor_id"],
        "operation_id": row["operation_id"],
        "created_at": int(row["created_at"]),
    }


def read_public_revision(
    conn: sqlite3.Connection,
    room_id: str,
    revision: int,
) -> dict[str, Any]:
    """Read canonical revision content without operator mutation metadata."""
    record = read_revision(conn, room_id, revision)
    return {
        "room_id": record["room_id"],
        "object_id": record["object_id"],
        "revision": record["revision"],
        "markdown": record["markdown"],
        "content_hash": record["content_hash"],
        "updated_at": record["created_at"],
    }


def list_history(
    conn: sqlite3.Connection,
    room_id: str,
    *,
    since_revision: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    if type(since_revision) is not int or since_revision < 0:
        raise ValueError("since_revision must be a non-negative integer")
    if type(limit) is not int or limit < 1:
        raise ValueError("limit must be a positive integer")
    limit = min(limit, MAX_HISTORY_PAGE)
    rows = conn.execute(
        """SELECT revision, content_hash, actor_kind, actor_id,
                  operation_id, created_at
           FROM coord_brief_revisions
           WHERE room_id = ? AND revision > ?
           ORDER BY revision LIMIT ?""",
        (room_id, since_revision, limit),
    ).fetchall()
    current = read_current(conn, room_id)
    revisions = [
        {
            "room_id": room_id,
            "object_id": brief_object_id(room_id),
            "revision": int(row["revision"]),
            "content_hash": row["content_hash"],
            "actor_kind": row["actor_kind"],
            "actor_id": row["actor_id"],
            "operation_id": row["operation_id"],
            "created_at": int(row["created_at"]),
        }
        for row in rows
    ]
    next_revision = revisions[-1]["revision"] if revisions else since_revision
    return {
        "revisions": revisions,
        "next_revision": next_revision,
        "has_more": current["revision"] > next_revision,
        "current_revision": current["revision"],
    }


def set_brief(
    room_id: str,
    markdown: str,
    *,
    expected_revision: int,
    operation_id: str,
) -> dict[str, Any]:
    """Atomically update projection/history/audit/attention as operator."""
    encoded = _validate_markdown(markdown)
    _validate_expected_revision(expected_revision)
    content_hash = hashlib.sha256(encoded).hexdigest()
    object_id = brief_object_id(room_id)
    request = {
        "room_id": room_id,
        "markdown": markdown,
        "expected_revision": expected_revision,
    }

    def _set(conn: sqlite3.Connection) -> dict[str, Any]:
        room = conn.execute(
            "SELECT 1 FROM rooms WHERE room_id = ?", (room_id,)
        ).fetchone()
        if room is None:
            raise BriefRevisionNotFound("room")
        current = conn.execute(
            "SELECT revision FROM coord_briefs WHERE room_id = ?",
            (room_id,),
        ).fetchone()
        actual_revision = int(current["revision"]) if current else 0
        changed_at = store.now_ms()

        def write_projection(revision: int) -> None:
            conn.execute(
                """INSERT INTO coord_briefs
                   (room_id, revision, markdown, content_hash, actor_kind,
                    actor_id, operation_id, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(room_id) DO UPDATE SET
                     revision = excluded.revision,
                     markdown = excluded.markdown,
                     content_hash = excluded.content_hash,
                     actor_kind = excluded.actor_kind,
                     actor_id = excluded.actor_id,
                     operation_id = excluded.operation_id,
                     updated_at = excluded.updated_at""",
                (
                    room_id,
                    revision,
                    markdown,
                    content_hash,
                    LOCAL_OPERATOR_KIND,
                    LOCAL_OPERATOR_ID,
                    operation_id,
                    changed_at,
                ),
            )

        def append_history(revision: int) -> None:
            conn.execute(
                """INSERT INTO coord_brief_revisions
                   (room_id, revision, markdown, content_hash, actor_kind,
                    actor_id, operation_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    room_id,
                    revision,
                    markdown,
                    content_hash,
                    LOCAL_OPERATOR_KIND,
                    LOCAL_OPERATOR_ID,
                    operation_id,
                    changed_at,
                ),
            )

        revision = apply_revisioned_change(
            expected_revision=expected_revision,
            actual_revision=actual_revision,
            write_projection=write_projection,
            append_history=append_history,
        )

        from .outbox import enqueue_coord_event

        enqueue_coord_event(
            conn,
            "coord.brief_updated",
            {
                "actor": LOCAL_OPERATOR_ID,
                "room_id": room_id,
                "object_id": object_id,
                "revision": revision,
                "content_hash": content_hash,
                "operation_id": operation_id,
                "operation_type": "coord.brief.set",
            },
        )
        attention_count = attention.create_state_attention_edges(
            conn,
            room_id=room_id,
            kind="brief_changed",
            object_id=object_id,
            revision=revision,
            created_at=changed_at,
        )
        result = _public_current(
            room_id,
            conn.execute(
                """SELECT revision, markdown, content_hash, updated_at
                   FROM coord_briefs WHERE room_id = ?""",
                (room_id,),
            ).fetchone(),
        )
        result["attention_count"] = attention_count
        return result

    return execute_mutation(
        operation_id=operation_id,
        operation_type="coord.brief.set",
        request=request,
        mutate=_set,
    )
