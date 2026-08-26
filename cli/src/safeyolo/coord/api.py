"""Agent API surface for the coord plane.

This is the authoritative interface. The MCP server is a thin adapter over
these functions. CLI commands are another adapter. Both go through the same
grant checks.
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

from . import store
from .envelope import Envelope, validate_content_type
from .identity import (
    get_or_create_instance_id,
    new_agent_id,
    new_msg_id,
    new_room_id,
)

READ_PAGE_MAX = 200


class GrantError(PermissionError):
    """Raised when the caller lacks a valid grant for the requested operation."""


class NotFoundError(LookupError):
    """Raised when a room / agent / message does not exist."""


class ConflictError(ValueError):
    """Raised on unique-constraint violations (duplicate name, etc.)."""


# ---------- bootstrap / registry ----------


def bootstrap() -> str:
    """Initialize schema + instance identity. Returns instance_id. Idempotent."""
    store.init_schema()
    instance_id = get_or_create_instance_id()
    with store.connect() as conn:
        conn.execute("INSERT OR IGNORE INTO instance(id) VALUES (?)", (instance_id,))
    return instance_id


def add_agent(name: str) -> str:
    """Mint a new agent_id for `name`. Returns agent_id."""
    if not name or not name.strip():
        raise ValueError("agent name must be non-empty")
    agent_id = new_agent_id()
    now = store.now_ms()
    with store.connect() as conn:
        try:
            conn.execute(
                "INSERT INTO agents(agent_id, name, created_at) VALUES (?, ?, ?)",
                (agent_id, name, now),
            )
        except sqlite3.IntegrityError as e:
            raise ConflictError(f"agent name {name!r} already exists") from e
    return agent_id


def list_agents() -> list[dict[str, Any]]:
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT agent_id, name, created_at FROM agents ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


def get_agent(agent_id: str) -> dict[str, Any]:
    with store.connect() as conn:
        row = conn.execute(
            "SELECT agent_id, name, created_at FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
    if not row:
        raise NotFoundError(f"agent_id {agent_id!r} not found")
    return dict(row)


# ---------- rooms ----------


def create_room(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("room name must be non-empty")
    room_id = new_room_id()
    now = store.now_ms()
    with store.connect() as conn:
        try:
            conn.execute(
                "INSERT INTO rooms(room_id, name, created_at) VALUES (?, ?, ?)",
                (room_id, name, now),
            )
        except sqlite3.IntegrityError as e:
            raise ConflictError(f"room name {name!r} already exists") from e
    return room_id


def list_rooms() -> list[dict[str, Any]]:
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT room_id, name, created_at FROM rooms ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


def _resolve_room(conn: sqlite3.Connection, name: str) -> str:
    row = conn.execute("SELECT room_id FROM rooms WHERE name = ?", (name,)).fetchone()
    if not row:
        raise NotFoundError(f"room {name!r} not found")
    return row["room_id"]


# ---------- grants ----------


def grant(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    permissions: list[str] | None = None,
) -> None:
    if principal_kind not in {"agent", "operator"}:
        raise ValueError(f"principal_kind must be 'agent' or 'operator', got {principal_kind!r}")
    permissions = permissions or ["send", "receive"]
    now = store.now_ms()
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        conn.execute(
            """INSERT INTO memberships
               (room_id, principal_kind, principal_id, permissions, granted_at)
               VALUES (?, ?, ?, ?, ?)""",
            (room_id, principal_kind, principal_id, ",".join(permissions), now),
        )


def _check_grant(
    conn: sqlite3.Connection,
    room_id: str,
    principal_kind: str,
    principal_id: str,
    required_perm: str,
) -> None:
    row = conn.execute(
        """SELECT permissions FROM memberships
           WHERE room_id = ? AND principal_kind = ? AND principal_id = ?
             AND revoked_at IS NULL
           ORDER BY granted_at DESC LIMIT 1""",
        (room_id, principal_kind, principal_id),
    ).fetchone()
    if not row:
        raise GrantError(
            f"no active grant for {principal_kind}:{principal_id} on this room"
        )
    perms = row["permissions"].split(",")
    if required_perm not in perms:
        raise GrantError(
            f"{required_perm!r} not in grant permissions {perms}"
        )


# ---------- agent-facing operations ----------


def join_room(room_name: str, principal_kind: str, principal_id: str) -> dict[str, Any]:
    """Attach to an existing membership. Does not grant anything.

    A room ID is not a capability; this call verifies a valid grant exists
    for the caller and returns room metadata + the caller's current
    sequence cursor position (0 = start of retained history).
    """
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        # Just verify some grant exists; both send/receive callers use join.
        row = conn.execute(
            """SELECT permissions FROM memberships
               WHERE room_id = ? AND principal_kind = ? AND principal_id = ?
                 AND revoked_at IS NULL
               ORDER BY granted_at DESC LIMIT 1""",
            (room_id, principal_kind, principal_id),
        ).fetchone()
        if not row:
            raise GrantError(
                f"no active grant for {principal_kind}:{principal_id} on room {room_name!r}"
            )
        return {
            "room_id": room_id,
            "room_name": room_name,
            "permissions": row["permissions"].split(","),
            "history_visibility": "retained",
        }


def send(
    room_name: str,
    sender_kind: str,
    sender_agent_id: str | None,
    body: str,
    declared_content_type: str = "text/markdown",
) -> dict[str, Any]:
    """Send a message. Envelope fields are SafeYolo-generated."""
    if sender_kind not in {"agent", "operator"}:
        raise ValueError(f"sender_kind must be 'agent' or 'operator', got {sender_kind!r}")
    if sender_kind == "agent" and not sender_agent_id:
        raise ValueError("sender_agent_id required when sender_kind='agent'")
    if sender_kind == "operator" and sender_agent_id is not None:
        raise ValueError("sender_agent_id must be None when sender_kind='operator'")

    content_type = validate_content_type(declared_content_type)
    instance_id = get_or_create_instance_id()
    msg_id = new_msg_id()
    sent_at = store.now_ms()

    principal_kind = sender_kind
    principal_id = sender_agent_id if sender_kind == "agent" else "operator"

    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "send")
        conn.execute(
            """INSERT INTO messages
               (msg_id, room_id, sent_at, sender_kind, sender_agent_id,
                origin_instance_id, content_type, body)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (msg_id, room_id, sent_at, sender_kind, sender_agent_id,
             instance_id, content_type, body),
        )
        # rowid == sequence
        sequence = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    envelope = Envelope(
        msg_id=msg_id,
        sent_at=sent_at,
        sender_kind=sender_kind,  # type: ignore[arg-type]
        sender_agent_id=sender_agent_id,
        origin_instance_id=instance_id,
        content_type=content_type,
        body=body,
    )
    return {"envelope": envelope.to_dict(), "sequence": sequence}


def read_room(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    since_sequence: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Return a bounded page of messages, with continuation metadata.

    Bounded per #371: authorization to retained history does not imply
    dumping the whole room in one response. Callers paginate via
    since_sequence + next_cursor.
    """
    limit = max(1, min(limit, READ_PAGE_MAX))
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "receive")
        rows = conn.execute(
            """SELECT msg_id, rowid AS sequence, sent_at, sender_kind,
                      sender_agent_id, origin_instance_id, content_type, body
               FROM messages
               WHERE room_id = ? AND rowid > ?
               ORDER BY rowid ASC LIMIT ?""",
            (room_id, since_sequence, limit),
        ).fetchall()
        # Detect truncation: is the earliest retained message > since_sequence
        # AND the caller asked for older than what we have? For v0 we only
        # detect truncation if the requested since_sequence=0 but the earliest
        # rowid in the room is > some threshold — v0 doesn't age out, so
        # history_truncated is always False. Wired for #371 spec so v1 can
        # populate it meaningfully.
    messages = [dict(r) for r in rows]
    next_cursor = messages[-1]["sequence"] if messages else since_sequence
    return {
        "messages": messages,
        "next_cursor": next_cursor,
        "has_more": len(messages) == limit,
        "history_truncated": False,
        "oldest_available_at": None,
    }


async def wait_for_message(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    since_sequence: int,
    timeout_seconds: float = 300.0,
    poll_interval_seconds: float = 0.5,
) -> dict[str, Any]:
    """Long-blocking read for the next message with sequence > since_sequence.

    Attention properties are harness-specific per #371: this blocks the
    MCP tool call; Claude Code resumes the LLM when the call returns.
    Returns immediately on first match or when timeout expires (empty page).
    """
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while True:
        page = read_room(
            room_name, principal_kind, principal_id,
            since_sequence=since_sequence, limit=READ_PAGE_MAX,
        )
        if page["messages"]:
            return page
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return page  # empty; caller sees `messages: []` and can retry
        await asyncio.sleep(min(poll_interval_seconds, remaining))
