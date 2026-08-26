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
    new_msg_id,
    new_room_id,
)

READ_PAGE_MAX = 200
MAX_BODY_BYTES = 256 * 1024


class NotFoundError(LookupError):
    """Raised when a room / agent / message does not exist."""


class NoMembershipError(NotFoundError):
    """Raised when the caller has no active membership on a room.

    Inherits from NotFoundError so unauthorized callers see the same 404 as
    callers probing for nonexistent rooms (per #20 fix). Splitting this from
    GrantError distinguishes "you are not a member" (404, indistinguishable
    from room-doesn't-exist to prevent enumeration) from "you are a member
    but you lack this permission" (403, a legitimate signal to a member).
    """


class GrantError(PermissionError):
    """Raised when a caller with an active membership lacks the specific
    permission needed for the requested operation (e.g. `receive`-only
    member calling `send`). 403 semantic — the caller IS in the room."""


class ConflictError(ValueError):
    """Raised on unique-constraint violations (duplicate name, etc.)."""


# ---------- bootstrap ----------


def bootstrap() -> str:
    """Initialize schema + instance identity. Returns instance_id. Idempotent."""
    store.init_schema()
    instance_id = get_or_create_instance_id()
    with store.connect() as conn:
        conn.execute("INSERT OR IGNORE INTO instance(id) VALUES (?)", (instance_id,))
    return instance_id


# Agents are NOT managed here. The authoritative registry is
# `safeyolo.agents_store`; coord references agent_id strings but never mints
# or lists them. See #371 identity model.


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
        try:
            conn.execute(
                """INSERT INTO memberships
                   (room_id, principal_kind, principal_id, permissions, granted_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (room_id, principal_kind, principal_id, ",".join(permissions), now),
            )
        except sqlite3.IntegrityError:
            # Two grants in the same millisecond collide on the PK
            # (room_id, principal_kind, principal_id, granted_at). Absorb as
            # a no-op: caller intent was "grant this principal", which the
            # first insert already achieved. #371 room semantics do not need
            # per-millisecond uniqueness.
            pass


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
        # No active membership — 404 semantic (indistinguishable from
        # nonexistent room to an unauthorized caller, per #20).
        raise NoMembershipError(
            f"no active membership for {principal_kind}:{principal_id}"
        )
    perms = row["permissions"].split(",")
    if required_perm not in perms:
        # Caller IS a member but lacks this specific permission —
        # 403 semantic. Legitimate signal to a member; not a leak.
        raise GrantError(
            f"permission {required_perm!r} denied; grant permits {perms}"
        )


def revoke_grant(
    room_name: str,
    principal_kind: str,
    principal_id: str,
) -> bool:
    """Revoke ALL active grants for the principal on `room_name`.

    Bug fix per stage-0 finding #18: the earlier implementation revoked only
    the most-recent grant row, but `_check_grant` also picks the newest
    active row — so with multiple grants, revoke reported success while
    access persisted via an older still-active grant. This now sets
    `revoked_at` on every row with `revoked_at IS NULL`. Idempotent: returns
    True if any row changed, False if there was nothing to revoke.

    Room-semantics per #371: revocation removes access but does NOT erase
    history. A future re-grant exposes whatever is still retained.
    """
    if principal_kind not in {"agent", "operator"}:
        raise ValueError(f"principal_kind must be 'agent' or 'operator', got {principal_kind!r}")
    now = store.now_ms()
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        cur = conn.execute(
            """UPDATE memberships SET revoked_at = ?
               WHERE room_id = ? AND principal_kind = ? AND principal_id = ?
                 AND revoked_at IS NULL""",
            (now, room_id, principal_kind, principal_id),
        )
        return cur.rowcount > 0


# ---------- agent-facing operations ----------


def join_room(room_name: str, principal_kind: str, principal_id: str) -> dict[str, Any]:
    """Attach to an existing membership. Does not grant anything.

    A room ID is not a capability; this call verifies a valid membership
    exists for the caller and returns room metadata. Missing membership
    raises NoMembershipError (404 semantic per #20); nonexistent room
    raises NotFoundError (also 404).
    """
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        row = conn.execute(
            """SELECT permissions FROM memberships
               WHERE room_id = ? AND principal_kind = ? AND principal_id = ?
                 AND revoked_at IS NULL
               ORDER BY granted_at DESC LIMIT 1""",
            (room_id, principal_kind, principal_id),
        ).fetchone()
        if not row:
            raise NoMembershipError(
                f"no active membership for {principal_kind}:{principal_id}"
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
    # Body must encode cleanly to UTF-8; a lone surrogate raises
    # UnicodeEncodeError (subclass of ValueError). Catch it explicitly to
    # keep the raw Python codec message out of the 400 response. Codex
    # finding, post-patch.
    try:
        body_bytes_len = len(body.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("invalid body encoding") from exc
    if body_bytes_len > MAX_BODY_BYTES:
        raise ValueError(f"body too large ({body_bytes_len} > {MAX_BODY_BYTES} bytes)")

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
    limit: int = 1,
    exclude_self: bool = True,
) -> dict[str, Any]:
    """Long-blocking read for the next message the caller has not sent.

    Semantics:
    - Wake is an attention edge, not a bulk fetch. Default `limit=1` returns
      the first message that qualifies; callers do their bulk catch-up via
      `read_room` from their cursor.
    - By default (`exclude_self=True`) the caller's own sends do NOT wake
      it — otherwise an agent that mis-advances its cursor spins on its
      own traffic. `read_room` remains inclusive for canonical history.
    - Blocks the tool call; Claude Code resumes the LLM when it returns.
      Returns an empty page on timeout so the caller can retry.
    """
    limit = max(1, min(limit, READ_PAGE_MAX))
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    # `scan_since` advances past filtered-out own messages within one poll
    # cycle so a burst of 200+ consecutive own sends cannot starve peer
    # messages sitting further back in the stream. If nothing peer-shaped
    # is retrievable, scan_since carries into the next poll tick.
    scan_since = since_sequence
    while True:
        page = read_room(
            room_name, principal_kind, principal_id,
            since_sequence=scan_since, limit=READ_PAGE_MAX,
        )
        candidates = page["messages"]
        if exclude_self and principal_kind == "agent":
            candidates = [m for m in candidates if m["sender_agent_id"] != principal_id]
        elif exclude_self and principal_kind == "operator":
            candidates = [m for m in candidates if m["sender_kind"] != "operator"]

        if candidates:
            trimmed = candidates[:limit]
            return {
                **page,
                "messages": trimmed,
                "next_cursor": trimmed[-1]["sequence"],
                "has_more": len(candidates) > limit or page["has_more"],
            }

        # No peer messages in this window. Advance scan_since past whatever
        # we just read (filtered or not) so (a) we don't re-scan the same
        # own-message batch on the next poll, and (b) the timeout cursor
        # reflects what we already scanned. Fixes bob/codex finding: a small
        # own-message batch (1..READ_PAGE_MAX-1) previously stayed at the
        # original cursor since page.has_more was False.
        if page["messages"]:
            scan_since = page["next_cursor"]

        # If more retained messages exist past this window, scan next window
        # immediately — starvation guard for 200+ own-message bursts.
        if page["has_more"]:
            continue

        # Fully drained. Wait for arrivals past our scan point.
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return {**page, "messages": [], "next_cursor": scan_since}
        await asyncio.sleep(min(poll_interval_seconds, remaining))
