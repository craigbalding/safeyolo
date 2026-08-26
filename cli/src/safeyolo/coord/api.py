"""Agent API surface for the coord plane.

This is the authoritative interface. The MCP server is a thin adapter over
these functions. CLI commands are another adapter. Both go through the same
grant checks.
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

from . import nats_client, store
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


async def create_room(name: str) -> str:
    """Create a room. Ensures the backing JetStream stream exists BEFORE
    recording the room in SQLite so a room without message storage cannot
    exist in the registry. If the SQLite insert fails (name collision),
    the stream is dropped to avoid orphaning storage.
    """
    if not name or not name.strip():
        raise ValueError("room name must be non-empty")
    room_id = new_room_id()
    now = store.now_ms()
    # NATS side first: ensure_room_stream is idempotent, so if we
    # later crash between it and the SQLite insert on a retry the
    # second attempt is safe.
    await nats_client.ensure_room_stream(room_id)
    try:
        with store.connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO rooms(room_id, name, created_at) VALUES (?, ?, ?)",
                    (room_id, name, now),
                )
            except sqlite3.IntegrityError as e:
                raise ConflictError(f"room name {name!r} already exists") from e
    except BaseException:
        # SQLite failed after stream creation — drop the orphan.
        await nats_client.delete_room_stream(room_id)
        raise
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


def list_members(room_name: str) -> list[dict[str, Any]]:
    """Return active room members deduplicated by principal.

    Read-only — does NOT permission-check the caller; the addon does that
    before calling (via `join_room`) so per-#20 rules apply (non-member gets
    404 as if the room didn't exist). Returns tuples ready to be joined
    against agents_store by the caller.
    """
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        rows = conn.execute(
            """SELECT DISTINCT principal_kind, principal_id
               FROM memberships
               WHERE room_id = ? AND revoked_at IS NULL""",
            (room_id,),
        ).fetchall()
    return [{"principal_kind": r["principal_kind"], "principal_id": r["principal_id"]} for r in rows]


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


async def send(
    room_name: str,
    sender_kind: str,
    sender_agent_id: str | None,
    body: str,
    declared_content_type: str = "text/markdown",
    sender_agent_name: str | None = None,
) -> dict[str, Any]:
    """Send a message via JetStream. Envelope fields SafeYolo-generated.

    `sender_agent_name` is display metadata per #22: SafeYolo-generated
    (never caller-supplied), persisted at send time in the envelope
    stored in JetStream. Authorization decisions still use
    `sender_agent_id`; the name is for humans and LLMs reading the
    transcript. Persisting at send means retained history keeps naming
    even after the agent is removed from the registry.

    v1: messages live in JetStream stream ROOM_<room_id>. `msg_id` is
    SafeYolo-generated and carried as `Nats-Msg-Id` header so an
    ambiguous PubAck can be retried inside the dedup window without
    duplicating (reviewer point 7). `sequence` returned is the
    JetStream stream sequence.
    """
    if sender_kind not in {"agent", "operator"}:
        raise ValueError(f"sender_kind must be 'agent' or 'operator', got {sender_kind!r}")
    if sender_kind == "agent" and not sender_agent_id:
        raise ValueError("sender_agent_id required when sender_kind='agent'")
    if sender_kind == "operator" and sender_agent_id is not None:
        raise ValueError("sender_agent_id must be None when sender_kind='operator'")
    if sender_kind == "operator" and sender_agent_name is not None:
        raise ValueError("sender_agent_name must be None when sender_kind='operator'")
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

    # Grants + room resolution remain in SQLite. NATS is the substrate
    # for messages only; membership state is authoritative in the
    # coord store (reviewer preferred a hybrid over a full rewrite).
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "send")

    envelope = Envelope(
        msg_id=msg_id,
        sent_at=sent_at,
        sender_kind=sender_kind,  # type: ignore[arg-type]
        sender_agent_id=sender_agent_id,
        sender_agent_name=sender_agent_name,
        origin_instance_id=instance_id,
        content_type=content_type,
        body=body,
    ).to_dict()
    sequence = await nats_client.publish_envelope(room_id, envelope)
    return {"envelope": envelope, "sequence": sequence}


async def read_room(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    since_sequence: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Return a bounded page of retained history from JetStream.

    v1: reads via an ephemeral pull consumer on ROOM_<room_id>. No
    durable per-participant state — matches stage 0's caller-owned
    cursor contract exactly (reviewer point 4).

    `history_truncated` / `oldest_available_at` are populated from
    the stream's first_seq / first_ts (task #35): if the caller asked
    for messages older than the stream floor, they're told about it
    with the oldest-available timestamp.
    """
    limit = max(1, min(limit, READ_PAGE_MAX))
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "receive")

    envelopes = await nats_client.fetch_since(
        room_id, since_sequence, limit, timeout=0.5,
    )

    # Re-check grant AFTER the fetch: JetStream's fetch can block
    # briefly, so a revoke that lands while we're waiting must not
    # ship messages the caller has since lost permission to see. Same
    # TOCTOU as wait_for_message; the empty response mirrors the
    # NoMembership 404 the addon would have returned for a fresh call.
    try:
        with store.connect() as conn:
            _check_grant(conn, room_id, principal_kind, principal_id, "receive")
    except (NoMembershipError, GrantError):
        raise

    # The stream sequence lives on the envelope as `_stream_seq`; API
    # callers see it as `sequence` (same shape as stage 0).
    messages = []
    for env in envelopes:
        m = {k: v for k, v in env.items() if k != "_stream_seq"}
        m["sequence"] = env["_stream_seq"]
        messages.append(m)
    next_cursor = messages[-1]["sequence"] if messages else since_sequence

    # Truncation reporting from stream state (task #35). Only fetch the
    # oldest-message timestamp when we've actually detected truncation —
    # keeps the read hot path to one JetStream RPC.
    state = await nats_client.room_stream_state(room_id)
    history_truncated = False
    oldest_available_at = None
    if state["first_seq"] > 0 and since_sequence < state["first_seq"] - 1:
        history_truncated = True
        oldest_available_at = await nats_client.oldest_message_ts(
            room_id, state["first_seq"],
        )

    # has_more is best-effort: if fetch returned `limit` messages there
    # may or may not be more. Callers who care follow with another
    # read_room from next_cursor.
    return {
        "messages": messages,
        "next_cursor": next_cursor,
        "has_more": len(messages) == limit,
        "history_truncated": history_truncated,
        "oldest_available_at": oldest_available_at,
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

    v1 semantics preserved from stage 0:
    - Wake is an attention edge, not a bulk fetch. Default `limit=1`.
    - `exclude_self=True` (default) filters caller's own sends so an
      agent that mis-advances its cursor cannot spin on its own traffic
      (stage 0 #9). `read_room` stays inclusive for canonical history.
    - Starvation guard: `scan_since` advances past filtered-empty
      windows within a single wait so 200+ own-message bursts do not
      hide peer messages beyond the READ_PAGE_MAX window.
    - Revocation check inside the loop: if the caller loses their
      grant mid-flight (task #37), return empty rather than deliver a
      message that arrived after revocation.
    - Truncation reporting is deliberately NOT surfaced here: wait is
      an attention edge, `read_room` is the mandatory catch-up path
      where truncation is disclosed. The response always sets
      `history_truncated: false` / `oldest_available_at: null` — a
      caller that wakes from wait and needs canonical history must
      call `read_room` to see either the truncation flags or the
      messages preceding the wake edge.

    Blocks the caller (an HTTP long-poll or an MCP tool call);
    the runtime returns when a peer message qualifies or timeout hits.
    """
    limit = max(1, min(limit, READ_PAGE_MAX))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds

    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "receive")

    scan_since = since_sequence
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return {
                "messages": [],
                "next_cursor": scan_since,
                "has_more": False,
                "history_truncated": False,
                "oldest_available_at": None,
            }

        # Re-check grant BEFORE fetching so a mid-flight revocation
        # short-circuits before we go back to NATS (task #37).
        try:
            with store.connect() as conn:
                _check_grant(conn, room_id, principal_kind, principal_id, "receive")
        except (NoMembershipError, GrantError):
            return {
                "messages": [],
                "next_cursor": scan_since,
                "has_more": False,
                "history_truncated": False,
                "oldest_available_at": None,
            }

        # JetStream fetch: this waits server-side up to poll_interval
        # for a message. If nothing arrives it returns [] and we loop.
        fetch_timeout = min(poll_interval_seconds, remaining)
        envelopes = await nats_client.fetch_since(
            room_id, scan_since, READ_PAGE_MAX, timeout=fetch_timeout,
        )

        if exclude_self and principal_kind == "agent":
            candidates = [e for e in envelopes if e.get("sender_agent_id") != principal_id]
        elif exclude_self and principal_kind == "operator":
            candidates = [e for e in envelopes if e.get("sender_kind") != "operator"]
        else:
            candidates = envelopes

        if candidates:
            # Re-check grant AFTER fetch: the check before fetch cannot
            # cover a revoke that lands WHILE we were blocked waiting for
            # a message. Without this second check, a revoked caller
            # would receive the first peer message that arrived during
            # their blocked wait. Task #37 correctness case.
            try:
                with store.connect() as conn:
                    _check_grant(conn, room_id, principal_kind, principal_id, "receive")
            except (NoMembershipError, GrantError):
                return {
                    "messages": [],
                    "next_cursor": scan_since,
                    "has_more": False,
                    "history_truncated": False,
                    "oldest_available_at": None,
                }
            trimmed = candidates[:limit]
            out = []
            for env in trimmed:
                m = {k: v for k, v in env.items() if k != "_stream_seq"}
                m["sequence"] = env["_stream_seq"]
                out.append(m)
            return {
                "messages": out,
                "next_cursor": out[-1]["sequence"],
                "has_more": len(candidates) > limit,
                "history_truncated": False,
                "oldest_available_at": None,
            }

        # No peer messages in this window. If we saw any own-messages,
        # advance the cursor so we don't re-fetch them next iteration.
        if envelopes:
            scan_since = envelopes[-1]["_stream_seq"]
