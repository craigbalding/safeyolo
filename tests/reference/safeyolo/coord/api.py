"""Agent API surface for the coord plane.

This is the authoritative interface. The MCP server is a thin adapter over
these functions. CLI commands are another adapter. Both go through the same
grant checks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
from typing import Any

from safeyolo.agents_store import (
    load_all_agents_snapshot,
    locked_all_agents_snapshot,
)

from . import attention, brief, inventory, nats_client, store
from .envelope import Envelope, validate_content_type
from .identity import (
    get_or_create_instance_id,
    new_msg_id,
    new_room_id,
)
from .kernel import (
    LOCAL_OPERATOR_ID,
    execute_mutation,
)
from .kernel import (
    OperationConflictError as _OperationConflictError,
)
from .kernel import RevisionConflictError as _RevisionConflictError

OperationConflictError = _OperationConflictError
RevisionConflictError = _RevisionConflictError
NOTIFY_OMITTED = attention.NOTIFY_OMITTED

log = logging.getLogger("safeyolo.coord.api")

READ_PAGE_MAX = 200
# How long one outstanding pull request may stay open while waiting. This is
# not a poll interval: nothing happens while it is outstanding unless a
# message arrives, so a quiet room costs one request per window rather than
# one per tick. Kept well under a typical server max_request_expires.
_WAIT_FETCH_WINDOW_S = 30.0
# After a wake, how long to spend collecting anything else already stored.
_WAIT_DRAIN_S = 0.05
# A page is bounded by bytes as well as by message count. The count alone is
# not a resource bound: 200 legal messages can be hundreds of MiB on the wire,
# because a 256 KiB body can expand to roughly 1.5 MiB once JSON-escaped.
# Measured against serialized wire size, not raw body length.
READ_PAGE_MAX_BYTES = 4 * 1024 * 1024
MAX_BODY_BYTES = 256 * 1024
_MSG_ID_RE = re.compile(r"^msg-[0-9a-f]{32}$")


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
    from .outbox import project_pending

    project_pending()
    inventory.discover_provider_adapters()
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


def inspect_room_access(
    room_name: str,
    principals: list[tuple[str, str]],
) -> dict[str, Any]:
    """Read one room and selected active grants without changing Coord state."""
    with store.connect_readonly() as conn:
        room_id = _resolve_room(conn, room_name)
        permissions = {}
        for kind, principal_id in principals:
            try:
                current = _active_permissions(
                    conn,
                    room_id,
                    kind,
                    principal_id,
                )
            except NoMembershipError:
                current = []
            permissions[f"{kind}:{principal_id}"] = current
    return {
        "room_id": room_id,
        "room_name": room_name,
        "permissions": permissions,
    }


def _resolve_room(conn: sqlite3.Connection, name: str) -> str:
    row = conn.execute("SELECT room_id FROM rooms WHERE name = ?", (name,)).fetchone()
    if not row:
        raise NotFoundError(f"room {name!r} not found")
    return row["room_id"]


# ---------- trusted operator brief ----------


async def set_brief(
    room_name: str,
    markdown: str,
    *,
    expected_revision: int,
    operation_id: str,
) -> dict[str, Any]:
    """Set trusted room intent through the local operator-only surface."""
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
    result = brief.set_brief(
        room_id,
        markdown,
        expected_revision=expected_revision,
        operation_id=operation_id,
    )
    try:
        from .outbox import project_attention_hints

        await project_attention_hints()
    except Exception as exc:  # SQLite edges remain authoritative and pending
        log.warning(
            "brief attention wake hints remain pending for %s revision %s: %s",
            room_id,
            result["revision"],
            type(exc).__name__,
        )
    return result


def show_brief(
    room_name: str,
    *,
    revision: int | None = None,
) -> dict[str, Any]:
    """Read current or immutable brief state from the local operator surface."""
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        if revision is None:
            return brief.read_current(conn, room_id)
        try:
            return brief.read_revision(conn, room_id, revision)
        except brief.BriefRevisionNotFound as exc:
            raise NotFoundError("brief revision not found") from exc


def list_brief_history(
    room_name: str,
    *,
    since_revision: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """List metadata for immutable brief revisions as local operator."""
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        return brief.list_history(
            conn,
            room_id,
            since_revision=since_revision,
            limit=limit,
        )


def read_brief(
    room_name: str,
    principal_kind: str,
    principal_id: str,
) -> dict[str, Any]:
    """Read current trusted intent after a same-snapshot membership check."""
    with store.connect() as conn:
        conn.execute("BEGIN")
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "receive")
        result = brief.read_current(conn, room_id)
        conn.execute("COMMIT")
        return result


# ---------- authoritative room inventory ----------


def _inventory_snapshot(
    room_name: str,
    principal_kind: str | None,
    principal_id: str | None,
) -> tuple[str, inventory.InventorySnapshot, dict[str, Any]]:
    """Pin room authorization and all SQLite-owned state to one snapshot."""
    with store.connect() as conn:
        conn.execute("BEGIN")
        room_id = _resolve_room(conn, room_name)
        if principal_kind is not None:
            assert principal_id is not None
            _check_grant(
                conn,
                room_id,
                principal_kind,
                principal_id,
                "receive",
            )
        snapshot = inventory.read_snapshot(conn, room_id)
        current_brief = brief.read_current(conn, room_id)
        conn.execute("COMMIT")
    return room_id, snapshot, current_brief


async def get_room_state(
    room_name: str,
    principal_kind: str | None = None,
    principal_id: str | None = None,
) -> dict[str, Any]:
    """Return current bounded room state with explicit source provenance.

    ``principal_kind=None`` is the local operator/admin surface. Agent calls
    provide transport-derived identity and are authorized twice: before
    bounded provider I/O and again in the final state snapshot. Provider
    results are filtered against that final snapshot and a fresh locked policy
    read, so revocation/unadvertising cannot survive in a coord cache.
    """
    if (principal_kind is None) != (principal_id is None):
        raise ValueError("principal_kind and principal_id must be supplied together")
    room_id, preliminary, _preliminary_brief = _inventory_snapshot(
        room_name,
        principal_kind,
        principal_id,
    )
    preliminary_agents = inventory.configured_agents(
        await asyncio.to_thread(load_all_agents_snapshot)
    )
    requests = inventory.plan_provider_requests(
        room_id,
        preliminary,
        preliminary_agents,
    )
    provider_evidence = await inventory.query_providers(requests)

    # Hold the policy snapshot lock across the final SQLite authorization and
    # state snapshot. Otherwise a policy revoke followed by a room
    # advertisement can straddle the two reads and manufacture an intersection
    # that never existed at any instant.
    def final_authoritative_snapshot():
        with locked_all_agents_snapshot() as raw_agents:
            final_agents = inventory.configured_agents(raw_agents)
            final_room_id, final_snapshot, final_brief = _inventory_snapshot(
                room_name,
                principal_kind,
                principal_id,
            )
            return final_agents, final_room_id, final_snapshot, final_brief

    final_agents, final_room_id, final_snapshot, final_brief = (
        await asyncio.to_thread(final_authoritative_snapshot)
    )
    if final_room_id != room_id:
        raise RuntimeError("room identity changed during inventory read")
    instance_id = await asyncio.to_thread(get_or_create_instance_id)
    return inventory.build_room_state(
        room_id=room_id,
        room_name=room_name,
        snapshot=final_snapshot,
        agents=final_agents,
        provider_evidence=provider_evidence,
        origin_instance_id=instance_id,
        brief=final_brief,
        now_ms=store.now_ms(),
    )


def advertise_capability(
    room_name: str,
    agent_id: str,
    capability: str,
    *,
    advertised: bool,
    operation_id: str,
) -> dict[str, Any]:
    """Change an operator-owned room-visible capability label."""
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
    return inventory.set_capability_advertisement(
        room_id,
        agent_id,
        capability,
        advertised=advertised,
        operation_id=operation_id,
    )


def advertise_resource(
    room_name: str,
    provider: str,
    resource: str,
    *,
    advertised: bool,
    operation_id: str,
) -> dict[str, Any]:
    """Change an operator-owned room-visible provider resource label."""
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
    return inventory.set_resource_advertisement(
        room_id,
        provider,
        resource,
        advertised=advertised,
        operation_id=operation_id,
    )


def declare_capabilities(
    room_name: str,
    agent_id: str,
    capabilities: list[str],
    *,
    ttl_seconds: int,
) -> dict[str, Any]:
    """Replace one receive-authorized agent's untrusted declarations."""
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, "agent", agent_id, "receive")
        result = inventory.replace_declarations(
            conn,
            room_id,
            agent_id,
            capabilities,
            ttl_seconds=ttl_seconds,
        )
        conn.execute("COMMIT")
        return result


# ---------- grants ----------


def grant(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    permissions: list[str] | None = None,
    *,
    operation_id: str,
) -> None:
    if principal_kind not in {"agent", "operator"}:
        raise ValueError(f"principal_kind must be 'agent' or 'operator', got {principal_kind!r}")
    permissions = sorted(set(permissions or ["send", "receive"]))
    request = {
        "room_name": room_name,
        "principal_kind": principal_kind,
        "principal_id": principal_id,
        "permissions": permissions,
    }

    def _grant(conn: sqlite3.Connection) -> None:
        room_id = _resolve_room(conn, room_name)
        serialized_permissions = ",".join(permissions)
        active = conn.execute(
            """SELECT permissions FROM memberships
               WHERE room_id = ? AND principal_kind = ? AND principal_id = ?
                 AND revoked_at IS NULL
               ORDER BY granted_at DESC LIMIT 1""",
            (room_id, principal_kind, principal_id),
        ).fetchone()
        if active is not None and active["permissions"] == serialized_permissions:
            return

        latest = conn.execute(
            """SELECT MAX(granted_at) FROM memberships
               WHERE room_id = ? AND principal_kind = ? AND principal_id = ?""",
            (room_id, principal_kind, principal_id),
        ).fetchone()[0]
        granted_at = store.now_ms()
        if latest is not None:
            granted_at = max(granted_at, latest + 1)

        conn.execute(
            """INSERT INTO memberships
               (room_id, principal_kind, principal_id, permissions, granted_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                room_id,
                principal_kind,
                principal_id,
                serialized_permissions,
                granted_at,
            ),
        )
        from .outbox import enqueue_coord_event

        enqueue_coord_event(
            conn,
            "coord.grant_changed",
            {
                "actor": LOCAL_OPERATOR_ID,
                "room_id": room_id,
                "object_id": room_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "operation_id": operation_id,
                "operation_type": "coord.grant",
                "transition": "granted",
            },
        )

    return execute_mutation(
        operation_id=operation_id,
        operation_type="coord.grant",
        request=request,
        mutate=_grant,
    )


def _check_grant(
    conn: sqlite3.Connection,
    room_id: str,
    principal_kind: str,
    principal_id: str,
    required_perm: str,
) -> None:
    perms = _active_permissions(conn, room_id, principal_kind, principal_id)
    if required_perm not in perms:
        # Caller IS a member but lacks this specific permission —
        # 403 semantic. Legitimate signal to a member; not a leak.
        raise GrantError(
            f"permission {required_perm!r} denied; grant permits {perms}"
        )


def _active_permissions(
    conn: sqlite3.Connection,
    room_id: str,
    principal_kind: str,
    principal_id: str,
) -> list[str]:
    """Return the latest active grant's permissions or the 404-family error."""
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
    return row["permissions"].split(",")


def revoke_grant(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    *,
    operation_id: str,
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
    request = {
        "room_name": room_name,
        "principal_kind": principal_kind,
        "principal_id": principal_id,
    }

    def _revoke(conn: sqlite3.Connection) -> bool:
        room_id = _resolve_room(conn, room_name)
        cur = conn.execute(
            """UPDATE memberships SET revoked_at = ?
               WHERE room_id = ? AND principal_kind = ? AND principal_id = ?
                 AND revoked_at IS NULL""",
            (store.now_ms(), room_id, principal_kind, principal_id),
        )
        changed = cur.rowcount > 0
        if changed:
            from .outbox import enqueue_coord_event

            enqueue_coord_event(
                conn,
                "coord.grant_revoked",
                {
                    "actor": LOCAL_OPERATOR_ID,
                    "room_id": room_id,
                    "object_id": room_id,
                    "principal_kind": principal_kind,
                    "principal_id": principal_id,
                    "operation_id": operation_id,
                    "operation_type": "coord.revoke",
                    "transition": "revoked",
                },
            )
        return changed

    return execute_mutation(
        operation_id=operation_id,
        operation_type="coord.revoke",
        request=request,
        mutate=_revoke,
    )


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
    exists for the caller and returns room metadata. The trusted brief is
    present only when that active grant includes ``receive``; send-only
    members receive a null brief. Missing membership raises NoMembershipError
    (404 semantic per #20); nonexistent room raises NotFoundError (also 404).
    """
    with store.connect() as conn:
        conn.execute("BEGIN")
        room_id = _resolve_room(conn, room_name)
        permissions = _active_permissions(
            conn,
            room_id,
            principal_kind,
            principal_id,
        )
        result = {
            "room_id": room_id,
            "room_name": room_name,
            "permissions": permissions,
            "history_visibility": "retained",
            "brief": (
                brief.read_current(conn, room_id)
                if "receive" in permissions
                else None
            ),
        }
        conn.execute("COMMIT")
        return result


async def send(
    room_name: str,
    sender_kind: str,
    sender_agent_id: str | None,
    body: str,
    declared_content_type: str = "text/markdown",
    sender_agent_name: str | None = None,
    notify: Any = NOTIFY_OMITTED,
) -> dict[str, Any]:
    """Send a message via JetStream. Envelope fields SafeYolo-generated.

    `sender_agent_name` is display metadata per #22: SafeYolo-generated
    (never caller-supplied), persisted at send time in the envelope
    stored in JetStream. Authorization decisions still use
    `sender_agent_id`; the name is for humans and LLMs reading the
    transcript. Persisting at send means retained history keeps naming
    even after the agent is removed from the registry.

    Messages live in JetStream stream ROOM_<room_id>. `msg_id` is
    SafeYolo-generated and carried as `Nats-Msg-Id`. `sequence` returned is
    the JetStream stream sequence. Stage 1 stores attention intent only in an
    internal NATS header and returns `attention_status=ready|pending|lost`
    after the definite PubAck; pending means the accepted intent will be
    replayed, while lost means retention irrecoverably removed the canonical
    object before its attention could be projected.
    If the publish call loses its outcome, the caller is told acceptance is
    unknown: it cannot reuse the hidden msg_id, and a new send may duplicate
    the canonical message because Stage 1 exposes no send idempotency.
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

    # Establish the pre-Stage-1 projection frontier before this process can
    # publish a message carrying a Stage-1 manifest.
    await attention.ensure_room_projection(room_id)

    # Re-check sender authorization and snapshot exact recipient membership
    # generations immediately before publication.
    with store.connect() as conn:
        _check_grant(conn, room_id, principal_kind, principal_id, "send")
        manifest = attention.build_message_manifest(
            conn,
            room_id=room_id,
            msg_id=msg_id,
            sender_agent_id=sender_agent_id,
            notify=notify,
        )

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
    return await _publish_prepared_message(room_id, envelope, manifest)


async def prepare_operator_message(
    room_name: str,
    body: str,
    *,
    declared_content_type: str = "text/markdown",
    notify: Any = NOTIFY_OMITTED,
) -> dict[str, Any]:
    """Prepare one canonical operator message for a durable local outbox.

    This surface is intentionally local and operator-only.  It exists for the
    Dispatch one-shot scheduler, which must persist SafeYolo-minted envelope
    and attention IDs before a publish whose acknowledgement can be lost.
    Agent API and MCP callers cannot supply or reuse these fields.
    """
    if not isinstance(body, str):
        raise ValueError("body must be a string")
    try:
        body_bytes_len = len(body.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("invalid body encoding") from exc
    if body_bytes_len > MAX_BODY_BYTES:
        raise ValueError(f"body too large ({body_bytes_len} > {MAX_BODY_BYTES} bytes)")

    content_type = validate_content_type(declared_content_type)
    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, "operator", "operator", "send")

    await attention.ensure_room_projection(room_id)
    stream_state = await nats_client.room_stream_state(room_id)
    msg_id = new_msg_id()
    with store.connect() as conn:
        _check_grant(conn, room_id, "operator", "operator", "send")
        manifest = attention.build_message_manifest(
            conn,
            room_id=room_id,
            msg_id=msg_id,
            sender_agent_id=None,
            notify=notify,
        )

    envelope = Envelope(
        msg_id=msg_id,
        sent_at=store.now_ms(),
        sender_kind="operator",
        sender_agent_id=None,
        sender_agent_name=None,
        origin_instance_id=get_or_create_instance_id(),
        content_type=content_type,
        body=body,
    ).to_dict()
    return {
        "room_id": room_id,
        "since_sequence": int(stream_state["last_seq"]),
        "envelope": envelope,
        "attention_manifest": manifest.to_header(),
    }


def _validate_prepared_operator_message(
    room_name: str,
    prepared: Any,
) -> tuple[str, dict[str, Any], attention.AttentionManifest, int]:
    if not isinstance(prepared, dict) or set(prepared) != {
        "room_id",
        "since_sequence",
        "envelope",
        "attention_manifest",
    }:
        raise ValueError("invalid prepared operator message")
    room_id = prepared["room_id"]
    since_sequence = prepared["since_sequence"]
    envelope = prepared["envelope"]
    if not isinstance(room_id, str) or type(since_sequence) is not int or since_sequence < 0:
        raise ValueError("invalid prepared operator message metadata")
    if not isinstance(envelope, dict) or set(envelope) != {
        "msg_id",
        "sent_at",
        "sender_kind",
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "content_type",
        "body",
    }:
        raise ValueError("invalid prepared operator envelope")
    msg_id = envelope.get("msg_id")
    if not isinstance(msg_id, str) or not _MSG_ID_RE.fullmatch(msg_id):
        raise ValueError("invalid prepared operator msg_id")
    if (
        envelope.get("sender_kind") != "operator"
        or envelope.get("sender_agent_id") is not None
        or envelope.get("sender_agent_name") is not None
        or envelope.get("origin_instance_id") != get_or_create_instance_id()
    ):
        raise ValueError("prepared message is not a canonical local operator envelope")
    if type(envelope.get("sent_at")) is not int or envelope["sent_at"] < 0:
        raise ValueError("invalid prepared operator timestamp")
    validate_content_type(envelope.get("content_type"))
    body = envelope.get("body")
    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("invalid prepared operator body")
    manifest_header = prepared["attention_manifest"]
    if not isinstance(manifest_header, str):
        raise ValueError("invalid prepared attention manifest")
    manifest = attention.parse_manifest(manifest_header, expected_msg_id=msg_id)

    with store.connect() as conn:
        resolved_room_id = _resolve_room(conn, room_name)
        if resolved_room_id != room_id:
            raise ValueError("prepared operator message belongs to another room")
        _check_grant(conn, room_id, "operator", "operator", "send")
    return room_id, envelope, manifest, since_sequence


async def find_prepared_operator_message(
    room_name: str,
    prepared: Any,
) -> dict[str, Any] | None:
    """Reconcile a prepared send against retained history without replaying it."""
    _, envelope, _, cursor = _validate_prepared_operator_message(room_name, prepared)
    while True:
        page = await read_room(
            room_name,
            "operator",
            "operator",
            since_sequence=cursor,
            limit=READ_PAGE_MAX,
        )
        for message in page["messages"]:
            if message.get("msg_id") == envelope["msg_id"]:
                return message
        if page["history_truncated"]:
            raise nats_client.CoordDataError(
                "prepared Dispatch send is older than retained room history; "
                "refusing a possibly duplicate replay"
            )
        cursor = page["next_cursor"]
        if not page["has_more"]:
            return None


async def publish_prepared_operator_message(
    room_name: str,
    prepared: Any,
) -> dict[str, Any]:
    """Publish a persisted local-operator message with stable retry identity."""
    room_id, envelope, manifest, _ = _validate_prepared_operator_message(room_name, prepared)
    await attention.ensure_room_projection(room_id)
    with store.connect() as conn:
        _check_grant(conn, room_id, "operator", "operator", "send")
    return await _publish_prepared_message(room_id, envelope, manifest)


async def _publish_prepared_message(
    room_id: str,
    envelope: dict[str, Any],
    manifest: attention.AttentionManifest,
) -> dict[str, Any]:
    msg_id = envelope["msg_id"]
    sequence = await nats_client.publish_envelope(
        room_id,
        envelope,
        attention_manifest=manifest.to_header(),
    )

    # PubAck is the canonical acceptance point. Projection failure after it
    # must never be reported as "message unsent": the persisted manifest is
    # the recovery source.
    attention_status = "pending"
    try:
        watermark = await attention.materialize_room_attention(
            room_id,
            through_sequence=sequence,
        )
        if watermark >= sequence:
            attention_status = (
                "lost"
                if attention.projection_sequence_was_lost(room_id, sequence)
                else "ready"
            )
    except Exception as exc:  # recovery remains durable in JetStream
        log.warning(
            "attention materialization pending for %s: %s",
            msg_id,
            type(exc).__name__,
        )
    try:
        from .outbox import project_attention_hints

        await project_attention_hints()
    except Exception as exc:  # the SQLite feed is already authoritative
        log.warning(
            "attention wake hints remain pending after %s: %s",
            msg_id,
            type(exc).__name__,
        )
    return {
        "envelope": envelope,
        "sequence": sequence,
        "attention_status": attention_status,
        "attention_intent": manifest.public_intent(),
    }


def _trim_page_to_byte_bound(messages: list[dict]) -> list[dict]:
    """Cut a page to a whole-message prefix within READ_PAGE_MAX_BYTES.

    Only ever returns a prefix, never a partial message, so the caller's
    cursor stays on a message boundary and a follow-up read resumes cleanly.
    At least one message is always returned: a single message larger than the
    bound must still be delivered, or a cursor sitting behind it could never
    advance.

    This trims after receipt. Bounding the pull itself would be better --
    JetStream supports max_bytes on pull requests -- but nats-py's legacy
    PullSubscription.fetch() exposes only batch and timeout, so that needs a
    raw-pull helper or the newer consumer API.
    """
    if not messages:
        return messages
    kept: list[dict] = []
    total = 0
    for m in messages:
        total += len(json.dumps(m, separators=(",", ":")).encode("utf-8"))
        if kept and total > READ_PAGE_MAX_BYTES:
            break
        kept.append(m)
    return kept


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
        m = {k: v for k, v in env.items() if not k.startswith("_")}
        m["sequence"] = env["_stream_seq"]
        if principal_kind == "operator":
            manifest = attention.manifest_for_envelope(env)
            m["attention_intent"] = (
                manifest.public_intent()
                if manifest is not None
                else {"mode": "room"}
            )
        messages.append(m)
    messages = _trim_page_to_byte_bound(messages)
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

    # has_more is exact: the stream state we already fetched for truncation
    # reporting tells us whether anything remains past the cursor. The old
    # `len(messages) == limit` was best-effort and, now that a page can also
    # be cut short by the byte bound, would have been wrong as well as vague.
    return {
        "messages": messages,
        "next_cursor": next_cursor,
        "has_more": state["last_seq"] > next_cursor,
        "history_truncated": history_truncated,
        "oldest_available_at": oldest_available_at,
    }


def _qualifies_as_wake(
    env: dict, principal_kind: str, principal_id: str, exclude_self: bool
) -> bool:
    """Apply legacy self filtering plus Stage-1 target-aware wake semantics."""
    base_legacy_wake = True
    if exclude_self:
        if principal_kind == "agent":
            base_legacy_wake = env.get("sender_agent_id") != principal_id
        elif principal_kind == "operator":
            base_legacy_wake = env.get("sender_kind") != "operator"
    # Operator chat observation is not an agent attention feed and preserves
    # its existing room-tail behavior.
    if principal_kind == "operator":
        return base_legacy_wake
    manifest = attention.manifest_for_envelope(env)
    if manifest is None or manifest.mode == "legacy_room":
        return base_legacy_wake
    if principal_kind == "agent":
        # Explicit self-targeting is intentional and is not removed by the
        # legacy exclude_self default.
        return any(item.agent_id == principal_id for item in manifest.recipients)
    return False


async def wait_for_attention(
    principal_id: str,
    *,
    since_sequence: int,
    timeout_seconds: float = 300.0,
    limit: int = 1,
) -> dict[str, Any]:
    return await attention.wait_for_attention(
        principal_id,
        since_sequence=since_sequence,
        timeout_seconds=timeout_seconds,
        limit=limit,
    )


async def read_attention(
    principal_id: str,
    attention_id: str,
) -> dict[str, Any]:
    try:
        return await attention.read_attention_object(principal_id, attention_id)
    except attention.AttentionObjectNotFound as exc:
        raise NotFoundError("attention object not found or not accessible") from exc


async def recover_attention() -> None:
    """Upgrade room storage, then project accepted manifests and wake hints."""
    await nats_client.upgrade_room_streams()
    await attention.recover_all_attention()
    from .outbox import project_attention_hints

    await project_attention_hints()


async def wait_for_message(
    room_name: str,
    principal_kind: str,
    principal_id: str,
    since_sequence: int,
    timeout_seconds: float = 300.0,
    fetch_window_seconds: float = _WAIT_FETCH_WINDOW_S,
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
    - No `has_more`. Wait is an attention edge, not a page: a field
      meaning "more in this wake scan" reads as "backlog remains" and
      cannot answer that question, since the scan window is bounded.
      `read_room` answers it correctly and is the mandatory catch-up
      path anyway -- see the cursor rule below.
    - CURSOR RULE. After waking, read from your existing canonical
      (pre-wait) cursor, NOT from this response's `next_cursor`.
      `exclude_self` means the wake edge can sit past your own sends,
      and `read_room` is inclusive of them: with a canonical cursor at
      10, your own message at 11 and a peer at 12, waking returns
      `next_cursor=12` and `read_room(12)` silently omits 11. Process
      the full page, then advance the canonical cursor to the highest
      sequence seen. The caller owns that cursor; wait never does.
    - Event-driven, not timed. One ephemeral consumer serves the whole
      call, and each fetch asks for a SINGLE message with a long
      server-side window, so the server completes the request the
      instant a message is stored. A quiet room costs one outstanding
      pull request per `fetch_window_seconds`, not a fetch every tick.
      Each fetch asks for one message, which keeps the wait on the
      client's single-message path rather than its batch-filling loop.
      Latency is the same either way on nats-py 2.15 -- a partial batch
      comes back immediately -- so this is about code path, not speed.
    - `fetch_window_seconds` bounds a single outstanding request, not a
      sleep between requests. Nothing happens while it is outstanding
      unless a message arrives.
    - Truncation reporting is deliberately NOT surfaced here: wait is
      an attention edge, `read_room` is the mandatory catch-up path
      where truncation is disclosed. The response always sets
      `history_truncated: false` / `oldest_available_at: null` — a
      caller that wakes from wait and needs canonical history must
      call `read_room` (from the canonical cursor, per the rule above)
      to see either the truncation flags or the messages preceding the
      wake edge.

    Blocks the caller (an HTTP long-poll or an MCP tool call);
    the runtime returns when a peer message qualifies or timeout hits.
    """
    limit = max(1, min(limit, READ_PAGE_MAX))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds

    with store.connect() as conn:
        room_id = _resolve_room(conn, room_name)
        _check_grant(conn, room_id, principal_kind, principal_id, "receive")

    async with nats_client.pull_session(room_id, since_sequence) as session:
        return await _wait_loop(
            session,
            room_id=room_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            scan_since=since_sequence,
            deadline=deadline,
            loop=loop,
            fetch_window_seconds=fetch_window_seconds,
            limit=limit,
            exclude_self=exclude_self,
        )


async def _wait_loop(
    session,
    *,
    room_id: str,
    principal_kind: str,
    principal_id: str,
    scan_since: int,
    deadline: float,
    loop,
    fetch_window_seconds: float,
    limit: int,
    exclude_self: bool,
) -> dict[str, Any]:
    """Poll one already-open consumer until a peer lands or time runs out."""
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return {
                "messages": [],
                "next_cursor": scan_since,
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
                "history_truncated": False,
                "oldest_available_at": None,
            }

        # Ask for ONE message with a long server-side window. The server
        # completes the request as soon as a message is stored, so this is a
        # subscription in behaviour even though the transport is a pull.
        #
        # Batch size is not about latency here: measured against nats-py
        # 2.15, fetch(200, timeout=10) returns a partial batch ~1ms after a
        # message arrives, exactly like fetch(1). It is about which client
        # code path runs. batch == 1 routes to _fetch_one; anything larger
        # routes to _fetch_n, whose multi-request deadline loop raises a bare
        # asyncio.TimeoutError -- the path that surfaced to an operator as
        # `NatsUnavailable: fetch failed:` on a quiet room. That is handled
        # now, but an attention edge has no reason to be in a batch-filling
        # loop at all.
        envelopes = await session.fetch(
            1, timeout=min(fetch_window_seconds, remaining))
        if envelopes and (
            limit > 1
            or not _qualifies_as_wake(
                envelopes[0], principal_kind, principal_id, exclude_self)
        ):
            # Drain only when that one message cannot end the wait by itself:
            # it was the caller's own traffic (skip the rest of the burst in
            # one request rather than a round trip per message), or the
            # caller asked for more than one message on the wake. In the
            # ordinary case -- a peer message and limit=1 -- returning
            # straight away avoids a second NATS request and the drain window
            # before the attention edge is released.
            envelopes += await session.fetch(
                READ_PAGE_MAX - 1, timeout=_WAIT_DRAIN_S)

        candidates = [
            e for e in envelopes
            if _qualifies_as_wake(e, principal_kind, principal_id, exclude_self)
        ]

        if candidates:
            # Re-check grant AFTER fetch: the check before fetch cannot
            # cover a revoke that lands WHILE we were blocked waiting for
            # a message. Without this second check, a revoked caller
            # would receive the first peer message that arrived during
            # their blocked wait. Task #37 correctness case.
            try:
                with store.connect() as conn:
                    _check_grant(conn, room_id, principal_kind, principal_id, "receive")
                    if principal_kind == "agent":
                        candidates = [
                            env
                            for env in candidates
                            if attention.message_wake_authorized(
                                conn,
                                room_id=room_id,
                                envelope=env,
                                agent_id=principal_id,
                            )
                        ]
            except (NoMembershipError, GrantError):
                return {
                    "messages": [],
                    "next_cursor": scan_since,
                    "history_truncated": False,
                    "oldest_available_at": None,
                }
            if candidates:
                trimmed = candidates[:limit]
                out = []
                for env in trimmed:
                    m = {k: v for k, v in env.items() if not k.startswith("_")}
                    m["sequence"] = env["_stream_seq"]
                    out.append(m)
                return {
                    "messages": out,
                    "next_cursor": out[-1]["sequence"],
                    "history_truncated": False,
                    "oldest_available_at": None,
                }

        # No peer messages in this window. If we saw any own-messages,
        # advance the cursor so we don't re-fetch them next iteration.
        if envelopes:
            scan_since = envelopes[-1]["_stream_seq"]
