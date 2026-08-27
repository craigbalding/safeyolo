"""Durable targeted-attention feed and JetStream recovery projection."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from safeyolo.agents_store import load_all_agents

from . import nats_client, store
from .identity import new_attention_id

log = logging.getLogger("safeyolo.coord.attention")

MANIFEST_VERSION = 1
MAX_FEED_PAGE = 200
RECOVERY_PAGE = 200
WAIT_HINT_WINDOW_S = 30.0

_ATTENTION_ID_RE = re.compile(r"^attn-[0-9a-f]{32}$")
_AGENT_ID_RE = re.compile(r"^ag-[A-Za-z0-9_-]+$")
_MANIFEST_MODES = frozenset({"none", "room", "agents", "legacy_room"})


class AttentionTargetError(ValueError):
    """A requested target is not an eligible room recipient."""


class AttentionObjectNotFound(LookupError):
    """An attention edge is absent or not authorized for this caller."""


class _NotifyOmitted:
    pass


NOTIFY_OMITTED = _NotifyOmitted()


@dataclass(frozen=True)
class RecipientIntent:
    attention_id: str
    agent_id: str
    membership_granted_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "attention_id": self.attention_id,
            "agent_id": self.agent_id,
            "membership_granted_at": self.membership_granted_at,
        }


@dataclass(frozen=True)
class AttentionManifest:
    msg_id: str
    mode: str
    recipients: tuple[RecipientIntent, ...]
    version: int = MANIFEST_VERSION

    def to_header(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "msg_id": self.msg_id,
                "mode": self.mode,
                "recipients": [recipient.to_dict() for recipient in self.recipients],
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _active_receive_generations(
    conn: sqlite3.Connection,
    room_id: str,
) -> dict[str, int]:
    rows = conn.execute(
        """WITH latest AS (
               SELECT principal_id, MAX(granted_at) AS granted_at
               FROM memberships
               WHERE room_id = ? AND principal_kind = 'agent'
                 AND revoked_at IS NULL
               GROUP BY principal_id
           )
           SELECT m.principal_id, m.granted_at, m.permissions
           FROM memberships AS m
           JOIN latest AS l
             ON l.principal_id = m.principal_id
            AND l.granted_at = m.granted_at
           WHERE m.room_id = ? AND m.principal_kind = 'agent'
             AND m.revoked_at IS NULL""",
        (room_id, room_id),
    ).fetchall()
    return {
        row["principal_id"]: row["granted_at"]
        for row in rows
        if "receive" in row["permissions"].split(",")
    }


def _normalize_notify(notify: Any) -> tuple[str, list[str]]:
    if notify is NOTIFY_OMITTED:
        return "legacy_room", []
    if isinstance(notify, str):
        if notify not in {"none", "room"}:
            raise ValueError("notify must be 'none', 'room', or a list of agent names")
        return notify, []
    if not isinstance(notify, list):
        raise ValueError("notify must be 'none', 'room', or a list of agent names")
    names: list[str] = []
    seen: set[str] = set()
    for value in notify:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("notify target names must be non-empty strings")
        if value not in seen:
            seen.add(value)
            names.append(value)
    return ("agents" if names else "none"), names


def build_message_manifest(
    conn: sqlite3.Connection,
    *,
    room_id: str,
    msg_id: str,
    sender_agent_id: str | None,
    notify: Any,
) -> AttentionManifest:
    """Resolve public notify intent to exact durable membership generations."""
    mode, target_names = _normalize_notify(notify)
    eligible = _active_receive_generations(conn, room_id)

    if mode in {"room", "legacy_room"}:
        target_ids = sorted(
            agent_id
            for agent_id in eligible
            if agent_id != sender_agent_id
        )
    elif mode == "agents":
        agents = load_all_agents()
        name_to_id = {
            name: str(metadata["agent_id"])
            for name, metadata in agents.items()
            if isinstance(metadata, dict) and metadata.get("agent_id")
        }
        target_ids = []
        seen_ids: set[str] = set()
        for name in target_names:
            agent_id = name_to_id.get(name)
            if agent_id is None or agent_id not in eligible:
                raise AttentionTargetError(
                    "one or more notify targets are not active room members"
                )
            if agent_id not in seen_ids:
                seen_ids.add(agent_id)
                target_ids.append(agent_id)
    else:
        target_ids = []

    return AttentionManifest(
        msg_id=msg_id,
        mode=mode,
        recipients=tuple(
            RecipientIntent(
                attention_id=new_attention_id(),
                agent_id=agent_id,
                membership_granted_at=eligible[agent_id],
            )
            for agent_id in target_ids
        ),
    )


def parse_manifest(header: str, *, expected_msg_id: str) -> AttentionManifest:
    """Strictly validate persisted Stage-1 intent; corruption fails loud."""
    try:
        value = json.loads(header)
    except (TypeError, ValueError) as exc:
        raise nats_client.CoordDataError("corrupt Stage-1 attention manifest") from exc
    if not isinstance(value, dict) or set(value) != {
        "version",
        "msg_id",
        "mode",
        "recipients",
    }:
        raise nats_client.CoordDataError("malformed Stage-1 attention manifest")
    if type(value["version"]) is not int or value["version"] != MANIFEST_VERSION:
        raise nats_client.CoordDataError("unsupported Stage-1 attention manifest version")
    if value["msg_id"] != expected_msg_id:
        raise nats_client.CoordDataError("attention manifest msg_id mismatch")
    if value["mode"] not in _MANIFEST_MODES:
        raise nats_client.CoordDataError("invalid Stage-1 attention mode")
    raw_recipients = value["recipients"]
    if not isinstance(raw_recipients, list):
        raise nats_client.CoordDataError("invalid Stage-1 attention recipients")

    recipients: list[RecipientIntent] = []
    attention_ids: set[str] = set()
    generations: set[tuple[str, int]] = set()
    for raw in raw_recipients:
        if not isinstance(raw, dict) or set(raw) != {
            "attention_id",
            "agent_id",
            "membership_granted_at",
        }:
            raise nats_client.CoordDataError("malformed Stage-1 attention recipient")
        attention_id = raw["attention_id"]
        agent_id = raw["agent_id"]
        granted_at = raw["membership_granted_at"]
        if not isinstance(attention_id, str) or not _ATTENTION_ID_RE.fullmatch(
            attention_id
        ):
            raise nats_client.CoordDataError("invalid Stage-1 attention_id")
        if not isinstance(agent_id, str) or not _AGENT_ID_RE.fullmatch(agent_id):
            raise nats_client.CoordDataError("invalid Stage-1 recipient agent_id")
        if type(granted_at) is not int or granted_at < 0:
            raise nats_client.CoordDataError(
                "invalid Stage-1 membership generation"
            )
        generation = (agent_id, granted_at)
        if attention_id in attention_ids or generation in generations:
            raise nats_client.CoordDataError("duplicate Stage-1 attention recipient")
        attention_ids.add(attention_id)
        generations.add(generation)
        recipients.append(
            RecipientIntent(
                attention_id=attention_id,
                agent_id=agent_id,
                membership_granted_at=granted_at,
            )
        )
    if value["mode"] == "none" and recipients:
        raise nats_client.CoordDataError("notify=none manifest has recipients")
    if value["mode"] == "agents" and not recipients:
        raise nats_client.CoordDataError("targeted manifest has no recipients")
    return AttentionManifest(
        msg_id=expected_msg_id,
        mode=value["mode"],
        recipients=tuple(recipients),
        version=value["version"],
    )


def manifest_for_envelope(envelope: dict) -> AttentionManifest | None:
    header = envelope.get("_attention_manifest_header")
    if header is None:
        return None
    if not isinstance(header, str):
        raise nats_client.CoordDataError("invalid Stage-1 attention header type")
    return parse_manifest(header, expected_msg_id=envelope.get("msg_id"))


def _edge_values(row: sqlite3.Row) -> tuple[Any, ...]:
    return (
        row["recipient_agent_id"],
        row["attention_id"],
        row["room_id"],
        row["kind"],
        row["object_id"],
        row["revision_or_sequence"],
        row["membership_granted_at"],
    )


def _materialize_recipient(
    conn: sqlite3.Connection,
    *,
    room_id: str,
    envelope: dict,
    recipient: RecipientIntent,
) -> None:
    sequence = int(envelope["_stream_seq"])
    logical = conn.execute(
        """SELECT * FROM coord_attention_edges
           WHERE recipient_agent_id = ? AND kind = 'message'
             AND object_id = ? AND membership_granted_at = ?""",
        (recipient.agent_id, envelope["msg_id"], recipient.membership_granted_at),
    ).fetchone()
    by_id = conn.execute(
        "SELECT * FROM coord_attention_edges WHERE attention_id = ?",
        (recipient.attention_id,),
    ).fetchone()
    expected = (
        recipient.agent_id,
        recipient.attention_id,
        room_id,
        "message",
        envelope["msg_id"],
        sequence,
        recipient.membership_granted_at,
    )
    if logical is not None or by_id is not None:
        if logical is None or by_id is None or _edge_values(logical) != expected:
            raise nats_client.CoordDataError("conflicting logical attention edge")
        return

    conn.execute(
        """INSERT OR IGNORE INTO coord_attention_feeds
           (recipient_agent_id, last_sequence) VALUES (?, 0)""",
        (recipient.agent_id,),
    )
    feed_sequence = conn.execute(
        """SELECT last_sequence + 1 FROM coord_attention_feeds
           WHERE recipient_agent_id = ?""",
        (recipient.agent_id,),
    ).fetchone()[0]
    conn.execute(
        """UPDATE coord_attention_feeds SET last_sequence = ?
           WHERE recipient_agent_id = ?""",
        (feed_sequence, recipient.agent_id),
    )
    conn.execute(
        """INSERT INTO coord_attention_edges
           (recipient_agent_id, feed_sequence, attention_id, room_id, kind,
            object_id, revision_or_sequence, membership_granted_at, created_at)
           VALUES (?, ?, ?, ?, 'message', ?, ?, ?, ?)""",
        (
            recipient.agent_id,
            feed_sequence,
            recipient.attention_id,
            room_id,
            envelope["msg_id"],
            sequence,
            recipient.membership_granted_at,
            int(envelope["sent_at"]),
        ),
    )
    from .outbox import enqueue_attention_hint

    enqueue_attention_hint(
        conn,
        attention_id=recipient.attention_id,
        recipient_agent_id=recipient.agent_id,
        feed_sequence=feed_sequence,
    )


async def ensure_room_projection(room_id: str) -> int:
    """Create the pre-Stage-1 recovery frontier before message publication."""
    with store.connect() as conn:
        row = conn.execute(
            """SELECT last_sequence FROM coord_message_attention_projection
               WHERE room_id = ?""",
            (room_id,),
        ).fetchone()
    if row is not None:
        return int(row[0])
    state = await nats_client.room_stream_state(room_id)
    # Anything already below the retained floor predates Stage 1: every
    # Stage-1 sender calls this initializer before publishing its manifest.
    baseline = max(0, state["first_seq"] - 1)
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT OR IGNORE INTO coord_message_attention_projection
               (room_id, last_sequence, updated_at) VALUES (?, ?, ?)""",
            (room_id, baseline, store.now_ms()),
        )
        row = conn.execute(
            """SELECT last_sequence FROM coord_message_attention_projection
               WHERE room_id = ?""",
            (room_id,),
        ).fetchone()
        conn.execute("COMMIT")
    return int(row[0])


async def materialize_room_attention(
    room_id: str,
    *,
    through_sequence: int | None = None,
    max_messages: int | None = None,
) -> int:
    """Advance one room's contiguous message-attention projection."""
    watermark = await ensure_room_projection(room_id)
    state = await nats_client.room_stream_state(room_id)
    target = state["last_seq"] if through_sequence is None else through_sequence
    if target <= watermark:
        return watermark
    if state["first_seq"] > watermark + 1:
        raise nats_client.CoordDataError(
            "message-attention projection has a non-contiguous retention gap"
        )

    processed = 0
    while watermark < target:
        if max_messages is not None and processed >= max_messages:
            break
        page_limit = min(RECOVERY_PAGE, target - watermark)
        if max_messages is not None:
            page_limit = min(page_limit, max_messages - processed)
        envelopes = await nats_client.fetch_since(
            room_id,
            watermark,
            page_limit,
            timeout=0.5,
        )
        if not envelopes:
            raise nats_client.CoordDataError(
                "message-attention projection could not read its next sequence"
            )
        expected = watermark + 1
        manifests: list[AttentionManifest | None] = []
        for envelope in envelopes:
            if envelope.get("_stream_seq") != expected:
                raise nats_client.CoordDataError(
                    "message-attention projection encountered a sequence gap"
                )
            manifests.append(manifest_for_envelope(envelope))
            expected += 1

        with store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                """SELECT last_sequence
                   FROM coord_message_attention_projection
                   WHERE room_id = ?""",
                (room_id,),
            ).fetchone()[0]
            if current != watermark:
                conn.execute("ROLLBACK")
                watermark = int(current)
                continue
            try:
                for envelope, manifest in zip(envelopes, manifests, strict=True):
                    if manifest is not None:
                        for recipient in manifest.recipients:
                            _materialize_recipient(
                                conn,
                                room_id=room_id,
                                envelope=envelope,
                                recipient=recipient,
                            )
                new_watermark = int(envelopes[-1]["_stream_seq"])
                conn.execute(
                    """UPDATE coord_message_attention_projection
                       SET last_sequence = ?, updated_at = ?
                       WHERE room_id = ? AND last_sequence = ?""",
                    (new_watermark, store.now_ms(), room_id, watermark),
                )
                conn.execute("COMMIT")
            except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
                conn.execute("ROLLBACK")
                raise nats_client.CoordDataError(
                    "attention materialization violated its SQLite invariant"
                ) from exc
        processed += len(envelopes)
        watermark = new_watermark
    return watermark


def _authorized_room_ids(agent_id: str) -> list[str]:
    with store.connect() as conn:
        rows = conn.execute(
            """WITH latest AS (
                   SELECT room_id, MAX(granted_at) AS granted_at
                   FROM memberships
                   WHERE principal_kind = 'agent' AND principal_id = ?
                     AND revoked_at IS NULL
                   GROUP BY room_id
               )
               SELECT m.room_id, m.permissions
               FROM memberships AS m
               JOIN latest AS l
                 ON l.room_id = m.room_id AND l.granted_at = m.granted_at
               WHERE m.principal_kind = 'agent' AND m.principal_id = ?
                 AND m.revoked_at IS NULL
               ORDER BY m.room_id""",
            (agent_id, agent_id),
        ).fetchall()
    return [
        row["room_id"]
        for row in rows
        if "receive" in row["permissions"].split(",")
    ]


async def recover_attention_for_agent(agent_id: str) -> None:
    for room_id in _authorized_room_ids(agent_id):
        await materialize_room_attention(room_id)


async def recover_all_attention() -> None:
    with store.connect() as conn:
        room_ids = [
            row[0] for row in conn.execute("SELECT room_id FROM rooms ORDER BY room_id")
        ]
    for room_id in room_ids:
        await materialize_room_attention(room_id)


def _edge_is_authorized(conn: sqlite3.Connection, row: sqlite3.Row) -> bool:
    grant = conn.execute(
        """SELECT granted_at, permissions FROM memberships
           WHERE room_id = ? AND principal_kind = 'agent'
             AND principal_id = ? AND revoked_at IS NULL
           ORDER BY granted_at DESC LIMIT 1""",
        (
            row["room_id"],
            row["recipient_agent_id"],
        ),
    ).fetchone()
    return (
        grant is not None
        and grant["granted_at"] == row["membership_granted_at"]
        and "receive" in grant["permissions"].split(",")
    )


def message_wake_authorized(
    conn: sqlite3.Connection,
    *,
    room_id: str,
    envelope: dict,
    agent_id: str,
) -> bool:
    """Apply Stage-1 targeting and exact-grant checks to a legacy wait."""
    manifest = manifest_for_envelope(envelope)
    if manifest is None or manifest.mode == "legacy_room":
        return True
    recipient = next(
        (item for item in manifest.recipients if item.agent_id == agent_id),
        None,
    )
    if recipient is None:
        return False
    grant = conn.execute(
        """SELECT granted_at, permissions FROM memberships
           WHERE room_id = ? AND principal_kind = 'agent'
             AND principal_id = ? AND revoked_at IS NULL
           ORDER BY granted_at DESC LIMIT 1""",
        (room_id, agent_id),
    ).fetchone()
    return (
        grant is not None
        and grant["granted_at"] == recipient.membership_granted_at
        and "receive" in grant["permissions"].split(",")
    )


def read_feed(agent_id: str, since_sequence: int, limit: int) -> dict[str, Any]:
    if type(since_sequence) is not int or since_sequence < 0:
        raise ValueError("attention cursor must be a non-negative integer")
    limit = max(1, min(limit, MAX_FEED_PAGE))
    with store.connect() as conn:
        highwater_row = conn.execute(
            """SELECT last_sequence FROM coord_attention_feeds
               WHERE recipient_agent_id = ?""",
            (agent_id,),
        ).fetchone()
        highwater = int(highwater_row[0]) if highwater_row is not None else 0
        rows = conn.execute(
            """SELECT e.* FROM coord_attention_edges AS e
               JOIN memberships AS m
                 ON m.room_id = e.room_id
                AND m.principal_kind = 'agent'
                AND m.principal_id = e.recipient_agent_id
                AND m.granted_at = e.membership_granted_at
                AND m.revoked_at IS NULL
               WHERE e.recipient_agent_id = ? AND e.feed_sequence > ?
                 AND instr(',' || m.permissions || ',', ',receive,') > 0
                 AND NOT EXISTS (
                     SELECT 1 FROM memberships AS newer
                     WHERE newer.room_id = m.room_id
                       AND newer.principal_kind = 'agent'
                       AND newer.principal_id = m.principal_id
                       AND newer.revoked_at IS NULL
                       AND newer.granted_at > m.granted_at
                 )
               ORDER BY e.feed_sequence LIMIT ?""",
            (agent_id, since_sequence, limit),
        ).fetchall()
        returned = [row for row in rows if _edge_is_authorized(conn, row)]
        if returned and len(returned) == limit:
            next_cursor = int(returned[-1]["feed_sequence"])
        else:
            # A caller-owned cursor is monotonic even if the caller supplied
            # a value ahead of the current allocator high-watermark.
            next_cursor = max(since_sequence, highwater)
    return {
        "edges": [
            {
                "attention_id": row["attention_id"],
                "room_id": row["room_id"],
                "kind": row["kind"],
                "object_id": row["object_id"],
                "revision_or_sequence": row["revision_or_sequence"],
            }
            for row in returned
        ],
        "next_cursor": next_cursor,
    }


async def wait_for_attention(
    agent_id: str,
    *,
    since_sequence: int,
    timeout_seconds: float,
    limit: int,
    fetch_window_seconds: float = WAIT_HINT_WINDOW_S,
) -> dict[str, Any]:
    """Wait on one identity-derived feed without consuming server-side state."""
    await recover_attention_for_agent(agent_id)
    page = read_feed(agent_id, since_sequence, limit)
    if page["edges"] or page["next_cursor"] != since_sequence:
        return page

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    async with nats_client.attention_subscription(agent_id) as subscription:
        # Ledger-after-subscribe closes the query/subscribe race.
        page = read_feed(agent_id, since_sequence, limit)
        if page["edges"] or page["next_cursor"] != since_sequence:
            return page
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return page
            await subscription.wait(min(fetch_window_seconds, remaining))
            # A PubAck can be followed by a failed SQLite projection, in
            # which case no wake hint exists yet. Periodically replay the
            # durable JetStream intent while the long-poll is outstanding.
            await recover_attention_for_agent(agent_id)
            page = read_feed(agent_id, since_sequence, limit)
            if page["edges"] or page["next_cursor"] != since_sequence:
                return page


def _public_message(envelope: dict) -> dict[str, Any]:
    message = {key: value for key, value in envelope.items() if not key.startswith("_")}
    message["sequence"] = envelope["_stream_seq"]
    return message


async def read_attention_object(agent_id: str, attention_id: str) -> dict[str, Any]:
    """Read the canonical object referenced by one authorized edge."""
    with store.connect() as conn:
        row = conn.execute(
            """SELECT * FROM coord_attention_edges
               WHERE recipient_agent_id = ? AND attention_id = ?""",
            (agent_id, attention_id),
        ).fetchone()
        if row is None or not _edge_is_authorized(conn, row):
            raise AttentionObjectNotFound(attention_id)
        edge = dict(row)
    if edge["kind"] != "message":
        raise nats_client.CoordDataError("unsupported canonical attention kind")
    envelope = await nats_client.get_envelope_at(
        edge["room_id"], edge["revision_or_sequence"]
    )
    if envelope.get("msg_id") != edge["object_id"]:
        raise nats_client.CoordDataError("attention edge canonical object mismatch")
    manifest = manifest_for_envelope(envelope)
    if manifest is None or not any(
        recipient.attention_id == attention_id
        and recipient.agent_id == agent_id
        and recipient.membership_granted_at == edge["membership_granted_at"]
        for recipient in manifest.recipients
    ):
        raise nats_client.CoordDataError("attention edge manifest mismatch")
    with store.connect() as conn:
        row = conn.execute(
            """SELECT * FROM coord_attention_edges
               WHERE recipient_agent_id = ? AND attention_id = ?""",
            (agent_id, attention_id),
        ).fetchone()
        if row is None or not _edge_is_authorized(conn, row):
            raise AttentionObjectNotFound(attention_id)
    return {
        "edge": {
            "attention_id": edge["attention_id"],
            "room_id": edge["room_id"],
            "kind": edge["kind"],
            "object_id": edge["object_id"],
            "revision_or_sequence": edge["revision_or_sequence"],
        },
        "object": _public_message(envelope),
    }
