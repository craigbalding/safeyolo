"""SafeYolo's async NATS client + JetStream helpers for the coord v1
substrate.

Owns the connection to the SafeYolo-managed nats-server (see
nats_runtime for that side). All operations here assume the runtime
is up; the addon's NATS-unavailable isolation (task #36) sits above
this module and translates errors into coord 503s without breaking
the proxy.

Design decisions (per #371 comment 5421943173 + reviewer feedback):
    - One SafeYolo-owned NATS connection per process, opened lazily
      on first use and reused. nats-py handles reconnect internally;
      we surface connectivity as a `NatsUnavailable` exception when
      the client fails to reach the server.
    - Per-room JetStream stream `ROOM_<room_id>` on subject
      `rooms.<room_id>`. Streams created on demand (idempotent).
      FileStorage + LimitsPolicy + DiscardOld. Finite MaxBytes /
      MaxAge / MaxMsgSize on each stream; the global JetStream
      max_file_store from nats_runtime caps total disk.
    - Reads use EPHEMERAL pull consumers with deliver_by_start_sequence.
      Reviewer point 4: matches stage 0's caller-owned cursor contract
      exactly — no durable per-participant state means no server-side
      semantic changes to the API.
    - Publish uses `Nats-Msg-Id = msg_id` header so an ambiguous
      PubAck can be retried with the same msg_id inside the JetStream
      duplicate window without duplicating the message (reviewer
      point 7).

Deliberately NOT here:
    - Grant/membership storage: those stay in coord.store (SQLite).
    - Room registry: also stays in coord.store; this module only
      manages the JetStream stream that backs a given room.
"""

from __future__ import annotations

import json
from typing import Any

import nats
from nats.errors import Error as NatsError
from nats.errors import NoServersError
from nats.errors import TimeoutError as NatsTimeout
from nats.js.api import (
    ConsumerConfig,
    DeliverPolicy,
    DiscardPolicy,
    RetentionPolicy,
    StorageType,
)
from nats.js.errors import NotFoundError

from . import nats_runtime

# Per-room bounds. The global account cap from nats_runtime
# (JETSTREAM_MAX_FILE_STORE) caps everything above; these caps stop
# one hyperactive room from taking more than its share.
_ROOM_MAX_BYTES = 100 * 1024 * 1024        # 100 MiB
_ROOM_MAX_AGE_S = 7 * 24 * 60 * 60         # 7 days (nats-py takes seconds)
_ROOM_MAX_MSG_SIZE = 256 * 1024            # matches coord.api MAX_BODY_BYTES
_DEDUP_WINDOW_S = 2 * 60                   # 2 minutes

# Ephemeral fetch defaults; the API layer chooses timeouts explicitly.
_DEFAULT_FETCH_TIMEOUT_S = 5.0


class NatsUnavailable(RuntimeError):
    """SafeYolo's NATS runtime is unreachable. Callers should surface
    this as a coord 503 without failing the containing proxy."""


# ---------- connection lifecycle ----------

# Single connection per process. Lazily created; nats-py handles the
# reconnect loop internally so we don't reopen from scratch on every
# transient blip. No asyncio.Lock here on purpose: an asyncio.Lock is
# bound to the event loop it's used on, and tests recreate the loop per
# case which would leak lock state across tests. Race on connect is a
# non-issue in the single-loop production case; if two coros do race a
# first connect, one wins and the other's client is superseded.
_client: nats.aio.client.Client | None = None
_js: Any | None = None


async def get_jetstream():
    """Return a live JetStream context, connecting lazily on first call.

    Raises NatsUnavailable if the server is unreachable. The caller
    should map this to a coord 503 (task #36) rather than letting it
    escape as a generic 500.
    """
    global _client, _js
    if _client is not None and _client.is_connected:
        return _js
    user, password = nats_runtime.client_user_credentials()
    try:
        client = await nats.connect(
            nats_runtime.client_url(),
            user=user,
            password=password,
            allow_reconnect=True,
            max_reconnect_attempts=-1,
            reconnect_time_wait=0.5,
            connect_timeout=2.0,
            name="safeyolo-coord",
        )
    except (NoServersError, NatsError, OSError) as e:
        raise NatsUnavailable(f"cannot reach nats-server: {e!s}") from e
    _client = client
    _js = client.jetstream()
    return _js


async def close() -> None:
    """Best-effort teardown. Safe to call multiple times."""
    global _client, _js
    client = _client
    _client = None
    _js = None
    if client is not None:
        try:
            await client.close()
        except Exception:  # noqa: BLE001, S110
            pass  # best-effort teardown; explicit swallow


def reset_for_tests() -> None:
    """Sync reset of module state. For test fixtures that recreate the
    event loop per test — the async close() runs on the wrong loop and
    stale state leaks across tests. This just drops the references;
    the previous connection's transport will be garbage collected."""
    global _client, _js
    _client = None
    _js = None


# ---------- stream naming ----------


def stream_name_for_room(room_id: str) -> str:
    """Per-room stream. Kept distinct from the subject so one bad
    room can't collide with a management topic later."""
    return f"ROOM_{room_id}"


def subject_for_room(room_id: str) -> str:
    return f"rooms.{room_id}"


# ---------- stream management ----------


async def ensure_room_stream(room_id: str) -> None:
    """Create the per-room JetStream stream if it does not already
    exist. Idempotent.
    """
    js = await get_jetstream()
    name = stream_name_for_room(room_id)
    try:
        await js.stream_info(name)
        return  # already exists
    except NotFoundError:
        pass
    await js.add_stream(
        name=name,
        subjects=[subject_for_room(room_id)],
        storage=StorageType.FILE,
        retention=RetentionPolicy.LIMITS,
        discard=DiscardPolicy.OLD,
        max_bytes=_ROOM_MAX_BYTES,
        max_age=_ROOM_MAX_AGE_S,
        max_msg_size=_ROOM_MAX_MSG_SIZE,
        duplicate_window=_DEDUP_WINDOW_S,
        num_replicas=1,
    )


async def delete_room_stream(room_id: str) -> bool:
    """Drop a room's stream. Idempotent — returns False if it wasn't
    there. Not currently exercised in v1 (no room-removal command),
    but included for symmetry + future cleanup."""
    js = await get_jetstream()
    try:
        await js.delete_stream(stream_name_for_room(room_id))
        return True
    except NotFoundError:
        return False


async def room_stream_state(room_id: str) -> dict:
    """Read stream state (first_seq, last_seq, messages, bytes, etc.)
    from JetStream. Used by the API layer to populate
    `history_truncated` / `oldest_available_at` (task #35).
    """
    js = await get_jetstream()
    try:
        info = await js.stream_info(stream_name_for_room(room_id))
    except NotFoundError:
        return {"first_seq": 0, "last_seq": 0, "messages": 0, "first_ts": None}
    state = info.state
    return {
        "first_seq": state.first_seq,
        "last_seq": state.last_seq,
        "messages": state.messages,
        # first_ts is a datetime; ISO-format for consumer-side rendering.
        # None if the stream is empty.
        "first_ts": state.first_ts.isoformat() if state.first_ts else None,
    }


# ---------- publish ----------


async def publish_envelope(room_id: str, envelope: dict) -> int:
    """Publish one message envelope to a room and return its stream
    sequence.

    Uses `Nats-Msg-Id = envelope['msg_id']` so an ambiguous PubAck
    (network partition, timeout) can be retried with the same msg_id
    inside JetStream's duplicate window without producing a duplicate
    message (reviewer point 7).
    """
    js = await get_jetstream()
    body = json.dumps(envelope).encode()
    try:
        ack = await js.publish(
            subject_for_room(room_id),
            body,
            stream=stream_name_for_room(room_id),
            headers={"Nats-Msg-Id": envelope["msg_id"]},
        )
    except (NoServersError, NatsTimeout, NatsError, OSError) as e:
        raise NatsUnavailable(f"publish failed: {e!s}") from e
    return ack.seq


# ---------- fetch ----------


async def fetch_since(
    room_id: str,
    since_sequence: int,
    limit: int,
    timeout: float = _DEFAULT_FETCH_TIMEOUT_S,
) -> list[dict]:
    """Fetch up to `limit` envelopes with stream sequence > since_sequence.

    Uses an ephemeral pull consumer (reviewer point 4: no durable
    per-participant state). Returns envelopes decoded from JSON with an
    added `_stream_seq` field. Empty list if no messages arrive within
    `timeout`.
    """
    js = await get_jetstream()
    start_seq = max(1, since_sequence + 1)
    try:
        psub = await js.pull_subscribe(
            subject_for_room(room_id),
            durable=None,
            stream=stream_name_for_room(room_id),
            config=ConsumerConfig(
                deliver_policy=DeliverPolicy.BY_START_SEQUENCE,
                opt_start_seq=start_seq,
            ),
        )
    except NotFoundError:
        return []
    except (NoServersError, NatsError, OSError) as e:
        raise NatsUnavailable(f"consumer create failed: {e!s}") from e
    try:
        try:
            msgs = await psub.fetch(limit, timeout=timeout)
        except NatsTimeout:
            return []
        out: list[dict] = []
        for m in msgs:
            try:
                envelope = json.loads(m.data.decode())
            except (ValueError, UnicodeDecodeError):
                await m.ack()   # skip corrupt, don't stall the consumer
                continue
            envelope["_stream_seq"] = m.metadata.sequence.stream
            out.append(envelope)
            await m.ack()
        return out
    finally:
        try:
            await psub.unsubscribe()
        except Exception:  # noqa: BLE001, S110
            pass  # best-effort teardown; explicit swallow
