"""SafeYolo's async NATS client + JetStream helpers for the coord v1
substrate.

Owns the connection to the SafeYolo-managed nats-server (see
nats_runtime for that side). The addon's NATS-unavailable isolation
sits above this module: every NATS operation here that can hit the
network wraps connectivity failures in `NatsUnavailable`, so a
NATS-down blip becomes a coord 503 rather than a proxy 500.

Design decisions (per #371 comment 5421943173 + reviewer feedback):
    - One SafeYolo-owned NATS connection per process. Lazily created
      under a per-loop asyncio.Lock so racing coroutines don't leak
      one of two competing clients (reviewer round-3 point 6).
    - Per-room JetStream stream `ROOM_<room_id>` on subject
      `rooms.<room_id>`. Streams created on demand (idempotent).
      FileStorage + LimitsPolicy + DiscardOld. Finite MaxBytes /
      MaxAge / MaxMsgSize on each stream; the global JetStream
      max_file_store from nats_runtime caps total disk. On existing
      streams the config is verified against the expected contract;
      drift fails loud so a silent stale-config bump can't happen
      (reviewer round-3 point 5).
    - Reads use EPHEMERAL pull consumers with deliver_by_start_sequence.
      The consumer is explicitly deleted after every fetch so
      /messages+/wait traffic does not leave a rolling population of
      server-side consumer resources (reviewer round-3 point 3).
    - Publish uses `Nats-Msg-Id = msg_id` header so an ambiguous
      PubAck can be retried with the same msg_id inside the JetStream
      duplicate window without duplicating the message.
    - Corrupt envelopes are a storage-integrity failure, not an
      expected bad-peer case (SafeYolo is the sole writer). They raise
      `CoordDataError` so the caller sees a 500 instead of a silent
      hole in the room history (reviewer round-3 point 4).

Deliberately NOT here:
    - Grant/membership storage: those stay in coord.store (SQLite).
    - Room registry: also stays in coord.store; this module only
      manages the JetStream stream that backs a given room.
"""

from __future__ import annotations

import asyncio
import contextlib
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
# The API-layer body cap is 256 KiB (MAX_BODY_BYTES). The envelope
# JSON adds ids, timestamps, sender_agent_name, content_type, and
# origin_instance_id on top of that body. A max-sized body must
# still fit through JetStream, so the stream ceiling is set to the
# body cap plus headroom for envelope + Nats-Msg-Id header overhead.
_ROOM_MAX_MSG_SIZE = 320 * 1024
_DEDUP_WINDOW_S = 2 * 60                   # 2 minutes

# Ephemeral fetch defaults; the API layer chooses timeouts explicitly.
_DEFAULT_FETCH_TIMEOUT_S = 5.0


class NatsUnavailable(RuntimeError):
    """SafeYolo's NATS runtime is unreachable. Callers should surface
    this as a coord 503 without failing the containing proxy."""


class CoordDataError(RuntimeError):
    """Persisted JetStream data is not shaped like a coord envelope.

    Since SafeYolo is the sole writer of these subjects, an unshaped
    payload is a storage-integrity failure — the caller should see a
    500, not a silent gap in room history."""


class StreamConfigDrift(RuntimeError):
    """An existing per-room stream's config no longer matches the
    SafeYolo contract. Fails loud instead of silently continuing on
    a stale ceiling (reviewer round-3 point 5)."""


# NATS errors that mean "runtime is unreachable" and should surface as
# NatsUnavailable to the caller. NatsTimeout is intentionally NOT
# in this set at every callsite — an empty pull fetch times out
# legitimately, so callers that treat timeout as "no messages" must
# handle it themselves before calling the wrapper.
_UNAVAILABLE_EXCEPTIONS = (NoServersError, NatsError, OSError)


# ---------- connection lifecycle ----------

# Single connection per process — but nats-py transports are bound to
# the asyncio loop they were opened on. Production has one long-lived
# loop so this reduces to a real singleton; tests using asyncio.run()
# open a fresh loop per call, so we track the owning loop and reconnect
# transparently if it changes. Without this the second asyncio.run()
# call in a test hangs on a dead transport.
_client: nats.aio.client.Client | None = None
_js: Any | None = None
_client_loop: asyncio.AbstractEventLoop | None = None

# Lazily created lock. asyncio.Lock is bound to the loop it was made
# on, so we recreate it whenever the owning loop changes (tests do
# this by using asyncio.run per call; production has one stable loop).
_connect_lock: asyncio.Lock | None = None
_connect_lock_loop: asyncio.AbstractEventLoop | None = None


def _lock_for_current_loop(current_loop: asyncio.AbstractEventLoop) -> asyncio.Lock:
    """Return a lock bound to `current_loop`. Recreate on loop change."""
    global _connect_lock, _connect_lock_loop
    if _connect_lock is None or _connect_lock_loop is not current_loop:
        _connect_lock = asyncio.Lock()
        _connect_lock_loop = current_loop
    return _connect_lock


async def get_jetstream():
    """Return a live JetStream context, connecting lazily on first call.

    Raises NatsUnavailable if the server is unreachable. The caller
    should map this to a coord 503 rather than letting it escape as
    a generic 500.
    """
    global _client, _js, _client_loop
    current_loop = asyncio.get_running_loop()
    # Fast path: already connected on this loop.
    if (
        _client is not None
        and _client_loop is current_loop
        and _client.is_connected
    ):
        return _js
    # Serialize concurrent first-connects so we don't create two live
    # clients and leak the loser (reviewer round-3 point 6).
    lock = _lock_for_current_loop(current_loop)
    async with lock:
        # Recheck under lock: another coro may have connected while we
        # were waiting.
        if (
            _client is not None
            and _client_loop is current_loop
            and _client.is_connected
        ):
            return _js
        if _client is not None and _client_loop is not current_loop:
            # Loop changed — the transport is bound to a loop we can no
            # longer touch. Drop refs; GC cleans up.
            _client = None
            _js = None
        user, password = nats_runtime.client_user_credentials()
        try:
            # Bounded reconnect attempts: `-1` (unlimited) makes the
            # initial connect() loop forever when the server is down,
            # so a coord request during a NATS outage would never
            # surface as NatsUnavailable. A small cap gives nats-py
            # room to ride out a transient blip but still fails fast
            # when the server really isn't there.
            client = await nats.connect(
                nats_runtime.client_url(),
                user=user,
                password=password,
                allow_reconnect=True,
                max_reconnect_attempts=3,
                reconnect_time_wait=0.5,
                connect_timeout=2.0,
                name="safeyolo-coord",
            )
        except _UNAVAILABLE_EXCEPTIONS as e:
            raise NatsUnavailable(f"cannot reach nats-server: {e!s}") from e
        _client = client
        _js = client.jetstream()
        _client_loop = current_loop
        return _js


async def close() -> None:
    """Best-effort teardown. Safe to call multiple times."""
    global _client, _js, _client_loop
    client = _client
    _client = None
    _js = None
    _client_loop = None
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
    global _client, _js, _client_loop, _connect_lock, _connect_lock_loop
    _client = None
    _js = None
    _client_loop = None
    _connect_lock = None
    _connect_lock_loop = None


# ---------- stream naming ----------


def stream_name_for_room(room_id: str) -> str:
    """Per-room stream. Kept distinct from the subject so one bad
    room can't collide with a management topic later."""
    return f"ROOM_{room_id}"


def subject_for_room(room_id: str) -> str:
    return f"rooms.{room_id}"


# ---------- stream management ----------


def _expected_stream_fields() -> dict[str, Any]:
    """The subset of stream config SafeYolo enforces. Compared against
    live streams by ensure_room_stream to catch stale-config drift."""
    return {
        "storage": StorageType.FILE,
        "retention": RetentionPolicy.LIMITS,
        "discard": DiscardPolicy.OLD,
        "max_bytes": _ROOM_MAX_BYTES,
        "max_age": _ROOM_MAX_AGE_S,
        "max_msg_size": _ROOM_MAX_MSG_SIZE,
        "duplicate_window": _DEDUP_WINDOW_S,
    }


def _stream_config_matches(config: Any) -> tuple[bool, dict[str, Any]]:
    """Return (matches, mismatches) for the SafeYolo-enforced subset of
    a live stream's config. `max_age` and `duplicate_window` come back
    from nats-py in nanoseconds on some versions, seconds on others —
    normalize to seconds before comparing."""
    expected = _expected_stream_fields()
    mismatches: dict[str, Any] = {}
    for field, want in expected.items():
        got = getattr(config, field, None)
        # nats-py may hand back timedelta / nanoseconds — coerce.
        if field in {"max_age", "duplicate_window"}:
            if hasattr(got, "total_seconds"):
                got = got.total_seconds()
            elif isinstance(got, int) and got > _ROOM_MAX_AGE_S * 1_000_000:
                got = got // 1_000_000_000  # nanoseconds → seconds
        if got != want:
            mismatches[field] = {"expected": want, "actual": got}
    return (not mismatches, mismatches)


async def ensure_room_stream(room_id: str) -> None:
    """Create the per-room JetStream stream if it does not already
    exist. Idempotent.

    On an existing stream, verifies the config still matches the
    SafeYolo contract and raises `StreamConfigDrift` if a prior version
    of the code (or an operator) left different limits in place.
    """
    js = await get_jetstream()
    name = stream_name_for_room(room_id)
    try:
        info = await js.stream_info(name)
    except NotFoundError:
        info = None
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"stream_info failed: {e!s}") from e

    if info is not None:
        matches, mismatches = _stream_config_matches(info.config)
        if not matches:
            raise StreamConfigDrift(
                f"stream {name!r} config drift; expected/actual: {mismatches}"
            )
        return

    try:
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
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"add_stream failed: {e!s}") from e


async def delete_room_stream(room_id: str) -> bool:
    """Drop a room's stream. Idempotent — returns False if it wasn't
    there. Wrapped so a NATS outage during rollback (create_room
    failing after ensure_room_stream) still surfaces as NatsUnavailable
    rather than a bare NatsError."""
    js = await get_jetstream()
    try:
        await js.delete_stream(stream_name_for_room(room_id))
        return True
    except NotFoundError:
        return False
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"delete_stream failed: {e!s}") from e


async def room_stream_state(room_id: str) -> dict:
    """Read stream state (first_seq, last_seq, messages, bytes) from
    JetStream. Used by the API layer to detect truncation; the
    timestamp for the oldest surviving message is fetched separately
    via oldest_message_ts to keep this call cheap on the read hot path.
    """
    js = await get_jetstream()
    try:
        info = await js.stream_info(stream_name_for_room(room_id))
    except NotFoundError:
        return {"first_seq": 0, "last_seq": 0, "messages": 0}
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"stream_info failed: {e!s}") from e
    state = info.state
    return {
        "first_seq": state.first_seq,
        "last_seq": state.last_seq,
        "messages": state.messages,
    }


async def oldest_message_ts(room_id: str, first_seq: int) -> str | None:
    """Return the ISO-8601 timestamp of the oldest surviving message in
    the room's stream, or None if the stream is empty.

    nats-py's `StreamState` dataclass omits `first_ts`, so we peek the
    first message directly via `get_msg`. Only called when the API
    layer has already detected truncation — read hot path is unaffected.
    A NATS-down error is surfaced as NatsUnavailable so the whole read
    fails cleanly rather than hiding the outage behind a null timestamp.
    """
    if first_seq <= 0:
        return None
    js = await get_jetstream()
    try:
        raw = await js._jsm.get_msg(stream_name_for_room(room_id), seq=first_seq)
    except NotFoundError:
        return None
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"get_msg failed: {e!s}") from e
    if raw.time is None:
        return None
    return raw.time.isoformat()


# ---------- publish ----------


async def publish_envelope(room_id: str, envelope: dict) -> int:
    """Publish one message envelope to a room and return its stream
    sequence.

    Uses `Nats-Msg-Id = envelope['msg_id']` so an ambiguous PubAck
    (network partition, timeout) can be retried with the same msg_id
    inside JetStream's duplicate window without producing a duplicate.
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
    except (NatsTimeout, *_UNAVAILABLE_EXCEPTIONS) as e:
        raise NatsUnavailable(f"publish failed: {e!s}") from e
    return ack.seq


# ---------- fetch ----------


async def _delete_consumer_best_effort(js: Any, stream: str, consumer: str) -> None:
    """Explicitly delete the ephemeral consumer we just used. Swallow
    NotFound (already gone) but surface real NATS errors — a delete
    failure that isn't NotFound means the server-side consumer will
    linger until inactivity cleans it up, which is exactly the leak
    reviewer round-3 point 3 flags."""
    try:
        await js._jsm.delete_consumer(stream, consumer)
    except NotFoundError:
        return
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"delete_consumer failed: {e!s}") from e


async def fetch_since(
    room_id: str,
    since_sequence: int,
    limit: int,
    timeout: float = _DEFAULT_FETCH_TIMEOUT_S,
) -> list[dict]:
    """Fetch up to `limit` envelopes with stream sequence > since_sequence.

    Uses an ephemeral pull consumer. The consumer is explicitly deleted
    on the way out so /messages+/wait traffic does not leave a rolling
    population of server-side consumer resources
    (reviewer round-3 point 3).

    Returns envelopes decoded from JSON with an added `_stream_seq`
    field. Empty list if no messages arrive within `timeout`. A
    persisted payload that is not a JSON object raises `CoordDataError`
    — SafeYolo is the sole writer, so this signals storage corruption.
    """
    js = await get_jetstream()
    stream = stream_name_for_room(room_id)
    start_seq = max(1, since_sequence + 1)
    try:
        psub = await js.pull_subscribe(
            subject_for_room(room_id),
            durable=None,
            stream=stream,
            config=ConsumerConfig(
                deliver_policy=DeliverPolicy.BY_START_SEQUENCE,
                opt_start_seq=start_seq,
            ),
        )
    except NotFoundError:
        return []
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"consumer create failed: {e!s}") from e
    consumer_name = psub._consumer

    try:
        try:
            msgs = await psub.fetch(limit, timeout=timeout)
        except NatsTimeout:
            return []
        except _UNAVAILABLE_EXCEPTIONS as e:
            raise NatsUnavailable(f"fetch failed: {e!s}") from e
        out: list[dict] = []
        for m in msgs:
            try:
                envelope = json.loads(m.data.decode())
            except (ValueError, UnicodeDecodeError) as e:
                # SafeYolo wrote this. Unshaped payload = corruption.
                # ACK first so the consumer moves past this seq, then
                # raise — the caller sees a 500 and the bad message is
                # not silently dropped from the record.
                with contextlib.suppress(Exception):
                    await m.ack()
                raise CoordDataError(
                    f"corrupt envelope at stream {stream} seq "
                    f"{m.metadata.sequence.stream}: {e!s}"
                ) from e
            if not isinstance(envelope, dict) or "msg_id" not in envelope:
                with contextlib.suppress(Exception):
                    await m.ack()
                raise CoordDataError(
                    f"non-envelope payload at stream {stream} seq "
                    f"{m.metadata.sequence.stream}"
                )
            envelope["_stream_seq"] = m.metadata.sequence.stream
            out.append(envelope)
            try:
                await m.ack()
            except _UNAVAILABLE_EXCEPTIONS as e:
                raise NatsUnavailable(f"ack failed: {e!s}") from e
        return out
    finally:
        # unsubscribe() closes our inbox; delete_consumer removes the
        # actual server-side consumer. nats-py's ephemeral consumers
        # rely on inactivity-based cleanup otherwise, which leaks state
        # under high /messages+/wait volume.
        with contextlib.suppress(Exception):
            await psub.unsubscribe()
        await _delete_consumer_best_effort(js, stream, consumer_name)


async def consumer_count(room_id: str) -> int:
    """Server-side consumer count for the room's stream. Used by tests
    to prove that ephemeral consumers are actually cleaned up rather
    than lingering until nats-py's inactivity threshold fires."""
    js = await get_jetstream()
    try:
        info = await js.stream_info(stream_name_for_room(room_id))
    except NotFoundError:
        return 0
    except _UNAVAILABLE_EXCEPTIONS as e:
        raise NatsUnavailable(f"stream_info failed: {e!s}") from e
    return info.state.consumer_count
