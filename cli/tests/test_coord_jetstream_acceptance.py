"""Reviewer-mandated acceptance tests for the coord JetStream substrate.

Six invariants the reviewer called out on the stage-1 handoff. These sit
above the unit tests in test_coord_v0.py — they verify substrate
properties (durability, retention reporting, per-room isolation, auth,
availability isolation, mid-flight revoke) rather than the API surface.

Each test starts a real nats-server, so they are slower than unit tests
by design. Marked with sensible timeouts so a hung fetch fails loudly
rather than sitting on the runner.
"""

from __future__ import annotations

import asyncio

import nats
import pytest
from nats.errors import Error as NatsError
from nats.errors import NoServersError

from safeyolo.coord import api, nats_client
from safeyolo.coord import nats_runtime as nr


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def coord_env(nats_env):
    """Isolated coord dir + running NATS + reset client state.

    Same pattern as test_coord_v0.coord_env — nats_env (from conftest.py)
    isolates SAFEYOLO_COORD_DATA_DIR and symlinks the cached binary; we
    start the server and reset the module-level nats-py client so a
    stale connection from a prior test cannot leak in."""
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    return nats_env


AGENT_A = "ag-aaaa000000000000000000000000aaaa"
AGENT_B = "ag-bbbb000000000000000000000000bbbb"


# ---------- 1. Durability across nats-server restart ----------


@pytest.mark.timeout(30)
def test_publish_then_restart_message_survives(coord_env):
    """A PubAck'd message must survive a full nats-server stop+start.

    JetStream FileStorage — the whole reason we picked it over pure NATS
    core — should replay the message from disk on reboot. Reviewer point:
    if this fails, the substrate isn't durable and stage-1 has bought
    nothing over stage-0's SQLite.
    """
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    r = _run(api.send("r", "agent", AGENT_A, "durable"))
    seq_before = r["sequence"]

    # Full restart: stop the server, drop the client (fresh loop will
    # reconnect on next call anyway), start the server back up.
    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)

    page = _run(api.read_room("r", "agent", AGENT_B))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "durable"
    assert page["messages"][0]["sequence"] == seq_before


@pytest.mark.timeout(30)
def test_safeyolo_stop_start_lifecycle_preserves_messages(coord_env):
    """Reviewer round-4 acceptance: exercise the coord lifecycle
    exactly the way `safeyolo stop`/`safeyolo start` do (via the
    _stop_coord_best_effort / _start_coord_best_effort helpers, not
    raw nats_runtime calls). Confirms the issue's specific acceptance
    signal — restarting SafeYolo does not lose accepted messages —
    routes through the same code path the operator hits."""
    from safeyolo.commands.lifecycle import (
        _start_coord_best_effort,
        _stop_coord_best_effort,
    )

    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    r = _run(api.send("r", "agent", AGENT_A, "safeyolo restart survivor"))
    seq_before = r["sequence"]

    # Simulate `safeyolo stop` / `safeyolo start` — same helpers the
    # CLI invokes. The wrappers eat exceptions and log, so a real
    # stop/start on a healthy install is a no-throw round-trip.
    _stop_coord_best_effort()
    nats_client.reset_for_tests()
    _start_coord_best_effort()

    page = _run(api.read_room("r", "agent", AGENT_B))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "safeyolo restart survivor"
    assert page["messages"][0]["sequence"] == seq_before


@pytest.mark.timeout(30)
def test_instance_id_minted_at_safeyolo_start(nats_env):
    """Reviewer round-6 point 4: #371 says safeyolo_instance_id is
    generated on first `safeyolo start`, not lazily on first coord
    API request. Verify _start_coord_best_effort mints the ID
    itself so `safeyolo status` can display it immediately after
    startup — without waiting for an agent to poke coord."""
    from safeyolo.commands.lifecycle import (
        _start_coord_best_effort,
        _stop_coord_best_effort,
    )
    from safeyolo.coord.identity import instance_id_file

    nats_client.reset_for_tests()

    # Pre-start: no instance_id file exists (nats_env just wrote the
    # binary + isolated coord dir).
    assert not instance_id_file().exists()

    try:
        _start_coord_best_effort()
        # Post-start: instance_id file exists and has a valid ID.
        path = instance_id_file()
        assert path.exists(), \
            "safeyolo start must mint instance_id eagerly, not lazily"
        content = path.read_text().strip()
        assert content.startswith("sy-"), f"malformed instance_id: {content!r}"
    finally:
        _stop_coord_best_effort()


# ---------- 2. Retention truncation is reported to the caller ----------


@pytest.mark.timeout(30)
def test_retention_truncation_surfaces_history_flags(coord_env):
    """When the per-room retention cap discards old messages, a read that
    starts from a sequence older than the surviving floor must set
    `history_truncated=True` AND populate `oldest_available_at`.

    We shrink the room's stream to `max_msgs=3` after creation so a small
    number of publishes is enough to force truncation — no need to fill
    100 MiB per test.
    """
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)

    async def shrink():
        js = await nats_client.get_jetstream()
        room_id = api.list_rooms()[0]["room_id"]
        # Cap at 3 messages. DiscardOld matches the runtime default.
        await js.update_stream(
            name=nats_client.stream_name_for_room(room_id),
            subjects=[nats_client.subject_for_room(room_id)],
            max_msgs=3,
        )
    _run(shrink())

    # Send 6; only the last 3 survive.
    for i in range(6):
        _run(api.send("r", "agent", AGENT_A, f"m{i}"))

    page = _run(api.read_room("r", "agent", AGENT_A, since_sequence=0))
    bodies = [m["body"] for m in page["messages"]]
    assert bodies == ["m3", "m4", "m5"]
    assert page["history_truncated"] is True, \
        "retention discarded older messages; caller must be told"
    assert page["oldest_available_at"] is not None, \
        "history_truncated=True requires oldest_available_at populated"


# ---------- 3. Cross-room isolation ----------


@pytest.mark.timeout(30)
def test_cross_room_isolation_hyperactive_room_does_not_starve_peer(coord_env):
    """Reviewer point 3: room A hitting its own retention cap must not
    hollow out room B. Per-room max_bytes/max_msgs contain the blast
    radius so one noisy room cannot destroy another's history.
    """
    _run(api.create_room("hot"))
    _run(api.create_room("cold"))
    api.grant("hot", "agent", AGENT_A)
    api.grant("cold", "agent", AGENT_A)

    # Cap hot at 2 messages.
    async def cap_hot():
        js = await nats_client.get_jetstream()
        hot_id = next(r["room_id"] for r in api.list_rooms() if r["name"] == "hot")
        await js.update_stream(
            name=nats_client.stream_name_for_room(hot_id),
            subjects=[nats_client.subject_for_room(hot_id)],
            max_msgs=2,
        )
    _run(cap_hot())

    # Fill hot beyond its cap, then send one to cold.
    for i in range(5):
        _run(api.send("hot", "agent", AGENT_A, f"hot{i}"))
    _run(api.send("cold", "agent", AGENT_A, "survives"))

    hot_page = _run(api.read_room("hot", "agent", AGENT_A))
    cold_page = _run(api.read_room("cold", "agent", AGENT_A))

    # hot lost old messages; cold is untouched.
    assert [m["body"] for m in hot_page["messages"]] == ["hot3", "hot4"]
    assert hot_page["history_truncated"] is True
    assert [m["body"] for m in cold_page["messages"]] == ["survives"]
    assert cold_page["history_truncated"] is False


# ---------- 4. NATS unavailable → 503 (isolated from proxy) ----------


@pytest.mark.timeout(30)
def test_nats_unavailable_surfaces_as_nats_unavailable_not_500(coord_env):
    """When nats-server dies, coord operations must raise
    NatsUnavailable (which the addon maps to 503). Bare RuntimeError
    would leak to the proxy as a 500 and would risk taking a well-behaved
    proxy path down with a message-plane failure.
    """
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)

    # Kill NATS mid-flight.
    nr.stop_server()
    nats_client.reset_for_tests()

    with pytest.raises(nats_client.NatsUnavailable):
        _run(api.send("r", "agent", AGENT_A, "into the void"))


# ---------- 5. Unauthenticated NATS connections rejected ----------


@pytest.mark.timeout(30)
def test_nats_rejects_unauthenticated_client(coord_env):
    """Runtime pins mandatory auth even on 127.0.0.1 — an unauthenticated
    connection MUST NOT be accepted. Guards against a future refactor
    silently reintroducing a `no_auth_user` or a default account.
    """
    async def try_anon():
        try:
            await nats.connect(
                nr.client_url(),
                connect_timeout=2.0,
                allow_reconnect=False,
                max_reconnect_attempts=0,
            )
        except (NoServersError, NatsError, OSError) as e:
            return e
        return None
    err = _run(try_anon())
    assert err is not None, \
        "unauthenticated client should have been rejected; got a connection"


# ---------- 6. Revocation during a blocked wait ----------


@pytest.mark.timeout(15)
def test_revoke_during_blocked_wait_returns_empty(coord_env):
    """Task #37: a mid-flight revoke must short-circuit an in-progress
    wait before the next peer message can leak to the revoked caller.

    Alice waits with no messages available; while she's blocked, alice
    is revoked and bob sends. Alice's wait must return empty rather
    than deliver bob's message she now has no right to see.
    """
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    async def scenario():
        async def revoke_then_send():
            await asyncio.sleep(0.3)
            api.revoke_grant("r", "agent", AGENT_A)
            # After alice is revoked, bob sends. This must NOT wake alice.
            await api.send("r", "agent", AGENT_B, "not for alice")

        wait_task = asyncio.create_task(
            api.wait_for_message(
                "r", "agent", AGENT_A, since_sequence=0,
                timeout_seconds=3, fetch_window_seconds=0.1,
            )
        )
        await revoke_then_send()
        return await wait_task

    page = asyncio.run(scenario())
    assert page["messages"] == [], \
        "revoked caller must not receive messages sent after revoke"


# ---------- 7. NatsUnavailable is truly consistent across ops ----------


@pytest.mark.timeout(45)
def test_send_read_wait_all_fail_with_nats_unavailable_when_nats_down(coord_env):
    """Reviewer round-3 point 1: NatsUnavailable must be the SINGLE
    boundary across every NATS-touching op. Killing NATS mid-flight
    then invoking send/read/wait must raise NatsUnavailable, not a raw
    nats-py exception that would escape as a proxy 500 and take a
    healthy request path down with it."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)

    nr.stop_server()
    nats_client.reset_for_tests()

    with pytest.raises(nats_client.NatsUnavailable):
        _run(api.send("r", "agent", AGENT_A, "into the void"))

    with pytest.raises(nats_client.NatsUnavailable):
        _run(api.read_room("r", "agent", AGENT_A))

    with pytest.raises(nats_client.NatsUnavailable):
        _run(api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=1, fetch_window_seconds=0.05,
        ))


# ---------- 8. Max-sized body survives (envelope headroom) ----------


@pytest.mark.timeout(30)
def test_body_at_api_max_survives_jetstream(coord_env):
    """Reviewer round-3 point 2: a body exactly at the API cap must
    make it through JetStream. If MaxMsgSize == MAX_BODY_BYTES the
    envelope overhead pushes the total past the limit and a valid
    max-sized body is rejected. Pin the headroom with this test."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    big = "x" * api.MAX_BODY_BYTES
    r = _run(api.send("r", "agent", AGENT_A, big, sender_agent_name="alice"))
    assert r["sequence"] > 0

    page = _run(api.read_room("r", "agent", AGENT_B))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == big


@pytest.mark.timeout(30)
def test_body_at_api_max_survives_jetstream_non_ascii(coord_env):
    """Reviewer round-5 point 1: an ASCII body of `x` doesn't exercise
    JSON's Unicode-escape behavior. A legal 256 KiB body of `é` used to
    serialize to ~768 KiB (because json.dumps' default ensure_ascii=True
    expanded each 2-byte UTF-8 char to `\\u00e9`, 6 chars), blowing past
    a tight stream ceiling. This test locks in the ensure_ascii=False
    fix + 2 MiB headroom."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    # 128 KiB of `é` = 256 KiB UTF-8 = MAX_BODY_BYTES on the nose.
    per_char_bytes = len("é".encode("utf-8"))
    assert per_char_bytes == 2
    big = "é" * (api.MAX_BODY_BYTES // per_char_bytes)
    assert len(big.encode("utf-8")) == api.MAX_BODY_BYTES

    r = _run(api.send("r", "agent", AGENT_A, big, sender_agent_name="alice"))
    assert r["sequence"] > 0

    page = _run(api.read_room("r", "agent", AGENT_B))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == big


@pytest.mark.timeout(30)
def test_missing_jetstream_stream_for_existing_room_raises_coord_data_error(coord_env):
    """Reviewer round-5 point 2: SQLite says the room exists but the
    JetStream stream is gone. Silently returning an empty page would
    hide the data loss. Must surface as CoordDataError (→ addon 500).
    delete_room_stream itself stays idempotent."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    room_id = next(r["room_id"] for r in api.list_rooms() if r["name"] == "r")

    # Directly drop the stream out from under the still-registered room.
    async def drop():
        js = await nats_client.get_jetstream()
        await js.delete_stream(nats_client.stream_name_for_room(room_id))
    _run(drop())

    # Any read of the room now raises CoordDataError rather than
    # reporting a false empty page.
    with pytest.raises(nats_client.CoordDataError):
        _run(api.read_room("r", "agent", AGENT_A))

    # A publish to the still-registered room must also surface the
    # data loss (reviewer round-6 point 2). Otherwise the send would
    # be broadly reported as NatsUnavailable → 503, which would look
    # like an outage the operator should wait out rather than a
    # storage integrity failure to investigate.
    with pytest.raises(nats_client.CoordDataError):
        _run(api.send("r", "agent", AGENT_A, "publish into a vanished stream"))

    # Idempotent delete stays a no-op returning False.
    async def redelete():
        return await nats_client.delete_room_stream(room_id)
    assert _run(redelete()) is False


# ---------- 9. Ephemeral consumers are actually cleaned up ----------


@pytest.mark.timeout(45)
def test_repeated_read_and_wait_do_not_grow_consumer_count(coord_env):
    """Reviewer round-3 point 3: nats-py's PullSubscription.unsubscribe
    only tears down the client-side inbox; the server-side consumer
    lingers until an inactivity threshold fires. Verify that the
    explicit delete_consumer we do after every fetch keeps the
    consumer_count from creeping up under /messages+/wait traffic."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)
    _run(api.send("r", "agent", AGENT_B, "seed"))

    room_id = next(r["room_id"] for r in api.list_rooms() if r["name"] == "r")

    # Twenty read+wait cycles should not accumulate consumers.
    async def hammer():
        for _ in range(20):
            await api.read_room("r", "agent", AGENT_A)
            await api.wait_for_message(
                "r", "agent", AGENT_A, since_sequence=0,
                timeout_seconds=0.05, fetch_window_seconds=0.02,
            )
        return await nats_client.consumer_count(room_id)

    remaining = asyncio.run(hammer())
    assert remaining == 0, (
        f"ephemeral consumers leaked; server still has {remaining} on the stream"
    )


# ---------- 10. Corrupt persisted envelope surfaces as CoordDataError ----------


@pytest.mark.timeout(30)
def test_corrupt_persisted_envelope_raises_coord_data_error(coord_env):
    """Reviewer round-3 point 4: SafeYolo is the sole writer of these
    subjects, so a payload that is not a JSON envelope is a storage
    integrity failure. It must surface as CoordDataError (→ addon 500)
    rather than being ACKed and silently skipped, which would produce
    an unexplained hole in room history."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    room_id = next(r["room_id"] for r in api.list_rooms() if r["name"] == "r")

    # Publish a non-JSON payload directly onto the room's subject,
    # bypassing api.send (which enforces envelope shape).
    async def poison():
        js = await nats_client.get_jetstream()
        await js.publish(
            nats_client.subject_for_room(room_id),
            b"not a valid json envelope",
            stream=nats_client.stream_name_for_room(room_id),
            headers={"Nats-Msg-Id": "poisoned-1"},
        )
    _run(poison())

    with pytest.raises(nats_client.CoordDataError):
        _run(api.read_room("r", "agent", AGENT_A))


# ---------- 12. read_room has the same TOCTOU protection as wait ----------


@pytest.mark.timeout(15)
def test_revoke_during_blocked_read_raises_no_membership(coord_env):
    """Reviewer round-4 point 2: read_room checks receive, then does a
    potentially blocking JetStream fetch, then returns messages. A
    revoke that lands while the fetch is blocked must NOT ship a peer
    message the caller has since lost permission to see. Semantically
    matches #20: post-revoke, all reads are 404.
    """
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    async def scenario():
        async def revoke_then_send():
            # Let read_room's fetch start (~50ms), then revoke + publish
            # while the fetch is still waiting for a message.
            await asyncio.sleep(0.05)
            api.revoke_grant("r", "agent", AGENT_A)
            await api.send("r", "agent", AGENT_B, "not for alice")

        read_task = asyncio.create_task(
            api.read_room("r", "agent", AGENT_A, since_sequence=0)
        )
        await revoke_then_send()
        return await read_task

    with pytest.raises(api.NoMembershipError):
        asyncio.run(scenario())


# ---------- 13. Stream config drift fails loud ----------


@pytest.mark.timeout(30)
def test_existing_stream_with_different_config_fails_loud(coord_env):
    """Reviewer round-3 point 5: `ensure_room_stream` used to accept
    any existing ROOM_* as good enough. A future bump of MaxAge /
    MaxBytes / dedup would silently miss all pre-existing streams.
    Now: config drift raises StreamConfigDrift so the operator has
    to explicitly reconcile."""
    _run(api.create_room("r"))
    room_id = next(r["room_id"] for r in api.list_rooms() if r["name"] == "r")

    async def bend():
        js = await nats_client.get_jetstream()
        # Cut max_bytes to something obviously not our contract.
        await js.update_stream(
            name=nats_client.stream_name_for_room(room_id),
            subjects=[nats_client.subject_for_room(room_id)],
            max_bytes=1024,
        )
    _run(bend())

    # A subsequent ensure_room_stream on the same room_id must refuse
    # rather than silently continuing with the shrunk cap.
    async def check():
        await nats_client.ensure_room_stream(room_id)
    with pytest.raises(nats_client.StreamConfigDrift):
        _run(check())
