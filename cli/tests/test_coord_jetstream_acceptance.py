"""Acceptance tests for the coord JetStream substrate.

These tests verify substrate properties such as durability, retention
reporting, per-room isolation, authorization, availability isolation, and
mid-flight revocation. They complement the API-focused unit tests in
test_coord_v0.py.

Each test starts a real nats-server, so they are slower than unit tests
by design. Marked with sensible timeouts so a hung fetch fails loudly
rather than sitting on the runner.
"""

from __future__ import annotations

import asyncio
import hmac
import json
from unittest.mock import patch

import nats
import pytest
from nats.errors import Error as NatsError
from nats.errors import NoServersError
from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.coord import api, nats_client
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.identity import instance_id_file, new_operation_id


def _run(coro):
    return asyncio.run(coro)


def _grant(*args, **kwargs):
    kwargs.setdefault("operation_id", new_operation_id())
    return api.grant(*args, **kwargs)


def _revoke_grant(*args, **kwargs):
    kwargs.setdefault("operation_id", new_operation_id())
    return api.revoke_grant(*args, **kwargs)


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

    JetStream FileStorage, unlike the in-memory NATS core, should replay the
    message from disk after a restart. Failure means the substrate does not
    provide its required durability.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)

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
    """A CLI lifecycle restart preserves messages accepted by coord.

    Exercise the same best-effort helpers used by `safeyolo stop` and
    `safeyolo start`, rather than calling the NATS runtime directly.
    """
    from safeyolo.commands.lifecycle import (
        _start_coord_best_effort,
        _stop_coord_best_effort,
    )

    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)

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


@pytest.mark.timeout(45)
def test_manual_credential_rotation_preserves_history_and_redacts_evidence(
    coord_env, caplog, capsys
):
    """Exercise the operator runbook against a disposable real NATS server.

    An ordinary lifecycle restart must reuse the credential. Removing only
    the credential while stopped must replace it, reject the former password,
    accept the replacement, and leave retained JetStream history readable.
    Public lifecycle/status output plus generated config/log diagnostics must
    not contain either raw value.
    """
    from safeyolo.commands.lifecycle import (
        _start_coord_best_effort,
        _stop_coord_best_effort,
    )

    _run(api.create_room("credential-rotation"))
    _grant("credential-rotation", "agent", AGENT_A)
    sent = _run(
        api.send(
            "credential-rotation",
            "agent",
            AGENT_A,
            "retained before credential rotation",
        )
    )
    original = nr.read_credentials()

    # Ordinary stop/start reuses the credential and retained history.
    _stop_coord_best_effort()
    nats_client.reset_for_tests()
    _start_coord_best_effort()
    reused = nr.read_credentials()
    if not hmac.compare_digest(original, reused):
        pytest.fail("ordinary stop/start unexpectedly rotated NATS credential")
    page = _run(
        api.read_room("credential-rotation", "agent", AGENT_A)
    )
    assert page["messages"][0]["sequence"] == sent["sequence"]

    # Follow the runbook: stop, remove exactly creds, then start.
    _stop_coord_best_effort()
    nats_client.reset_for_tests()
    nr.nats_creds_path().unlink()
    assert nr.nats_data_path().is_dir()
    _start_coord_best_effort()
    replacement = nr.read_credentials()
    if hmac.compare_digest(original, replacement):
        pytest.fail("delete-while-stopped did not rotate NATS credential")

    async def auth_succeeds(password: str) -> bool:
        try:
            connection = await nats.connect(
                nr.client_url(),
                user=nr.client_user_credentials()[0],
                password=password,
                connect_timeout=2.0,
                allow_reconnect=False,
                max_reconnect_attempts=0,
            )
        except (NatsError, OSError, TimeoutError):
            return False
        await connection.close()
        return True

    assert not _run(auth_succeeds(original))
    assert _run(auth_succeeds(replacement))

    nats_client.reset_for_tests()
    page = _run(
        api.read_room("credential-rotation", "agent", AGENT_A)
    )
    assert [message["body"] for message in page["messages"]] == [
        "retained before credential rotation"
    ]
    assert page["messages"][0]["sequence"] == sent["sequence"]

    captured = capsys.readouterr()
    evidence = "\n".join(
        (
            captured.out,
            captured.err,
            caplog.text,
            json.dumps(nr.status(), sort_keys=True),
            nr.nats_config_path().read_text(),
            nr._tail_log(),
        )
    )
    if any(secret in evidence for secret in (original, replacement)):
        pytest.fail("raw NATS credential appeared in public or diagnostic evidence")
    assert nr.nats_root().stat().st_mode & 0o777 == 0o700
    assert nr.nats_creds_path().stat().st_mode & 0o777 == 0o600


@pytest.mark.timeout(30)
def test_instance_id_minted_at_safeyolo_start(nats_env):
    """The first `safeyolo start` creates the instance ID eagerly.

    Status must be able to display the ID before any agent calls the coord API.
    """
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


@pytest.mark.timeout(45)
def test_running_proxy_start_reconciles_coord_and_preserves_state(
    nats_env, tmp_config_dir
):
    """Repeated starts repair only Coord and preserve its durable state."""
    runner = CliRunner()
    nats_client.reset_for_tests()

    with (
        patch(
            "safeyolo.commands.lifecycle.is_proxy_running",
            return_value=True,
            autospec=True,
        ),
        patch("safeyolo.commands.lifecycle.start_proxy", autospec=True) as start_proxy,
    ):
        repaired = runner.invoke(app, ["start", "--no-wait"])
        assert repaired.exit_code == 0, repaired.output
        assert "coord dependency repaired" in repaired.output.lower()
        assert nr.is_healthy()
        start_proxy.assert_not_called()

        instance_id = instance_id_file().read_text()
        _run(api.create_room("start-reconcile"))
        _grant("start-reconcile", "agent", AGENT_A)
        _grant("start-reconcile", "agent", AGENT_B)
        sent = _run(
            api.send(
                "start-reconcile",
                "agent",
                AGENT_A,
                "survives repeated start reconciliation",
                notify="room",
            )
        )
        attention_before = _run(
            api.wait_for_attention(
                AGENT_B,
                since_sequence=0,
                timeout_seconds=0.1,
            )
        )
        assert len(attention_before["edges"]) == 1

        nr.stop_server()
        nats_client.reset_for_tests()
        repaired_again = runner.invoke(app, ["start", "--no-wait"])
        assert repaired_again.exit_code == 0, repaired_again.output
        assert "coord dependency repaired" in repaired_again.output.lower()
        assert instance_id_file().read_text() == instance_id

        page = _run(api.read_room("start-reconcile", "agent", AGENT_B))
        assert [message["body"] for message in page["messages"]] == [
            "survives repeated start reconciliation"
        ]
        assert page["messages"][0]["sequence"] == sent["sequence"]
        attention_after = _run(
            api.wait_for_attention(
                AGENT_B,
                since_sequence=0,
                timeout_seconds=0.1,
            )
        )
        assert attention_after == attention_before

        running = nr._read_pidfile()
        assert running is not None
        healthy = runner.invoke(app, ["start", "--no-wait"])
        assert healthy.exit_code == 0, healthy.output
        assert "coord dependency is already healthy" in healthy.output.lower()
        assert nr._read_pidfile() == running
        start_proxy.assert_not_called()


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
    _grant("r", "agent", AGENT_A)

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
    """One room reaching its retention cap does not erase another's history.

    Per-room byte and message caps isolate a noisy room from its peers.
    """
    _run(api.create_room("hot"))
    _run(api.create_room("cold"))
    _grant("hot", "agent", AGENT_A)
    _grant("cold", "agent", AGENT_A)

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
    _grant("r", "agent", AGENT_A)

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
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)

    async def scenario():
        async def revoke_then_send():
            await asyncio.sleep(0.3)
            _revoke_grant("r", "agent", AGENT_A)
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
    """All NATS operations expose the same unavailable error boundary.

    After NATS stops, send, read, and wait must raise `NatsUnavailable`
    instead of leaking a nats-py exception. A raw exception would escape as
    proxy HTTP 500 and could take down a healthy request path with a
    message-plane failure.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)

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
    """A body at the API limit fits in JetStream with envelope overhead.

    If JetStream `MaxMsgSize` equaled `MAX_BODY_BYTES`, the envelope would
    push a valid maximum-sized body past the stream limit. This test requires
    the stream to reserve headroom for the envelope.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)

    big = "x" * api.MAX_BODY_BYTES
    r = _run(api.send("r", "agent", AGENT_A, big, sender_agent_name="alice"))
    assert r["sequence"] > 0

    page = _run(api.read_room("r", "agent", AGENT_B))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == big


@pytest.mark.timeout(30)
def test_body_at_api_max_survives_jetstream_non_ascii(coord_env):
    """A non-ASCII body at the API byte limit fits in JetStream.

    With the `json.dumps` default `ensure_ascii=True`, each two-byte `é`
    becomes the six-byte escape `\\u00e9`. A valid 256 KiB body would expand
    to about 768 KiB. SafeYolo uses `ensure_ascii=False` and sets the stream
    message limit to 2 MiB, which provides headroom without changing the body.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)

    # 128 KiB of `é` = 256 KiB UTF-8 = MAX_BODY_BYTES on the nose.
    per_char_bytes = len("é".encode())
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
    """A missing stream for a registered room is a data-integrity error.

    SQLite still records the room, but its JetStream stream is absent.
    Returning an empty page would hide data loss. Reads and writes must raise
    `CoordDataError`, which the addon reports as HTTP 500. Deleting an already
    missing stream stays idempotent.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
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
    # data loss. Otherwise the send would
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
    """Repeated reads and waits do not leak server-side consumers.

    `PullSubscription.unsubscribe` tears down only the client-side inbox. The
    explicit consumer deletion after each fetch must keep the server count at
    zero.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)
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
    """A persisted payload that is not a JSON envelope is a data error.

    SafeYolo is the sole writer of these subjects. The read must raise
    `CoordDataError` instead of acknowledging and silently skipping the bad
    payload. Skipping it would create an unexplained hole in room history;
    the addon reports the integrity failure as HTTP 500.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
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
    """A receive revocation during a blocked read prevents message delivery.

    `read_room` checks permission before and after its potentially blocking
    JetStream fetch. A caller that loses permission during the fetch must not
    receive the peer message. This matches issue #20: after revocation, API
    reads must return HTTP 404.
    """
    _run(api.create_room("r"))
    _grant("r", "agent", AGENT_A)
    _grant("r", "agent", AGENT_B)

    async def scenario():
        async def revoke_then_send():
            # Let read_room's fetch start (~50ms), then revoke + publish
            # while the fetch is still waiting for a message.
            await asyncio.sleep(0.05)
            _revoke_grant("r", "agent", AGENT_A)
            await api.send("r", "agent", AGENT_B, "not for alice")

        read_task = asyncio.create_task(
            api.read_room("r", "agent", AGENT_A, since_sequence=0)
        )
        await revoke_then_send()
        return await read_task

    with pytest.raises(api.NoMembershipError):
        asyncio.run(scenario())


# ---------- 13. Stream config upgrades and drift ----------


@pytest.mark.timeout(30)
def test_more_than_ten_rooms_share_storage_without_reservations(coord_env):
    async def scenario():
        for index in range(12):
            name = f"room-{index}"
            await api.create_room(name)
            _grant(name, "agent", AGENT_A)
            await api.send(name, "agent", AGENT_A, name)
        js = await nats_client.get_jetstream()
        account = await js.account_info()
        assert account.streams == 12
        assert account.storage > 0
        for index in range(12):
            page = await api.read_room(f"room-{index}", "agent", AGENT_A)
            assert [m["body"] for m in page["messages"]] == [f"room-{index}"]

    _run(scenario())


@pytest.mark.timeout(30)
def test_legacy_room_reservations_upgrade_in_place_before_new_room(coord_env):
    async def scenario():
        js = await nats_client.get_jetstream()
        rooms = []
        for index in range(10):
            name = f"legacy-{index}"
            room_id = await api.create_room(name)
            _grant(name, "agent", AGENT_A)
            sent = await api.send(name, "agent", AGENT_A, f"retained-{index}")
            rooms.append((name, room_id, sent))
        for _, room_id, _ in rooms:
            config = (await js.stream_info(nats_client.stream_name_for_room(room_id))).config
            config.max_bytes = 100 * 1024 * 1024
            await js.update_stream(config)

        # Exercise the normal create path, not an operator-only migration helper.
        await api.create_room("eleventh")
        for name, room_id, sent in rooms:
            info = await js.stream_info(nats_client.stream_name_for_room(room_id))
            assert info.config.max_bytes == -1
            assert info.state.messages == 1
            page = await api.read_room(name, "agent", AGENT_A)
            assert page["messages"][0]["msg_id"] == sent["envelope"]["msg_id"]
            assert page["messages"][0]["sequence"] == sent["sequence"]
        # Startup reconciliation also upgrades retained rooms without creating one.
        legacy_name = nats_client.stream_name_for_room(rooms[0][1])
        config = (await js.stream_info(legacy_name)).config
        await js.update_stream(config.evolve(max_bytes=100 * 1024 * 1024))
        await api.recover_attention()
        assert (await js.stream_info(legacy_name)).config.max_bytes == -1
        # Repeating reconciliation must leave the same stream and message identities.
        await api.recover_attention()
        assert (await js.account_info()).streams == 11

    _run(scenario())


@pytest.mark.timeout(30)
def test_shared_storage_still_rejects_writes_at_global_capacity(nats_env, monkeypatch):
    # Exercise the real server at a small budget, not a GiB of fixture writes.
    monkeypatch.setattr(nr, "JETSTREAM_MAX_FILE_STORE", 256 * 1024)
    nr.start_server(ready_timeout=8)
    nats_client.reset_for_tests()
    api.bootstrap()

    async def scenario():
        for room in ("first", "second"):
            await api.create_room(room)
            _grant(room, "agent", AGENT_A)
        accepted = 0
        with pytest.raises(nats_client.NatsUnavailable, match="(storage|resources|maximum)"):
            for index in range(40):
                await api.send("first" if index % 2 else "second", "agent", AGENT_A, "x" * (16 * 1024))
                accepted += 1
        assert 0 < accepted < 40
        for room in ("first", "second"):
            page = await api.read_room(room, "agent", AGENT_A)
            assert page["messages"]

    _run(scenario())


@pytest.mark.timeout(30)
def test_room_upgrade_preserves_other_configuration_and_rejects_unknown_drift(coord_env):
    async def scenario():
        room_id = await api.create_room("r")
        js = await nats_client.get_jetstream()
        name = nats_client.stream_name_for_room(room_id)
        config = (await js.stream_info(name)).config
        config.max_bytes = 100 * 1024 * 1024
        config.description = "Retain operator description"
        await js.update_stream(config)
        await nats_client.ensure_room_stream(room_id)
        updated = (await js.stream_info(name)).config
        assert updated.max_bytes == -1
        assert updated.description == config.description
        config = updated
        config.max_bytes = 100 * 1024 * 1024
        config.max_msgs = 17
        await js.update_stream(config)
        with pytest.raises(nats_client.StreamConfigDrift):
            await nats_client.ensure_room_stream(room_id)
        unchanged = (await js.stream_info(name)).config
        assert unchanged.max_bytes == 100 * 1024 * 1024
        assert unchanged.max_msgs == 17

    _run(scenario())


@pytest.mark.timeout(30)
def test_existing_stream_with_different_config_fails_loud(coord_env):
    """An existing room stream with different settings fails explicitly.

    Changes to maximum age, maximum bytes, or deduplication settings must not
    silently skip pre-existing streams. Configuration drift requires operator
    reconciliation.
    """
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
