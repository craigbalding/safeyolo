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
                timeout_seconds=3, poll_interval_seconds=0.1,
            )
        )
        await revoke_then_send()
        return await wait_task

    page = asyncio.run(scenario())
    assert page["messages"] == [], \
        "revoked caller must not receive messages sent after revoke"
