"""Stage-1 targeted-attention contracts over real JetStream storage."""

from __future__ import annotations

import asyncio
import json

import pytest

from safeyolo.agents_store import save_agent
from safeyolo.coord import api, attention, nats_client, outbox, store
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.envelope import INTERNAL_ATTENTION_HEADER, Envelope
from safeyolo.coord.identity import (
    get_or_create_instance_id,
    new_msg_id,
    new_operation_id,
)

AGENTS = {
    "alice": "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bob": "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "codey": "ag-cccccccccccccccccccccccccccccccc",
    "dana": "ag-dddddddddddddddddddddddddddddddd",
    "mallory": "ag-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
}


@pytest.fixture
def attention_env(nats_env, monkeypatch):
    config_dir = nats_env / "config"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(nats_env / "logs"))
    for name, agent_id in AGENTS.items():
        save_agent(name, {"agent_id": agent_id})
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    return nats_env


def _grant(
    room: str,
    kind: str,
    principal_id: str,
    permissions: list[str] | None = None,
) -> None:
    api.grant(
        room,
        kind,
        principal_id,
        permissions=permissions,
        operation_id=new_operation_id(),
    )


async def _room(name: str, *, operator: bool = False) -> str:
    room_id = await api.create_room(name)
    _grant(name, "agent", AGENTS["alice"])
    _grant(name, "agent", AGENTS["bob"])
    _grant(name, "agent", AGENTS["codey"])
    _grant(name, "agent", AGENTS["dana"], ["send"])
    if operator:
        _grant(name, "operator", "operator")
    return room_id


def _edge_for(page: dict, object_id: str) -> dict | None:
    return next(
        (edge for edge in page["edges"] if edge["object_id"] == object_id),
        None,
    )


def test_targeting_visibility_feed_and_compatibility(attention_env):
    async def scenario() -> None:
        await _room("one", operator=True)
        await _room("two")
        legacy_room_id = await _room("legacy")

        # A retained pre-Stage-1 message has no internal manifest and keeps
        # the original per-room broadcast-wake behavior.
        legacy_id = new_msg_id()
        legacy_envelope = Envelope(
            msg_id=legacy_id,
            sent_at=store.now_ms(),
            sender_kind="agent",
            sender_agent_id=AGENTS["alice"],
            sender_agent_name="alice",
            origin_instance_id=get_or_create_instance_id(),
            content_type="text/markdown",
            body="pre-stage-one",
        ).to_dict()
        js = await nats_client.get_jetstream()
        await js.publish(
            nats_client.subject_for_room(legacy_room_id),
            json.dumps(legacy_envelope).encode(),
            stream=nats_client.stream_name_for_room(legacy_room_id),
            headers={"Nats-Msg-Id": legacy_id},
        )
        legacy_wake = await api.wait_for_message(
            "legacy",
            "agent",
            AGENTS["codey"],
            since_sequence=0,
            timeout_seconds=0.05,
        )
        assert [message["body"] for message in legacy_wake["messages"]] == [
            "pre-stage-one"
        ]
        await attention.materialize_room_attention(legacy_room_id)
        assert _edge_for(attention.read_feed(AGENTS["codey"], 0, 20), legacy_id) is None

        targeted = await api.send(
            "one",
            "agent",
            AGENTS["alice"],
            "for bob",
            sender_agent_name="alice",
            notify=["bob"],
        )
        assert targeted["attention_status"] == "ready"

        # Addressing changes attention, not retained-history visibility, and
        # the internal manifest is absent from the public envelope/read API.
        visible = await api.read_room("one", "agent", AGENTS["codey"])
        assert visible["messages"][0]["body"] == "for bob"
        assert not {
            "notify",
            "recipients",
            "_attention_manifest_header",
        } & visible["messages"][0].keys()
        assert not {"notify", "recipients"} & targeted["envelope"].keys()

        bob = await api.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=0.1
        )
        bob_edge = _edge_for(bob, targeted["envelope"]["msg_id"])
        assert bob_edge is not None
        # Delivery is caller-cursor-driven: replaying the same cursor returns
        # the same logical attention ID, and no consumed cursor is stored.
        replay = await api.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=0.1
        )
        assert replay["edges"] == bob["edges"]
        canonical = await api.read_attention(
            AGENTS["bob"], bob_edge["attention_id"]
        )
        assert canonical["object"]["body"] == "for bob"
        with pytest.raises(api.NotFoundError):
            await api.read_attention(
                AGENTS["codey"], bob_edge["attention_id"]
            )

        codey = await api.wait_for_attention(
            AGENTS["codey"], since_sequence=0, timeout_seconds=0.05
        )
        assert codey == {"edges": [], "next_cursor": 0}

        # The legacy room wait is target-aware for Stage-1 messages.
        bob_wake = await api.wait_for_message(
            "one",
            "agent",
            AGENTS["bob"],
            since_sequence=0,
            timeout_seconds=0.05,
        )
        assert [message["body"] for message in bob_wake["messages"]] == [
            "for bob"
        ]
        codey_wake = await api.wait_for_message(
            "one",
            "agent",
            AGENTS["codey"],
            since_sequence=0,
            timeout_seconds=0.05,
        )
        assert codey_wake["messages"] == []

        second_room = await api.send(
            "two",
            "agent",
            AGENTS["alice"],
            "also for bob",
            notify=["bob"],
        )
        multiplexed = await api.wait_for_attention(
            AGENTS["bob"],
            since_sequence=bob["next_cursor"],
            timeout_seconds=0.1,
        )
        assert _edge_for(
            multiplexed, second_room["envelope"]["msg_id"]
        ) is not None

        quiet = await api.send(
            "one",
            "agent",
            AGENTS["alice"],
            "history only",
            notify="none",
        )
        bob_after_quiet = await api.wait_for_attention(
            AGENTS["bob"],
            since_sequence=multiplexed["next_cursor"],
            timeout_seconds=0.05,
        )
        assert _edge_for(
            bob_after_quiet, quiet["envelope"]["msg_id"]
        ) is None

        # Raw omission retains broadcast wake semantics. The sending agent is
        # excluded, while every active receive-capable peer is included.
        omitted = await api.send(
            "one", "agent", AGENTS["alice"], "legacy raw omission"
        )
        codey_after_omitted = await api.wait_for_attention(
            AGENTS["codey"], since_sequence=0, timeout_seconds=0.1
        )
        assert _edge_for(
            codey_after_omitted, omitted["envelope"]["msg_id"]
        ) is not None
        alice_after_omitted = await api.wait_for_attention(
            AGENTS["alice"], since_sequence=0, timeout_seconds=0.05
        )
        assert _edge_for(
            alice_after_omitted, omitted["envelope"]["msg_id"]
        ) is None
        # Dana has send-only membership and therefore owns no feed edge.
        dana = await api.wait_for_attention(
            AGENTS["dana"], since_sequence=0, timeout_seconds=0.05
        )
        assert dana == {"edges": [], "next_cursor": 0}

        explicit_self = await api.send(
            "one",
            "agent",
            AGENTS["alice"],
            "self reminder",
            notify=["alice"],
        )
        alice = await api.wait_for_attention(
            AGENTS["alice"], since_sequence=0, timeout_seconds=0.1
        )
        assert _edge_for(
            alice, explicit_self["envelope"]["msg_id"]
        ) is not None
        self_wake = await api.wait_for_message(
            "one",
            "agent",
            AGENTS["alice"],
            since_sequence=omitted["sequence"],
            timeout_seconds=0.05,
        )
        assert [message["body"] for message in self_wake["messages"]] == [
            "self reminder"
        ]

        operator_broadcast = await api.send(
            "one", "operator", None, "operator broadcast", notify="room"
        )
        bob_after_operator = await api.wait_for_attention(
            AGENTS["bob"],
            since_sequence=bob_after_quiet["next_cursor"],
            timeout_seconds=0.1,
            limit=20,
        )
        assert _edge_for(
            bob_after_operator, operator_broadcast["envelope"]["msg_id"]
        ) is not None

        before = await nats_client.room_stream_state(
            api.join_room("one", "agent", AGENTS["alice"])["room_id"]
        )
        with pytest.raises(
            attention.AttentionTargetError,
            match="one or more notify targets are not active room members",
        ):
            await api.send(
                "one",
                "agent",
                AGENTS["alice"],
                "not for mallory",
                notify=["mallory"],
            )
        with pytest.raises(attention.AttentionTargetError) as unknown:
            await api.send(
                "one",
                "agent",
                AGENTS["alice"],
                "not for unknown",
                notify=["not-registered"],
            )
        assert str(unknown.value) == (
            "one or more notify targets are not active room members"
        )
        after = await nats_client.room_stream_state(
            api.join_room("one", "agent", AGENTS["alice"])["room_id"]
        )
        assert after["last_seq"] == before["last_seq"]

    asyncio.run(scenario())


def test_puback_recovery_generation_concurrency_and_corruption(
    attention_env, monkeypatch
):
    async def scenario() -> None:
        room_id = await _room("recovery")
        real_materialize = attention.materialize_room_attention

        async def fail_projection(*_args, **_kwargs):
            raise RuntimeError("injected SQLite projection failure")

        monkeypatch.setattr(attention, "materialize_room_attention", fail_projection)
        accepted = await api.send(
            "recovery",
            "agent",
            AGENTS["alice"],
            "accepted before SQLite",
            notify=["bob"],
        )
        assert accepted["attention_status"] == "pending"
        history = await api.read_room("recovery", "agent", AGENTS["bob"])
        assert history["messages"][0]["body"] == "accepted before SQLite"

        monkeypatch.setattr(attention, "materialize_room_attention", real_materialize)

        async def lose_hint(*_args, **_kwargs):
            raise nats_client.NatsUnavailable("injected lost nudge")

        monkeypatch.setattr(nats_client, "publish_attention_hint", lose_hint)
        await api.recover_attention()
        recovered = await api.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=0.1
        )
        recovered_edge = _edge_for(
            recovered, accepted["envelope"]["msg_id"]
        )
        assert recovered_edge is not None

        # Revocation followed by re-grant cannot make an edge for the old
        # generation visible again. Skipping it advances only the returned
        # caller cursor, never a server-side consumed position.
        api.revoke_grant(
            "recovery",
            "agent",
            AGENTS["bob"],
            operation_id=new_operation_id(),
        )
        _grant("recovery", "agent", AGENTS["bob"])
        stale = attention.read_feed(AGENTS["bob"], 0, 20)
        assert stale["edges"] == []
        assert stale["next_cursor"] == recovered["next_cursor"]
        with pytest.raises(api.NotFoundError):
            await api.read_attention(
                AGENTS["bob"], recovered_edge["attention_id"]
            )

        # Accept two more messages without materializing either, then race
        # two projectors. The CAS watermark can repeat work but cannot skip;
        # each logical msg_id+generation has exactly one SQLite edge.
        monkeypatch.setattr(attention, "materialize_room_attention", fail_projection)
        first = await api.send(
            "recovery",
            "agent",
            AGENTS["alice"],
            "concurrent one",
            notify=["bob"],
        )
        second = await api.send(
            "recovery",
            "agent",
            AGENTS["alice"],
            "concurrent two",
            notify=["bob"],
        )
        monkeypatch.setattr(attention, "materialize_room_attention", real_materialize)
        watermarks = await asyncio.gather(
            real_materialize(room_id), real_materialize(room_id)
        )
        assert watermarks == [second["sequence"], second["sequence"]]
        with store.connect() as conn:
            assert conn.execute(
                """SELECT last_sequence
                   FROM coord_message_attention_projection WHERE room_id = ?""",
                (room_id,),
            ).fetchone()[0] == second["sequence"]
            for result in (first, second):
                assert conn.execute(
                    """SELECT count(*) FROM coord_attention_edges
                       WHERE recipient_agent_id = ? AND object_id = ?""",
                    (AGENTS["bob"], result["envelope"]["msg_id"]),
                ).fetchone()[0] == 1

        corrupt_room_id = await _room("corrupt")
        baseline = await attention.ensure_room_projection(corrupt_room_id)
        msg_id = new_msg_id()
        envelope = Envelope(
            msg_id=msg_id,
            sent_at=store.now_ms(),
            sender_kind="agent",
            sender_agent_id=AGENTS["alice"],
            sender_agent_name="alice",
            origin_instance_id=get_or_create_instance_id(),
            content_type="text/markdown",
            body="corrupt internal intent",
        ).to_dict()
        js = await nats_client.get_jetstream()
        ack = await js.publish(
            nats_client.subject_for_room(corrupt_room_id),
            json.dumps(envelope).encode(),
            stream=nats_client.stream_name_for_room(corrupt_room_id),
            headers={
                "Nats-Msg-Id": msg_id,
                INTERNAL_ATTENTION_HEADER: "{not-json",
            },
        )
        with pytest.raises(nats_client.CoordDataError, match="corrupt"):
            await real_materialize(corrupt_room_id)
        with store.connect() as conn:
            watermark = conn.execute(
                """SELECT last_sequence
                   FROM coord_message_attention_projection WHERE room_id = ?""",
                (corrupt_room_id,),
            ).fetchone()[0]
        assert watermark == baseline < ack.seq

        # A later valid message receives a definite PubAck but remains
        # explicitly pending because recovery cannot advance past corruption.
        later = await api.send(
            "corrupt",
            "agent",
            AGENTS["alice"],
            "accepted after corrupt predecessor",
            notify=["bob"],
        )
        assert later["sequence"] > ack.seq
        assert later["attention_status"] == "pending"
        with pytest.raises(nats_client.CoordDataError):
            await attention.recover_all_attention()
        with store.connect() as conn:
            assert conn.execute(
                """SELECT last_sequence
                   FROM coord_message_attention_projection WHERE room_id = ?""",
                (corrupt_room_id,),
            ).fetchone()[0] == baseline

    asyncio.run(scenario())


def test_wait_checks_ledger_again_after_subscribing(monkeypatch):
    calls = 0

    async def recover(_agent_id):
        return None

    def read(_agent_id, _since, _limit):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"edges": [], "next_cursor": 0}
        return {
            "edges": [
                {
                    "attention_id": "attn-" + "a" * 32,
                    "room_id": "rm-r",
                    "kind": "message",
                    "object_id": "msg-m",
                    "revision_or_sequence": 1,
                }
            ],
            "next_cursor": 1,
        }

    class Subscription:
        async def wait(self, _timeout):
            raise AssertionError("ledger-after-subscribe edge should return first")

    class Context:
        async def __aenter__(self):
            return Subscription()

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(attention, "recover_attention_for_agent", recover)
    monkeypatch.setattr(attention, "read_feed", read)
    monkeypatch.setattr(nats_client, "attention_subscription", lambda _agent: Context())

    page = asyncio.run(
        attention.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=1, limit=1
        )
    )
    assert page["next_cursor"] == 1
    assert calls == 2


def test_hint_publish_crash_retries_without_new_logical_edge(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path / "coord"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    api.bootstrap()
    attention_id = "attn-" + "f" * 32
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        outbox.enqueue_attention_hint(
            conn,
            attention_id=attention_id,
            recipient_agent_id=AGENTS["bob"],
            feed_sequence=1,
        )
        conn.execute("COMMIT")

    published = []

    async def publish(agent_id, hint_attention_id):
        published.append((agent_id, hint_attention_id))

    def crash(_event_id):
        raise RuntimeError("process died after publish")

    monkeypatch.setattr(nats_client, "publish_attention_hint", publish)
    assert asyncio.run(outbox.project_attention_hints(_after_publish=crash)) == 0
    assert asyncio.run(outbox.project_attention_hints()) == 1
    assert published == [
        (AGENTS["bob"], attention_id),
        (AGENTS["bob"], attention_id),
    ]
    with store.connect() as conn:
        row = conn.execute(
            """SELECT delivered_at, attempt_count FROM coord_outbox
               WHERE event_type = 'coord.attention_hint'"""
        ).fetchone()
    assert row["delivered_at"] is not None
    assert row["attempt_count"] == 2
