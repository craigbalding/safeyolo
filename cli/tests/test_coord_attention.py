"""Stage-1 targeted-attention contracts over real JetStream storage."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

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

SUPERVISOR_PATH = Path(__file__).resolve().parents[2] / "contrib/codex-coord-supervisor.py"


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


def test_nested_factory_conversation_concurrency_and_restart(attention_env, tmp_path):
    """Exercise the factory adapter over real retained Coord and attention."""

    async def scenario() -> None:
        room_id = await _room("nested-factory", operator=True)
        spec = importlib.util.spec_from_file_location(
            "nested_factory_supervisor",
            SUPERVISOR_PATH,
        )
        assert spec is not None and spec.loader is not None
        supervisor = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = supervisor
        spec.loader.exec_module(supervisor)

        roles = {
            "coordinator": "alice",
            "owner": "bob",
            "reviewer": "codey",
        }
        handoffs = (
            supervisor.Handoff(
                "TASK",
                "coordinator",
                "owner",
                ("DONE", "BLOCKED", "FAILED"),
                ("coordinator",),
            ),
            supervisor.Handoff(
                "TASK",
                "coordinator",
                "reviewer",
                ("DONE", "BLOCKED", "FAILED"),
                ("coordinator",),
            ),
            supervisor.Handoff(
                "REVIEW_READY",
                "owner",
                "reviewer",
                ("READY", "CHANGES_REQUIRED", "BLOCKED"),
                ("owner", "coordinator"),
            ),
        )

        def config(role: str):
            return supervisor.Config(
                agent_name=roles[role],
                rooms=("nested-factory",),
                coordinators=frozenset({"alice"}),
                factory_name="nested-factory",
                factory_role=role,
                factory_roles=tuple(roles.items()),
                factory_handoffs=handoffs,
                factory_operator_role="coordinator",
                factory_operator_types=("ACTIVATE", "DIRECTION"),
                contract_sha256="a" * 64,
                workspace=str(tmp_path),
                wait_seconds=5,
                page_limit=16,
                startup_timeout_seconds=30,
                work_timeout_seconds=30,
                completion_grace_seconds=5,
                terminate_grace_seconds=1,
                backoff_initial_seconds=2,
                backoff_max_seconds=10,
            )

        def wait_event(state, objects, next_cursor):
            return {
                "type": "item.completed",
                "item": {
                    "type": "mcp_tool_call",
                    "server": "safeyolo-coord",
                    "tool": "wait_for_coord",
                    "arguments": {
                        "since_sequence": state["safe_cursor"],
                        "timeout_seconds": 5,
                        "limit": 16,
                    },
                    "result": {
                        "structured_content": {
                            "objects": objects,
                            "next_cursor": next_cursor,
                        }
                    },
                    "error": None,
                    "status": "completed",
                },
            }

        def send_event(result, *, room_name, body, notify):
            return {
                "type": "item.completed",
                "item": {
                    "type": "mcp_tool_call",
                    "server": "safeyolo-coord",
                    "tool": "send",
                    "arguments": {
                        "room_name": room_name,
                        "body": body,
                        "notify": notify,
                    },
                    "result": {"structured_content": result},
                    "error": None,
                    "status": "completed",
                },
            }

        room_ids = {room_id: "nested-factory"}
        coordinator_path = tmp_path / "coordinator-state.json"
        coordinator_state = supervisor.empty_state()
        coordinator = supervisor.EventConsumer(
            config("coordinator"),
            coordinator_state,
            coordinator_path,
            room_ids,
        )

        question = await api.send(
            "nested-factory",
            "operator",
            None,
            "What is active, and please check both implementation and security evidence?",
            notify=["alice"],
        )
        assert question["attention_intent"] == {"mode": "targeted"}
        alice_page = await api.wait_for_attention(
            AGENTS["alice"],
            since_sequence=0,
            timeout_seconds=0.1,
        )
        question_edge = _edge_for(alice_page, question["envelope"]["msg_id"])
        assert question_edge is not None
        question_object = await api.read_attention(
            AGENTS["alice"], question_edge["attention_id"]
        )
        coordinator.consume(
            wait_event(coordinator_state, [question_object], alice_page["next_cursor"])
        )
        assert coordinator_state["in_flight"][0]["requires_terminal"] is False

        answer = await api.send(
            "nested-factory",
            "agent",
            AGENTS["alice"],
            "Both checks are being assigned independently.",
            sender_agent_name="alice",
            notify="none",
        )
        assert answer["attention_intent"] == {"mode": "none"}
        coordinator.consume(
            send_event(
                answer,
                room_name="nested-factory",
                body=answer["envelope"]["body"],
                notify="none",
            )
        )
        coordinator.consume({"type": "turn.completed"})
        assert coordinator_state["in_flight"] == []

        forge_target = "https://example.test/checks/forge"
        forge_body = f"TASK target={forge_target} assignee=bob"
        forge_send = await api.send(
            "nested-factory",
            "agent",
            AGENTS["alice"],
            forge_body,
            sender_agent_name="alice",
            notify=["bob"],
        )
        lens_target = "https://example.test/checks/lens"
        lens_body = f"TASK target={lens_target} assignee=codey"
        lens_send = await api.send(
            "nested-factory",
            "agent",
            AGENTS["alice"],
            lens_body,
            sender_agent_name="alice",
            notify=["codey"],
        )
        coordinator.consume(
            send_event(
                forge_send,
                room_name="nested-factory",
                body=forge_body,
                notify=["bob"],
            )
        )
        coordinator.consume(
            send_event(
                lens_send,
                room_name="nested-factory",
                body=lens_body,
                notify=["codey"],
            )
        )
        assert {item["recipient_agent"] for item in coordinator_state["awaiting_handoffs"]} == {
            "bob",
            "codey",
        }

        worker_objects = {}
        for role, sent in (("owner", forge_send), ("reviewer", lens_send)):
            agent_name = roles[role]
            page = await api.wait_for_attention(
                AGENTS[agent_name],
                since_sequence=0,
                timeout_seconds=0.1,
            )
            edge = _edge_for(page, sent["envelope"]["msg_id"])
            assert edge is not None
            worker_objects[role] = await api.read_attention(
                AGENTS[agent_name], edge["attention_id"]
            )

        nr.stop_server()
        nats_client.reset_for_tests()
        nr.start_server(ready_timeout=8.0)
        coordinator_state = supervisor.load_state(coordinator_path)
        coordinator = supervisor.EventConsumer(
            config("coordinator"),
            coordinator_state,
            coordinator_path,
            room_ids,
        )

        responses = []
        for role, target in (("owner", forge_target), ("reviewer", lens_target)):
            request_attention = worker_objects[role]["edge"]["attention_id"]
            sender_name = roles[role]
            response = await api.send(
                "nested-factory",
                "agent",
                AGENTS[sender_name],
                f"DONE target={target} attention_id={request_attention}",
                sender_agent_name=sender_name,
                notify=["alice"],
            )
            responses.append(response)

        response_page = await api.wait_for_attention(
            AGENTS["alice"],
            since_sequence=coordinator_state["safe_cursor"],
            timeout_seconds=0.1,
            limit=16,
        )
        response_objects = []
        for response in responses:
            edge = _edge_for(response_page, response["envelope"]["msg_id"])
            assert edge is not None
            response_objects.append(
                await api.read_attention(AGENTS["alice"], edge["attention_id"])
            )
        coordinator.consume(
            wait_event(
                coordinator_state,
                response_objects,
                response_page["next_cursor"],
            )
        )
        assert coordinator_state["awaiting_handoffs"] == []
        coordinator.consume({"type": "turn.completed"})
        assert coordinator_state["in_flight"] == []

        restarted = supervisor.load_state(coordinator_path)
        replay = supervisor.EventConsumer(
            config("coordinator"),
            restarted,
            coordinator_path,
            room_ids,
        )
        replay.consume(
            wait_event(restarted, response_objects, restarted["safe_cursor"])
        )
        assert restarted["in_flight"] == []
        assert restarted["awaiting_handoffs"] == []

        retained = await api.read_room(
            "nested-factory", "operator", "operator", limit=20
        )
        bodies = [message["body"] for message in retained["messages"]]
        assert "Both checks are being assigned independently." in bodies
        assert any(body.startswith(f"DONE target={forge_target} ") for body in bodies)
        assert any(body.startswith(f"DONE target={lens_target} ") for body in bodies)

    asyncio.run(scenario())


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
        assert targeted["attention_intent"] == {"mode": "targeted"}
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


def test_operator_targeting_is_selective_validated_and_restart_safe(attention_env):
    async def scenario() -> None:
        await _room("operator-target", operator=True)

        targeted = await api.send(
            "operator-target",
            "operator",
            None,
            "operator to bob",
            notify=["bob"],
        )
        bob_page = await api.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=0.1
        )
        bob_edge = _edge_for(bob_page, targeted["envelope"]["msg_id"])
        assert bob_edge is not None
        for name in ("alice", "codey"):
            page = await api.wait_for_attention(
                AGENTS[name], since_sequence=0, timeout_seconds=0.05
            )
            assert _edge_for(page, targeted["envelope"]["msg_id"]) is None

        broadcast = await api.send(
            "operator-target",
            "operator",
            None,
            "operator to room",
            notify="room",
        )
        assert broadcast["attention_intent"] == {"mode": "room"}
        for name in ("alice", "bob", "codey"):
            page = await api.wait_for_attention(
                AGENTS[name], since_sequence=0, timeout_seconds=0.1, limit=20
            )
            assert _edge_for(page, broadcast["envelope"]["msg_id"]) is not None
        canonical = await api.read_attention(
            AGENTS["bob"], bob_edge["attention_id"]
        )
        assert canonical["object"]["sender_kind"] == "operator"
        assert canonical["object"]["sender_agent_id"] is None
        assert canonical["object"]["sender_agent_name"] is None

        operator_history = await api.read_room(
            "operator-target", "operator", "operator"
        )
        operator_targeted = next(
            message
            for message in operator_history["messages"]
            if message["msg_id"] == targeted["envelope"]["msg_id"]
        )
        assert operator_targeted["attention_intent"] == {"mode": "targeted"}

        for target in ("mallory", "dana"):
            with pytest.raises(attention.AttentionTargetError):
                await api.send(
                    "operator-target",
                    "operator",
                    None,
                    "invalid target",
                    notify=[target],
                )
        api.revoke_grant(
            "operator-target",
            "agent",
            AGENTS["bob"],
            operation_id=new_operation_id(),
        )
        with pytest.raises(attention.AttentionTargetError):
            await api.send(
                "operator-target",
                "operator",
                None,
                "revoked target",
                notify=["bob"],
            )

        nr.stop_server()
        nats_client.reset_for_tests()
        nr.start_server(ready_timeout=8.0)
        history = await api.read_room(
            "operator-target", "agent", AGENTS["alice"]
        )
        retained = next(
            message
            for message in history["messages"]
            if message["msg_id"] == targeted["envelope"]["msg_id"]
        )
        assert retained["sender_kind"] == "operator"
        assert retained["sender_agent_id"] is None
        assert retained["sender_agent_name"] is None
        assert "attention_intent" not in retained

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

        # Restart the persistent message substrate while the accepted intent
        # is still absent from SQLite. Recovery must replay the NATS header.
        nr.stop_server()
        nats_client.reset_for_tests()
        nr.start_server(ready_timeout=8.0)
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

        # Feed delivery remains SQLite-only once an edge is materialized.
        # Stopping NATS must not suppress the current-generation edges.
        nr.stop_server()
        nats_client.reset_for_tests()
        without_nats = await api.wait_for_attention(
            AGENTS["bob"],
            since_sequence=recovered["next_cursor"],
            timeout_seconds=0.1,
            limit=20,
        )
        assert {
            first["envelope"]["msg_id"],
            second["envelope"]["msg_id"],
        } <= {edge["object_id"] for edge in without_nats["edges"]}

    asyncio.run(scenario())


def test_wait_checks_ledger_again_after_subscribing(monkeypatch):
    calls = 0

    async def recover(_agent_id):
        return None

    def read(_agent_id, _since, _limit):
        nonlocal calls
        calls += 1
        if calls <= 2:
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
    assert calls == 3


def test_publish_classifies_post_dispatch_timeout_as_ambiguous(monkeypatch):
    class JetStream:
        async def publish(self, *_args, **_kwargs):
            raise nats_client.NatsTimeout()

    async def jetstream():
        return JetStream()

    monkeypatch.setattr(nats_client, "get_jetstream", jetstream)
    with pytest.raises(nats_client.NatsPublishOutcomeUnknown):
        asyncio.run(
            nats_client.publish_envelope(
                "rm-test",
                {"msg_id": new_msg_id()},
                attention_manifest="{}",
            )
        )


def test_publish_preserves_known_pre_dispatch_unavailability(monkeypatch):
    async def unavailable_before_dispatch():
        raise nats_client.NatsUnavailable("no server connection")

    monkeypatch.setattr(
        nats_client,
        "get_jetstream",
        unavailable_before_dispatch,
    )
    with pytest.raises(nats_client.NatsUnavailable) as raised:
        asyncio.run(
            nats_client.publish_envelope(
                "rm-test",
                {"msg_id": new_msg_id()},
                attention_manifest="{}",
            )
        )
    assert type(raised.value) is nats_client.NatsUnavailable


def test_wait_returns_durable_ledger_edge_without_touching_nats(monkeypatch):
    edge = {
        "attention_id": "attn-" + "b" * 32,
        "room_id": "rm-r",
        "kind": "message",
        "object_id": "msg-m",
        "revision_or_sequence": 1,
    }

    def read(_agent_id, _since, _limit):
        return {"edges": [edge], "next_cursor": 1}

    async def forbidden_recovery(_agent_id):
        raise AssertionError("durable ledger delivery must not depend on NATS")

    monkeypatch.setattr(attention, "read_feed", read)
    monkeypatch.setattr(
        attention, "recover_attention_for_agent", forbidden_recovery
    )

    page = asyncio.run(
        attention.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=1, limit=1
        )
    )
    assert page == {"edges": [edge], "next_cursor": 1}


def test_wait_reads_ledger_after_hint_before_retrying_recovery(monkeypatch):
    reads = 0
    recoveries = 0
    edge = {
        "attention_id": "attn-" + "c" * 32,
        "room_id": "rm-r",
        "kind": "message",
        "object_id": "msg-m",
        "revision_or_sequence": 1,
    }

    def read(_agent_id, _since, _limit):
        nonlocal reads
        reads += 1
        if reads < 4:
            return {"edges": [], "next_cursor": 0}
        return {"edges": [edge], "next_cursor": 1}

    async def recover(_agent_id):
        nonlocal recoveries
        recoveries += 1
        if recoveries > 1:
            raise AssertionError("a hinted ledger edge must precede recovery")

    class Subscription:
        async def wait(self, _timeout):
            return True

    class Context:
        async def __aenter__(self):
            return Subscription()

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(attention, "read_feed", read)
    monkeypatch.setattr(attention, "recover_attention_for_agent", recover)
    monkeypatch.setattr(nats_client, "attention_subscription", lambda _agent: Context())

    page = asyncio.run(
        attention.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=1, limit=1
        )
    )
    assert page == {"edges": [edge], "next_cursor": 1}
    assert recoveries == 1
    assert reads == 4


def test_wait_closes_ledger_race_when_hint_subscription_fails(monkeypatch):
    reads = 0
    edge = {
        "attention_id": "attn-" + "d" * 32,
        "room_id": "rm-r",
        "kind": "message",
        "object_id": "msg-m",
        "revision_or_sequence": 1,
    }

    def read(_agent_id, _since, _limit):
        nonlocal reads
        reads += 1
        if reads < 3:
            return {"edges": [], "next_cursor": 0}
        return {"edges": [edge], "next_cursor": 1}

    async def recover(_agent_id):
        return None

    class FailedContext:
        async def __aenter__(self):
            raise nats_client.NatsUnavailable("injected subscribe failure")

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(attention, "read_feed", read)
    monkeypatch.setattr(attention, "recover_attention_for_agent", recover)
    monkeypatch.setattr(
        nats_client,
        "attention_subscription",
        lambda _agent: FailedContext(),
    )

    page = asyncio.run(
        attention.wait_for_attention(
            AGENTS["bob"], since_sequence=0, timeout_seconds=1, limit=1
        )
    )
    assert page == {"edges": [edge], "next_cursor": 1}
    assert reads == 3


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


def test_real_retention_gap_advances_with_one_audit_and_later_edge(attention_env, monkeypatch):
    async def scenario() -> None:
        room_id = await _room("retention-gap")
        real_materialize = attention.materialize_room_attention

        async def leave_unmaterialized(*_args, **_kwargs):
            raise RuntimeError("simulate death before SQLite projection")

        monkeypatch.setattr(
            attention,
            "materialize_room_attention",
            leave_unmaterialized,
        )
        expired = await api.send(
            "retention-gap",
            "agent",
            AGENTS["alice"],
            "will expire before projection",
            notify=["bob"],
        )
        assert expired["attention_status"] == "pending"

        # Use JetStream's real LimitsPolicy/DiscardOld retention path. Reducing
        # max_msgs to one makes the next accepted message advance first_seq
        # across the unmaterialized canonical object.
        js = await nats_client.get_jetstream()
        info = await js.stream_info(nats_client.stream_name_for_room(room_id))
        info.config.max_msgs = 1
        await js.update_stream(config=info.config)
        retained = await api.send(
            "retention-gap",
            "agent",
            AGENTS["alice"],
            "still retained",
            notify=["bob"],
        )
        assert retained["attention_status"] == "pending"
        state = await nats_client.room_stream_state(room_id)
        assert state == {
            "first_seq": retained["sequence"],
            "last_seq": retained["sequence"],
            "messages": 1,
        }

        monkeypatch.setattr(
            attention,
            "materialize_room_attention",
            real_materialize,
        )
        # Competing projectors may observe the same old floor. Only one can
        # durably record/advance it, and both finish on the retained message.
        watermarks = await asyncio.gather(
            real_materialize(room_id),
            real_materialize(room_id),
        )
        assert watermarks == [retained["sequence"], retained["sequence"]]
        assert await real_materialize(room_id) == retained["sequence"]

        page = attention.read_feed(AGENTS["bob"], 0, 20)
        assert _edge_for(page, expired["envelope"]["msg_id"]) is None
        assert _edge_for(page, retained["envelope"]["msg_id"]) is not None
        with store.connect() as conn:
            assert (
                conn.execute(
                    """SELECT count(*) FROM coord_attention_edges
                   WHERE recipient_agent_id = ? AND object_id = ?""",
                    (AGENTS["bob"], retained["envelope"]["msg_id"]),
                ).fetchone()[0]
                == 1
            )
            losses = conn.execute(
                """SELECT payload_json FROM coord_outbox
                   WHERE event_type = 'coord.attention_projection_lost'"""
            ).fetchall()
            watermark = conn.execute(
                """SELECT last_sequence
                   FROM coord_message_attention_projection WHERE room_id = ?""",
                (room_id,),
            ).fetchone()[0]
        assert watermark == retained["sequence"]
        assert len(losses) == 1
        details = json.loads(losses[0]["payload_json"])["details"]
        assert details == {
            "room_id": room_id,
            "from_sequence": expired["sequence"],
            "to_sequence": expired["sequence"],
        }

    asyncio.run(scenario())


def test_send_reports_lost_when_retention_overtakes_its_projection(
    attention_env, monkeypatch
):
    async def scenario() -> None:
        room_id = await _room("send-loss")
        assert await attention.ensure_room_projection(room_id) == 0
        js = await nats_client.get_jetstream()
        info = await js.stream_info(nats_client.stream_name_for_room(room_id))
        info.config.max_msgs = 1
        await js.update_stream(config=info.config)

        real_publish = nats_client.publish_envelope

        async def publish_then_evict(
            publish_room_id: str,
            envelope: dict,
            *,
            attention_manifest: str,
        ) -> int:
            sequence = await real_publish(
                publish_room_id,
                envelope,
                attention_manifest=attention_manifest,
            )
            filler_id = new_msg_id()
            filler = Envelope(
                msg_id=filler_id,
                sent_at=store.now_ms(),
                sender_kind="operator",
                sender_agent_id=None,
                sender_agent_name=None,
                origin_instance_id=get_or_create_instance_id(),
                content_type="text/markdown",
                body="retention filler",
            ).to_dict()
            filler_manifest = attention.AttentionManifest(
                msg_id=filler_id,
                mode="none",
                recipients=(),
            )
            await js.publish(
                nats_client.subject_for_room(publish_room_id),
                json.dumps(filler).encode(),
                stream=nats_client.stream_name_for_room(publish_room_id),
                headers={
                    "Nats-Msg-Id": filler_id,
                    INTERNAL_ATTENTION_HEADER: filler_manifest.to_header(),
                },
            )
            return sequence

        monkeypatch.setattr(
            nats_client,
            "publish_envelope",
            publish_then_evict,
        )
        accepted = await api.send(
            "send-loss",
            "agent",
            AGENTS["alice"],
            "accepted then immediately expired",
            notify=["bob"],
        )
        assert accepted["attention_status"] == "lost"
        assert attention.projection_sequence_was_lost(
            room_id,
            accepted["sequence"],
        )
        assert _edge_for(
            attention.read_feed(AGENTS["bob"], 0, 20),
            accepted["envelope"]["msg_id"],
        ) is None

    asyncio.run(scenario())


def test_corrupt_room_does_not_stop_later_healthy_room_recovery(attention_env):
    async def scenario() -> None:
        room_ids = {
            "left": await _room("left"),
            "right": await _room("right"),
        }
        names_by_id = {room_id: name for name, room_id in room_ids.items()}
        corrupt_id, healthy_id = sorted(names_by_id)
        await attention.ensure_room_projection(corrupt_id)
        await attention.ensure_room_projection(healthy_id)

        corrupt_msg_id = new_msg_id()
        corrupt_envelope = Envelope(
            msg_id=corrupt_msg_id,
            sent_at=store.now_ms(),
            sender_kind="agent",
            sender_agent_id=AGENTS["alice"],
            sender_agent_name="alice",
            origin_instance_id=get_or_create_instance_id(),
            content_type="text/markdown",
            body="corrupt first room",
        ).to_dict()
        js = await nats_client.get_jetstream()
        await js.publish(
            nats_client.subject_for_room(corrupt_id),
            json.dumps(corrupt_envelope).encode(),
            stream=nats_client.stream_name_for_room(corrupt_id),
            headers={
                "Nats-Msg-Id": corrupt_msg_id,
                INTERNAL_ATTENTION_HEADER: "{broken",
            },
        )

        healthy_msg_id = new_msg_id()
        with store.connect() as conn:
            healthy_manifest = attention.build_message_manifest(
                conn,
                room_id=healthy_id,
                msg_id=healthy_msg_id,
                sender_agent_id=AGENTS["alice"],
                notify=["bob"],
            )
        healthy_envelope = Envelope(
            msg_id=healthy_msg_id,
            sent_at=store.now_ms(),
            sender_kind="agent",
            sender_agent_id=AGENTS["alice"],
            sender_agent_name="alice",
            origin_instance_id=get_or_create_instance_id(),
            content_type="text/markdown",
            body="healthy later room",
        ).to_dict()
        await nats_client.publish_envelope(
            healthy_id,
            healthy_envelope,
            attention_manifest=healthy_manifest.to_header(),
        )

        # recover_all orders by room_id, so the corrupt room is guaranteed to
        # be attempted first. Its loud failure is reported only after the
        # unrelated retained manifest has materialized.
        with pytest.raises(
            nats_client.CoordDataError,
            match=corrupt_id,
        ):
            await attention.recover_all_attention()
        recovered = attention.read_feed(AGENTS["bob"], 0, 20)
        edge = _edge_for(recovered, healthy_msg_id)
        assert edge is not None

        with pytest.raises(nats_client.CoordDataError, match=corrupt_id):
            await attention.recover_all_attention()
        replay = attention.read_feed(AGENTS["bob"], 0, 20)
        assert replay["edges"] == recovered["edges"]
        with store.connect() as conn:
            assert (
                conn.execute(
                    """SELECT count(*) FROM coord_attention_edges
                   WHERE recipient_agent_id = ? AND object_id = ?""",
                    (AGENTS["bob"], healthy_msg_id),
                ).fetchone()[0]
                == 1
            )

    asyncio.run(scenario())


def test_new_projection_baselines_all_retained_legacy_history(attention_env, monkeypatch):
    async def scenario() -> None:
        room_id = await _room("legacy-baseline")
        js = await nats_client.get_jetstream()
        for index in range(50):
            msg_id = new_msg_id()
            envelope = Envelope(
                msg_id=msg_id,
                sent_at=store.now_ms(),
                sender_kind="agent",
                sender_agent_id=AGENTS["alice"],
                sender_agent_name="alice",
                origin_instance_id=get_or_create_instance_id(),
                content_type="text/markdown",
                body=f"legacy {index}",
            ).to_dict()
            await js.publish(
                nats_client.subject_for_room(room_id),
                json.dumps(envelope).encode(),
                stream=nats_client.stream_name_for_room(room_id),
                headers={"Nats-Msg-Id": msg_id},
            )

        baselines = await asyncio.gather(
            attention.ensure_room_projection(room_id),
            attention.ensure_room_projection(room_id),
        )
        assert baselines == [50, 50]

        async def forbidden_fetch(*_args, **_kwargs):
            raise AssertionError("known legacy history must not be rescanned")

        monkeypatch.setattr(nats_client, "fetch_since", forbidden_fetch)
        assert await attention.materialize_room_attention(room_id) == 50
        assert attention.read_feed(AGENTS["bob"], 0, 20) == {
            "edges": [],
            "next_cursor": 0,
        }

    asyncio.run(scenario())


def test_feed_pagination_revocation_interleaving_and_ahead_cursor(attention_env):
    async def scenario() -> None:
        await _room("feed-one")
        await _room("feed-two")
        sent = []
        for room_name, body in (
            ("feed-one", "one"),
            ("feed-two", "two"),
            ("feed-one", "three"),
            ("feed-two", "four"),
        ):
            sent.append(
                await api.send(
                    room_name,
                    "agent",
                    AGENTS["alice"],
                    body,
                    notify=["bob"],
                )
            )

        first = attention.read_feed(AGENTS["bob"], 0, 2)
        second = attention.read_feed(AGENTS["bob"], first["next_cursor"], 2)
        assert [edge["object_id"] for edge in first["edges"]] == [
            sent[0]["envelope"]["msg_id"],
            sent[1]["envelope"]["msg_id"],
        ]
        assert first["next_cursor"] == 2
        assert [edge["object_id"] for edge in second["edges"]] == [
            sent[2]["envelope"]["msg_id"],
            sent[3]["envelope"]["msg_id"],
        ]
        assert second["next_cursor"] == 4
        assert attention.read_feed(AGENTS["bob"], 99, 20) == {
            "edges": [],
            "next_cursor": 99,
        }

        api.revoke_grant(
            "feed-one",
            "agent",
            AGENTS["bob"],
            operation_id=new_operation_id(),
        )
        after_skip = attention.read_feed(AGENTS["bob"], 0, 1)
        assert [edge["object_id"] for edge in after_skip["edges"]] == [sent[1]["envelope"]["msg_id"]]
        assert after_skip["next_cursor"] == 2
        final = attention.read_feed(
            AGENTS["bob"],
            after_skip["next_cursor"],
            1,
        )
        assert [edge["object_id"] for edge in final["edges"]] == [sent[3]["envelope"]["msg_id"]]
        assert final["next_cursor"] == 4

    asyncio.run(scenario())


def test_feed_highwater_and_rows_share_one_sqlite_snapshot(attention_env, monkeypatch):
    async def setup() -> tuple[str, str, int]:
        room_id = await _room("snapshot")
        first = await api.send(
            "snapshot",
            "agent",
            AGENTS["alice"],
            "already visible",
            notify=["bob"],
        )
        with store.connect() as conn:
            generation = conn.execute(
                """SELECT granted_at FROM memberships
                   WHERE room_id = ? AND principal_id = ? AND revoked_at IS NULL""",
                (room_id, AGENTS["bob"]),
            ).fetchone()[0]
        return room_id, first["envelope"]["msg_id"], generation

    room_id, first_msg_id, generation = asyncio.run(setup())
    real_connect = store.connect
    raced = False
    second_msg_id = "msg-snapshot-race"

    def insert_concurrent_edge() -> None:
        with real_connect() as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute(
                """UPDATE coord_attention_feeds SET last_sequence = 2
                   WHERE recipient_agent_id = ?""",
                (AGENTS["bob"],),
            )
            writer.execute(
                """INSERT INTO coord_attention_edges
                   (recipient_agent_id, feed_sequence, attention_id, room_id,
                    kind, object_id, revision_or_sequence,
                    membership_granted_at, created_at)
                   VALUES (?, 2, ?, ?, 'message', ?, 2, ?, ?)""",
                (
                    AGENTS["bob"],
                    "attn-" + "9" * 32,
                    room_id,
                    second_msg_id,
                    generation,
                    store.now_ms(),
                ),
            )
            writer.execute("COMMIT")

    class RacingConnection:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, sql, parameters=()):
            nonlocal raced
            if "SELECT e.* FROM coord_attention_edges" in sql and not raced:
                raced = True
                insert_concurrent_edge()
            return self._connection.execute(sql, parameters)

        def __getattr__(self, name):
            return getattr(self._connection, name)

    @contextmanager
    def racing_connect():
        with real_connect() as connection:
            yield RacingConnection(connection)

    monkeypatch.setattr(attention.store, "connect", racing_connect)
    page = attention.read_feed(AGENTS["bob"], 0, 20)
    assert raced
    assert [edge["object_id"] for edge in page["edges"]] == [first_msg_id]
    assert page["next_cursor"] == 1
    next_page = attention.read_feed(AGENTS["bob"], page["next_cursor"], 20)
    assert [edge["object_id"] for edge in next_page["edges"]] == [second_msg_id]
    assert next_page["next_cursor"] == 2


@pytest.mark.timeout(45)
def test_real_broker_acceptance_with_ambiguous_puback_recovers_once(
    attention_env,
    monkeypatch,
):
    async def scenario() -> None:
        room_id = await _room("ambiguous-puback")
        real_publish = nats_client.publish_envelope
        accepted_sequence = None

        async def accept_then_hide_puback(
            publish_room_id: str,
            envelope: dict,
            *,
            attention_manifest: str,
        ) -> int:
            nonlocal accepted_sequence
            accepted_sequence = await real_publish(
                publish_room_id,
                envelope,
                attention_manifest=attention_manifest,
            )
            # The real broker has stored the canonical object, but the caller
            # observes the same result it would see if the PubAck were lost in
            # transit after acceptance.
            raise nats_client.NatsPublishOutcomeUnknown(
                "connection closed after broker acceptance"
            )

        monkeypatch.setattr(
            nats_client,
            "publish_envelope",
            accept_then_hide_puback,
        )
        with pytest.raises(nats_client.NatsPublishOutcomeUnknown):
            await api.send(
                "ambiguous-puback",
                "agent",
                AGENTS["alice"],
                "accepted without a caller-visible PubAck",
                notify=["bob"],
            )

        assert accepted_sequence == 1
        assert await nats_client.room_stream_state(room_id) == {
            "first_seq": 1,
            "last_seq": 1,
            "messages": 1,
        }
        assert attention.read_feed(AGENTS["bob"], 0, 20)["edges"] == []

        monkeypatch.setattr(nats_client, "publish_envelope", real_publish)
        await api.recover_attention()
        recovered = attention.read_feed(AGENTS["bob"], 0, 20)
        await api.recover_attention()
        replayed = attention.read_feed(AGENTS["bob"], 0, 20)
        assert len(recovered["edges"]) == 1
        assert recovered == replayed
        assert recovered["edges"][0]["revision_or_sequence"] == accepted_sequence

    asyncio.run(scenario())


@pytest.mark.timeout(45)
def test_process_death_after_puback_recovers_in_fresh_process_after_nats_restart(
    attention_env,
):
    async def setup() -> tuple[str, int]:
        room_id = await _room("process-crash")
        baseline = await attention.ensure_room_projection(room_id)
        return room_id, baseline

    room_id, baseline = asyncio.run(setup())
    assert baseline == 0
    child_env = dict(os.environ)
    send_script = f"""
import asyncio
import os
from safeyolo.coord import api, attention

async def die_after_puback(*_args, **_kwargs):
    os._exit(86)

attention.materialize_room_attention = die_after_puback
asyncio.run(api.send(
    "process-crash",
    "agent",
    {AGENTS["alice"]!r},
    "accepted but caller saw process death",
    sender_agent_name="alice",
    notify=["bob"],
))
raise SystemExit(99)
"""
    died = subprocess.run(
        [sys.executable, "-c", send_script],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert died.returncode == 86, died.stderr

    state = asyncio.run(nats_client.room_stream_state(room_id))
    assert state["last_seq"] == 1 and state["messages"] == 1
    with store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM coord_attention_edges").fetchone()[0] == 0

    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)

    recover_script = f"""
import asyncio
import json
from safeyolo.coord import api, attention

api.bootstrap()
asyncio.run(api.recover_attention())
print("RECOVERED=" + json.dumps(attention.read_feed({AGENTS["bob"]!r}, 0, 20), sort_keys=True))
"""

    def recover_in_fresh_process() -> dict:
        completed = subprocess.run(
            [sys.executable, "-c", recover_script],
            env=child_env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        line = next(value for value in completed.stdout.splitlines() if value.startswith("RECOVERED="))
        return json.loads(line.removeprefix("RECOVERED="))

    recovered = recover_in_fresh_process()
    replayed = recover_in_fresh_process()
    assert len(recovered["edges"]) == 1
    assert replayed == recovered
    with store.connect() as conn:
        assert (
            conn.execute(
                """SELECT count(*) FROM coord_attention_edges
               WHERE recipient_agent_id = ?""",
                (AGENTS["bob"],),
            ).fetchone()[0]
            == 1
        )
