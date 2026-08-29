from __future__ import annotations

from contextlib import contextmanager
from datetime import date
from pathlib import Path

import pytest

from safeyolo.coord import api, dispatch_schedule
from safeyolo.coord.nats_client import NatsPublishOutcomeUnknown


def prepared(body: str = "TASK relay test") -> dict:
    return {
        "room_id": "rm-" + "1" * 32,
        "since_sequence": 10,
        "envelope": {
            "msg_id": "msg-" + "2" * 32,
            "sent_at": 1_800_000_000_000,
            "sender_kind": "operator",
            "sender_agent_id": None,
            "sender_agent_name": None,
            "origin_instance_id": "sy-" + "3" * 32,
            "content_type": "text/markdown",
            "body": body,
        },
        "attention_manifest": "{}",
    }


def test_task_has_deterministic_daily_weekly_and_monthly_boundaries() -> None:
    key, body = dispatch_schedule.render_task(date(2026, 6, 1), weekly_on="monday")
    assert key == "dispatch-production/2026-06-01"
    assert "daily 2026-06-01" in body
    assert "weekly 2026-W22 (2026-05-25 through 2026-05-31)" in body
    assert "monthly 2026-05 (2026-05-01 through 2026-05-31)" in body
    assert body.count("TASK relay") == 1
    assert "valid to produce nothing" in body
    assert "configured weekly boundary is monday" in body
    assert "dispatch-publication" in body
    assert "must not hold an issue delivery claim or occupy Forge or Lens" in body

    _, automatic = dispatch_schedule.render_task(
        date(2026, 6, 2),
        weekly_on="monday",
        publication_mode="automatic",
    )
    assert "operator explicitly selected automatic publication" in automatic
    assert "without a publication PR" in automatic


@pytest.mark.asyncio
async def test_preparation_mints_only_a_canonical_operator_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grants: list[tuple] = []

    @contextmanager
    def connect():
        yield object()

    class Manifest:
        def to_header(self):
            return "trusted-manifest"

    async def ensure_room_projection(room_id):
        assert room_id == "rm-" + "1" * 32

    async def room_stream_state(room_id):
        assert room_id == "rm-" + "1" * 32
        return {"last_seq": 41}

    def check_grant(_conn, room_id, principal_kind, principal_id, permission):
        grants.append((room_id, principal_kind, principal_id, permission))

    def build_message_manifest(_conn, **kwargs):
        assert kwargs["sender_agent_id"] is None
        assert kwargs["notify"] == ["relay"]
        return Manifest()

    monkeypatch.setattr(api.store, "connect", connect)
    monkeypatch.setattr(api.store, "now_ms", lambda: 1_800_000_000_000)
    monkeypatch.setattr(api, "_resolve_room", lambda _conn, _room: "rm-" + "1" * 32)
    monkeypatch.setattr(api, "_check_grant", check_grant)
    monkeypatch.setattr(api.attention, "ensure_room_projection", ensure_room_projection)
    monkeypatch.setattr(api.attention, "build_message_manifest", build_message_manifest)
    monkeypatch.setattr(api.nats_client, "room_stream_state", room_stream_state)
    monkeypatch.setattr(api, "new_msg_id", lambda: "msg-" + "2" * 32)
    monkeypatch.setattr(api, "get_or_create_instance_id", lambda: "sy-" + "3" * 32)

    value = await api.prepare_operator_message(
        "backlog",
        "TASK relay produce",
        notify=["relay"],
    )
    assert value["since_sequence"] == 41
    assert value["attention_manifest"] == "trusted-manifest"
    assert value["envelope"] == {
        "msg_id": "msg-" + "2" * 32,
        "sent_at": 1_800_000_000_000,
        "sender_kind": "operator",
        "sender_agent_id": None,
        "sender_agent_name": None,
        "origin_instance_id": "sy-" + "3" * 32,
        "content_type": "text/markdown",
        "body": "TASK relay produce",
    }
    assert grants == [
        ("rm-" + "1" * 32, "operator", "operator", "send"),
        ("rm-" + "1" * 32, "operator", "operator", "send"),
    ]


def test_prepared_envelope_cannot_impersonate_an_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = prepared()
    value["envelope"]["sender_kind"] = "agent"
    value["envelope"]["sender_agent_id"] = "ag-" + "4" * 32
    monkeypatch.setattr(api, "get_or_create_instance_id", lambda: "sy-" + "3" * 32)
    with pytest.raises(ValueError, match="canonical local operator"):
        api._validate_prepared_operator_message("backlog", value)


@pytest.mark.asyncio
async def test_delivery_is_operator_prepared_targeted_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple] = []

    async def prepare_operator_message(room, body, **kwargs):
        calls.append(("prepare", room, body, kwargs))
        return prepared(body)

    async def find_prepared_operator_message(room, value):
        calls.append(("find", room, value))
        return None

    async def publish_prepared_operator_message(room, value):
        calls.append(("publish", room, value))
        return {"sequence": 17}

    monkeypatch.setattr(dispatch_schedule.api, "prepare_operator_message", prepare_operator_message)
    monkeypatch.setattr(
        dispatch_schedule.api,
        "find_prepared_operator_message",
        find_prepared_operator_message,
    )
    monkeypatch.setattr(
        dispatch_schedule.api,
        "publish_prepared_operator_message",
        publish_prepared_operator_message,
    )
    ledger = dispatch_schedule.DispatchScheduleLedger(tmp_path / "dispatch.json")
    first = await dispatch_schedule.deliver_task(
        "backlog",
        date(2026, 8, 29),
        ledger=ledger,
    )
    second = await dispatch_schedule.deliver_task(
        "backlog",
        date(2026, 8, 29),
        ledger=ledger,
    )

    assert first.status == "delivered"
    assert second.status == "already-delivered"
    assert first.sequence == second.sequence == 17
    assert [call[0] for call in calls] == ["prepare", "find", "publish"]
    prepare_call = calls[0]
    assert prepare_call[1] == "backlog"
    assert prepare_call[3] == {
        "declared_content_type": "text/markdown",
        "notify": ["relay"],
    }
    assert prepare_call[2].startswith("TASK relay ")


@pytest.mark.asyncio
async def test_unknown_publish_reconciles_without_a_second_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    published = 0
    visible = False

    async def prepare_operator_message(_room, body, **_kwargs):
        return prepared(body)

    async def find_prepared_operator_message(_room, _value):
        if visible:
            return {"msg_id": "msg-" + "2" * 32, "sequence": 29}
        return None

    async def publish_prepared_operator_message(_room, _value):
        nonlocal published, visible
        published += 1
        visible = True
        raise NatsPublishOutcomeUnknown("lost acknowledgement")

    monkeypatch.setattr(dispatch_schedule.api, "prepare_operator_message", prepare_operator_message)
    monkeypatch.setattr(
        dispatch_schedule.api,
        "find_prepared_operator_message",
        find_prepared_operator_message,
    )
    monkeypatch.setattr(
        dispatch_schedule.api,
        "publish_prepared_operator_message",
        publish_prepared_operator_message,
    )
    ledger = dispatch_schedule.DispatchScheduleLedger(tmp_path / "dispatch.json")
    with pytest.raises(NatsPublishOutcomeUnknown):
        await dispatch_schedule.deliver_task(
            "backlog",
            date(2026, 8, 29),
            ledger=ledger,
        )
    result = await dispatch_schedule.deliver_task(
        "backlog",
        date(2026, 8, 29),
        ledger=ledger,
    )
    assert result.status == "reconciled"
    assert result.sequence == 29
    assert published == 1


def test_schedule_change_for_same_task_key_fails_closed(
    tmp_path: Path,
) -> None:
    ledger = dispatch_schedule.DispatchScheduleLedger(tmp_path / "dispatch.json")
    records = {
        "dispatch-production/2026-08-29": {
            "body_sha256": "different",
            "prepared": prepared(),
            "room": "backlog",
            "sequence": 1,
            "status": "delivered",
        }
    }
    with ledger.locked():
        ledger.write_unlocked(records)

    with pytest.raises(dispatch_schedule.DispatchScheduleError, match="different room or schedule"):
        import asyncio

        asyncio.run(
            dispatch_schedule.deliver_task(
                "other",
                date(2026, 8, 29),
                ledger=ledger,
            )
        )
