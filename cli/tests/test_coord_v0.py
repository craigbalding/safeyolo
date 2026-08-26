"""Smoke tests for the coord v0 substrate (#371 dogfood).

The coord layer treats agent_id as an opaque string. Agent-registry
integration is exercised in tests/test_agent_api_coord.py; here we only
verify the storage/grant/API surface.
"""

from __future__ import annotations

import asyncio

import pytest

from safeyolo.coord import api


@pytest.fixture
def coord_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path))
    api.bootstrap()
    return tmp_path


AGENT_A = "ag-aaaa000000000000000000000000aaaa"
AGENT_B = "ag-bbbb000000000000000000000000bbbb"
AGENT_C = "ag-cccc000000000000000000000000cccc"


def test_bootstrap_is_idempotent(coord_env):
    a = api.bootstrap()
    b = api.bootstrap()
    assert a == b


def test_room_grant_and_send_and_read(coord_env):
    api.create_room("huddle")
    api.grant("huddle", "agent", AGENT_A)
    api.grant("huddle", "agent", AGENT_B)

    r = api.send("huddle", "agent", AGENT_A, "hey bob")
    assert r["envelope"]["sender_agent_id"] == AGENT_A
    assert r["envelope"]["sender_kind"] == "agent"
    assert r["envelope"]["origin_instance_id"].startswith("sy-")
    assert r["sequence"] > 0

    page = api.read_room("huddle", "agent", AGENT_B)
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "hey bob"
    assert page["messages"][0]["sender_agent_id"] == AGENT_A
    assert page["has_more"] is False
    assert page["history_truncated"] is False


def test_grant_enforcement(coord_env):
    api.create_room("huddle")
    api.grant("huddle", "agent", AGENT_A)

    with pytest.raises(api.GrantError):
        api.send("huddle", "agent", AGENT_C, "sneaking in")
    with pytest.raises(api.GrantError):
        api.read_room("huddle", "agent", AGENT_C)
    with pytest.raises(api.GrantError):
        api.join_room("huddle", "agent", AGENT_C)


def test_operator_send_and_agent_read(coord_env):
    api.create_room("huddle")
    api.grant("huddle", "agent", AGENT_A)
    api.grant("huddle", "operator", "operator")

    api.send("huddle", "operator", None, "kicking off")
    page = api.read_room("huddle", "agent", AGENT_A)
    assert page["messages"][0]["sender_kind"] == "operator"
    assert page["messages"][0]["sender_agent_id"] is None


def test_envelope_field_validation(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)

    with pytest.raises(ValueError, match="sender_agent_id required"):
        api.send("r", "agent", None, "x")
    with pytest.raises(ValueError, match="must be None"):
        api.send("r", "operator", "some-id", "x")
    with pytest.raises(ValueError, match="content_type"):
        api.send("r", "agent", AGENT_A, "x", declared_content_type="application/exe")


def test_read_room_pagination_bound(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    for i in range(5):
        api.send("r", "agent", AGENT_A, f"msg {i}")

    page = api.read_room("r", "agent", AGENT_A, limit=3)
    assert len(page["messages"]) == 3
    assert page["has_more"] is True

    page2 = api.read_room("r", "agent", AGENT_A, since_sequence=page["next_cursor"], limit=3)
    assert len(page2["messages"]) == 2
    assert page2["has_more"] is False


@pytest.mark.timeout(10)
def test_wait_for_message_wakes(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    async def scenario():
        async def delayed_send():
            await asyncio.sleep(0.2)
            return api.send("r", "agent", AGENT_A, "wake up")

        _, page = await asyncio.gather(
            delayed_send(),
            api.wait_for_message("r", "agent", AGENT_B, since_sequence=0, timeout_seconds=3),
        )
        return page

    page = asyncio.run(scenario())
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "wake up"


@pytest.mark.timeout(5)
def test_wait_for_message_times_out_gracefully(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=0.5, poll_interval_seconds=0.1,
        )

    page = asyncio.run(scenario())
    assert page["messages"] == []
