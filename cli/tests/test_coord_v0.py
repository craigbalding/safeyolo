"""Smoke tests for the coord v0 substrate (#371 dogfood).

Not exhaustive — this is disposable code that #371's v1 replaces. Tests here
guard against v0 regressions during the dogfood so the agents building v1 can
trust the substrate.
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


def test_bootstrap_is_idempotent(coord_env):
    a = api.bootstrap()
    b = api.bootstrap()
    assert a == b


def test_agent_id_is_distinct_from_name(coord_env):
    aid = api.add_agent("alice")
    assert aid != "alice"
    assert aid.startswith("ag-")
    # Re-add same name is rejected in v0
    with pytest.raises(api.ConflictError):
        api.add_agent("alice")


def test_room_grant_and_send_and_read(coord_env):
    alice = api.add_agent("alice")
    bob = api.add_agent("bob")
    api.create_room("huddle")
    api.grant("huddle", "agent", alice)
    api.grant("huddle", "agent", bob)

    r = api.send("huddle", "agent", alice, "hey bob")
    assert r["envelope"]["sender_agent_id"] == alice
    assert r["envelope"]["sender_kind"] == "agent"
    assert r["envelope"]["origin_instance_id"].startswith("sy-")
    assert r["sequence"] > 0

    page = api.read_room("huddle", "agent", bob)
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "hey bob"
    assert page["messages"][0]["sender_agent_id"] == alice
    assert page["has_more"] is False
    assert page["history_truncated"] is False


def test_grant_enforcement(coord_env):
    alice = api.add_agent("alice")
    dave = api.add_agent("dave")
    api.create_room("huddle")
    api.grant("huddle", "agent", alice)

    with pytest.raises(api.GrantError):
        api.send("huddle", "agent", dave, "sneaking in")
    with pytest.raises(api.GrantError):
        api.read_room("huddle", "agent", dave)
    with pytest.raises(api.GrantError):
        api.join_room("huddle", "agent", dave)


def test_operator_send_and_agent_read(coord_env):
    alice = api.add_agent("alice")
    api.create_room("huddle")
    api.grant("huddle", "agent", alice)
    api.grant("huddle", "operator", "operator")

    api.send("huddle", "operator", None, "kicking off")
    page = api.read_room("huddle", "agent", alice)
    assert page["messages"][0]["sender_kind"] == "operator"
    assert page["messages"][0]["sender_agent_id"] is None


def test_envelope_field_validation(coord_env):
    alice = api.add_agent("alice")
    api.create_room("r")
    api.grant("r", "agent", alice)

    with pytest.raises(ValueError, match="sender_agent_id required"):
        api.send("r", "agent", None, "x")
    with pytest.raises(ValueError, match="must be None"):
        api.send("r", "operator", "some-id", "x")
    with pytest.raises(ValueError, match="content_type"):
        api.send("r", "agent", alice, "x", declared_content_type="application/exe")


def test_read_room_pagination_bound(coord_env):
    alice = api.add_agent("alice")
    api.create_room("r")
    api.grant("r", "agent", alice)
    for i in range(5):
        api.send("r", "agent", alice, f"msg {i}")

    page = api.read_room("r", "agent", alice, limit=3)
    assert len(page["messages"]) == 3
    assert page["has_more"] is True

    page2 = api.read_room("r", "agent", alice, since_sequence=page["next_cursor"], limit=3)
    assert len(page2["messages"]) == 2
    assert page2["has_more"] is False


@pytest.mark.timeout(10)
def test_wait_for_message_wakes(coord_env):
    alice = api.add_agent("alice")
    bob = api.add_agent("bob")
    api.create_room("r")
    api.grant("r", "agent", alice)
    api.grant("r", "agent", bob)

    async def scenario():
        async def delayed_send():
            await asyncio.sleep(0.2)
            return api.send("r", "agent", alice, "wake up")

        _, page = await asyncio.gather(
            delayed_send(),
            api.wait_for_message("r", "agent", bob, since_sequence=0, timeout_seconds=3),
        )
        return page

    page = asyncio.run(scenario())
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "wake up"


@pytest.mark.timeout(5)
def test_wait_for_message_times_out_gracefully(coord_env):
    alice = api.add_agent("alice")
    api.create_room("r")
    api.grant("r", "agent", alice)

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", alice, since_sequence=0,
            timeout_seconds=0.5, poll_interval_seconds=0.1,
        )

    page = asyncio.run(scenario())
    assert page["messages"] == []
