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


@pytest.mark.timeout(5)
def test_wait_excludes_self_by_default(coord_env):
    """Reviewer point 4: an agent's own send does not wake it."""
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.send("r", "agent", AGENT_A, "my own message")

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=0.5, poll_interval_seconds=0.1,
        )

    page = asyncio.run(scenario())
    assert page["messages"] == []


@pytest.mark.timeout(5)
def test_wait_includes_self_when_asked(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.send("r", "agent", AGENT_A, "my own message")

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=1, poll_interval_seconds=0.1,
            exclude_self=False,
        )

    page = asyncio.run(scenario())
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "my own message"


def test_read_room_always_includes_self(coord_env):
    """Canonical history is inclusive per reviewer point 4."""
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.send("r", "agent", AGENT_A, "my own message")

    page = api.read_room("r", "agent", AGENT_A)
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "my own message"


@pytest.mark.timeout(5)
def test_wait_default_limit_is_one(coord_env):
    """Reviewer point 5: wake is an attention edge, not a bulk fetch."""
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)
    for i in range(5):
        api.send("r", "agent", AGENT_B, f"msg {i}")

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=1, poll_interval_seconds=0.05,
        )

    page = asyncio.run(scenario())
    assert len(page["messages"]) == 1
    assert page["has_more"] is True


def test_revoke_grant_returns_true_when_active(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    assert api.revoke_grant("r", "agent", AGENT_A) is True


def test_revoke_grant_idempotent(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.revoke_grant("r", "agent", AGENT_A)
    assert api.revoke_grant("r", "agent", AGENT_A) is False


def test_revoke_then_ops_fail(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.send("r", "agent", AGENT_A, "before")
    api.revoke_grant("r", "agent", AGENT_A)

    with pytest.raises(api.GrantError):
        api.join_room("r", "agent", AGENT_A)
    with pytest.raises(api.GrantError):
        api.send("r", "agent", AGENT_A, "denied")
    with pytest.raises(api.GrantError):
        api.read_room("r", "agent", AGENT_A)


def test_regrant_exposes_retained_history(coord_env):
    """Room semantic per #371: re-grant sees retained history."""
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    api.send("r", "agent", AGENT_B, "before revoke")
    api.revoke_grant("r", "agent", AGENT_A)
    api.send("r", "agent", AGENT_B, "during revoke")
    api.grant("r", "agent", AGENT_A)

    page = api.read_room("r", "agent", AGENT_A)
    bodies = [m["body"] for m in page["messages"]]
    assert "before revoke" in bodies
    assert "during revoke" in bodies


def test_body_over_max_rejected(coord_env):
    api.create_room("r")
    api.grant("r", "agent", AGENT_A)
    big = "x" * (api.MAX_BODY_BYTES + 1024)
    with pytest.raises(ValueError, match="body too large"):
        api.send("r", "agent", AGENT_A, big)
