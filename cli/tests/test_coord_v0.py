"""Smoke tests for the coord substrate.

The coord layer treats agent_id as an opaque string. Agent-registry
integration is exercised in tests/test_agent_api_coord.py; here we only
verify the storage/grant/API surface.

v1 (JetStream): the API layer is async — `create_room`, `send`,
`read_room`, `wait_for_message` all `await` into `nats_client`. These
tests wrap each call in `asyncio.run(...)` so the sync test surface
stays intact.
"""

from __future__ import annotations

import asyncio

import pytest

from safeyolo.coord import api, nats_client
from safeyolo.coord import nats_runtime as nr


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def coord_env(nats_env):
    """Isolated coord dir + running nats-server + reset client state.

    `nats_env` (from conftest.py) already isolates SAFEYOLO_COORD_DATA_DIR
    and symlinks in the session-cached nats-server binary. On top of that
    we start the server, reset the module-level nats-py client (so a stale
    connection from a prior test doesn't leak in), and bootstrap the
    coord schema. Teardown stops the server via `nats_env`.
    """
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    return nats_env


AGENT_A = "ag-aaaa000000000000000000000000aaaa"
AGENT_B = "ag-bbbb000000000000000000000000bbbb"
AGENT_C = "ag-cccc000000000000000000000000cccc"


def test_bootstrap_is_idempotent(coord_env):
    a = api.bootstrap()
    b = api.bootstrap()
    assert a == b


def test_room_grant_and_send_and_read(coord_env):
    _run(api.create_room("huddle"))
    api.grant("huddle", "agent", AGENT_A)
    api.grant("huddle", "agent", AGENT_B)

    r = _run(api.send("huddle", "agent", AGENT_A, "hey bob", sender_agent_name="alice"))
    assert r["envelope"]["sender_agent_id"] == AGENT_A
    assert r["envelope"]["sender_agent_name"] == "alice"  # #22
    assert r["envelope"]["sender_kind"] == "agent"
    assert r["envelope"]["origin_instance_id"].startswith("sy-")
    assert r["sequence"] > 0

    page = _run(api.read_room("huddle", "agent", AGENT_B))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "hey bob"
    assert page["messages"][0]["sender_agent_id"] == AGENT_A
    assert page["messages"][0]["sender_agent_name"] == "alice"  # #22 persisted
    assert page["has_more"] is False
    assert page["history_truncated"] is False


def test_operator_send_has_null_agent_name(coord_env):
    """Per #22: operator envelopes must have sender_agent_name=None on the
    wire — operator identity is not a registry name."""
    _run(api.create_room("r"))
    api.grant("r", "operator", "operator")
    r = _run(api.send("r", "operator", None, "kicking off"))
    assert r["envelope"]["sender_kind"] == "operator"
    assert r["envelope"]["sender_agent_id"] is None
    assert r["envelope"]["sender_agent_name"] is None


def test_operator_send_rejects_explicit_agent_name(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "operator", "operator")
    with pytest.raises(ValueError, match="sender_agent_name must be None"):
        _run(api.send("r", "operator", None, "x", sender_agent_name="oops"))


def test_list_members_dedups_and_is_ordered(coord_env):
    """Per reviewer point on #22: multiple active grant rows for the same
    principal must NOT appear multiple times in the roster."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_A)  # duplicate
    api.grant("r", "agent", AGENT_B)
    api.grant("r", "operator", "operator")
    members = api.list_members("r")
    # DISTINCT on (kind, id) — 3 distinct: alice, bob, operator
    principals = {(m["principal_kind"], m["principal_id"]) for m in members}
    assert principals == {("agent", AGENT_A), ("agent", AGENT_B), ("operator", "operator")}
    assert len(members) == 3


def test_list_members_excludes_revoked(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)
    api.revoke_grant("r", "agent", AGENT_A)
    members = api.list_members("r")
    principals = {(m["principal_kind"], m["principal_id"]) for m in members}
    assert principals == {("agent", AGENT_B)}


def test_grant_enforcement(coord_env):
    """Non-member access — per #20, this is NoMembershipError (404
    semantic), distinct from GrantError (403, member with wrong perm)."""
    _run(api.create_room("huddle"))
    api.grant("huddle", "agent", AGENT_A)

    with pytest.raises(api.NoMembershipError):
        _run(api.send("huddle", "agent", AGENT_C, "sneaking in"))
    with pytest.raises(api.NoMembershipError):
        _run(api.read_room("huddle", "agent", AGENT_C))
    with pytest.raises(api.NoMembershipError):
        api.join_room("huddle", "agent", AGENT_C)


def test_permission_denied_is_grant_error(coord_env):
    """Member with wrong permission (e.g. receive-only calling send)
    gets GrantError (403), NOT NoMembershipError (404). Per #20 split."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A, permissions=["receive"])
    # receive-only member: read OK, send raises GrantError (not NoMembership)
    _run(api.read_room("r", "agent", AGENT_A))
    with pytest.raises(api.GrantError, match="permission 'send' denied"):
        _run(api.send("r", "agent", AGENT_A, "no send perm"))


def test_no_membership_and_nonexistent_room_are_both_404_family(coord_env):
    """Per #20: unauthorized caller cannot distinguish nonexistent room
    from room-they-lack-membership-in. Both raise NotFoundError-family
    exceptions."""
    _run(api.create_room("exists"))
    api.grant("exists", "agent", AGENT_A)

    # Nonexistent room
    with pytest.raises(api.NotFoundError):
        api.join_room("does-not-exist", "agent", AGENT_C)
    # Room exists but caller has no membership
    with pytest.raises(api.NotFoundError):  # NoMembershipError IS NotFoundError
        api.join_room("exists", "agent", AGENT_C)


def test_operator_send_and_agent_read(coord_env):
    _run(api.create_room("huddle"))
    api.grant("huddle", "agent", AGENT_A)
    api.grant("huddle", "operator", "operator")

    _run(api.send("huddle", "operator", None, "kicking off"))
    page = _run(api.read_room("huddle", "agent", AGENT_A))
    assert page["messages"][0]["sender_kind"] == "operator"
    assert page["messages"][0]["sender_agent_id"] is None


def test_envelope_field_validation(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)

    with pytest.raises(ValueError, match="sender_agent_id required"):
        _run(api.send("r", "agent", None, "x"))
    with pytest.raises(ValueError, match="must be None"):
        _run(api.send("r", "operator", "some-id", "x"))
    with pytest.raises(ValueError, match="content_type"):
        _run(api.send("r", "agent", AGENT_A, "x", declared_content_type="application/exe"))


def test_read_room_pagination_bound(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    for i in range(5):
        _run(api.send("r", "agent", AGENT_A, f"msg {i}"))

    page = _run(api.read_room("r", "agent", AGENT_A, limit=3))
    assert len(page["messages"]) == 3
    assert page["has_more"] is True

    page2 = _run(api.read_room("r", "agent", AGENT_A,
                               since_sequence=page["next_cursor"], limit=3))
    assert len(page2["messages"]) == 2
    assert page2["has_more"] is False


@pytest.mark.timeout(10)
def test_wait_for_message_wakes(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    async def scenario():
        async def delayed_send():
            await asyncio.sleep(0.2)
            return await api.send("r", "agent", AGENT_A, "wake up")

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
    _run(api.create_room("r"))
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
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    _run(api.send("r", "agent", AGENT_A, "my own message"))

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=0.5, poll_interval_seconds=0.1,
        )

    page = asyncio.run(scenario())
    assert page["messages"] == []


@pytest.mark.timeout(5)
def test_wait_includes_self_when_asked(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    _run(api.send("r", "agent", AGENT_A, "my own message"))

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
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    _run(api.send("r", "agent", AGENT_A, "my own message"))

    page = _run(api.read_room("r", "agent", AGENT_A))
    assert len(page["messages"]) == 1
    assert page["messages"][0]["body"] == "my own message"


@pytest.mark.timeout(5)
def test_wait_default_limit_is_one(coord_env):
    """Reviewer point 5: wake is an attention edge, not a bulk fetch."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)
    for i in range(5):
        _run(api.send("r", "agent", AGENT_B, f"msg {i}"))

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=1, poll_interval_seconds=0.05,
        )

    page = asyncio.run(scenario())
    assert len(page["messages"]) == 1
    assert page["has_more"] is True


def test_revoke_grant_returns_true_when_active(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    assert api.revoke_grant("r", "agent", AGENT_A) is True


def test_revoke_grant_idempotent(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.revoke_grant("r", "agent", AGENT_A)
    assert api.revoke_grant("r", "agent", AGENT_A) is False


def test_revoke_then_ops_fail(coord_env):
    """Post-revoke, all ops raise NoMembershipError (404 per #20).
    A revoked principal has no active membership — same as never having
    joined — and must not be able to distinguish that from room absence."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    _run(api.send("r", "agent", AGENT_A, "before"))
    api.revoke_grant("r", "agent", AGENT_A)

    with pytest.raises(api.NoMembershipError):
        api.join_room("r", "agent", AGENT_A)
    with pytest.raises(api.NoMembershipError):
        _run(api.send("r", "agent", AGENT_A, "denied"))
    with pytest.raises(api.NoMembershipError):
        _run(api.read_room("r", "agent", AGENT_A))


def test_regrant_exposes_retained_history(coord_env):
    """Room semantic per #371: re-grant sees retained history."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    _run(api.send("r", "agent", AGENT_B, "before revoke"))
    api.revoke_grant("r", "agent", AGENT_A)
    _run(api.send("r", "agent", AGENT_B, "during revoke"))
    api.grant("r", "agent", AGENT_A)

    page = _run(api.read_room("r", "agent", AGENT_A))
    bodies = [m["body"] for m in page["messages"]]
    assert "before revoke" in bodies
    assert "during revoke" in bodies


def test_body_over_max_rejected(coord_env):
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    big = "x" * (api.MAX_BODY_BYTES + 1024)
    with pytest.raises(ValueError, match="body too large"):
        _run(api.send("r", "agent", AGENT_A, big))


def test_revoke_cancels_all_active_grants(coord_env):
    """Bug #18: revoke used to cancel only the newest grant, letting
    _check_grant fall back to an older active one. Verify multi-grant.
    Post-revoke, expect NoMembershipError (per #20 semantic split)."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_A)  # second grant, still active
    api.grant("r", "agent", AGENT_A)  # third
    assert api.revoke_grant("r", "agent", AGENT_A) is True
    # After revoke, NO active grant should exist — access must fail.
    with pytest.raises(api.NoMembershipError):
        api.join_room("r", "agent", AGENT_A)
    with pytest.raises(api.NoMembershipError):
        _run(api.read_room("r", "agent", AGENT_A))
    # Idempotent: nothing left to revoke.
    assert api.revoke_grant("r", "agent", AGENT_A) is False


def test_grant_absorbs_same_ms_collision(coord_env):
    """Bug #19: two grants in the same millisecond used to trip the PK.
    Absorbed as no-op — caller intent 'grant this principal' is already
    satisfied by the first insert."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    # Force same-millisecond by mocking now_ms to a constant
    from unittest.mock import patch
    with patch("safeyolo.coord.store.now_ms", return_value=api.store.now_ms()):
        # Should NOT raise IntegrityError
        api.grant("r", "agent", AGENT_A)
        api.grant("r", "agent", AGENT_A)


@pytest.mark.timeout(5)
def test_wait_advances_cursor_past_partial_own_batch(coord_env):
    """Codex finding: scan_since must advance past a filtered-empty batch
    even when page.has_more is False (small own-message batch). Previously
    the timeout cursor stayed at since_sequence, forcing re-scan next poll."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    _run(api.send("r", "agent", AGENT_A, "own message"))

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=0.5, poll_interval_seconds=0.1,
        )

    page = asyncio.run(scenario())
    assert page["messages"] == []
    assert page["next_cursor"] > 0, "cursor did not advance past filtered own message"


def test_content_type_non_string_rejected_cleanly(coord_env):
    """Codex finding: unhashable content_type (dict, list) used to hit
    `dict in frozenset(...)` -> TypeError -> reached generic 500 boundary.
    Should be a caller-shaped ValueError."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    with pytest.raises(ValueError, match="content_type must be a string"):
        _run(api.send("r", "agent", AGENT_A, "hi", declared_content_type={"a": 1}))
    with pytest.raises(ValueError, match="content_type must be a string"):
        _run(api.send("r", "agent", AGENT_A, "hi", declared_content_type=[1, 2]))


def test_body_with_lone_surrogate_rejected_cleanly(coord_env):
    """Codex finding: body containing a lone surrogate raised
    UnicodeEncodeError (subclass of ValueError), caught by the generic
    ValueError branch which leaked raw codec text into the 400."""
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    with pytest.raises(ValueError, match="^invalid body encoding$"):
        _run(api.send("r", "agent", AGENT_A, "hello\ud800world"))


def test_instance_id_creation_is_race_safe(tmp_path, monkeypatch):
    """Codex finding: two concurrent callers on a fresh install used to
    mint different IDs (read-check-write with no lock).

    Doesn't need NATS — pure identity/store race check."""
    from concurrent.futures import ThreadPoolExecutor

    from safeyolo.coord.identity import get_or_create_instance_id
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: get_or_create_instance_id(), range(32)))
    unique = set(results)
    assert len(unique) == 1, f"race produced {len(unique)} distinct instance IDs: {unique}"


@pytest.mark.timeout(30)
def test_wait_does_not_starve_on_own_message_burst(coord_env):
    """Bob's finding #17: without a scan-cursor, 200+ consecutive own
    messages before a peer message would keep the wait re-reading the same
    filtered-empty window forever.
    """
    _run(api.create_room("r"))
    api.grant("r", "agent", AGENT_A)
    api.grant("r", "agent", AGENT_B)

    # 210 own messages, exceeds READ_PAGE_MAX (200)
    for i in range(api.READ_PAGE_MAX + 10):
        _run(api.send("r", "agent", AGENT_A, f"own {i}"))
    # One peer message after the burst
    _run(api.send("r", "agent", AGENT_B, "peer past the burst"))

    async def scenario():
        return await api.wait_for_message(
            "r", "agent", AGENT_A, since_sequence=0,
            timeout_seconds=5, poll_interval_seconds=0.05,
        )

    page = asyncio.run(scenario())
    assert len(page["messages"]) == 1, \
        "wait should have scanned past the own-message burst and seen the peer"
    assert page["messages"][0]["body"] == "peer past the burst"
    assert page["messages"][0]["sender_agent_id"] == AGENT_B
