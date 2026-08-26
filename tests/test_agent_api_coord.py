"""Tests for coord routes in the Agent API addon.

These verify the security boundary #371 depends on: agent identity for coord
operations MUST come from `_resolve_agent_id` (transport attribution), NOT
from any caller-supplied field. Grant enforcement is exercised end-to-end
via the addon (not just via the underlying coord.api).
"""

import asyncio
import os
from unittest.mock import patch

import json
import pytest
from agent_api import AGENT_API_HOST, AgentAPI
from mitmproxy.test import taddons, tflow

AGENT_TOKEN = "a" * 64


@pytest.fixture
def isolated_state(tmp_path, monkeypatch, _binary_cache):
    """Isolated policy.toml + coord dir + running nats-server per test.

    Coord v1 stores messages in JetStream, so every test that exercises
    the coord addon needs an actual nats-server. `_binary_cache` (session
    scope, defined in conftest.py) hands us the pre-downloaded binary;
    we symlink it into the per-test versioned path and start the server.
    """
    from safeyolo.coord import nats_client
    from safeyolo.coord import nats_runtime as nr
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path / "coord"))
    (tmp_path / "cfg").mkdir()
    dest = nr.nats_binary_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        os.symlink(_binary_cache, dest)
    nr.start_server(ready_timeout=8.0)
    # Reset the nats-py module singleton so a stale connection from a
    # prior test doesn't leak into this event loop.
    nats_client.reset_for_tests()
    yield tmp_path
    nr.stop_server()


def _await(coro):
    """Run one async coord.api call from a sync test body."""
    return asyncio.run(coro)


@pytest.fixture
def api(isolated_state):
    addon = AgentAPI()
    with taddons.context(addon) as tctx:
        tctx.options.agent_api_enabled = True
        yield addon


def _make_flow(path, method="GET", body=None):
    url = f"https://{AGENT_API_HOST}{path}"
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.url = url
    flow.request.host = AGENT_API_HOST
    flow.request.headers["authorization"] = f"Bearer {AGENT_TOKEN}"
    if body is not None:
        flow.request.content = json.dumps(body).encode()
        flow.request.headers["content-type"] = "application/json"
    return flow


def _run(addon, flow):
    with patch("pdp.tokens.read_active_token", return_value=AGENT_TOKEN):
        asyncio.run(addon.request(flow))


def _register_agent(name):
    """Add an agent to the isolated policy.toml + mint agent_id."""
    from safeyolo.agents_store import _new_agent_id, save_agent
    save_agent(name, {"agent_id": _new_agent_id()})


def _setup_room_with_grants(room, agents):
    """Create a coord room and grant each listed agent name."""
    from safeyolo.agents_store import get_or_mint_agent_id
    from safeyolo.coord import api as coord_api
    coord_api.bootstrap()
    _await(coord_api.create_room(room))
    for name in agents:
        coord_api.grant(room, "agent", get_or_mint_agent_id(name))


def _as_agent(name):
    """Force `_resolve_agent_id` to attribute the request to `name`."""
    return patch.object(AgentAPI, "_resolve_agent_id", return_value=name)


class TestCoordIdentity:
    def test_unregistered_agent_denied(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("huddle", ["alice"])
        with _as_agent("mallory"):
            flow = _make_flow("/api/coord/rooms/huddle/join", method="POST")
            _run(api, flow)
        assert flow.response.status_code == 403
        assert "not registered" in json.loads(flow.response.content)["error"]

    def test_no_source_attribution_denied(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("huddle", ["alice"])
        with _as_agent(None):
            flow = _make_flow("/api/coord/rooms/huddle/join", method="POST")
            _run(api, flow)
        assert flow.response.status_code == 403
        assert "identify agent" in json.loads(flow.response.content)["error"]

    def test_caller_cannot_supply_identity(self, api, isolated_state):
        """Even if the caller puts sender_agent_id in the body, the addon uses
        transport-attributed identity."""
        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("huddle", ["alice", "bob"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/huddle/send", method="POST",
                body={"body": "hi", "sender_agent_id": "spoofed"},
            )
            _run(api, flow)
        assert flow.response.status_code == 200
        env = json.loads(flow.response.content)["envelope"]
        # The stored envelope carries alice's agent_id, not "spoofed".
        from safeyolo.agents_store import get_agent_id
        assert env["sender_agent_id"] == get_agent_id("alice")


class TestCoordGrantEnforcement:
    def test_send_denied_without_membership_is_404(self, api, isolated_state):
        """Per #20: non-member sees 404 (indistinguishable from nonexistent
        room), NOT 403 which would confirm the room exists."""
        _register_agent("alice")
        _register_agent("dave")
        _setup_room_with_grants("huddle", ["alice"])  # dave has no grant
        with _as_agent("dave"):
            flow = _make_flow(
                "/api/coord/rooms/huddle/send", method="POST",
                body={"body": "sneaking in"},
            )
            _run(api, flow)
        assert flow.response.status_code == 404
        # Generic body: no room name echoed
        assert "huddle" not in flow.response.content.decode()

    def test_permission_denied_is_403_not_404(self, api, isolated_state):
        """Per #20 split: a member with wrong permission gets 403 (legitimate
        auth signal), NOT 404. Non-member gets 404 (no membership)."""
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api
        _register_agent("alice")
        coord_api.bootstrap()
        _await(coord_api.create_room("r"))
        alice_id = get_or_mint_agent_id("alice")
        # alice has receive only, no send
        coord_api.grant("r", "agent", alice_id, permissions=["receive"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "no send perm"})
            _run(api, flow)
        assert flow.response.status_code == 403
        # 403 body carries the permission info — that's a legitimate signal
        # to a member (they know the room exists; they need send permission).
        assert "permission" in flow.response.content.decode().lower()

    def test_nonexistent_room_and_no_membership_indistinguishable(self, api, isolated_state):
        """Both cases must return identical 404 responses to prevent
        room-existence enumeration (per bob's #20 finding)."""
        _register_agent("alice")
        _register_agent("dave")
        _setup_room_with_grants("exists-r", ["alice"])
        # 1: dave probing nonexistent room
        with _as_agent("dave"):
            flow1 = _make_flow("/api/coord/rooms/does-not-exist/join", method="POST")
            _run(api, flow1)
        # 2: dave probing existing room he has no membership on
        with _as_agent("dave"):
            flow2 = _make_flow("/api/coord/rooms/exists-r/join", method="POST")
            _run(api, flow2)
        assert flow1.response.status_code == 404
        assert flow2.response.status_code == 404
        # Bodies identical — no room name in either
        assert flow1.response.content == flow2.response.content
        assert "exists-r" not in flow2.response.content.decode()

    def test_send_and_read_roundtrip(self, api, isolated_state):
        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("huddle", ["alice", "bob"])

        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/huddle/send", method="POST",
                body={"body": "hello bob"},
            )
            _run(api, flow)
        assert flow.response.status_code == 200

        with _as_agent("bob"):
            flow = _make_flow(
                "/api/coord/rooms/huddle/messages?since=0&limit=10",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 200
        page = json.loads(flow.response.content)
        assert len(page["messages"]) == 1
        assert page["messages"][0]["body"] == "hello bob"


class TestCoordEnvelope:
    def test_bad_content_type_400(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/send", method="POST",
                body={"body": "x", "declared_content_type": "application/exe"},
            )
            _run(api, flow)
        assert flow.response.status_code == 400

    def test_empty_body_400(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/send", method="POST",
                body={"body": ""},
            )
            _run(api, flow)
        assert flow.response.status_code == 400

    def test_nonexistent_room_404(self, api, isolated_state):
        _register_agent("alice")
        from safeyolo.coord import api as coord_api
        coord_api.bootstrap()
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/does-not-exist/join", method="POST",
            )
            _run(api, flow)
        assert flow.response.status_code == 404


class TestCoordWait:
    def test_wait_times_out_empty(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&timeout=0.2",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 200
        assert json.loads(flow.response.content)["messages"] == []


class TestCoordBoundaryEscape:
    """Regression for reviewer point 1: any exception inside the async
    internal-API dispatch MUST synthesise a response and MUST NOT allow
    mitmproxy to continue upstream. Two injection points."""

    def test_exception_in_handler_returns_500_no_escape(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("huddle", ["alice"])
        with _as_agent("alice"), \
             patch("safeyolo.coord.api.join_room", side_effect=RuntimeError("boom-handler")):
            flow = _make_flow("/api/coord/rooms/huddle/join", method="POST")
            _run(api, flow)
        # Response set → mitmproxy will not forward upstream
        assert flow.response is not None
        assert flow.response.status_code == 500
        # Sanitised — raw exception text not echoed
        assert "boom-handler" not in flow.response.content.decode()

    def test_exception_in_identity_resolution_returns_500(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("huddle", ["alice"])
        with _as_agent("alice"), \
             patch("safeyolo.agents_store.get_agent_id",
                   side_effect=RuntimeError("boom-identity")):
            flow = _make_flow("/api/coord/rooms/huddle/join", method="POST")
            _run(api, flow)
        assert flow.response is not None
        assert flow.response.status_code == 500
        assert "boom-identity" not in flow.response.content.decode()

    def test_typeerror_is_500_not_400(self, api, isolated_state):
        """Bob's finding #15: a signature mismatch between the addon and
        coord.api is a server bug, not a caller mistake. Must be 500 (which
        looks like a deployment problem) rather than a plausible-looking 400
        (which sends the caller checking their query params).
        """
        _register_agent("alice")
        _setup_room_with_grants("huddle", ["alice"])
        with _as_agent("alice"), \
             patch("safeyolo.coord.api.join_room",
                   side_effect=TypeError("join_room() got an unexpected keyword argument 'foo'")):
            flow = _make_flow("/api/coord/rooms/huddle/join", method="POST")
            _run(api, flow)
        assert flow.response is not None
        assert flow.response.status_code == 500, \
            "TypeError from callee = server bug, must not be 400"


class TestCoordWaitSelfExclusion:
    """Reviewer point 4: read_room stays inclusive; wait_for_message
    excludes self by default."""

    def test_own_send_does_not_wake_default(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "own message"})
            _run(api, flow)
        assert flow.response.status_code == 200

        # Wait at since=0; own send should not wake.
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&timeout=0.3", method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 200
        assert json.loads(flow.response.content)["messages"] == []

    def test_own_send_wakes_when_include_self(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "own message"})
            _run(api, flow)

        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&timeout=1&include_self=true",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 200
        page = json.loads(flow.response.content)
        assert len(page["messages"]) == 1
        assert page["messages"][0]["body"] == "own message"

    def test_read_room_always_includes_self(self, api, isolated_state):
        """Canonical history is inclusive per reviewer point 4."""
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "own message"})
            _run(api, flow)

        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        assert len(page["messages"]) == 1
        assert page["messages"][0]["body"] == "own message"


class TestCoordWaitLimit:
    """Reviewer point 5: /wait default limit=1 (attention edge, not bulk)."""

    def test_wait_default_limit_is_one(self, api, isolated_state):
        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("r", ["alice", "bob"])
        for i in range(5):
            with _as_agent("bob"):
                flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                                  body={"body": f"msg {i}"})
                _run(api, flow)

        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/wait?since=0&timeout=1",
                              method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        assert len(page["messages"]) == 1
        assert page["has_more"] is True

    def test_wait_explicit_limit(self, api, isolated_state):
        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("r", ["alice", "bob"])
        for i in range(5):
            with _as_agent("bob"):
                flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                                  body={"body": f"msg {i}"})
                _run(api, flow)

        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/wait?since=0&timeout=1&limit=3",
                              method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        assert len(page["messages"]) == 3
        assert page["has_more"] is True


class TestCoordRevokeRoundtrip:
    """Reviewer point 8: full grant → revoke → re-grant cycle,
    with retained history visible after re-grant."""

    def test_grant_revoke_regrant_history_retained(self, api, isolated_state):
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api

        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("r", ["alice", "bob"])
        alice_id = get_or_mint_agent_id("alice")

        # bob sends before revoke
        with _as_agent("bob"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "before revoke"})
            _run(api, flow)

        # alice can read
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 200
        assert len(json.loads(flow.response.content)["messages"]) == 1

        # revoke alice
        assert coord_api.revoke_grant("r", "agent", alice_id) is True

        # bob sends during revoked interval
        with _as_agent("bob"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "during revoke"})
            _run(api, flow)

        # alice cannot join / send / read / wait — per #20 this is 404
        # (indistinguishable from nonexistent room). Revoked = no membership.
        for path, method, body in [
            ("/api/coord/rooms/r/join", "POST", None),
            ("/api/coord/rooms/r/send", "POST", {"body": "denied"}),
            ("/api/coord/rooms/r/messages?since=0", "GET", None),
            ("/api/coord/rooms/r/wait?since=0&timeout=0.1", "GET", None),
        ]:
            with _as_agent("alice"):
                flow = _make_flow(path, method=method, body=body)
                _run(api, flow)
            assert flow.response.status_code == 404, f"{path} should be 404"

        # re-grant: retained history becomes visible again (room semantic)
        coord_api.grant("r", "agent", alice_id)
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 200
        bodies = [m["body"] for m in json.loads(flow.response.content)["messages"]]
        assert "before revoke" in bodies
        assert "during revoke" in bodies

    def test_revoke_idempotent(self, isolated_state):
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        alice_id = get_or_mint_agent_id("alice")
        assert coord_api.revoke_grant("r", "agent", alice_id) is True
        assert coord_api.revoke_grant("r", "agent", alice_id) is False


class TestCoordBodyCap:
    def test_body_over_max_returns_413(self, api, isolated_state):
        from safeyolo.mitm_addons.agent_api import COORD_MAX_BODY_BYTES
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        big = "x" * (COORD_MAX_BODY_BYTES + 1024)
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": big})
            _run(api, flow)
        assert flow.response.status_code == 413

    def test_body_at_max_bytes_survives_through_addon(self, api, isolated_state):
        """Reviewer round-6 point 1: an ASCII body of exactly
        COORD_MAX_BODY_BYTES must actually round-trip through the addon.
        The old code shared one 256 KiB limit for both raw HTTP and
        parsed body, so wrapping the body as {"body":"..."} pushed the
        envelope over the raw cap and a legal max-sized body was
        rejected at the adapter boundary before api.send saw it."""
        from safeyolo.mitm_addons.agent_api import COORD_MAX_BODY_BYTES
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        big = "x" * COORD_MAX_BODY_BYTES
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": big})
            _run(api, flow)
        assert flow.response.status_code == 200
        env = json.loads(flow.response.content)["envelope"]
        assert env["body"] == big


class TestCoordValidationErrors:
    """Reviewer point 7: 400s carry stable actionable strings, no raw
    Python exception text."""

    def test_invalid_since_400(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=abc", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid since"

    def test_invalid_limit_400(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&limit=xyz&timeout=0.1",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid limit"

    def test_limit_zero_is_400_on_messages(self, api, isolated_state):
        """Live dogfood finding: /messages?limit=0 used to silently
        min-clamp to 1 and return one message, which is a surprising
        UX for a caller who asked for zero. Reject explicitly instead."""
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0&limit=0",
                              method="GET")
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid limit"

    def test_limit_zero_is_400_on_wait(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&limit=0&timeout=0.1",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid limit"

    def test_invalid_timeout_400(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&timeout=nope",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid timeout"

    def test_out_of_range_since_is_400(self, api, isolated_state):
        """Bug #21: out-of-range cursor used to reach SQLite and 500 as
        OverflowError. Should be caller-shaped 400."""
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                f"/api/coord/rooms/r/messages?since={1 << 70}",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid since"

    def test_negative_since_is_400(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/messages?since=-1",
                method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 400
        assert json.loads(flow.response.content)["error"] == "invalid since"


class TestCoordMembersEndpoint:
    """Per #22: /members lets peers bind agent_id to a trusted
    display name so body-prefix folklore stops being the identity."""

    def test_members_endpoint_returns_roster_with_names(self, api, isolated_state):
        _register_agent("alice")
        _register_agent("bob")
        _register_agent("codey")
        _setup_room_with_grants("r", ["alice", "bob", "codey"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/members", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 200
        page = json.loads(flow.response.content)
        agent_members = [m for m in page["members"] if m["principal_kind"] == "agent"]
        names = {m["agent_name"] for m in agent_members}
        assert names == {"alice", "bob", "codey"}
        # Every agent entry carries agent_id + origin_instance_id + name
        for m in agent_members:
            assert m["agent_id"].startswith("ag-")
            assert m["origin_instance_id"].startswith("sy-")
        # Operator entry (from _setup_room_with_grants with_operator=True by default? No — that helper only grants listed agents)
        # Not asserted; helper does not grant operator.

    def test_members_endpoint_dedups_multi_grant(self, api, isolated_state):
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        # Grant alice a second time — multi-grant is valid
        alice_id = get_or_mint_agent_id("alice")
        coord_api.grant("r", "agent", alice_id)
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/members", method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        assert len([m for m in page["members"] if m.get("agent_name") == "alice"]) == 1

    def test_members_endpoint_404_for_non_member(self, api, isolated_state):
        """Per #20: non-member sees 404 (same as nonexistent room), not
        403. /members is not a discovery oracle either."""
        _register_agent("alice")
        _register_agent("mallory")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("mallory"):
            flow = _make_flow("/api/coord/rooms/r/members", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 404
        assert "r" not in flow.response.content.decode() or "not found" in flow.response.content.decode().lower()

    def test_members_endpoint_reflects_revocation(self, api, isolated_state):
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api
        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("r", ["alice", "bob"])
        # revoke bob
        bob_id = get_or_mint_agent_id("bob")
        coord_api.revoke_grant("r", "agent", bob_id)
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/members", method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        names = {m.get("agent_name") for m in page["members"] if m["principal_kind"] == "agent"}
        assert names == {"alice"}


class TestCoordSenderAgentName:
    """Per #22: envelope carries SafeYolo-generated sender_agent_name so
    peers don't need to lookup /members for every message."""

    def test_send_envelope_carries_agent_name(self, api, isolated_state):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "hello"})
            _run(api, flow)
        env = json.loads(flow.response.content)["envelope"]
        assert env["sender_agent_name"] == "alice"

    def test_read_room_returns_stored_agent_name(self, api, isolated_state):
        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("r", ["alice", "bob"])
        with _as_agent("alice"):
            _run(api, _make_flow("/api/coord/rooms/r/send", method="POST",
                                 body={"body": "hi"}))
        with _as_agent("bob"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        assert page["messages"][0]["sender_agent_name"] == "alice"

    def test_caller_cannot_forge_sender_agent_name(self, api, isolated_state):
        """Body-supplied sender_agent_name must be ignored; envelope
        carries the transport-derived name."""
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "spoof", "sender_agent_name": "bob"})
            _run(api, flow)
        env = json.loads(flow.response.content)["envelope"]
        assert env["sender_agent_name"] == "alice"  # not "bob"


class TestCoordNatsUnavailableIsolation:
    """Reviewer round-3 point 1: killing NATS mid-flight must surface
    as coord 503, NOT a proxy-breaking 500. Health endpoint (which does
    not touch NATS) must keep answering 200 through the outage."""

    def test_send_returns_503_when_nats_down(self, api, isolated_state):
        from safeyolo.coord import nats_client as ncli
        from safeyolo.coord import nats_runtime as nr

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])

        # Kill the server that isolated_state started.
        nr.stop_server()
        ncli.reset_for_tests()

        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/send", method="POST",
                              body={"body": "into the void"})
            _run(api, flow)
        assert flow.response.status_code == 503
        assert "unavailable" in json.loads(flow.response.content)["error"]

    def test_read_and_wait_return_503_when_nats_down(self, api, isolated_state):
        from safeyolo.coord import nats_client as ncli
        from safeyolo.coord import nats_runtime as nr

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        nr.stop_server()
        ncli.reset_for_tests()

        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 503

        with _as_agent("alice"):
            flow = _make_flow(
                "/api/coord/rooms/r/wait?since=0&timeout=0.5", method="GET",
            )
            _run(api, flow)
        assert flow.response.status_code == 503

    def test_non_coord_health_endpoint_survives_nats_outage(self, api, isolated_state):
        """The proxy's /health path must keep answering even when the
        coord message plane is unreachable — coord is best-effort infra
        on top of the proxy, never a dependency of it."""
        from safeyolo.coord import nats_client as ncli
        from safeyolo.coord import nats_runtime as nr

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        nr.stop_server()
        ncli.reset_for_tests()

        flow = _make_flow("/health", method="GET")
        _run(api, flow)
        assert flow.response is not None
        assert flow.response.status_code == 200


class TestCoordCorruptEnvelopeIsolation:
    """Reviewer round-3 point 4: corrupt persisted envelopes surface as
    coord 500 at the addon boundary — the addon does not paper them
    over as an empty page (which would hide the storage-integrity gap)."""

    def test_corrupt_envelope_returns_500(self, api, isolated_state):
        import asyncio as _asyncio

        from safeyolo.coord import api as coord_api
        from safeyolo.coord import nats_client as ncli

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        room_id = next(
            r["room_id"] for r in coord_api.list_rooms() if r["name"] == "r"
        )

        async def poison():
            js = await ncli.get_jetstream()
            await js.publish(
                ncli.subject_for_room(room_id),
                b"not a valid json envelope",
                stream=ncli.stream_name_for_room(room_id),
                headers={"Nats-Msg-Id": "poisoned-e2e"},
            )
        _asyncio.run(poison())

        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        # Not a silent [] page — the addon boundary sees the coord data
        # error and surfaces it as a generic 500.
        assert flow.response.status_code == 500


