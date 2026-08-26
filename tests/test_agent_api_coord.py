"""Tests for coord routes in the Agent API addon.

These verify the security boundary #371 depends on: agent identity for coord
operations MUST come from `_resolve_agent_id` (transport attribution), NOT
from any caller-supplied field. Grant enforcement is exercised end-to-end
via the addon (not just via the underlying coord.api).
"""

import asyncio
import json
from unittest.mock import patch

import pytest
from agent_api import AGENT_API_HOST, AgentAPI
from mitmproxy.test import taddons, tflow

AGENT_TOKEN = "a" * 64


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    """Isolated policy.toml + coord DB per test."""
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path / "coord"))
    (tmp_path / "cfg").mkdir()
    return tmp_path


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
    coord_api.create_room(room)
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
    def test_send_denied_without_grant(self, api, isolated_state):
        _register_agent("alice")
        _register_agent("dave")
        _setup_room_with_grants("huddle", ["alice"])  # dave has no grant
        with _as_agent("dave"):
            flow = _make_flow(
                "/api/coord/rooms/huddle/send", method="POST",
                body={"body": "sneaking in"},
            )
            _run(api, flow)
        assert flow.response.status_code == 403

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

        # alice cannot join / send / read / wait
        for path, method, body in [
            ("/api/coord/rooms/r/join", "POST", None),
            ("/api/coord/rooms/r/send", "POST", {"body": "denied"}),
            ("/api/coord/rooms/r/messages?since=0", "GET", None),
            ("/api/coord/rooms/r/wait?since=0&timeout=0.1", "GET", None),
        ]:
            with _as_agent("alice"):
                flow = _make_flow(path, method=method, body=body)
                _run(api, flow)
            assert flow.response.status_code == 403, f"{path} should be 403"

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
