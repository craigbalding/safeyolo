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
