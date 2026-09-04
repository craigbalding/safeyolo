"""Tests for coord routes in the Agent API addon.

These verify the security boundary #371 depends on: agent identity for coord
operations MUST come from `_resolve_agent_id` (transport attribution), NOT
from any caller-supplied field. Grant enforcement is exercised end-to-end
via the addon (not just via the underlying coord.api).
"""

import asyncio
import json
import os
import secrets
from unittest.mock import patch

import pytest
from agent_api import AGENT_API_HOST, AgentAPI
from mitmproxy.test import taddons, tflow

AGENT_TOKEN = "a" * 64


def _grant(*args, **kwargs):
    from safeyolo.coord import api as coord_api
    from safeyolo.coord.identity import new_operation_id

    kwargs.setdefault("operation_id", new_operation_id())
    return coord_api.grant(*args, **kwargs)


def _revoke_grant(*args, **kwargs):
    from safeyolo.coord import api as coord_api
    from safeyolo.coord.identity import new_operation_id

    kwargs.setdefault("operation_id", new_operation_id())
    return coord_api.revoke_grant(*args, **kwargs)


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
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", secrets.token_hex(8))
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
    try:
        nr.stop_server()
    finally:
        nr.nats_test_endpoints_path().unlink(missing_ok=True)


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
    with patch(
        "pdp.tokens.read_active_token", autospec=True, return_value=AGENT_TOKEN
    ):
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
        _grant(room, "agent", get_or_mint_agent_id(name))


def _as_agent(name):
    """Force `_resolve_agent_id` to attribute the request to `name`."""
    return patch.object(
        AgentAPI, "_resolve_agent_id", autospec=True, return_value=name
    )


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

    def test_uds_ip_map_conflict_is_403(self, api, isolated_state):
        """Merge regression (codey seq 100): the coord route must reject a
        request whose UDS-attributed identity disagrees with the IP-map
        identity. Uses the REAL merged _resolve_agent_id path — no
        _as_agent mock — so the assurance-branch identity boundary is
        exercised through the coord adapter as it will run in prod.
        Silently trusting either source would be a cross-agent escalation
        primitive.
        """
        from types import SimpleNamespace

        from safeyolo.proxy_modes.unix_listener import UnixMode

        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("huddle", ["alice", "bob"])

        # Flow the way it arrives at a per-agent UDS listener: proxy_mode
        # carries the trusted UDS identity, peername is the mapped IP.
        flow = _make_flow("/api/coord/rooms/huddle/send", method="POST",
                          body={"body": "conflict probe"})
        flow.client_conn.peername = ("10.0.0.5", 12345)
        flow.client_conn.proxy_mode = UnixMode.parse(
            "unix:/tmp/10.0.0.5_alice/proxy.sock"
        )

        # A service-discovery addon that maps the SAME source IP to a
        # DIFFERENT agent. resolve_agent_identity should raise CONFLICT,
        # is_resolved=False, _resolve_agent_id returns None, coord 403s.
        stub_sd = SimpleNamespace(get_client_for_ip=lambda ip: "bob")
        with patch.object(
            AgentAPI,
            "_find_addon",
            autospec=True,
            side_effect=lambda _self, name: (
                stub_sd if name == "service-discovery" else None
            ),
        ):
            _run(api, flow)

        assert flow.response.status_code == 403
        assert "identify agent" in json.loads(flow.response.content)["error"]


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
        _grant("r", "agent", alice_id, permissions=["receive"])
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


def test_nested_factory_agent_rooms_survive_restart_and_reject_observer_send(
    api, isolated_state
):
    """Exercise one Relay-to-Forge-to-Lens chain over retained agent rooms."""
    from safeyolo.agents_store import get_or_mint_agent_id
    from safeyolo.commands.factory import _ensure_factory_rooms
    from safeyolo.coord import api as coord_api
    from safeyolo.coord import nats_client
    from safeyolo.coord import nats_runtime as nr

    roles = ("relay", "forge", "lens")
    for name in (*roles, "qa"):
        _register_agent(name)
    coord_api.bootstrap()
    _ensure_factory_rooms("nested-factory", iter(roles))
    qa_id = get_or_mint_agent_id("qa")
    for name in roles:
        _grant(f"{name}-agent", "agent", qa_id, permissions=["receive"])

    def request(name, path, *, method="GET", body=None):
        with _as_agent(name):
            flow = _make_flow(path, method=method, body=body)
            _run(api, flow)
        return flow

    def send(name, room, body, notify="none"):
        flow = request(
            name,
            f"/api/coord/rooms/{room}/send",
            method="POST",
            body={"body": body, "notify": notify},
        )
        assert flow.response.status_code == 200
        return json.loads(flow.response.content)

    def stdout_line(name, text):
        event = json.dumps(
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": text},
            },
            separators=(",", ":"),
        )
        sent = send(name, f"{name}-agent", event)
        assert sent["attention_intent"] == {"mode": "none"}

    issue_target = "https://github.com/craigbalding/safeyolo/issues/1"
    task = f"TASK target={issue_target} assignee=forge"
    task_send = send("relay", "nested-factory", task, ["forge"])
    stdout_line("relay", task)
    forge_wait = request(
        "forge", "/api/coord/attention/wait?since=0&timeout=0.1"
    )
    forge_page = json.loads(forge_wait.response.content)
    task_edge = forge_page["edges"][0]
    assert task_edge["object_id"] == task_send["envelope"]["msg_id"]

    head = "a" * 40
    review_target = (
        "https://github.com/craigbalding/safeyolo/pull/2/commits/" + head
    )
    review = f"REVIEW_READY target={review_target}"
    review_send = send("forge", "nested-factory", review, ["lens"])
    stdout_line("forge", review)
    lens_wait = request(
        "lens", "/api/coord/attention/wait?since=0&timeout=0.1"
    )
    review_edge = json.loads(lens_wait.response.content)["edges"][0]
    assert review_edge["object_id"] == review_send["envelope"]["msg_id"]

    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)

    retained = request(
        "qa", "/api/coord/rooms/forge-agent/messages?since=0&limit=10"
    )
    assert retained.response.status_code == 200
    retained_bodies = [
        message["body"]
        for message in json.loads(retained.response.content)["messages"]
    ]
    assert any(review in body for body in retained_bodies)

    ready = f"READY target={review_target} attention_id={review_edge['attention_id']}"
    ready_send = send("lens", "nested-factory", ready, ["forge"])
    stdout_line("lens", ready)
    forge_response_wait = request(
        "forge",
        f"/api/coord/attention/wait?since={forge_page['next_cursor']}&timeout=0.1",
    )
    ready_edges = json.loads(forge_response_wait.response.content)["edges"]
    assert [edge["object_id"] for edge in ready_edges] == [
        ready_send["envelope"]["msg_id"]
    ]
    done = f"DONE target={issue_target} attention_id={task_edge['attention_id']}"
    done_send = send("forge", "nested-factory", done, ["relay"])
    stdout_line("forge", done)
    relay_wait = request(
        "relay", "/api/coord/attention/wait?since=0&timeout=0.1"
    )
    relay_edges = json.loads(relay_wait.response.content)["edges"]
    assert [edge["object_id"] for edge in relay_edges] == [
        done_send["envelope"]["msg_id"]
    ]

    observed = {}
    for name in roles:
        history = request(
            "qa",
            f"/api/coord/rooms/{name}-agent/messages?since=0&limit=10",
        )
        assert history.response.status_code == 200
        observed[name] = [
            message["body"]
            for message in json.loads(history.response.content)["messages"]
        ]
    assert any(task in body for body in observed["relay"])
    assert any(review in body for body in observed["forge"])
    assert any(done in body for body in observed["forge"])
    assert any(ready in body for body in observed["lens"])

    denied = request(
        "qa",
        "/api/coord/rooms/forge-agent/send",
        method="POST",
        body={"body": "observer must not steer"},
    )
    assert denied.response.status_code == 403
    assert "permission" in denied.response.content.decode().lower()


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
        from safeyolo.coord import api as coord_api

        _register_agent("alice")
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
             patch(
                 "safeyolo.coord.api.join_room",
                 autospec=True,
                 side_effect=RuntimeError("boom-handler"),
             ):
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
             patch(
                 "safeyolo.agents_store.get_agent_id",
                 autospec=True,
                 side_effect=RuntimeError("boom-identity"),
             ):
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
             patch(
                 "safeyolo.coord.api.join_room",
                 autospec=True,
                 side_effect=TypeError(
                     "join_room() got an unexpected keyword argument 'foo'"
                 ),
             ):
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
        assert "has_more" not in page, "wait must not report a backlog field"

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
        assert "has_more" not in page, "wait must not report a backlog field"


class TestCoordRevokeRoundtrip:
    """Reviewer point 8: full grant → revoke → re-grant cycle,
    with retained history visible after re-grant."""

    def test_grant_revoke_regrant_history_retained(self, api, isolated_state):
        from safeyolo.agents_store import get_or_mint_agent_id

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
        assert _revoke_grant("r", "agent", alice_id) is True

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
        _grant("r", "agent", alice_id)
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, flow)
        assert flow.response.status_code == 200
        bodies = [m["body"] for m in json.loads(flow.response.content)["messages"]]
        assert "before revoke" in bodies
        assert "during revoke" in bodies

    def test_revoke_idempotent(self, isolated_state):
        from safeyolo.agents_store import get_or_mint_agent_id

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        alice_id = get_or_mint_agent_id("alice")
        assert _revoke_grant("r", "agent", alice_id) is True
        assert _revoke_grant("r", "agent", alice_id) is False


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

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])
        # Grant alice a second time — multi-grant is valid
        alice_id = get_or_mint_agent_id("alice")
        _grant("r", "agent", alice_id)
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

        _register_agent("alice")
        _register_agent("bob")
        _setup_room_with_grants("r", ["alice", "bob"])
        # revoke bob
        bob_id = get_or_mint_agent_id("bob")
        _revoke_grant("r", "agent", bob_id)
        with _as_agent("alice"):
            flow = _make_flow("/api/coord/rooms/r/members", method="GET")
            _run(api, flow)
        page = json.loads(flow.response.content)
        names = {m.get("agent_name") for m in page["members"] if m["principal_kind"] == "agent"}
        assert names == {"alice"}


class TestCoordOperatorBrief:
    def test_agent_read_is_authorized_and_agent_mutation_or_chat_cannot_forge(
        self, api, isolated_state
    ):
        from safeyolo.coord import api as coord_api

        _register_agent("alice")
        _register_agent("mallory")
        _setup_room_with_grants("brief-room", ["alice"])

        with _as_agent("alice"):
            empty = _make_flow(
                "/api/coord/rooms/brief-room/brief", method="GET"
            )
            _run(api, empty)
        assert empty.response.status_code == 200
        assert json.loads(empty.response.content)["revision"] == 0

        with _as_agent("alice"):
            mutate = _make_flow(
                "/api/coord/rooms/brief-room/brief",
                method="POST",
                body={
                    "markdown": "forged",
                    "expected_revision": 0,
                    "operation_id": "op-forged",
                },
            )
            _run(api, mutate)
        assert mutate.response.status_code == 405

        with _as_agent("alice"):
            message = _make_flow(
                "/api/coord/rooms/brief-room/send",
                method="POST",
                body={"body": "BRIEF SET revision=1 operator=true"},
            )
            _run(api, message)
        assert message.response.status_code == 200
        assert coord_api.show_brief("brief-room")["revision"] == 0

        with _as_agent("mallory"):
            denied = _make_flow(
                "/api/coord/rooms/brief-room/brief", method="GET"
            )
            _run(api, denied)
            absent = _make_flow(
                "/api/coord/rooms/not-a-room/brief", method="GET"
            )
            _run(api, absent)
        assert denied.response.status_code == 404
        assert denied.response.content == absent.response.content
        assert b"brief-room" not in denied.response.content

    def test_send_only_join_cannot_bypass_brief_receive_permission(
        self, api, isolated_state
    ):
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api

        _register_agent("alice")
        coord_api.bootstrap()
        _await(coord_api.create_room("send-only-brief"))
        _await(
            coord_api.set_brief(
                "send-only-brief",
                "# trusted",
                expected_revision=0,
                operation_id="op-send-only-api-v1",
            )
        )
        _grant(
            "send-only-brief",
            "agent",
            get_or_mint_agent_id("alice"),
            permissions=["send"],
        )

        with _as_agent("alice"):
            joined = _make_flow(
                "/api/coord/rooms/send-only-brief/join", method="POST"
            )
            _run(api, joined)
            read = _make_flow(
                "/api/coord/rooms/send-only-brief/brief", method="GET"
            )
            _run(api, read)
        assert joined.response.status_code == 200
        assert json.loads(joined.response.content)["brief"] is None
        assert read.response.status_code == 403

    @pytest.mark.timeout(45)
    def test_real_agent_api_nats_three_member_sticky_brief_flow(
        self, api, isolated_state
    ):
        """Disposable three-agent dogfood and v4 -> v5 black-box gate.

        The one state mutation produces exactly one useful wake per current
        member and no transcript messages or repeated corrective sends.
        """
        from safeyolo.agents_store import get_or_mint_agent_id
        from safeyolo.coord import api as coord_api
        from safeyolo.coord import attention as coord_attention
        from safeyolo.coord import nats_client
        from safeyolo.coord import nats_runtime as nr

        for name in ("alice", "bob", "codey", "later"):
            _register_agent(name)
        coord_api.bootstrap()
        _await(coord_api.create_room("sticky"))

        # Build v4 before members arrive. Later joiners should need no
        # transcript replay to learn it.
        for revision in range(1, 5):
            result = _await(
                coord_api.set_brief(
                    "sticky",
                    f"# Intent v{revision}\n\nEvidence before inference.",
                    expected_revision=revision - 1,
                    operation_id=f"op-brief-v{revision}",
                )
            )
            assert result["attention_count"] == 0

        for name in ("alice", "bob", "codey"):
            _grant(
                "sticky",
                "agent",
                get_or_mint_agent_id(name),
                operation_id=f"op-grant-{name}",
            )
            with _as_agent(name):
                joined = _make_flow(
                    "/api/coord/rooms/sticky/join", method="POST"
                )
                _run(api, joined)
            brief_at_join = json.loads(joined.response.content)["brief"]
            assert brief_at_join["revision"] == 4
            assert brief_at_join["markdown"].startswith("# Intent v4")

        v5 = _await(
            coord_api.set_brief(
                "sticky",
                "# Intent v5\n\nMessages succinct; evidence before inference.",
                expected_revision=4,
                operation_id="op-brief-v5",
            )
        )
        assert v5["attention_count"] == 3

        attention_ids = {}
        useful_wakeups = 0
        for name in ("alice", "bob", "codey"):
            with _as_agent(name):
                waited = _make_flow(
                    "/api/coord/attention/wait?since=0&timeout=2&limit=10",
                    method="GET",
                )
                _run(api, waited)
            page = json.loads(waited.response.content)
            assert len(page["edges"]) == 1
            edge = page["edges"][0]
            assert edge["kind"] == "brief_changed"
            assert edge["revision_or_sequence"] == 5
            attention_ids[name] = edge["attention_id"]

            with _as_agent(name):
                resolved = _make_flow(
                    f"/api/coord/attention/{edge['attention_id']}/object",
                    method="GET",
                )
                _run(api, resolved)
                current = _make_flow(
                    "/api/coord/rooms/sticky/brief", method="GET"
                )
                _run(api, current)
            canonical = json.loads(resolved.response.content)["object"]
            assert canonical == json.loads(current.response.content)
            assert canonical["revision"] == 5
            useful_wakeups += 1

        assert useful_wakeups == 3

        # An ambiguous caller retry replays the result and creates no second
        # audit or wake edge.
        assert _await(
            coord_api.set_brief(
                "sticky",
                "# Intent v5\n\nMessages succinct; evidence before inference.",
                expected_revision=4,
                operation_id="op-brief-v5",
            )
        ) == v5
        for name in ("alice", "bob", "codey"):
            agent_id = get_or_mint_agent_id(name)
            assert len(coord_attention.read_feed(agent_id, 0, 10)["edges"]) == 1

        _revoke_grant(
            "sticky",
            "agent",
            get_or_mint_agent_id("codey"),
            operation_id="op-revoke-codey",
        )
        with _as_agent("codey"):
            denied_brief = _make_flow(
                "/api/coord/rooms/sticky/brief", method="GET"
            )
            _run(api, denied_brief)
            denied_edge = _make_flow(
                f"/api/coord/attention/{attention_ids['codey']}/object",
                method="GET",
            )
            _run(api, denied_edge)
        assert denied_brief.response.status_code == 404
        assert denied_edge.response.status_code == 404

        # NATS restart does not own brief state; current and history persist.
        nr.stop_server()
        nats_client.reset_for_tests()
        nr.start_server(ready_timeout=8.0)
        assert coord_api.show_brief("sticky")["revision"] == 5
        assert coord_api.list_brief_history("sticky")["current_revision"] == 5

        _grant(
            "sticky",
            "agent",
            get_or_mint_agent_id("later"),
            operation_id="op-grant-later",
        )
        with _as_agent("later"):
            later = _make_flow(
                "/api/coord/rooms/sticky/join", method="POST"
            )
            _run(api, later)
            history = _make_flow(
                "/api/coord/rooms/sticky/messages?since=0", method="GET"
            )
            _run(api, history)
        assert json.loads(later.response.content)["brief"]["revision"] == 5
        assert json.loads(history.response.content)["messages"] == []


class TestCoordRoomInventory:
    def test_state_join_and_declarations_use_transport_identity(
        self, api, isolated_state
    ):
        from safeyolo.agents_store import get_or_mint_agent_id, save_agent
        from safeyolo.coord import api as coord_api

        _register_agent("alice")
        _register_agent("bob")
        _register_agent("codey")
        alice_id = get_or_mint_agent_id("alice")
        bob_id = get_or_mint_agent_id("bob")
        save_agent(
            "alice",
            {
                "agent_id": alice_id,
                "services": {
                    "github": {
                        "capability": "write_pr",
                        "token": "credential-must-not-leak",
                    }
                },
            },
        )
        coord_api.bootstrap()
        _await(coord_api.create_room("inventory-api"))
        _grant("inventory-api", "agent", alice_id)
        _grant("inventory-api", "agent", bob_id, permissions=["send"])
        coord_api.advertise_capability(
            "inventory-api",
            alice_id,
            "github:write_pr",
            advertised=True,
            operation_id="op-inventory-api-ad",
        )

        with _as_agent("alice"):
            declared = _make_flow(
                "/api/coord/rooms/inventory-api/declarations",
                method="POST",
                body={"capabilities": ["skill:python"], "ttl_seconds": 60},
            )
            _run(api, declared)
            state = _make_flow(
                "/api/coord/rooms/inventory-api/state", method="GET"
            )
            _run(api, state)
            joined = _make_flow(
                "/api/coord/rooms/inventory-api/join", method="POST"
            )
            _run(api, joined)
        assert declared.response.status_code == 200
        assert state.response.status_code == 200
        public_state = json.loads(state.response.content)
        alice = next(
            member
            for member in public_state["members"]
            if member["agent_id"] == alice_id
        )
        assert alice["verified"][0]["capability"] == "github:write_pr"
        assert alice["declared"][0]["capability"] == "skill:python"
        assert b"credential-must-not-leak" not in state.response.content
        assert json.loads(joined.response.content)["state"]["members"] == (
            public_state["members"]
        )

        with _as_agent("bob"):
            denied = _make_flow(
                "/api/coord/rooms/inventory-api/state", method="GET"
            )
            _run(api, denied)
            send_only_join = _make_flow(
                "/api/coord/rooms/inventory-api/join", method="POST"
            )
            _run(api, send_only_join)
        assert denied.response.status_code == 403
        assert send_only_join.response.status_code == 200
        assert json.loads(send_only_join.response.content)["state"] is None

        with _as_agent("codey"):
            nonmember = _make_flow(
                "/api/coord/rooms/inventory-api/state", method="GET"
            )
            _run(api, nonmember)
            nonexistent = _make_flow(
                "/api/coord/rooms/missing-inventory-room/state", method="GET"
            )
            _run(api, nonexistent)
            cannot_mutate_state = _make_flow(
                "/api/coord/rooms/inventory-api/state",
                method="POST",
                body={"verified": [{"capability": "github:admin"}]},
            )
            _run(api, cannot_mutate_state)
        assert nonmember.response.status_code == 404
        assert nonmember.response.content == nonexistent.response.content
        assert cannot_mutate_state.response.status_code == 405

        _revoke_grant("inventory-api", "agent", alice_id)
        with _as_agent("alice"):
            revoked = _make_flow(
                "/api/coord/rooms/inventory-api/state", method="GET"
            )
            _run(api, revoked)
        assert revoked.response.status_code == 404

    @pytest.mark.timeout(45)
    def test_real_agent_api_nats_three_agent_inventory_dogfood(
        self, api, isolated_state
    ):
        """Three peers discover current capability/lease state with no chat."""
        from safeyolo.agents_store import get_or_mint_agent_id, save_agent
        from safeyolo.coord import api as coord_api
        from safeyolo.coord import inventory, nats_client
        from safeyolo.coord import nats_runtime as nr

        inventory.clear_provider_adapters()
        try:
            for name in ("alice", "bob", "codey"):
                _register_agent(name)
            agent_ids = {
                name: get_or_mint_agent_id(name)
                for name in ("alice", "bob", "codey")
            }
            for name, agent_id in agent_ids.items():
                save_agent(
                    name,
                    {
                        "agent_id": agent_id,
                        "services": {
                            "rundeck": {
                                "capability": f"{name}_runner",
                                "token": f"credential-{name}-must-not-leak",
                            }
                        },
                    },
                )
            now = coord_api.store.now_ms()
            provider_dir = inventory.provider_snapshot_dir()
            provider_dir.mkdir(parents=True)
            (provider_dir / "rundeck.json").write_text(
                json.dumps(
                    {
                        "capabilities": [
                            {
                                "agent_id": agent_id,
                                "capability": f"rundeck:{name}_runner",
                                "availability": "available",
                                "observed_at": now,
                                "valid_until": now + 30_000,
                                "token": "provider-token-must-not-leak",
                            }
                            for name, agent_id in agent_ids.items()
                        ],
                        "leases": [
                            {
                                "resource": "acceptance_runner",
                                "state": "held",
                                "holder_agent_id": agent_ids["bob"],
                                "observed_at": now,
                                "valid_until": now + 30_000,
                                "account": "provider-account-must-not-leak",
                            }
                        ],
                    }
                )
            )
            coord_api.bootstrap()
            _await(coord_api.create_room("inventory-dogfood"))
            for name, agent_id in agent_ids.items():
                _grant("inventory-dogfood", "agent", agent_id)
                coord_api.advertise_capability(
                    "inventory-dogfood",
                    agent_id,
                    f"rundeck:{name}_runner",
                    advertised=True,
                    operation_id=f"op-inventory-dogfood-{name}",
                )
            coord_api.advertise_resource(
                "inventory-dogfood",
                "rundeck",
                "acceptance_runner",
                advertised=True,
                operation_id="op-inventory-dogfood-resource",
            )

            useful_state_reads = 0
            canonical_members = None
            for name in ("alice", "bob", "codey"):
                with _as_agent(name):
                    flow = _make_flow(
                        "/api/coord/rooms/inventory-dogfood/state",
                        method="GET",
                    )
                    _run(api, flow)
                assert flow.response.status_code == 200
                assert b"must-not-leak" not in flow.response.content
                state = json.loads(flow.response.content)
                assert all(
                    member["verified"][0]["availability"] == "available"
                    for member in state["members"]
                )
                assert state["resource_leases"][0]["holder_agent_id"] == agent_ids[
                    "bob"
                ]
                canonical_members = canonical_members or state["members"]
                assert state["members"] == canonical_members
                useful_state_reads += 1
            assert useful_state_reads == 3

            with _as_agent("alice"):
                history = _make_flow(
                    "/api/coord/rooms/inventory-dogfood/messages?since=0",
                    method="GET",
                )
                _run(api, history)
            assert json.loads(history.response.content)["messages"] == []

            nr.stop_server()
            nats_client.reset_for_tests()
            # Simulate process-local integration loss as well as substrate
            # restart. Bootstrap reconstructs the production adapter from the
            # provider-owned durable public snapshot; the test never calls the
            # manual registration hook.
            inventory.clear_provider_adapters()
            coord_api.bootstrap()
            nr.start_server(ready_timeout=8.0)
            with _as_agent("codey"):
                restarted = _make_flow(
                    "/api/coord/rooms/inventory-dogfood/state",
                    method="GET",
                )
                _run(api, restarted)
            assert restarted.response.status_code == 200
            restarted_state = json.loads(restarted.response.content)
            assert len(restarted_state["members"]) == 3
            assert all(
                member["verified"][0]["availability"] == "available"
                for member in restarted_state["members"]
            )
            assert restarted_state["resource_leases"][0][
                "holder_agent_id"
            ] == agent_ids["bob"]

            (provider_dir / "rundeck.json").unlink()
            with _as_agent("alice"):
                removed = _make_flow(
                    "/api/coord/rooms/inventory-dogfood/state",
                    method="GET",
                )
                _run(api, removed)
            removed_state = json.loads(removed.response.content)
            assert all(
                member["verified"][0]["availability"] == "unknown"
                for member in removed_state["members"]
            )
            assert removed_state["resource_leases"][0]["state"] == "unknown"
        finally:
            inventory.clear_provider_adapters()


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

    @pytest.mark.parametrize(
        ("path", "api_name", "operation", "cause", "expected_class"),
        (
            (
                "/api/coord/rooms/audit-room/messages?since=0",
                "read_room",
                "room.messages",
                ConnectionRefusedError("connection refused"),
                "ConnectionRefusedError",
            ),
            (
                "/api/coord/rooms/audit-room/wait?since=0&timeout=0.1",
                "wait_for_message",
                "room.wait",
                TimeoutError("consumer creation timed out"),
                "TimeoutError",
            ),
        ),
    )
    def test_distinct_chained_causes_are_audited_with_room_operation(
        self,
        api,
        isolated_state,
        monkeypatch,
        path,
        api_name,
        operation,
        cause,
        expected_class,
    ):
        from safeyolo.coord import api as coord_api
        from safeyolo.coord.nats_client import NatsUnavailable

        _register_agent("alice")
        _setup_room_with_grants("audit-room", ["alice"])
        room_id = next(
            room["room_id"]
            for room in coord_api.list_rooms()
            if room["name"] == "audit-room"
        )

        async def unavailable_operation(**_kwargs):
            raise NatsUnavailable("read failed") from cause

        monkeypatch.setattr(coord_api, api_name, unavailable_operation)
        with patch("agent_api.write_event", autospec=True) as audit:
            with _as_agent("alice"):
                flow = _make_flow(path, method="GET")
                _run(api, flow)

        assert flow.response.status_code == 503
        assert flow.response.content == (
            b'{"error": "coordination substrate unavailable"}'
        )
        assert audit.call_args.args == ("coord.nats_unavailable",)
        event = audit.call_args.kwargs
        assert event["kind"].value == "coord"
        assert event["details"]["operation"] == operation
        assert event["details"]["room_id"] == room_id
        assert event["details"]["error_class"] == expected_class
        assert event["details"]["reason"].startswith(f"{expected_class}:")

    def test_no_cause_fallback_excludes_room_name_and_message_body(
        self, api, isolated_state, monkeypatch
    ):
        from safeyolo.coord import api as coord_api
        from safeyolo.coord.nats_client import NatsUnavailable

        _register_agent("alice")
        _setup_room_with_grants("untrusted-room-name", ["alice"])

        async def unavailable_send(**_kwargs):
            raise NatsUnavailable("password=must-not-appear")

        monkeypatch.setattr(coord_api, "send", unavailable_send)
        with patch("agent_api.write_event", autospec=True) as audit:
            with _as_agent("alice"):
                flow = _make_flow(
                    "/api/coord/rooms/untrusted-room-name/send",
                    method="POST",
                    body={"body": "raw-room-message-must-not-appear"},
                )
                _run(api, flow)

        assert flow.response.content == (
            b'{"error": "coordination substrate unavailable"}'
        )
        event = audit.call_args.kwargs
        assert event["details"]["operation"] == "room.send"
        assert event["details"]["error_class"] == "NatsUnavailable"
        assert event["details"]["reason"] == "NatsUnavailable"
        rendered = repr(audit.call_args)
        assert "untrusted-room-name" not in rendered
        assert "raw-room-message-must-not-appear" not in rendered
        assert "must-not-appear" not in rendered

    @pytest.mark.parametrize(
        ("path", "api_name", "operation"),
        (
            (
                "/api/coord/attention/wait?since=0&timeout=0.1",
                "wait_for_attention",
                "attention.wait",
            ),
            (
                f"/api/coord/attention/attn-{'a' * 32}/object",
                "read_attention",
                "attention.read",
            ),
        ),
    )
    def test_attention_failures_have_stable_operation_attribution(
        self, api, isolated_state, monkeypatch, path, api_name, operation
    ):
        from safeyolo.coord import api as coord_api
        from safeyolo.coord.nats_client import NatsUnavailable

        _register_agent("alice")

        async def unavailable_attention(*_args, **_kwargs):
            try:
                raise OSError("attention transport failed")
            except OSError as cause:
                raise NatsUnavailable("attention failed") from cause

        monkeypatch.setattr(coord_api, api_name, unavailable_attention)
        with patch("agent_api.write_event", autospec=True) as audit:
            with _as_agent("alice"):
                flow = _make_flow(path, method="GET")
                _run(api, flow)

        assert flow.response.content == (
            b'{"error": "coordination substrate unavailable"}'
        )
        details = audit.call_args.kwargs["details"]
        assert details["operation"] == operation
        assert details["error_class"] == "OSError"
        assert "room_id" not in details

    def test_cause_reason_is_redacted_sanitized_and_bounded(
        self, api, isolated_state, monkeypatch
    ):
        from safeyolo.coord import api as coord_api
        from safeyolo.coord.nats_client import NatsUnavailable

        _register_agent("alice")
        secret = "x" * 64

        async def unavailable_attention(*_args, **_kwargs):
            try:
                raise RuntimeError(
                    "nats://user:nats-password@127.0.0.1 "
                    "Authorization: Basic dXNlcjpzZWNyZXQ=, "
                    "Bearer bearer-secret; pass=short-secret, "
                    "nkey=short-nkey; jwt=short-jwt, seed=short-seed; "
                    "credentials=short-credentials, password=plain-secret; "
                    f"token={secret}\n" + "z" * 400
                )
            except RuntimeError as cause:
                raise NatsUnavailable("attention failed") from cause

        monkeypatch.setattr(
            coord_api, "wait_for_attention", unavailable_attention
        )
        with patch("agent_api.write_event", autospec=True) as audit:
            with _as_agent("alice"):
                flow = _make_flow(
                    "/api/coord/attention/wait?since=0&timeout=0.1",
                    method="GET",
                )
                _run(api, flow)

        reason = audit.call_args.kwargs["details"]["reason"]
        assert len(reason) <= 240
        assert "<redacted>" in reason
        for raw_secret in (
            "nats-password",
            "dXNlcjpzZWNyZXQ=",
            "bearer-secret",
            "short-secret",
            "short-nkey",
            "short-jwt",
            "short-seed",
            "short-credentials",
            "plain-secret",
            secret,
            "\n",
        ):
            assert raw_secret not in reason

    @pytest.mark.parametrize(
        ("message", "expected_reason"),
        (
            (
                'password="sec,ret" connection refused',
                "RuntimeError: password=<redacted>",
            ),
            (
                "pass='sec;ret' connection refused",
                "RuntimeError: pass=<redacted>",
            ),
            (
                'token="alpha,beta;gamma" connection refused',
                "RuntimeError: token=<redacted>",
            ),
        ),
    )
    def test_quoted_named_secret_values_use_only_a_trusted_safe_shape(
        self, message, expected_reason
    ):
        from agent_api import _coord_nats_reason

        from safeyolo.coord.nats_client import NatsUnavailable

        cause = RuntimeError(message)
        unavailable = NatsUnavailable("attention failed")
        unavailable.__cause__ = cause

        error_class, reason = _coord_nats_reason(unavailable)

        assert error_class == "RuntimeError"
        assert reason == expected_reason

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

    def test_send_reports_unknown_when_puback_outcome_is_ambiguous(self, api, isolated_state, monkeypatch):
        from safeyolo.coord import api as coord_api
        from safeyolo.coord.nats_client import NatsPublishOutcomeUnknown

        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])

        async def ambiguous_send(**_kwargs):
            try:
                raise TimeoutError("PubAck timed out")
            except TimeoutError as cause:
                raise NatsPublishOutcomeUnknown(
                    "connection closed after dispatch"
                ) from cause

        monkeypatch.setattr(coord_api, "send", ambiguous_send)
        with patch("agent_api.write_event", autospec=True) as audit:
            with _as_agent("alice"):
                flow = _make_flow(
                    "/api/coord/rooms/r/send",
                    method="POST",
                    body={"body": "possibly accepted"},
                )
                _run(api, flow)
        assert flow.response.status_code == 503
        payload = json.loads(flow.response.content)
        assert payload["send_outcome"] == "unknown"
        assert "JetStream may have accepted it" in payload["error"]
        assert "before retrying" in payload["error"]
        assert audit.call_args.args == ("coord.nats_publish_outcome_unknown",)
        details = audit.call_args.kwargs["details"]
        assert details["operation"] == "room.send"
        assert details["error_class"] == "TimeoutError"
        assert details["room_id"].startswith("rm-")

    def test_audit_write_failure_does_not_change_unavailable_response(
        self, api, isolated_state, monkeypatch
    ):
        from safeyolo.coord import api as coord_api
        from safeyolo.coord.nats_client import NatsUnavailable

        _register_agent("alice")

        async def unavailable_attention(*_args, **_kwargs):
            raise NatsUnavailable("no cause")

        monkeypatch.setattr(
            coord_api, "wait_for_attention", unavailable_attention
        )
        with patch(
            "agent_api.write_event",
            autospec=True,
            side_effect=RuntimeError("audit writer unavailable"),
        ):
            with _as_agent("alice"):
                flow = _make_flow(
                    "/api/coord/attention/wait?since=0&timeout=0.1",
                    method="GET",
                )
                _run(api, flow)

        assert flow.response.status_code == 503
        assert flow.response.content == (
            b'{"error": "coordination substrate unavailable"}'
        )

    def test_empty_long_polls_do_not_emit_nats_failure_audit(
        self, api, isolated_state
    ):
        _register_agent("alice")
        _setup_room_with_grants("r", ["alice"])

        with patch("agent_api.write_event", autospec=True) as audit:
            with _as_agent("alice"):
                room_wait = _make_flow(
                    "/api/coord/rooms/r/wait?since=0&timeout=0.05",
                    method="GET",
                )
                _run(api, room_wait)
            with _as_agent("alice"):
                attention_wait = _make_flow(
                    "/api/coord/attention/wait?since=0&timeout=0.05",
                    method="GET",
                )
                _run(api, attention_wait)

        assert room_wait.response.status_code == 200
        assert attention_wait.response.status_code == 200
        assert audit.call_count == 0

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


class TestCoordTargetedAttention:
    def test_real_transport_attribution_preserves_target_isolation(
        self, api, isolated_state
    ):
        from types import SimpleNamespace

        from safeyolo.proxy_modes.unix_listener import UnixMode

        for name in ("alice", "bob", "codey"):
            _register_agent(name)
        _setup_room_with_grants("transport", ["alice", "bob", "codey"])

        addresses = {
            "alice": "10.0.0.11",
            "bob": "10.0.0.12",
            "codey": "10.0.0.13",
        }
        by_address = {address: name for name, address in addresses.items()}
        stub_sd = SimpleNamespace(
            get_client_for_ip=lambda address: by_address.get(address)
        )

        def attributed_flow(name, path, *, method="GET", body=None):
            flow = _make_flow(path, method=method, body=body)
            address = addresses[name]
            flow.client_conn.peername = (address, 12345)
            flow.client_conn.proxy_mode = UnixMode.parse(
                f"unix:/tmp/{address}_{name}/proxy.sock"
            )
            return flow

        with patch.object(
            AgentAPI,
            "_find_addon",
            autospec=True,
            side_effect=lambda _self, name: (
                stub_sd if name == "service-discovery" else None
            ),
        ):
            sent = attributed_flow(
                "alice",
                "/api/coord/rooms/transport/send",
                method="POST",
                body={"body": "transport-targeted", "notify": ["bob"]},
            )
            _run(api, sent)
            bob_wait = attributed_flow(
                "bob",
                "/api/coord/attention/wait?since=0&timeout=0.1",
            )
            _run(api, bob_wait)
            codey_wait = attributed_flow(
                "codey",
                "/api/coord/attention/wait?since=0&timeout=0.05",
            )
            _run(api, codey_wait)

        assert sent.response.status_code == 200
        msg_id = json.loads(sent.response.content)["envelope"]["msg_id"]
        assert msg_id in {
            edge["object_id"]
            for edge in json.loads(bob_wait.response.content)["edges"]
        }
        assert json.loads(codey_wait.response.content) == {
            "edges": [],
            "next_cursor": 0,
        }

    def test_identity_derived_feed_target_isolation_and_object_read(
        self, api, isolated_state
    ):
        from safeyolo.agents_store import get_agent_id

        for name in ("alice", "bob", "codey", "mallory"):
            _register_agent(name)
        _setup_room_with_grants("r", ["alice", "bob", "codey"])

        with _as_agent("alice"):
            sent = _make_flow(
                "/api/coord/rooms/r/send",
                method="POST",
                body={"body": "for bob", "notify": ["bob"]},
            )
            _run(api, sent)
        assert sent.response.status_code == 200
        accepted = json.loads(sent.response.content)
        assert accepted["attention_status"] == "ready"
        assert "notify" not in accepted["envelope"]

        with _as_agent("bob"):
            bob_wait = _make_flow(
                "/api/coord/attention/wait?since=0&timeout=0.1", method="GET"
            )
            _run(api, bob_wait)
        assert bob_wait.response.status_code == 200
        bob_page = json.loads(bob_wait.response.content)
        assert len(bob_page["edges"]) == 1
        edge = bob_page["edges"][0]
        assert edge["object_id"] == accepted["envelope"]["msg_id"]

        with _as_agent("codey"):
            codey_wait = _make_flow(
                "/api/coord/attention/wait?since=0&timeout=0.05", method="GET"
            )
            _run(api, codey_wait)
        assert json.loads(codey_wait.response.content) == {
            "edges": [],
            "next_cursor": 0,
        }

        # Codey did not wake but can still read the retained room message.
        with _as_agent("codey"):
            history = _make_flow("/api/coord/rooms/r/messages?since=0", method="GET")
            _run(api, history)
        message = json.loads(history.response.content)["messages"][0]
        assert message["body"] == "for bob"
        assert "notify" not in message

        with _as_agent("bob"):
            object_read = _make_flow(
                f"/api/coord/attention/{edge['attention_id']}/object", method="GET"
            )
            _run(api, object_read)
        assert json.loads(object_read.response.content)["object"]["body"] == "for bob"

        with _as_agent("codey"):
            denied = _make_flow(
                f"/api/coord/attention/{edge['attention_id']}/object", method="GET"
            )
            _run(api, denied)
        assert denied.response.status_code == 404
        assert json.loads(denied.response.content)["error"] == (
            "attention not found or not accessible"
        )

        # An omitted raw Agent API notify retains room-broadcast semantics.
        with _as_agent("alice"):
            omitted = _make_flow(
                "/api/coord/rooms/r/send",
                method="POST",
                body={"body": "legacy omission"},
            )
            _run(api, omitted)
        omitted_msg_id = json.loads(omitted.response.content)["envelope"]["msg_id"]
        with _as_agent("codey"):
            omitted_wait = _make_flow(
                "/api/coord/attention/wait?since=0&timeout=0.1", method="GET"
            )
            _run(api, omitted_wait)
        assert omitted_msg_id in {
            item["object_id"]
            for item in json.loads(omitted_wait.response.content)["edges"]
        }

        # Registered-but-not-a-member and unknown names are indistinguishable.
        failures = []
        for target in ("mallory", "unknown-agent"):
            with _as_agent("alice"):
                failed = _make_flow(
                    "/api/coord/rooms/r/send",
                    method="POST",
                    body={"body": "invalid target", "notify": [target]},
                )
                _run(api, failed)
            failures.append(
                (failed.response.status_code, json.loads(failed.response.content))
            )
        assert failures[0] == failures[1] == (
            400,
            {"error": "one or more notify targets are not active room members"},
        )
        assert get_agent_id("alice") == accepted["envelope"]["sender_agent_id"]
