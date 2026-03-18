"""Tests for addons/agent_relay.py - read-only PDP relay."""

import json
from unittest.mock import Mock, patch

import pytest
from agent_relay import RELAY_HOST, AgentRelay
from flow_store import FlowStore
from mitmproxy.test import taddons, tflow

from pdp.tokens import create_readonly_token

ADMIN_TOKEN = "test-admin-token-for-relay-tests"


@pytest.fixture
def relay(monkeypatch):
    """Create AgentRelay with mitmproxy context."""
    monkeypatch.setenv("ADMIN_API_TOKEN", ADMIN_TOKEN)
    addon = AgentRelay()
    with taddons.context(addon) as tctx:
        tctx.options.agent_relay_enabled = True
        yield addon


@pytest.fixture
def valid_token():
    """Create a valid readonly token."""
    return create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)


def _patch_active_token(token_str):
    """Patch read_active_token to return the given token string."""
    return patch("pdp.tokens.read_active_token", return_value=token_str)


def _make_relay_flow(path="/health", method="GET", token=None, query=None):
    """Create a flow targeting the relay virtual host."""
    url = f"https://{RELAY_HOST}{path}"
    if query:
        url += f"?{query}"
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.url = url
    flow.request.host = RELAY_HOST
    if token:
        flow.request.headers["authorization"] = f"Bearer {token}"
    return flow


class TestRelayRouting:
    def test_ignores_non_relay_requests(self, relay):
        """Requests to other hosts pass through."""
        flow = tflow.tflow()
        flow.request.url = "https://api.openai.com/v1/chat"
        relay.request(flow)
        assert flow.response is None

    def test_intercepts_relay_host(self, relay, valid_token):
        """Requests to _safeyolo.proxy.internal get handled."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/health", token=valid_token)
            relay.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 200

    def test_disabled_addon_passes_through(self, valid_token, monkeypatch):
        """When disabled, relay requests pass through."""
        monkeypatch.setenv("ADMIN_API_TOKEN", ADMIN_TOKEN)
        addon = AgentRelay()
        with taddons.context(addon) as tctx:
            tctx.options.agent_relay_enabled = False
            flow = _make_relay_flow("/health", token=valid_token)
            addon.request(flow)
            assert flow.response is None


class TestAuth:
    def test_missing_auth_returns_401(self, relay):
        flow = _make_relay_flow("/health")
        relay.request(flow)
        assert flow.response.status_code == 401
        body = json.loads(flow.response.content)
        assert "Authorization required" in body["error"]

    def test_invalid_token_returns_401(self, relay):
        flow = _make_relay_flow("/health", token="invalid-token")
        relay.request(flow)
        assert flow.response.status_code == 401

    def test_expired_token_returns_401(self, relay):
        expired = create_readonly_token(ADMIN_TOKEN, ttl_seconds=-1)
        flow = _make_relay_flow("/health", token=expired)
        relay.request(flow)
        assert flow.response.status_code == 401

    def test_valid_token_succeeds(self, relay, valid_token):
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/health", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200

    def test_deleted_token_file_returns_401(self, relay, valid_token):
        """No token on disk (restart/revoke) rejects valid token."""
        with _patch_active_token(None):
            flow = _make_relay_flow("/health", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 401
            body = json.loads(flow.response.content)
            assert "revoked" in body["error"].lower()

    def test_replaced_token_rejects_old(self, relay):
        """Creating a new token invalidates the old one."""
        old_token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        new_token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)

        # Disk has the new token
        with _patch_active_token(new_token):
            # Old token should be rejected
            flow = _make_relay_flow("/health", token=old_token)
            relay.request(flow)
            assert flow.response.status_code == 401

            # New token should work
            flow = _make_relay_flow("/health", token=new_token)
            relay.request(flow)
            assert flow.response.status_code == 200


class TestMethods:
    def test_post_returns_405(self, relay, valid_token):
        flow = _make_relay_flow("/health", method="POST", token=valid_token)
        relay.request(flow)
        assert flow.response.status_code == 405

    def test_put_returns_405(self, relay, valid_token):
        flow = _make_relay_flow("/health", method="PUT", token=valid_token)
        relay.request(flow)
        assert flow.response.status_code == 405

    def test_delete_returns_405(self, relay, valid_token):
        flow = _make_relay_flow("/health", method="DELETE", token=valid_token)
        relay.request(flow)
        assert flow.response.status_code == 405


class TestEndpoints:
    def test_health(self, relay, valid_token):
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/health", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["relay"] == "ok"

    def test_agents_returns_discovery_data(self, relay, valid_token):
        """Test /agents returns agent data from service-discovery addon."""
        mock_sd = Mock()
        mock_sd.get_agents.return_value = {
            "agents": {"boris": {"ip": "172.20.0.5", "last_seen": 1000.0, "idle_seconds": 5.0}},
            "count": 1,
        }
        with _patch_active_token(valid_token), \
             patch.object(relay, "_find_addon", return_value=mock_sd):
            flow = _make_relay_flow("/agents", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] == 1
            assert "boris" in body["agents"]

    def test_agents_503_when_addon_missing(self, relay, valid_token):
        """Test /agents returns 503 when service-discovery not loaded."""
        with _patch_active_token(valid_token), \
             patch.object(relay, "_find_addon", return_value=None):
            flow = _make_relay_flow("/agents", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 503

    def test_unknown_endpoint_returns_404(self, relay, valid_token):
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/unknown", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 404
            body = json.loads(flow.response.content)
            assert "endpoints" in body

    def test_explain_missing_param(self, relay, valid_token):
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/explain", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_explain_with_request_id(self, relay, valid_token):
        """Test /explain returns 200 with request_id (log may not exist in test env)."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/explain", token=valid_token, query="request_id=req-0a1b2c3d4e5f")
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["request_id"] == "req-0a1b2c3d4e5f"
            assert isinstance(body["events"], list)

    def test_explain_invalid_request_id(self, relay, valid_token):
        """Test /explain rejects malformed request_id."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/explain", token=valid_token, query="request_id=../../../etc/passwd")
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_explain_rejects_short_request_id(self, relay, valid_token):
        """Test /explain rejects request_id that doesn't match expected format."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/explain", token=valid_token, query="request_id=req-123")
            relay.request(flow)
            assert flow.response.status_code == 400


class TestMetadata:
    def test_sets_blocked_by_metadata(self, relay, valid_token):
        """Relay sets blocked_by so downstream addons skip."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/health", token=valid_token)
            relay.request(flow)
            assert flow.metadata.get("blocked_by") == "agent-relay"

    def test_response_has_relay_header(self, relay, valid_token):
        """Responses include X-SafeYolo-Relay header."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/health", token=valid_token)
            relay.request(flow)
            assert flow.response.headers.get("X-SafeYolo-Relay") == "true"


# -- Flow Store API route tests --

def _make_post_relay_flow(path, body_dict, token):
    """Create a POST flow targeting the relay virtual host with JSON body."""
    flow = _make_relay_flow(path, method="POST", token=token)
    flow.request.content = json.dumps(body_dict).encode()
    flow.request.headers["content-type"] = "application/json"
    return flow


@pytest.fixture
def relay_with_store(monkeypatch, tmp_path):
    """Create AgentRelay with a mock flow-recorder addon that has a real FlowStore."""
    monkeypatch.setenv("ADMIN_API_TOKEN", ADMIN_TOKEN)
    addon = AgentRelay()

    # Create a real FlowStore
    db_path = str(tmp_path / "relay_test_flows.sqlite3")
    store = FlowStore(db_path=db_path)
    store.init_db()

    # Seed some test data
    store.record_flow({
        "request_id": "req-relay00001",
        "ts_start": 1710000100000,
        "ts_end": 1710000100084,
        "duration_ms": 84,
        "engagement_id": "acme-portal",
        "agent_id": "agent-1",
        "source_id": "172.20.0.5",
        "run": "sec1",
        "test": "idor-baseline",
        "role": "attacker",
        "context_json": None,
        "source_type": None,
        "flow_state": "completed",
        "scheme": "https",
        "host": "app.example.com",
        "port": 443,
        "method": "GET",
        "path": "/api/todos/42",
        "query_string": None,
        "full_url": "https://app.example.com/api/todos/42",
        "status_code": 200,
        "reason": None,
        "request_content_type": "application/json",
        "response_content_type": "application/json",
        "is_websocket": False,
        "request_headers_json": "[]",
        "response_headers_json": "[]",
        "request_body": b'{"action":"get"}',
        "response_body": b'{"id":42,"owner":"alice","role":"admin"}',
    })

    # Create mock recorder
    mock_recorder = Mock()
    mock_recorder.store = store

    with taddons.context(addon) as tctx:
        tctx.options.agent_relay_enabled = True
        # Patch _find_addon to return mock recorder for "flow-recorder"
        original_find = addon._find_addon

        def patched_find(name):
            if name == "flow-recorder":
                return mock_recorder
            return original_find(name)

        addon._find_addon = patched_find

        yield addon, store

    store.close()


class TestFlowStoreAPI:
    def test_post_flow_search(self, relay_with_store, valid_token):
        """POST /api/flows/search returns results."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/search",
                {"host": "app.example.com"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] == 1
            assert body["flows"][0]["host"] == "app.example.com"

    def test_get_flow_detail(self, relay_with_store, valid_token):
        """GET /api/flows/{id} returns flow metadata."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/api/flows/1", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["id"] == 1
            assert body["request_id"] == "req-relay00001"

    def test_get_flow_detail_not_found(self, relay_with_store, valid_token):
        """GET /api/flows/{id} returns 404 for missing flow."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/api/flows/99999", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 404

    def test_get_request_body(self, relay_with_store, valid_token):
        """GET /api/flows/{id}/request-body returns decompressed body."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/api/flows/1/request-body", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "body_base64" in body
            assert body["body_length"] > 0
            # Text-like content should include body_text
            assert "body_text" in body
            assert "action" in body["body_text"]

    def test_get_response_body(self, relay_with_store, valid_token):
        """GET /api/flows/{id}/response-body returns decompressed body."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/api/flows/1/response-body", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "body_base64" in body
            assert "body_text" in body
            assert "alice" in body["body_text"]

    def test_post_flow_endpoints(self, relay_with_store, valid_token):
        """POST /api/flows/endpoints returns grouped data."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/endpoints",
                {"engagement_id": "acme-portal"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] >= 1

    def test_post_flow_body_search(self, relay_with_store, valid_token):
        """POST /api/flows/body-search returns FTS results."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/body-search",
                {"engagement_id": "acme-portal", "query": "admin"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] >= 1

    def test_flow_store_503_when_not_available(self, relay, valid_token):
        """Flow store routes return 503 when recorder not loaded."""
        with _patch_active_token(valid_token), \
             patch.object(relay, "_find_addon", return_value=None):
            flow = _make_post_relay_flow(
                "/api/flows/search",
                {"host": "example.com"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 503

    def test_body_search_requires_engagement_id(self, relay_with_store, valid_token):
        """POST /api/flows/body-search requires engagement_id."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/body-search",
                {"query": "test"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_body_search_requires_query(self, relay_with_store, valid_token):
        """POST /api/flows/body-search requires query."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/body-search",
                {"engagement_id": "acme-portal"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_post_flow_diff(self, relay_with_store, valid_token):
        """POST /api/flows/diff returns comparison."""
        relay, store = relay_with_store
        # Add a second flow for diffing
        store.record_flow({
            "request_id": "req-relay00002",
            "ts_start": 1710000200000,
            "ts_end": 1710000200084,
            "duration_ms": 84,
            "engagement_id": "acme-portal",
            "agent_id": "agent-1",
            "source_id": "172.20.0.5",
            "run": "sec1",
            "test": "idor-baseline",
            "role": "attacker",
            "context_json": None,
            "source_type": None,
            "flow_state": "completed",
            "scheme": "https",
            "host": "app.example.com",
            "port": 443,
            "method": "GET",
            "path": "/api/todos/42",
            "query_string": None,
            "full_url": "https://app.example.com/api/todos/42",
            "status_code": 200,
            "reason": None,
            "request_content_type": "",
            "response_content_type": "application/json",
            "is_websocket": False,
            "request_headers_json": "[]",
            "response_headers_json": "[]",
            "request_body": b"",
            "response_body": b'{"id":42,"owner":"alice","role":"user"}',
        })
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/diff",
                {"flow_id_a": 1, "flow_id_b": 2},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "identical" in body
            assert "size_a" in body

    def test_post_flow_diff_missing_params(self, relay_with_store, valid_token):
        """POST /api/flows/diff requires flow_id_a and flow_id_b."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/diff",
                {"flow_id_a": 1},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_post_flow_diff_not_found(self, relay_with_store, valid_token):
        """POST /api/flows/diff returns 404 when flow missing."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/diff",
                {"flow_id_a": 1, "flow_id_b": 99999},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 404

    def test_post_flow_request_body_search(self, relay_with_store, valid_token):
        """POST /api/flows/request-body-search returns results."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/request-body-search",
                {"engagement_id": "acme-portal", "query": "action"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "flows" in body
            assert "count" in body

    def test_post_flow_request_body_search_missing_params(self, relay_with_store, valid_token):
        """POST /api/flows/request-body-search requires engagement_id and query."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/request-body-search",
                {"query": "test"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_post_flow_tag_add(self, relay_with_store, valid_token):
        """POST /api/flows/{id}/tag adds a tag."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/1/tag",
                {"tag": "confirmed", "value": "idor"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["tag"] == "confirmed"
            assert body["value"] == "idor"

    def test_post_flow_tag_missing_tag(self, relay_with_store, valid_token):
        """POST /api/flows/{id}/tag requires tag field."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_post_relay_flow(
                "/api/flows/1/tag",
                {"value": "something"},
                valid_token,
            )
            relay.request(flow)
            assert flow.response.status_code == 400

    def test_delete_flow_tag(self, relay_with_store, valid_token):
        """DELETE /api/flows/{id}/tag/{name} removes a tag."""
        relay, store = relay_with_store
        # First add a tag
        store.tag_flow(1, "confirmed", "idor")
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/api/flows/1/tag/confirmed", method="DELETE", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["deleted"] is True

    def test_delete_flow_tag_not_found(self, relay_with_store, valid_token):
        """DELETE /api/flows/{id}/tag/{name} returns 404 when tag missing."""
        relay, store = relay_with_store
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/api/flows/1/tag/nonexistent", method="DELETE", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 404

    def test_delete_on_non_flow_route_returns_405(self, relay, valid_token):
        """DELETE on non-flow route returns 405."""
        with _patch_active_token(valid_token):
            flow = _make_relay_flow("/health", method="DELETE", token=valid_token)
            relay.request(flow)
            assert flow.response.status_code == 405
