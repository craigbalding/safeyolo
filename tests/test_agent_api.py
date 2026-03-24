"""Tests for addons/agent_api.py - read-only agent API."""

import json
import secrets
from unittest.mock import Mock, patch

import pytest
from agent_api import AGENT_API_HOST, AgentAPI
from flow_store import FlowStore
from mitmproxy.test import taddons, tflow


def _make_agent_token():
    """Create a plain agent token (same format as proxy generates)."""
    return secrets.token_hex(32)


@pytest.fixture
def agent_token():
    """Create a valid agent token."""
    return _make_agent_token()


@pytest.fixture
def api(agent_token):
    """Create AgentAPI with mitmproxy context."""
    addon = AgentAPI()
    with taddons.context(addon) as tctx:
        tctx.options.agent_api_enabled = True
        yield addon


def _patch_active_token(token_str):
    """Patch read_active_token to return the given token string."""
    return patch("pdp.tokens.read_active_token", return_value=token_str)


def _make_api_flow(path="/health", method="GET", token=None, query=None):
    """Create a flow targeting the agent API virtual host."""
    url = f"https://{AGENT_API_HOST}{path}"
    if query:
        url += f"?{query}"
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.url = url
    flow.request.host = AGENT_API_HOST
    if token:
        flow.request.headers["authorization"] = f"Bearer {token}"
    return flow


class TestAPIRouting:
    def test_ignores_non_api_requests(self, api):
        """Requests to other hosts pass through."""
        flow = tflow.tflow()
        flow.request.url = "https://api.openai.com/v1/chat"
        api.request(flow)
        assert flow.response is None

    def test_intercepts_api_host(self, api, agent_token):
        """Requests to _safeyolo.proxy.internal get handled."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 200

    def test_disabled_addon_passes_through(self, agent_token):
        """When disabled, agent API requests pass through."""
        addon = AgentAPI()
        with taddons.context(addon) as tctx:
            tctx.options.agent_api_enabled = False
            flow = _make_api_flow("/health", token=agent_token)
            addon.request(flow)
            assert flow.response is None


class TestAuth:
    def test_missing_auth_returns_401(self, api):
        flow = _make_api_flow("/health")
        api.request(flow)
        assert flow.response.status_code == 401
        body = json.loads(flow.response.content)
        assert "Authorization required" in body["error"]

    def test_invalid_token_returns_401(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token="invalid-token")
            api.request(flow)
            assert flow.response.status_code == 401

    def test_valid_token_succeeds(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200

    def test_missing_token_file_returns_503(self, api):
        """No token on disk returns 503 (not configured)."""
        with _patch_active_token(None):
            flow = _make_api_flow("/health", token="some-token")
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert "not configured" in body["error"].lower()

    def test_replaced_token_rejects_old(self, api):
        """Creating a new token invalidates the old one."""
        old_token = _make_agent_token()
        new_token = _make_agent_token()

        # Disk has the new token
        with _patch_active_token(new_token):
            # Old token should be rejected
            flow = _make_api_flow("/health", token=old_token)
            api.request(flow)
            assert flow.response.status_code == 401

            # New token should work
            flow = _make_api_flow("/health", token=new_token)
            api.request(flow)
            assert flow.response.status_code == 200


class TestMethods:
    def test_post_returns_405(self, api, agent_token):
        flow = _make_api_flow("/health", method="POST", token=agent_token)
        api.request(flow)
        assert flow.response.status_code == 405

    def test_put_returns_405(self, api, agent_token):
        flow = _make_api_flow("/health", method="PUT", token=agent_token)
        api.request(flow)
        assert flow.response.status_code == 405

    def test_delete_returns_405(self, api, agent_token):
        flow = _make_api_flow("/health", method="DELETE", token=agent_token)
        api.request(flow)
        assert flow.response.status_code == 405


class TestEndpoints:
    def test_health(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["agent_api"] == "ok"

    def test_agents_returns_discovery_data(self, api, agent_token):
        """Test /agents returns agent data from service-discovery addon."""
        mock_sd = Mock()
        mock_sd.get_agents.return_value = {
            "agents": {"boris": {"ip": "172.20.0.5", "last_seen": 1000.0, "idle_seconds": 5.0}},
            "count": 1,
        }
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=mock_sd):
            flow = _make_api_flow("/agents", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] == 1
            assert "boris" in body["agents"]

    def test_agents_503_when_addon_missing(self, api, agent_token):
        """Test /agents returns 503 when service-discovery not loaded."""
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=None):
            flow = _make_api_flow("/agents", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503

    def test_unknown_endpoint_returns_404(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/unknown", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 404
            body = json.loads(flow.response.content)
            assert "endpoints" in body

    def test_explain_missing_param(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 400

    def test_explain_with_request_id(self, api, agent_token):
        """Test /explain returns 200 with request_id (log may not exist in test env)."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query="request_id=req-0a1b2c3d4e5f")
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["request_id"] == "req-0a1b2c3d4e5f"
            assert isinstance(body["events"], list)

    def test_explain_invalid_request_id(self, api, agent_token):
        """Test /explain rejects malformed request_id."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query="request_id=../../../etc/passwd")
            api.request(flow)
            assert flow.response.status_code == 400

    def test_explain_rejects_short_request_id(self, api, agent_token):
        """Test /explain rejects request_id that doesn't match expected format."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query="request_id=req-123")
            api.request(flow)
            assert flow.response.status_code == 400


class TestMetadata:
    def test_sets_blocked_by_metadata(self, api, agent_token):
        """Agent API sets blocked_by so downstream addons skip."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.metadata.get("blocked_by") == "agent-api"

    def test_response_has_agent_api_header(self, api, agent_token):
        """Responses include X-SafeYolo-Agent-API header."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.headers.get("X-SafeYolo-Agent-API") == "true"


# -- Flow Store API route tests --

def _make_post_api_flow(path, body_dict, token):
    """Create a POST flow targeting the agent API virtual host with JSON body."""
    flow = _make_api_flow(path, method="POST", token=token)
    flow.request.content = json.dumps(body_dict).encode()
    flow.request.headers["content-type"] = "application/json"
    return flow


@pytest.fixture
def api_with_store(tmp_path, agent_token):
    """Create AgentAPI with a mock flow-recorder addon that has a real FlowStore."""
    addon = AgentAPI()

    # Create a real FlowStore
    db_path = str(tmp_path / "api_test_flows.sqlite3")
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
        tctx.options.agent_api_enabled = True
        # Patch _find_addon to return mock recorder for "flow-recorder"
        original_find = addon._find_addon

        def patched_find(name):
            if name == "flow-recorder":
                return mock_recorder
            return original_find(name)

        addon._find_addon = patched_find

        yield addon, store, agent_token

    store.close()


class TestFlowStoreAPI:
    def test_post_flow_search(self, api_with_store):
        """POST /api/flows/search returns results."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/search",
                {"host": "app.example.com"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] == 1
            assert body["flows"][0]["host"] == "app.example.com"

    def test_get_flow_detail(self, api_with_store):
        """GET /api/flows/{id} returns flow metadata."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/1", token=token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["id"] == 1
            assert body["request_id"] == "req-relay00001"

    def test_get_flow_detail_not_found(self, api_with_store):
        """GET /api/flows/{id} returns 404 for missing flow."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/99999", token=token)
            api.request(flow)
            assert flow.response.status_code == 404

    def test_get_request_body(self, api_with_store):
        """GET /api/flows/{id}/request-body returns decompressed body."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/1/request-body", token=token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "body_base64" in body
            assert body["body_length"] > 0
            # Text-like content should include body_text
            assert "body_text" in body
            assert "action" in body["body_text"]

    def test_get_response_body(self, api_with_store):
        """GET /api/flows/{id}/response-body returns decompressed body."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/1/response-body", token=token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "body_base64" in body
            assert "body_text" in body
            assert "alice" in body["body_text"]

    def test_post_flow_endpoints(self, api_with_store):
        """POST /api/flows/endpoints returns grouped data."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/endpoints",
                {"engagement_id": "acme-portal"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] >= 1

    def test_post_flow_body_search(self, api_with_store):
        """POST /api/flows/body-search returns FTS results."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/body-search",
                {"engagement_id": "acme-portal", "query": "admin"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] >= 1

    def test_flow_store_503_when_not_available(self, api, agent_token):
        """Flow store routes return 503 when recorder not loaded."""
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=None):
            flow = _make_post_api_flow(
                "/api/flows/search",
                {"host": "example.com"},
                agent_token,
            )
            api.request(flow)
            assert flow.response.status_code == 503

    def test_body_search_requires_engagement_id(self, api_with_store):
        """POST /api/flows/body-search requires engagement_id."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/body-search",
                {"query": "test"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 400

    def test_body_search_requires_query(self, api_with_store):
        """POST /api/flows/body-search requires query."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/body-search",
                {"engagement_id": "acme-portal"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 400

    def test_post_flow_diff(self, api_with_store):
        """POST /api/flows/diff returns comparison."""
        api, store, token = api_with_store
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
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/diff",
                {"flow_id_a": 1, "flow_id_b": 2},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "identical" in body
            assert "size_a" in body

    def test_post_flow_diff_missing_params(self, api_with_store):
        """POST /api/flows/diff requires flow_id_a and flow_id_b."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/diff",
                {"flow_id_a": 1},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 400

    def test_post_flow_diff_not_found(self, api_with_store):
        """POST /api/flows/diff returns 404 when flow missing."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/diff",
                {"flow_id_a": 1, "flow_id_b": 99999},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 404

    def test_post_flow_request_body_search(self, api_with_store):
        """POST /api/flows/request-body-search returns results."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/request-body-search",
                {"engagement_id": "acme-portal", "query": "action"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "flows" in body
            assert "count" in body

    def test_post_flow_request_body_search_missing_params(self, api_with_store):
        """POST /api/flows/request-body-search requires engagement_id and query."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/request-body-search",
                {"query": "test"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 400

    def test_post_flow_tag_add(self, api_with_store):
        """POST /api/flows/{id}/tag adds a tag."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/1/tag",
                {"tag": "confirmed", "value": "idor"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["tag"] == "confirmed"
            assert body["value"] == "idor"

    def test_post_flow_tag_missing_tag(self, api_with_store):
        """POST /api/flows/{id}/tag requires tag field."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_post_api_flow(
                "/api/flows/1/tag",
                {"value": "something"},
                token,
            )
            api.request(flow)
            assert flow.response.status_code == 400

    def test_delete_flow_tag(self, api_with_store):
        """DELETE /api/flows/{id}/tag/{name} removes a tag."""
        api, store, token = api_with_store
        # First add a tag
        store.tag_flow(1, "confirmed", "idor")
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/1/tag/confirmed", method="DELETE", token=token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["deleted"] is True

    def test_delete_flow_tag_not_found(self, api_with_store):
        """DELETE /api/flows/{id}/tag/{name} returns 404 when tag missing."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/1/tag/nonexistent", method="DELETE", token=token)
            api.request(flow)
            assert flow.response.status_code == 404

    def test_delete_on_non_flow_route_returns_405(self, api, agent_token):
        """DELETE on non-flow route returns 405."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", method="DELETE", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 405
