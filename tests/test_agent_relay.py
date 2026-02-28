"""Tests for addons/agent_relay.py - read-only PDP relay."""

import json
from unittest.mock import patch

import pytest
from agent_relay import RELAY_HOST, AgentRelay
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
            flow = _make_relay_flow("/explain", token=valid_token, query="request_id=req-123")
            relay.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["request_id"] == "req-123"
            assert isinstance(body["events"], list)


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
