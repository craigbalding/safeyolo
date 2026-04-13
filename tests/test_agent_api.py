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
        assert body == {
            "error": "Authorization required",
            "hint": "Bearer <token>",
        }

    def test_invalid_token_returns_401(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token="invalid-token")
            api.request(flow)
            assert flow.response.status_code == 401
            body = json.loads(flow.response.content)
            assert body == {"error": "Invalid agent token"}

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
            assert body == {"error": "Agent token not configured"}

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

    def test_invalid_token_emits_audit_event(self, api, agent_token):
        """Failed auth writes a security.agent_auth_failed event."""
        with _patch_active_token(agent_token), \
             patch("agent_api.write_event") as mock_write:
            flow = _make_api_flow("/health", token="wrong-token")
            api.request(flow)
            assert flow.response.status_code == 401

            mock_write.assert_called_once()
            call_args = mock_write.call_args
            assert call_args[0][0] == "security.agent_auth_failed"
            assert call_args[1]["severity"].value == "high"
            assert call_args[1]["decision"].value == "deny"
            assert call_args[1]["addon"] == "agent-api"
            assert "path" in call_args[1]["details"]

    def test_bearer_prefix_required(self, api, agent_token):
        """Auth header without 'Bearer ' prefix is rejected as 401."""
        flow = _make_api_flow("/health")
        flow.request.headers["authorization"] = f"Token {agent_token}"
        api.request(flow)
        assert flow.response.status_code == 401
        body = json.loads(flow.response.content)
        assert body["hint"] == "Bearer <token>"


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

    def test_patch_returns_405(self, api, agent_token):
        """PATCH is not in the allowed methods set."""
        flow = _make_api_flow("/health", method="PATCH", token=agent_token)
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

    def test_unknown_endpoint_lists_all_routes(self, api, agent_token):
        """404 body includes the full list of available endpoints for discoverability."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/nonexistent", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 404
            body = json.loads(flow.response.content)
            endpoints = body["endpoints"]
            # Verify key routes are listed
            assert "/health" in endpoints
            assert "/status" in endpoints
            assert "/policy" in endpoints
            assert "/explain" in endpoints
            assert "/lookup" in endpoints
            assert "/budgets" in endpoints
            assert "/config" in endpoints
            assert "/memory" in endpoints
            assert "/circuits" in endpoints
            assert "/agents" in endpoints

    def test_handler_exception_returns_500(self, api, agent_token):
        """If a handler raises, the API returns 500 with the exception type."""
        with _patch_active_token(agent_token), \
             patch.object(api, "_handle_health", side_effect=RuntimeError("boom")):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 500
            body = json.loads(flow.response.content)
            assert body == {"error": "Internal error: RuntimeError"}


class TestExplain:
    def test_explain_missing_param(self, api, agent_token):
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 400
            body = json.loads(flow.response.content)
            assert body == {
                "error": "Invalid or missing request_id",
                "usage": "/explain?request_id=req-<32hex>",
            }

    def test_explain_with_request_id_no_log_file(self, api, agent_token):
        """When JSONL log doesn't exist, returns empty events list."""
        with _patch_active_token(agent_token):
            valid_id = "req-0a1b2c3d4e5f6789abcdef0123456789"
            flow = _make_api_flow("/explain", token=agent_token, query=f"request_id={valid_id}")
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["request_id"] == valid_id
            assert body["events"] == []

    def test_explain_invalid_request_id(self, api, agent_token):
        """Path traversal attempt is rejected."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query="request_id=../../../etc/passwd")
            api.request(flow)
            assert flow.response.status_code == 400

    def test_explain_rejects_short_request_id(self, api, agent_token):
        """Request ID that doesn't match req-<32hex> format is rejected."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query="request_id=req-123")
            api.request(flow)
            assert flow.response.status_code == 400

    def test_explain_rejects_old_12hex_format(self, api, agent_token):
        """Old 12-hex format is rejected (must be 32 hex)."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query="request_id=req-0a1b2c3d4e5f")
            api.request(flow)
            assert flow.response.status_code == 400

    def test_explain_finds_matching_events_in_jsonl(self, api, agent_token, tmp_path, monkeypatch):
        """Explain searches JSONL log and returns only events matching request_id."""
        target_id = "req-aabbccdd11223344aabbccdd11223344"
        other_id = "req-00000000000000000000000000000000"
        log_file = tmp_path / "safeyolo.jsonl"
        log_file.write_text(
            json.dumps({"request_id": target_id, "event": "traffic.request", "host": "example.com"}) + "\n"
            + json.dumps({"request_id": other_id, "event": "traffic.request", "host": "other.com"}) + "\n"
            + json.dumps({"request_id": target_id, "event": "traffic.response", "status_code": 200}) + "\n"
            + "not valid json\n"
        )
        monkeypatch.setenv("SAFEYOLO_LOG_PATH", str(log_file))

        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query=f"request_id={target_id}")
            api.request(flow)

        assert flow.response.status_code == 200
        body = json.loads(flow.response.content)
        assert body["request_id"] == target_id
        assert len(body["events"]) == 2
        assert body["events"][0]["host"] == "example.com"
        assert body["events"][1]["status_code"] == 200
        assert "truncated" not in body

    def test_explain_sets_truncated_flag_when_log_exceeds_limit(self, api, agent_token, tmp_path, monkeypatch):
        """When log exceeds MAX_EXPLAIN_LINES, truncated flag is set."""
        target_id = "req-aabbccdd11223344aabbccdd11223344"
        log_file = tmp_path / "safeyolo.jsonl"
        # Write more lines than MAX_EXPLAIN_LINES (10000)
        lines = []
        for i in range(10002):
            lines.append(json.dumps({"request_id": "req-00000000000000000000000000000000", "i": i}))
        # Put target at the end so it's in the retained window
        lines.append(json.dumps({"request_id": target_id, "event": "traffic.request"}))
        log_file.write_text("\n".join(lines) + "\n")

        monkeypatch.setenv("SAFEYOLO_LOG_PATH", str(log_file))

        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query=f"request_id={target_id}")
            api.request(flow)

        assert flow.response.status_code == 200
        body = json.loads(flow.response.content)
        assert body["truncated"] is True
        assert body["searched_lines"] == 10000
        # Target event was in the last 10000 lines, so it should be found
        assert len(body["events"]) == 1


class TestPDPEndpoints:
    """Tests for endpoints that proxy to PDP: /health, /status, /policy, /budgets, /config."""

    def test_health_pdp_available(self, api, agent_token):
        """When PDP is healthy, /health returns pdp: ok."""
        mock_client = Mock()
        mock_client.health_check.return_value = True
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {"agent_api": "ok", "pdp": "ok"}

    def test_health_pdp_unavailable(self, api, agent_token):
        """When PDP is not configured, /health returns pdp: unavailable."""
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=None):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {"agent_api": "ok", "pdp": "unavailable"}

    def test_health_pdp_unhealthy(self, api, agent_token):
        """When PDP health check fails, pdp field is 'unavailable'."""
        mock_client = Mock()
        mock_client.health_check.return_value = False
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {"agent_api": "ok", "pdp": "unavailable"}

    def test_status_returns_pdp_stats(self, api, agent_token):
        """/status proxies PDP stats."""
        mock_client = Mock()
        mock_client.get_stats.return_value = {
            "engine_version": "2.0",
            "policy_hash": "abc123",
            "eval_count": 42,
        }
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/status", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {
                "engine_version": "2.0",
                "policy_hash": "abc123",
                "eval_count": 42,
            }

    def test_status_503_when_pdp_unavailable(self, api, agent_token):
        """/status returns 503 when PDP not configured."""
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=None):
            flow = _make_api_flow("/status", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "PDP not available"}

    def test_policy_returns_baseline(self, api, agent_token):
        """/policy wraps baseline in a 'policy' key."""
        mock_client = Mock()
        mock_client.get_baseline.return_value = {"permissions": [], "budgets": {}}
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/policy", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {"policy": {"permissions": [], "budgets": {}}}

    def test_policy_503_when_pdp_unavailable(self, api, agent_token):
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=None):
            flow = _make_api_flow("/policy", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "PDP not available"}

    def test_budgets_returns_budget_stats(self, api, agent_token):
        """/budgets proxies PDP budget stats."""
        mock_client = Mock()
        mock_client.get_budget_stats.return_value = {
            "api.openai.com": {"used": 5, "limit": 100, "remaining": 95},
        }
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/budgets", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {
                "api.openai.com": {"used": 5, "limit": 100, "remaining": 95},
            }

    def test_budgets_503_when_pdp_unavailable(self, api, agent_token):
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=None):
            flow = _make_api_flow("/budgets", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "PDP not available"}

    def test_config_returns_sensor_config(self, api, agent_token):
        """/config proxies PDP sensor config."""
        mock_client = Mock()
        mock_client.get_sensor_config.return_value = {
            "credential_rules": [{"name": "openai"}],
            "scan_patterns": [],
        }
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/config", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {
                "credential_rules": [{"name": "openai"}],
                "scan_patterns": [],
            }

    def test_config_503_when_pdp_unavailable(self, api, agent_token):
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=None):
            flow = _make_api_flow("/config", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "PDP not available"}


class TestAddonEndpoints:
    """Tests for endpoints that delegate to other addons: /memory, /circuits."""

    def test_memory_returns_stats(self, api, agent_token):
        """/memory proxies memory-monitor stats."""
        mock_monitor = Mock()
        mock_monitor.get_stats.return_value = {
            "rss_mb": 128.5,
            "connections": 12,
        }
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=mock_monitor):
            flow = _make_api_flow("/memory", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {"rss_mb": 128.5, "connections": 12}

    def test_memory_503_when_addon_missing(self, api, agent_token):
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=None):
            flow = _make_api_flow("/memory", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "memory-monitor addon not loaded"}

    def test_circuits_returns_stats(self, api, agent_token):
        """/circuits proxies circuit-breaker stats."""
        mock_cb = Mock()
        mock_cb.get_stats.return_value = {
            "api.openai.com": {"state": "closed", "failures": 0},
        }
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=mock_cb):
            flow = _make_api_flow("/circuits", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body == {
                "api.openai.com": {"state": "closed", "failures": 0},
            }

    def test_circuits_503_when_addon_missing(self, api, agent_token):
        with _patch_active_token(agent_token), \
             patch.object(api, "_find_addon", return_value=None):
            flow = _make_api_flow("/circuits", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "circuit-breaker addon not loaded"}


class TestLookup:
    """Tests for GET /lookup?host=X - policy evaluation for a host."""

    def test_lookup_missing_host_returns_400(self, api, agent_token):
        """Missing host parameter returns 400 with usage hint."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/lookup", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 400
            body = json.loads(flow.response.content)
            assert body == {
                "error": "Missing 'host' parameter",
                "usage": "/lookup?host=example.com",
            }

    def test_lookup_pdp_unavailable_returns_503(self, api, agent_token):
        """When PDP is not configured, returns 503."""
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=None):
            flow = _make_api_flow("/lookup", token=agent_token, query="host=example.com")
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "PDP not available"}

    def test_lookup_engine_unavailable_returns_503(self, api, agent_token):
        """When policy engine is not accessible via client, returns 503."""
        mock_client = Mock()
        mock_client._pdp = None  # No PDP core attached
        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/lookup", token=agent_token, query="host=example.com")
            api.request(flow)
            assert flow.response.status_code == 503
            body = json.loads(flow.response.content)
            assert body == {"error": "Policy engine not available"}

    def test_lookup_returns_decision(self, api, agent_token):
        """Successful lookup returns host, agent, effect, reason."""
        mock_decision = Mock()
        mock_decision.effect = "allow"
        mock_decision.reason = "explicit permission"

        mock_engine = Mock()
        mock_engine.evaluate_request.return_value = mock_decision

        mock_pdp = Mock()
        mock_pdp._engine = mock_engine

        mock_client = Mock()
        mock_client._pdp = mock_pdp

        with _patch_active_token(agent_token), \
             patch.object(api, "_get_policy_client", return_value=mock_client):
            flow = _make_api_flow("/lookup", token=agent_token, query="host=api.openai.com")
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["host"] == "api.openai.com"
            assert body["effect"] == "allow"
            assert body["reason"] == "explicit permission"
            # agent comes from flow.metadata, which is None in this test
            assert body["agent"] is None


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

    def test_content_type_is_json(self, api, agent_token):
        """All responses have application/json content type."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/health", token=agent_token)
            api.request(flow)
            assert flow.response.headers.get("Content-Type") == "application/json"

    def test_error_responses_set_blocked_by(self, api):
        """Even 401 errors set blocked_by metadata (downstream addons must skip)."""
        flow = _make_api_flow("/health")
        api.request(flow)
        assert flow.response.status_code == 401
        assert flow.metadata.get("blocked_by") == "agent-api"

    def test_404_sets_blocked_by(self, api, agent_token):
        """404 responses set blocked_by metadata."""
        with _patch_active_token(agent_token):
            flow = _make_api_flow("/nonexistent", token=agent_token)
            api.request(flow)
            assert flow.response.status_code == 404
            assert flow.metadata.get("blocked_by") == "agent-api"


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
            assert body["body_length"] == 16  # len(b'{"action":"get"}')
            # Text-like content should include body_text
            assert body["body_text"] == '{"action":"get"}'

    def test_get_response_body(self, api_with_store):
        """GET /api/flows/{id}/response-body returns decompressed body."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/1/response-body", token=token)
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert "body_base64" in body
            assert body["body_text"] == '{"id":42,"owner":"alice","role":"admin"}'

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
            assert body["count"] == 1

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
            assert body["count"] == 1

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
            assert body["count"] == 1

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

    def test_get_flow_search_with_query_params(self, api_with_store):
        """GET /api/flows/search converts query params to filters."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow(
                "/api/flows/search",
                token=token,
                query="host=app.example.com&limit=5",
            )
            api.request(flow)
            assert flow.response.status_code == 200
            body = json.loads(flow.response.content)
            assert body["count"] == 1
            assert body["flows"][0]["host"] == "app.example.com"

    def test_post_flow_search_invalid_json(self, api_with_store):
        """POST /api/flows/search with invalid JSON returns 400."""
        api, store, token = api_with_store
        with _patch_active_token(token):
            flow = _make_api_flow("/api/flows/search", method="POST", token=token)
            flow.request.content = b"not json at all {{"
            flow.request.headers["content-type"] = "application/json"
            api.request(flow)
            assert flow.response.status_code == 400
            body = json.loads(flow.response.content)
            assert body == {"error": "Invalid JSON body"}


class TestEnvVarPaths:
    """Tests for SAFEYOLO_DATA_DIR and SAFEYOLO_LOG_PATH env var support.

    Contract:
    - Token path: SAFEYOLO_DATA_DIR/agent_token (falls back to /safeyolo/data/agent_token)
    - Log path: SAFEYOLO_LOG_PATH (falls back to /app/logs/safeyolo.jsonl)
    """

    def test_token_path_uses_safeyolo_data_dir(self, api, monkeypatch):
        """When SAFEYOLO_DATA_DIR is set, token is read from $SAFEYOLO_DATA_DIR/agent_token."""
        from pathlib import Path

        monkeypatch.setenv("SAFEYOLO_DATA_DIR", "/custom/data")
        captured_path = None

        def capture_read_active_token(path):
            nonlocal captured_path
            captured_path = path
            return "test-token-value"

        with patch("pdp.tokens.read_active_token", side_effect=capture_read_active_token):
            flow = _make_api_flow("/health", token="test-token-value")
            api.request(flow)

        assert captured_path == Path("/custom/data/agent_token")

    def test_token_path_falls_back_to_default(self, api, monkeypatch):
        """When SAFEYOLO_DATA_DIR is not set, token is read from /safeyolo/data/agent_token."""
        from pathlib import Path

        monkeypatch.delenv("SAFEYOLO_DATA_DIR", raising=False)
        captured_path = None

        def capture_read_active_token(path):
            nonlocal captured_path
            captured_path = path
            return "test-token-value"

        with patch("pdp.tokens.read_active_token", side_effect=capture_read_active_token):
            flow = _make_api_flow("/health", token="test-token-value")
            api.request(flow)

        assert captured_path == Path("/safeyolo/data/agent_token")

    def test_log_path_uses_safeyolo_log_path_env(self, api, agent_token, tmp_path, monkeypatch):
        """When SAFEYOLO_LOG_PATH is set, explain reads from that path."""
        target_id = "req-aabbccdd11223344aabbccdd11223344"
        log_file = tmp_path / "custom.jsonl"
        log_file.write_text(
            json.dumps({"request_id": target_id, "event": "traffic.request", "host": "custom.com"}) + "\n"
        )
        monkeypatch.setenv("SAFEYOLO_LOG_PATH", str(log_file))

        with _patch_active_token(agent_token):
            flow = _make_api_flow("/explain", token=agent_token, query=f"request_id={target_id}")
            api.request(flow)

        assert flow.response.status_code == 200
        body = json.loads(flow.response.content)
        assert len(body["events"]) == 1
        assert body["events"][0]["host"] == "custom.com"

    def test_log_path_falls_back_to_default(self, api, agent_token, monkeypatch):
        """When SAFEYOLO_LOG_PATH is not set, explain reads from /app/logs/safeyolo.jsonl."""
        monkeypatch.delenv("SAFEYOLO_LOG_PATH", raising=False)

        # The default path won't exist in test, so we get empty events (not an error)
        with _patch_active_token(agent_token):
            valid_id = "req-0a1b2c3d4e5f6789abcdef0123456789"
            flow = _make_api_flow("/explain", token=agent_token, query=f"request_id={valid_id}")
            api.request(flow)

        assert flow.response.status_code == 200
        body = json.loads(flow.response.content)
        assert body["events"] == []


# -- Gateway endpoint tests --
# DEFERRED: /gateway/services, /gateway/request-access, /gateway/submit-binding
# require complex setup with service-discovery, service-gateway, service-loader,
# and contract model mocking. These are better tested as integration tests or
# in a dedicated test file. The endpoint handler logic is ~300 LOC with multiple
# addon lookups, service registry calls, and contract validation.
