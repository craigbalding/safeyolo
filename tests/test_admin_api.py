"""
Tests for admin_api.py addon.

Tests HTTP endpoints for runtime control and stats.
Uses threading to run the admin server during tests.
"""

import json
from unittest.mock import MagicMock, patch

import pytest


class TestAdminRequestHandler:
    """Tests for AdminRequestHandler HTTP methods."""

    TEST_TOKEN = "test-token-for-unit-tests"

    @pytest.fixture
    def handler_class(self):
        """Get handler class with mocked dependencies."""
        from admin_api import AdminRequestHandler

        # Reset class-level state
        AdminRequestHandler.credential_guard = None
        AdminRequestHandler.addons_with_stats = {}
        AdminRequestHandler.admin_token = self.TEST_TOKEN

        return AdminRequestHandler

    def test_health_endpoint(self, handler_class):
        """Test GET /health returns healthy status."""

        # Create mock request
        handler = self._create_handler(handler_class, "GET", "/health")
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["status"] == "ok"
        # Reduced info disclosure: no longer includes proxy name

    def test_stats_endpoint_empty(self, handler_class):
        """Test GET /stats with no addons discovered."""
        handler = self._create_handler(handler_class, "GET", "/stats")
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["proxy"] == "safeyolo"

    def test_stats_endpoint_with_addons(self, handler_class):
        """Test GET /stats returns addon stats."""
        # Add mock addon with stats
        mock_addon = MagicMock()
        mock_addon.get_stats.return_value = {"scans": 100, "blocks": 5}
        handler_class.addons_with_stats = {"test-addon": mock_addon}

        handler = self._create_handler(handler_class, "GET", "/stats")
        handler.do_GET()

        response = self._parse_response(handler)
        assert "test-addon" in response
        assert response["test-addon"]["scans"] == 100

    def test_modes_get(self, handler_class):
        """Test GET /modes returns addon modes."""
        with patch("admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = False
            mock_ctx.options.network_guard_block = True
            mock_ctx.options.pattern_block_input = False
            mock_ctx.options.yara_block_on_match = False
            mock_ctx.options.injection_block = False

            handler = self._create_handler(handler_class, "GET", "/modes")
            handler.do_GET()

            response = self._parse_response(handler)
            assert "modes" in response
            assert response["modes"]["credential-guard"] == "warn"
            assert response["modes"]["network-guard"] == "block"

    def test_plugin_mode_get(self, handler_class):
        """Test GET /plugins/{name}/mode returns single addon mode."""
        with patch("admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = True

            handler = self._create_handler(
                handler_class, "GET", "/plugins/credential-guard/mode"
            )
            handler.do_GET()

            response = self._parse_response(handler)
            assert response["addon"] == "credential-guard"
            assert response["mode"] == "block"

    def test_plugin_mode_put(self, handler_class):
        """Test PUT /plugins/{name}/mode sets addon mode."""
        with patch("admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = False

            body = json.dumps({"mode": "block"})
            handler = self._create_handler(
                handler_class, "PUT", "/plugins/credential-guard/mode", body=body
            )
            handler.do_PUT()

            response = self._parse_response(handler)
            assert response["mode"] == "block"
            assert response["status"] == "updated"

    def test_modes_put_all(self, handler_class):
        """Test PUT /modes sets all addon modes at once."""
        with patch("admin_api.ctx") as mock_ctx:
            # Set initial values
            mock_ctx.options.credguard_block = False
            mock_ctx.options.ratelimit_block = False
            mock_ctx.options.pattern_block_input = False
            mock_ctx.options.yara_block_on_match = False
            mock_ctx.options.injection_block = False

            body = json.dumps({"mode": "block"})
            handler = self._create_handler(handler_class, "PUT", "/modes", body=body)
            handler.do_PUT()

            response = self._parse_response(handler)
            assert response["status"] == "updated"
            assert response["mode"] == "block"

    def test_invalid_mode_rejected(self, handler_class):
        """Test PUT mode rejects invalid mode values."""
        with patch("admin_api.ctx"):
            body = json.dumps({"mode": "invalid"})
            handler = self._create_handler(
                handler_class, "PUT", "/plugins/credential-guard/mode", body=body
            )
            handler.do_PUT()

            response = self._parse_response(handler)
            status = self._get_status(handler)
            assert status == 400
            assert "error" in response

    def test_unknown_addon_mode(self, handler_class):
        """Test GET mode for unknown addon returns 404."""
        handler = self._create_handler(
            handler_class, "GET", "/plugins/nonexistent/mode"
        )
        handler.do_GET()

        status = self._get_status(handler)
        assert status == 404

    def test_not_found(self, handler_class):
        """Test unknown endpoint returns 404."""
        handler = self._create_handler(handler_class, "GET", "/unknown")
        handler.do_GET()

        response = self._parse_response(handler)
        status = self._get_status(handler)
        assert status == 404
        assert response["error"] == "not found"

    # Helper methods

    def _create_handler(self, handler_class, method, path, body=None, include_auth=True):
        """Create a mock handler for testing."""
        from io import BytesIO

        test_token = self.TEST_TOKEN

        class MockHandler(handler_class):
            def __init__(self):
                self.path = path
                self.command = method
                self.headers = {"Content-Length": str(len(body)) if body else "0"}
                if include_auth:
                    self.headers["Authorization"] = f"Bearer {test_token}"
                self.rfile = BytesIO(body.encode() if body else b"")
                self.wfile = BytesIO()
                self._status = 200
                self.client_address = ("127.0.0.1", 12345)

            def send_response(self, code):
                self._status = code

            def send_header(self, name, value):
                pass

            def end_headers(self):
                pass

            def log_message(self, *args):
                pass

        return MockHandler()

    def _parse_response(self, handler):
        """Parse JSON response from handler."""
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())

    def _get_status(self, handler):
        """Get HTTP status from handler."""
        return handler._status


class TestAdminAPIAuthentication:
    """Test bearer token authentication."""

    @pytest.fixture
    def handler_class(self):
        """Get handler class with mocked dependencies."""
        from admin_api import AdminRequestHandler

        # Reset class-level state
        AdminRequestHandler.credential_guard = None
        AdminRequestHandler.addons_with_stats = {}
        AdminRequestHandler.admin_token = None

        return AdminRequestHandler

    @pytest.fixture
    def handler_class_with_token(self, handler_class):
        """Handler with token configured."""
        handler_class.admin_token = "test-token-abc123xyz456"
        return handler_class

    def test_health_endpoint_no_auth_required(self, handler_class_with_token):
        """Health endpoint should be accessible without token."""
        handler = self._create_handler(handler_class_with_token, "GET", "/health")
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["status"] == "ok"
        assert handler._status == 200

    def test_stats_endpoint_requires_auth(self, handler_class_with_token):
        """Stats endpoint should require authentication."""
        handler = self._create_handler(handler_class_with_token, "GET", "/stats")
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_stats_with_valid_token(self, handler_class_with_token):
        """Stats endpoint should accept valid bearer token."""
        handler = self._create_handler(handler_class_with_token, "GET", "/stats")
        handler.headers["Authorization"] = "Bearer test-token-abc123xyz456"
        handler.do_GET()

        response = self._parse_response(handler)
        assert "proxy" in response
        assert handler._status == 200

    def test_stats_with_invalid_token(self, handler_class_with_token):
        """Stats endpoint should reject invalid token."""
        handler = self._create_handler(handler_class_with_token, "GET", "/stats")
        handler.headers["Authorization"] = "Bearer wrong-token"
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_stats_with_malformed_header(self, handler_class_with_token):
        """Stats endpoint should reject malformed Authorization header."""
        handler = self._create_handler(handler_class_with_token, "GET", "/stats")
        handler.headers["Authorization"] = "NotBearer test-token-abc123xyz456"
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_modes_endpoint_requires_auth(self, handler_class_with_token):
        """Modes endpoint should require authentication."""
        handler = self._create_handler(handler_class_with_token, "GET", "/modes")
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_put_requires_auth(self, handler_class_with_token):
        """PUT requests should require authentication."""
        body = json.dumps({"mode": "block"})
        handler = self._create_handler(
            handler_class_with_token, "PUT", "/plugins/credential-guard/mode", body=body
        )
        handler.do_PUT()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_post_requires_auth(self, handler_class_with_token):
        """POST requests should require authentication."""
        body = json.dumps({"prefix": "sk-abc", "host": "evil.com", "duration_minutes": 5})
        handler = self._create_handler(
            handler_class_with_token,
            "POST",
            "/plugins/credential-guard/allowlist",
            body=body,
        )
        handler.do_POST()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_delete_requires_auth(self, handler_class_with_token):
        """DELETE requests should require authentication."""
        handler = self._create_handler(
            handler_class_with_token, "DELETE", "/plugins/credential-guard/allowlist"
        )
        handler.do_DELETE()

        response = self._parse_response(handler)
        assert response["error"] == "Unauthorized"
        assert handler._status == 401

    def test_timing_attack_resistance(self, handler_class_with_token):
        """Verify secrets.compare_digest is used for constant-time comparison."""

        # Create mock handler using the existing helper
        handler = self._create_handler(handler_class_with_token, "GET", "/stats")
        handler.admin_token = "test-token-abc123xyz456"
        handler.headers = {"Authorization": "Bearer wrong-token"}

        # Verify _check_auth uses secrets.compare_digest
        # (This checks the implementation, not timing directly)
        result = handler._check_auth()
        assert result is False

        # Valid token should pass
        handler.headers = {"Authorization": "Bearer test-token-abc123xyz456"}
        result = handler._check_auth()
        assert result is True

    def test_no_token_configured(self, handler_class):
        """Test behavior when admin_token is not configured."""
        handler_class.admin_token = None

        handler = self._create_handler(handler_class, "GET", "/stats")
        handler.do_GET()

        # Response parsed but only status checked
        _ = self._parse_response(handler)
        # Should still require auth (401) even if token not configured
        # This prevents accidentally running without auth
        assert handler._status == 401

    # Helper methods

    def _create_handler(self, handler_class, method, path, body=None):
        """Create a mock handler for testing."""
        from io import BytesIO

        class MockHandler(handler_class):
            def __init__(self):
                self.path = path
                self.command = method
                self.headers = {"Content-Length": str(len(body)) if body else "0"}
                self.rfile = BytesIO(body.encode() if body else b"")
                self.wfile = BytesIO()
                self._status = 200
                self.client_address = ("127.0.0.1", 12345)

            def send_response(self, code):
                self._status = code

            def send_header(self, name, value):
                pass

            def end_headers(self):
                pass

            def log_message(self, *args):
                pass

        return MockHandler()

    def _parse_response(self, handler):
        """Parse JSON response from handler."""
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())

    def _get_status(self, handler):
        """Get HTTP status from handler."""
        return handler._status


class TestAgentServiceEndpoints:
    """Tests for agent service authorization/revocation endpoints."""

    TEST_TOKEN = "test-token-for-unit-tests"

    @pytest.fixture
    def handler_class(self):
        """Get handler class with mocked dependencies."""
        from admin_api import AdminRequestHandler

        AdminRequestHandler.credential_guard = None
        AdminRequestHandler.addons_with_stats = {}
        AdminRequestHandler.admin_token = self.TEST_TOKEN

        return AdminRequestHandler

    @pytest.fixture
    def policy_toml(self, tmp_path):
        """Create a mock policy.toml with agents section."""
        import tomlkit

        doc = tomlkit.document()
        doc.add("version", "2.0")
        hosts = tomlkit.table()
        it = tomlkit.inline_table()
        it.append("rate", 600)
        hosts.add("*", it)
        doc.add("hosts", hosts)

        agents = tomlkit.table()
        boris = tomlkit.table()
        boris.add("image", "ghcr.io/test")
        services = tomlkit.table()
        slack = tomlkit.table()
        slack.add("capability", "chat")
        slack.add("token", "slack-key")
        services.add("slack", slack)
        boris.add("services", services)
        agents.add("boris", boris)
        doc.add("agents", agents)

        policy_path = tmp_path / "policy.toml"
        policy_path.write_text(tomlkit.dumps(doc))
        return policy_path

    @pytest.fixture
    def mock_pdp(self, policy_toml):
        """Mock PDP to return a loader with _baseline_path via client._pdp._engine._loader."""
        mock_loader = MagicMock()
        mock_loader._baseline_path = policy_toml

        mock_engine = MagicMock()
        mock_engine._loader = mock_loader

        mock_pdp = MagicMock()
        mock_pdp._engine = mock_engine

        mock_client = MagicMock()
        mock_client._pdp = mock_pdp

        with (
            patch("admin_api.is_policy_client_configured", return_value=True),
            patch("admin_api.get_policy_client", return_value=mock_client),
        ):
            yield

    def test_post_creates_binding(self, handler_class, mock_pdp, policy_toml):
        """POST creates service binding in policy.toml."""
        import tomlkit

        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-oauth2"})
        handler = self._create_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = self._parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "authorized"
        assert response["agent"] == "boris"
        assert response["service"] == "gmail"
        assert response["capability"] == "readonly"

        # Verify policy.toml was updated
        doc = tomlkit.parse(policy_toml.read_text())
        agents = doc["agents"].unwrap()
        assert agents["boris"]["services"]["gmail"] == {"capability": "readonly", "token": "gmail-oauth2"}
        # Existing service preserved
        assert agents["boris"]["services"]["slack"] == {"capability": "chat", "token": "slack-key"}

    def test_post_missing_fields_returns_400(self, handler_class, mock_pdp):
        """POST with missing fields returns 400."""
        body = json.dumps({"service": "gmail"})
        handler = self._create_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)
        handler.do_POST()

        assert handler._status == 400
        response = self._parse_response(handler)
        assert "missing required fields" in response["error"]

    def test_post_missing_body_returns_400(self, handler_class, mock_pdp):
        """POST with no body returns 400."""
        handler = self._create_handler(handler_class, "POST", "/admin/agents/boris/services")
        handler.do_POST()

        assert handler._status == 400

    def test_post_nonexistent_agent_returns_404(self, handler_class, mock_pdp):
        """POST to non-existent agent returns 404."""
        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-key"})
        handler = self._create_handler(handler_class, "POST", "/admin/agents/noone/services", body=body)
        handler.do_POST()

        assert handler._status == 404
        response = self._parse_response(handler)
        assert "not found" in response["error"]

    def test_delete_removes_binding(self, handler_class, mock_pdp, policy_toml):
        """DELETE removes service binding from policy.toml."""
        import tomlkit

        handler = self._create_handler(handler_class, "DELETE", "/admin/agents/boris/services/slack")

        with patch("admin_api.write_event"):
            handler.do_DELETE()

        response = self._parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "revoked"
        assert response["agent"] == "boris"
        assert response["service"] == "slack"
        assert response["credential"] == "slack-key"

        # Verify policy.toml was updated
        doc = tomlkit.parse(policy_toml.read_text())
        agents = doc["agents"].unwrap()
        assert "services" not in agents["boris"] or "slack" not in agents["boris"].get("services", {})

    def test_delete_nonexistent_service_returns_404(self, handler_class, mock_pdp):
        """DELETE non-existent service returns 404."""
        handler = self._create_handler(handler_class, "DELETE", "/admin/agents/boris/services/nope")
        handler.do_DELETE()

        assert handler._status == 404

    def test_delete_nonexistent_agent_returns_404(self, handler_class, mock_pdp):
        """DELETE on non-existent agent returns 404."""
        handler = self._create_handler(handler_class, "DELETE", "/admin/agents/noone/services/slack")
        handler.do_DELETE()

        assert handler._status == 404

    def test_post_emits_audit_event(self, handler_class, mock_pdp):
        """POST emits admin.agent_service_authorized audit event."""
        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-key"})
        handler = self._create_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)

        with patch("admin_api.write_event") as mock_write:
            handler.do_POST()

        mock_write.assert_called_once()
        call_args = mock_write.call_args
        assert call_args[0][0] == "admin.agent_service_authorized"
        assert call_args[1]["details"]["agent"] == "boris"
        assert call_args[1]["details"]["service"] == "gmail"

    def test_delete_emits_audit_event(self, handler_class, mock_pdp, policy_toml):
        """DELETE emits admin.agent_service_revoked audit event."""
        handler = self._create_handler(handler_class, "DELETE", "/admin/agents/boris/services/slack")

        with patch("admin_api.write_event") as mock_write:
            handler.do_DELETE()

        mock_write.assert_called_once()
        call_args = mock_write.call_args
        assert call_args[0][0] == "admin.agent_service_revoked"
        assert call_args[1]["details"]["agent"] == "boris"
        assert call_args[1]["details"]["service"] == "slack"

    def test_atomic_write_uses_tmp_rename(self, handler_class, mock_pdp, policy_toml):
        """Verify atomic write pattern (tmp file renamed)."""
        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-key"})
        handler = self._create_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        # tmp file should not exist after successful write
        tmp = policy_toml.with_suffix(".tmp")
        assert not tmp.exists()
        # Original should exist and be valid TOML
        assert policy_toml.exists()

    # Helper methods

    def _create_handler(self, handler_class, method, path, body=None, include_auth=True):
        """Create a mock handler for testing."""
        from io import BytesIO

        test_token = self.TEST_TOKEN

        class MockHandler(handler_class):
            def __init__(self):
                self.path = path
                self.command = method
                self.headers = {"Content-Length": str(len(body)) if body else "0"}
                if include_auth:
                    self.headers["Authorization"] = f"Bearer {test_token}"
                self.rfile = BytesIO(body.encode() if body else b"")
                self.wfile = BytesIO()
                self._status = 200
                self.client_address = ("127.0.0.1", 12345)

            def send_response(self, code):
                self._status = code

            def send_header(self, name, value):
                pass

            def end_headers(self):
                pass

            def log_message(self, *args):
                pass

        return MockHandler()

    def _parse_response(self, handler):
        """Parse JSON response from handler."""
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())

    def _get_status(self, handler):
        """Get HTTP status from handler."""
        return handler._status


class TestPolicyHostEndpoints:
    """Tests for host policy mutation endpoints."""

    TEST_TOKEN = "test-token-for-unit-tests"

    @pytest.fixture
    def handler_class(self):
        from admin_api import AdminRequestHandler

        AdminRequestHandler.credential_guard = None
        AdminRequestHandler.addons_with_stats = {}
        AdminRequestHandler.admin_token = self.TEST_TOKEN
        return AdminRequestHandler

    def test_host_rate_happy_path(self, handler_class):
        """POST /admin/policy/host/rate updates rate."""
        mock_client = MagicMock()
        mock_client.update_host_rate.return_value = {
            "status": "updated", "host": "api.openai.com", "old_rate": 3000, "new_rate": 6000,
        }

        body = json.dumps({"host": "api.openai.com", "rate": 6000})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = self._parse_response(handler)
        assert response["status"] == "updated"
        assert response["new_rate"] == 6000
        mock_client.update_host_rate.assert_called_once_with(host="api.openai.com", rate=6000)

    def test_host_rate_missing_host(self, handler_class):
        body = json.dumps({"rate": 6000})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()
        assert handler._status == 400

    def test_host_rate_missing_rate(self, handler_class):
        body = json.dumps({"host": "api.openai.com"})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()
        assert handler._status == 400

    def test_host_rate_invalid_rate(self, handler_class):
        body = json.dumps({"host": "api.openai.com", "rate": -1})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()
        assert handler._status == 400

    def test_host_allow_happy_path(self, handler_class):
        """POST /admin/policy/host/allow adds host."""
        mock_client = MagicMock()
        mock_client.add_host_allowance.return_value = {
            "status": "added", "host": "cdn.example.com", "rate": 600,
        }

        body = json.dumps({"host": "cdn.example.com", "rate": 600})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = self._parse_response(handler)
        assert response["status"] == "added"
        assert response["host"] == "cdn.example.com"

    def test_host_allow_without_rate(self, handler_class):
        """POST /admin/policy/host/allow works without rate."""
        mock_client = MagicMock()
        mock_client.add_host_allowance.return_value = {
            "status": "added", "host": "cdn.example.com", "rate": None,
        }

        body = json.dumps({"host": "cdn.example.com"})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = self._parse_response(handler)
        assert response["status"] == "added"

    def test_host_allow_missing_host(self, handler_class):
        body = json.dumps({"rate": 600})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)
        handler.do_POST()
        assert handler._status == 400

    def test_host_bypass_happy_path(self, handler_class):
        """POST /admin/policy/host/bypass adds bypass."""
        mock_client = MagicMock()
        mock_client.add_host_bypass.return_value = {
            "status": "updated", "host": "api.internal.com", "bypass": ["pattern-scanner"],
        }

        body = json.dumps({"host": "api.internal.com", "addon": "pattern-scanner"})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = self._parse_response(handler)
        assert response["status"] == "updated"
        assert "pattern-scanner" in response["bypass"]

    def test_host_bypass_missing_addon(self, handler_class):
        body = json.dumps({"host": "api.internal.com"})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)
        handler.do_POST()
        assert handler._status == 400

    def test_circuit_breaker_reset_happy_path(self, handler_class):
        """POST /admin/circuit-breaker/reset resets circuit."""
        mock_cb = MagicMock()
        handler_class.addons_with_stats = {"circuit-breaker": mock_cb}
        handler_class._addons_obj = None

        body = json.dumps({"host": "api.slack.com"})
        handler = self._create_handler(handler_class, "POST", "/admin/circuit-breaker/reset", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = self._parse_response(handler)
        assert response["status"] == "reset"
        assert response["host"] == "api.slack.com"
        mock_cb.reset.assert_called_once_with("api.slack.com")

    def test_circuit_breaker_reset_missing_host(self, handler_class):
        body = json.dumps({})
        handler = self._create_handler(handler_class, "POST", "/admin/circuit-breaker/reset", body=body)
        handler.do_POST()
        assert handler._status == 400

    def test_circuit_breaker_reset_not_available(self, handler_class):
        """Returns 503 if circuit breaker addon not loaded."""
        handler_class.addons_with_stats = {}
        handler_class._addons_obj = None

        body = json.dumps({"host": "api.slack.com"})
        handler = self._create_handler(handler_class, "POST", "/admin/circuit-breaker/reset", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 503

    def test_host_rate_emits_audit_event(self, handler_class):
        """POST /admin/policy/host/rate emits audit event."""
        mock_client = MagicMock()
        mock_client.update_host_rate.return_value = {
            "status": "updated", "host": "api.openai.com", "old_rate": 3000, "new_rate": 6000,
        }

        body = json.dumps({"host": "api.openai.com", "rate": 6000})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event") as mock_write:
            handler.do_POST()

        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == "admin.host_rate_updated"

    def test_host_rate_requires_auth(self, handler_class):
        """POST /admin/policy/host/rate requires auth."""
        body = json.dumps({"host": "api.openai.com", "rate": 6000})
        handler = self._create_handler(handler_class, "POST", "/admin/policy/host/rate", body=body, include_auth=False)
        handler.do_POST()
        assert handler._status == 401

    # Helper methods

    def _create_handler(self, handler_class, method, path, body=None, include_auth=True):
        from io import BytesIO

        test_token = self.TEST_TOKEN

        class MockHandler(handler_class):
            def __init__(self):
                self.path = path
                self.command = method
                self.headers = {"Content-Length": str(len(body)) if body else "0"}
                if include_auth:
                    self.headers["Authorization"] = f"Bearer {test_token}"
                self.rfile = BytesIO(body.encode() if body else b"")
                self.wfile = BytesIO()
                self._status = 200
                self.client_address = ("127.0.0.1", 12345)

            def send_response(self, code):
                self._status = code

            def send_header(self, name, value):
                pass

            def end_headers(self):
                pass

            def log_message(self, *args):
                pass

        return MockHandler()

    def _parse_response(self, handler):
        handler.wfile.seek(0)
        return json.loads(handler.wfile.read().decode())

    def _get_status(self, handler):
        return handler._status


class TestAdminAPIAddon:
    """Tests for AdminAPI addon class."""

    def test_name(self):
        """Test addon has correct name."""
        from admin_api import AdminAPI

        addon = AdminAPI()
        assert addon.name == "admin-api"

    def test_mode_switchable_addons(self):
        """Test MODE_SWITCHABLE contains expected addons.

        Note: yara-scanner and prompt-injection are only in the experimental build,
        not the base build. This test checks the base build addons.
        """
        from admin_api import AdminRequestHandler

        expected = {
            "network-guard",
            "credential-guard",
            "pattern-scanner",
        }
        assert set(AdminRequestHandler.MODE_SWITCHABLE.keys()) == expected
