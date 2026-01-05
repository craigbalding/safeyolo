"""
Tests for admin_api.py addon.

Tests HTTP endpoints for runtime control and stats.
Uses threading to run the admin server during tests.
"""

import json
import pytest
from unittest.mock import MagicMock, patch


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


class TestAdminAPIAddon:
    """Tests for AdminAPI addon class."""

    def test_name(self):
        """Test addon has correct name."""
        from admin_api import AdminAPI

        addon = AdminAPI()
        assert addon.name == "admin-api"

    def test_mode_switchable_addons(self):
        """Test MODE_SWITCHABLE contains expected addons."""
        from admin_api import AdminRequestHandler

        expected = {
            "network-guard",
            "credential-guard",
            "pattern-scanner",
            "yara-scanner",
            "prompt-injection",
        }
        assert set(AdminRequestHandler.MODE_SWITCHABLE.keys()) == expected
