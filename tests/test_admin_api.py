"""
Tests for admin_api.py addon.

Tests HTTP endpoints for runtime control and stats.
Uses threading to run the admin server during tests.
"""

import json
import pytest
import threading
import time
from http.server import HTTPServer
from unittest.mock import MagicMock, patch


class TestAdminRequestHandler:
    """Tests for AdminRequestHandler HTTP methods."""

    @pytest.fixture
    def handler_class(self):
        """Get handler class with mocked dependencies."""
        from addons.admin_api import AdminRequestHandler

        # Reset class-level state
        AdminRequestHandler.credential_guard = None
        AdminRequestHandler.addons_with_stats = {}

        return AdminRequestHandler

    @pytest.fixture
    def mock_credential_guard(self):
        """Create mock credential guard addon."""
        mock = MagicMock()
        mock.get_temp_allowlist.return_value = []
        mock.temp_allowlist = {}
        return mock

    def test_health_endpoint(self, handler_class):
        """Test GET /health returns healthy status."""
        from io import BytesIO

        # Create mock request
        handler = self._create_handler(handler_class, "GET", "/health")
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["status"] == "healthy"
        assert response["proxy"] == "safeyolo"

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

    def test_allowlist_get_empty(self, handler_class, mock_credential_guard):
        """Test GET /plugins/credential-guard/allowlist when empty."""
        handler_class.credential_guard = mock_credential_guard

        handler = self._create_handler(
            handler_class, "GET", "/plugins/credential-guard/allowlist"
        )
        handler.do_GET()

        response = self._parse_response(handler)
        assert response["allowlist"] == []

    def test_allowlist_get_no_guard(self, handler_class):
        """Test GET /plugins/credential-guard/allowlist without guard loaded."""
        handler_class.credential_guard = None

        handler = self._create_handler(
            handler_class, "GET", "/plugins/credential-guard/allowlist"
        )
        handler.do_GET()

        response = self._parse_response(handler)
        status = self._get_status(handler)
        assert status == 404
        assert "error" in response

    def test_allowlist_post(self, handler_class, mock_credential_guard):
        """Test POST /plugins/credential-guard/allowlist adds entry."""
        handler_class.credential_guard = mock_credential_guard

        body = json.dumps({"prefix": "sk-abc", "host": "evil.com", "duration_minutes": 5})
        handler = self._create_handler(
            handler_class,
            "POST",
            "/plugins/credential-guard/allowlist",
            body=body,
        )
        handler.do_POST()

        response = self._parse_response(handler)
        assert response["status"] == "added"
        mock_credential_guard.add_temp_allowlist.assert_called_once_with(
            "sk-abc", "evil.com", 300
        )

    def test_allowlist_post_missing_fields(self, handler_class, mock_credential_guard):
        """Test POST allowlist with missing required fields."""
        handler_class.credential_guard = mock_credential_guard

        body = json.dumps({"prefix": "sk-abc"})  # Missing host
        handler = self._create_handler(
            handler_class,
            "POST",
            "/plugins/credential-guard/allowlist",
            body=body,
        )
        handler.do_POST()

        response = self._parse_response(handler)
        status = self._get_status(handler)
        assert status == 400
        assert "error" in response

    def test_allowlist_delete(self, handler_class, mock_credential_guard):
        """Test DELETE /plugins/credential-guard/allowlist clears entries."""
        handler_class.credential_guard = mock_credential_guard
        mock_credential_guard.temp_allowlist = {"key": "value"}

        handler = self._create_handler(
            handler_class, "DELETE", "/plugins/credential-guard/allowlist"
        )
        handler.do_DELETE()

        response = self._parse_response(handler)
        assert response["status"] == "cleared"

    def test_modes_get(self, handler_class):
        """Test GET /modes returns addon modes."""
        with patch("addons.admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = False
            mock_ctx.options.ratelimit_block = True
            mock_ctx.options.pattern_block_input = False
            mock_ctx.options.yara_block_on_match = False
            mock_ctx.options.injection_block = False

            handler = self._create_handler(handler_class, "GET", "/modes")
            handler.do_GET()

            response = self._parse_response(handler)
            assert "modes" in response
            assert response["modes"]["credential-guard"] == "warn"
            assert response["modes"]["rate-limiter"] == "block"

    def test_plugin_mode_get(self, handler_class):
        """Test GET /plugins/{name}/mode returns single addon mode."""
        with patch("addons.admin_api.ctx") as mock_ctx:
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
        with patch("addons.admin_api.ctx") as mock_ctx:
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
        with patch("addons.admin_api.ctx") as mock_ctx:
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
        with patch("addons.admin_api.ctx"):
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
        from addons.admin_api import AdminAPI

        addon = AdminAPI()
        assert addon.name == "admin-api"

    def test_mode_switchable_addons(self):
        """Test MODE_SWITCHABLE contains expected addons."""
        from addons.admin_api import AdminRequestHandler

        expected = {
            "credential-guard",
            "rate-limiter",
            "pattern-scanner",
            "yara-scanner",
            "prompt-injection",
        }
        assert set(AdminRequestHandler.MODE_SWITCHABLE.keys()) == expected
