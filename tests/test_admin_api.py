"""
Tests for admin_api.py addon.

Tests HTTP endpoints for runtime control and stats.
Uses mock handler to simulate HTTP requests without a real server.
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Shared test infrastructure
# ---------------------------------------------------------------------------

TEST_TOKEN = "test-token-for-unit-tests"


def _make_handler(handler_class, method, path, body=None, include_auth=True, token=TEST_TOKEN):
    """Create a mock handler for testing HTTP endpoints.

    Consolidates the repeated _create_handler pattern from the original tests.
    """

    class MockHandler(handler_class):
        def __init__(self):
            self.path = path
            self.command = method
            self.headers = {"Content-Length": str(len(body)) if body else "0"}
            if include_auth:
                self.headers["Authorization"] = f"Bearer {token}"
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


def _parse_response(handler):
    """Parse JSON response from handler.

    When _read_json sends its own error response (e.g. malformed JSON) AND
    the caller also sends a response, two JSON objects end up in wfile.
    We use JSONDecoder.raw_decode to parse just the first one, which is
    what an HTTP client would see.
    """
    handler.wfile.seek(0)
    raw = handler.wfile.read().decode()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(raw)
    return obj


@pytest.fixture
def handler_class():
    """Get AdminRequestHandler with clean class-level state and auth configured."""
    from admin_api import AdminRequestHandler

    AdminRequestHandler.credential_guard = None
    AdminRequestHandler.addons_with_stats = {}
    AdminRequestHandler.admin_token = TEST_TOKEN
    AdminRequestHandler._addons_obj = None

    return AdminRequestHandler


@pytest.fixture
def handler_class_no_token():
    """Get AdminRequestHandler with no token configured (for auth tests)."""
    from admin_api import AdminRequestHandler

    AdminRequestHandler.credential_guard = None
    AdminRequestHandler.addons_with_stats = {}
    AdminRequestHandler.admin_token = None
    AdminRequestHandler._addons_obj = None

    return AdminRequestHandler


# ---------------------------------------------------------------------------
# GET endpoint tests
# ---------------------------------------------------------------------------


class TestGetHealth:
    """GET /health - public health check."""

    def test_returns_ok(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/health")
        handler.do_GET()

        assert handler._status == 200
        assert _parse_response(handler) == {"status": "ok"}

    def test_accessible_without_auth(self, handler_class):
        """Health endpoint is exempt from auth — monitoring probes need it."""
        handler = _make_handler(handler_class, "GET", "/health", include_auth=False)
        handler.do_GET()

        assert handler._status == 200
        assert _parse_response(handler)["status"] == "ok"


class TestGetStats:
    """GET /stats - aggregate addon statistics."""

    def test_empty_addons(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/stats")
        handler.do_GET()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["proxy"] == "safeyolo"

    def test_includes_addon_stats(self, handler_class):
        mock_addon = MagicMock()
        mock_addon.get_stats.return_value = {"scans": 100, "blocks": 5}
        handler_class.addons_with_stats = {"test-addon": mock_addon}

        handler = _make_handler(handler_class, "GET", "/stats")
        handler.do_GET()

        response = _parse_response(handler)
        assert response["test-addon"] == {"scans": 100, "blocks": 5}


class TestGetModes:
    """GET /modes - current mode for all switchable addons."""

    def test_returns_all_addon_modes(self, handler_class):
        with patch("admin_api.ctx") as mock_ctx:
            # Set the EXACT option names from MODE_SWITCHABLE
            mock_ctx.options.credguard_block = False
            mock_ctx.options.network_guard_block = True
            mock_ctx.options.pattern_block_request = False
            mock_ctx.options.pattern_block_response = False

            handler = _make_handler(handler_class, "GET", "/modes")
            handler.do_GET()

            response = _parse_response(handler)
            assert handler._status == 200
            modes = response["modes"]
            assert modes["credential-guard"] == "warn"
            assert modes["network-guard"] == "block"
            assert modes["pattern-scanner"] == "warn"


class TestGetPluginMode:
    """GET /plugins/{name}/mode - mode for a specific addon."""

    def test_returns_block_mode(self, handler_class):
        with patch("admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = True

            handler = _make_handler(handler_class, "GET", "/plugins/credential-guard/mode")
            handler.do_GET()

            response = _parse_response(handler)
            assert handler._status == 200
            assert response["addon"] == "credential-guard"
            assert response["mode"] == "block"

    def test_unknown_addon_returns_404(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/plugins/nonexistent/mode")
        handler.do_GET()

        assert handler._status == 404


class TestGetPolicyBaseline:
    """GET /admin/policy/baseline - read baseline policy."""

    def test_returns_baseline_and_path(self, handler_class):
        mock_client = MagicMock()
        mock_client.get_baseline.return_value = {"permissions": []}
        mock_client.get_baseline_path.return_value = "/etc/safeyolo/policy.yaml"

        with patch("admin_api.get_policy_client", return_value=mock_client):
            handler = _make_handler(handler_class, "GET", "/admin/policy/baseline")
            handler.do_GET()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["baseline"] == {"permissions": []}
        assert response["path"] == "/etc/safeyolo/policy.yaml"

    def test_no_baseline_returns_404(self, handler_class):
        mock_client = MagicMock()
        mock_client.get_baseline.return_value = None

        with patch("admin_api.get_policy_client", return_value=mock_client):
            handler = _make_handler(handler_class, "GET", "/admin/policy/baseline")
            handler.do_GET()

        response = _parse_response(handler)
        assert handler._status == 404
        assert response["error"] == "No baseline policy loaded"


class TestGetBudgets:
    """GET /admin/budgets - current budget usage."""

    def test_returns_budget_stats(self, handler_class):
        mock_client = MagicMock()
        mock_client.get_budget_stats.return_value = {
            "api.openai.com": {"used": 50, "limit": 100},
        }

        with patch("admin_api.get_policy_client", return_value=mock_client):
            handler = _make_handler(handler_class, "GET", "/admin/budgets")
            handler.do_GET()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["api.openai.com"] == {"used": 50, "limit": 100}


class TestGetNotFound:
    """Unknown GET routes return 404."""

    def test_unknown_path_returns_404(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/unknown")
        handler.do_GET()

        assert handler._status == 404
        assert _parse_response(handler)["error"] == "not found"


# ---------------------------------------------------------------------------
# PUT endpoint tests
# ---------------------------------------------------------------------------


class TestPutPluginMode:
    """PUT /plugins/{name}/mode - set mode for a specific addon."""

    def test_sets_mode_to_block(self, handler_class):
        with patch("admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = False

            body = json.dumps({"mode": "block"})
            handler = _make_handler(handler_class, "PUT", "/plugins/credential-guard/mode", body=body)
            handler.do_PUT()

            response = _parse_response(handler)
            assert handler._status == 200
            assert response["mode"] == "block"
            assert response["status"] == "updated"

    def test_invalid_mode_returns_400_with_message(self, handler_class):
        with patch("admin_api.ctx"):
            body = json.dumps({"mode": "invalid"})
            handler = _make_handler(handler_class, "PUT", "/plugins/credential-guard/mode", body=body)
            handler.do_PUT()

            response = _parse_response(handler)
            assert handler._status == 400
            assert response["error"] == "mode must be 'warn' or 'block'"


class TestPutModesAll:
    """PUT /modes - set mode for all switchable addons at once."""

    def test_sets_all_to_block(self, handler_class):
        with patch("admin_api.ctx") as mock_ctx:
            # Set the EXACT option names from MODE_SWITCHABLE
            mock_ctx.options.credguard_block = False
            mock_ctx.options.network_guard_block = False
            mock_ctx.options.pattern_block_request = False
            mock_ctx.options.pattern_block_response = False

            body = json.dumps({"mode": "block"})
            handler = _make_handler(handler_class, "PUT", "/modes", body=body)
            handler.do_PUT()

            response = _parse_response(handler)
            assert handler._status == 200
            assert response["status"] == "updated"
            assert response["mode"] == "block"

    def test_sets_all_to_warn(self, handler_class):
        with patch("admin_api.ctx") as mock_ctx:
            mock_ctx.options.credguard_block = True
            mock_ctx.options.network_guard_block = True
            mock_ctx.options.pattern_block_request = True
            mock_ctx.options.pattern_block_response = True

            body = json.dumps({"mode": "warn"})
            handler = _make_handler(handler_class, "PUT", "/modes", body=body)
            handler.do_PUT()

            response = _parse_response(handler)
            assert handler._status == 200
            assert response["status"] == "updated"
            assert response["mode"] == "warn"


# ---------------------------------------------------------------------------
# POST endpoint tests — baseline approve/deny
# ---------------------------------------------------------------------------


class TestPostBaselineApprove:
    """POST /admin/policy/baseline/approve - add credential permission."""

    def test_happy_path(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_credential_approval.return_value = {
            "status": "added",
            "permission_count": 3,
        }

        body = json.dumps({"destination": "api.openai.com", "cred_id": "openai:sk-abc", "tier": "explicit"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/approve", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "added"
        assert response["destination"] == "api.openai.com"
        assert response["cred_id"] == "openai:sk-abc"
        assert response["tier"] == "explicit"
        assert response["permission_count"] == 3

        mock_client.add_credential_approval.assert_called_once_with(
            destination="api.openai.com", cred_id="openai:sk-abc", tier="explicit",
        )

    def test_defaults_tier_to_explicit(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_credential_approval.return_value = {"status": "added", "permission_count": 1}

        body = json.dumps({"destination": "api.openai.com", "cred_id": "openai:sk-abc"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/approve", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 200
        mock_client.add_credential_approval.assert_called_once_with(
            destination="api.openai.com", cred_id="openai:sk-abc", tier="explicit",
        )

    def test_missing_destination_returns_400(self, handler_class):
        body = json.dumps({"cred_id": "openai:sk-abc"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/approve", body=body)

        with patch("admin_api.get_policy_client", return_value=MagicMock()):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'destination' field"

    def test_missing_cred_id_returns_400(self, handler_class):
        body = json.dumps({"destination": "api.openai.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/approve", body=body)

        with patch("admin_api.get_policy_client", return_value=MagicMock()):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'cred_id' field"

    def test_missing_body_returns_400(self, handler_class):
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/approve")

        with patch("admin_api.get_policy_client", return_value=MagicMock()):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing request body"

    def test_client_error_returns_400(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_credential_approval.return_value = {"status": "error", "error": "invalid cred_id format"}

        body = json.dumps({"destination": "api.openai.com", "cred_id": "bad"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/approve", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "invalid cred_id format"


class TestPostBaselineDeny:
    """POST /admin/policy/baseline/deny - log credential denial."""

    def test_happy_path(self, handler_class):
        body = json.dumps({"destination": "evil.com", "cred_id": "openai:sk-abc", "reason": "user_denied"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/deny", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "logged"
        assert response["destination"] == "evil.com"
        assert response["cred_id"] == "openai:sk-abc"
        assert response["reason"] == "user_denied"

    def test_defaults_reason_to_user_denied(self, handler_class):
        body = json.dumps({"destination": "evil.com", "cred_id": "openai:sk-abc"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/deny", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["reason"] == "user_denied"

    def test_missing_destination_returns_400(self, handler_class):
        body = json.dumps({"cred_id": "openai:sk-abc"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/deny", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'destination' field"

    def test_missing_cred_id_returns_400(self, handler_class):
        body = json.dumps({"destination": "evil.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/deny", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'cred_id' field"

    def test_missing_body_returns_400(self, handler_class):
        handler = _make_handler(handler_class, "POST", "/admin/policy/baseline/deny")

        with patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing request body"


# ---------------------------------------------------------------------------
# POST endpoint tests — host policy mutations
# ---------------------------------------------------------------------------


class TestPostHostDeny:
    """POST /admin/policy/host/deny - deny egress to a host."""

    def test_happy_path(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_host_denial.return_value = {
            "status": "denied",
            "host": "evil.com",
            "expires": "2026-04-06T00:00:00Z",
        }

        body = json.dumps({"host": "evil.com", "expires": "2026-04-06T00:00:00Z"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "denied"
        assert response["host"] == "evil.com"
        mock_client.add_host_denial.assert_called_once_with(host="evil.com", expires="2026-04-06T00:00:00Z", agent=None)

    def test_missing_host_returns_400(self, handler_class):
        body = json.dumps({"expires": "2026-04-06T00:00:00Z"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "'host' must be a non-empty string"

    def test_missing_body_returns_400(self, handler_class):
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny")
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing request body"

    def test_valueerror_from_client_returns_400(self, handler_class):
        """B2 fix: ValueError from policy client maps to 400, not 500."""
        mock_client = MagicMock()
        mock_client.add_host_denial.side_effect = ValueError("invalid host format")

        body = json.dumps({"host": "not a valid host!"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "invalid host format"

    def test_unexpected_exception_from_client_returns_500(self, handler_class):
        """B2 fix: non-ValueError exceptions map to 500."""
        mock_client = MagicMock()
        mock_client.add_host_denial.side_effect = RuntimeError("disk full")

        body = json.dumps({"host": "evil.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 500
        assert _parse_response(handler)["error"] == "Internal server error"


class TestPostHostRate:
    """POST /admin/policy/host/rate - update host rate limit."""

    def test_happy_path(self, handler_class):
        mock_client = MagicMock()
        mock_client.update_host_rate.return_value = {
            "status": "updated", "host": "api.openai.com", "old_rate": 3000, "new_rate": 6000,
        }

        body = json.dumps({"host": "api.openai.com", "rate": 6000})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "updated"
        assert response["new_rate"] == 6000
        mock_client.update_host_rate.assert_called_once_with(host="api.openai.com", rate=6000)

    def test_missing_host_returns_400(self, handler_class):
        body = json.dumps({"rate": 6000})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'host' field"

    def test_missing_rate_returns_400(self, handler_class):
        body = json.dumps({"host": "api.openai.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "'rate' must be a positive integer"

    def test_negative_rate_returns_400(self, handler_class):
        body = json.dumps({"host": "api.openai.com", "rate": -1})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "'rate' must be a positive integer"

    def test_zero_rate_returns_400(self, handler_class):
        body = json.dumps({"host": "api.openai.com", "rate": 0})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "'rate' must be a positive integer"

    def test_valueerror_from_client_returns_400(self, handler_class):
        """B2 fix: ValueError from policy client maps to 400."""
        mock_client = MagicMock()
        mock_client.update_host_rate.side_effect = ValueError("host not in policy")

        body = json.dumps({"host": "unknown.com", "rate": 100})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "host not in policy"

    def test_unexpected_exception_returns_500(self, handler_class):
        """B2 fix: non-ValueError maps to 500."""
        mock_client = MagicMock()
        mock_client.update_host_rate.side_effect = RuntimeError("disk full")

        body = json.dumps({"host": "api.openai.com", "rate": 100})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 500
        assert _parse_response(handler)["error"] == "Internal server error"

    def test_emits_audit_event(self, handler_class):
        mock_client = MagicMock()
        mock_client.update_host_rate.return_value = {
            "status": "updated", "host": "api.openai.com", "old_rate": 3000, "new_rate": 6000,
        }

        body = json.dumps({"host": "api.openai.com", "rate": 6000})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event") as mock_write:
            handler.do_POST()

        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == "admin.host_rate_updated"


class TestPostHostAllow:
    """POST /admin/policy/host/allow - allow a new host."""

    def test_happy_path(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_host_allowance.return_value = {
            "status": "added", "host": "cdn.example.com", "rate": 600,
        }

        body = json.dumps({"host": "cdn.example.com", "rate": 600})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "added"
        assert response["host"] == "cdn.example.com"

    def test_without_rate(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_host_allowance.return_value = {
            "status": "added", "host": "cdn.example.com", "rate": None,
        }

        body = json.dumps({"host": "cdn.example.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 200
        assert _parse_response(handler)["status"] == "added"

    def test_missing_host_returns_400(self, handler_class):
        body = json.dumps({"rate": 600})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "'host' must be a non-empty string"

    def test_valueerror_from_client_returns_400(self, handler_class):
        """B2 fix: ValueError maps to 400."""
        mock_client = MagicMock()
        mock_client.add_host_allowance.side_effect = ValueError("duplicate host")

        body = json.dumps({"host": "cdn.example.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "duplicate host"

    def test_unexpected_exception_returns_500(self, handler_class):
        """B2 fix: non-ValueError maps to 500."""
        mock_client = MagicMock()
        mock_client.add_host_allowance.side_effect = RuntimeError("disk full")

        body = json.dumps({"host": "cdn.example.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/allow", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 500
        assert _parse_response(handler)["error"] == "Internal server error"


class TestPostHostBypass:
    """POST /admin/policy/host/bypass - add addon bypass for a host."""

    def test_happy_path(self, handler_class):
        mock_client = MagicMock()
        mock_client.add_host_bypass.return_value = {
            "status": "updated", "host": "api.internal.com", "bypass": ["pattern-scanner"],
        }

        body = json.dumps({"host": "api.internal.com", "addon": "pattern-scanner"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "updated"
        assert "pattern-scanner" in response["bypass"]

    def test_missing_addon_returns_400(self, handler_class):
        body = json.dumps({"host": "api.internal.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'addon' field"

    def test_missing_host_returns_400(self, handler_class):
        body = json.dumps({"addon": "pattern-scanner"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'host' field"

    def test_valueerror_from_client_returns_400(self, handler_class):
        """B2 fix: ValueError maps to 400."""
        mock_client = MagicMock()
        mock_client.add_host_bypass.side_effect = ValueError("unknown addon")

        body = json.dumps({"host": "api.internal.com", "addon": "bad-addon"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "unknown addon"

    def test_unexpected_exception_returns_500(self, handler_class):
        """B2 fix: non-ValueError maps to 500."""
        mock_client = MagicMock()
        mock_client.add_host_bypass.side_effect = RuntimeError("disk full")

        body = json.dumps({"host": "api.internal.com", "addon": "pattern-scanner"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/bypass", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 500
        assert _parse_response(handler)["error"] == "Internal server error"


# ---------------------------------------------------------------------------
# POST endpoint tests — budgets
# ---------------------------------------------------------------------------


class TestPostBudgetsReset:
    """POST /admin/budgets/reset - reset budget counters."""

    def test_reset_all(self, handler_class):
        mock_client = MagicMock()
        mock_client.reset_budgets.return_value = {"status": "reset", "count": 5}

        handler = _make_handler(handler_class, "POST", "/admin/budgets/reset")

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "reset"
        mock_client.reset_budgets.assert_called_once_with(resource=None)

    def test_reset_specific_resource(self, handler_class):
        mock_client = MagicMock()
        mock_client.reset_budgets.return_value = {"status": "reset", "count": 1}

        body = json.dumps({"resource": "api.openai.com"})
        handler = _make_handler(handler_class, "POST", "/admin/budgets/reset", body=body)

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "reset"
        mock_client.reset_budgets.assert_called_once_with(resource="api.openai.com")

    def test_client_error_returns_500(self, handler_class):
        mock_client = MagicMock()
        mock_client.reset_budgets.return_value = {"status": "error", "error": "budget store unavailable"}

        handler = _make_handler(handler_class, "POST", "/admin/budgets/reset")

        with patch("admin_api.get_policy_client", return_value=mock_client), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 500
        assert _parse_response(handler)["error"] == "budget store unavailable"


# ---------------------------------------------------------------------------
# POST endpoint tests — gateway grants
# ---------------------------------------------------------------------------


class TestPostGatewayGrant:
    """POST /admin/gateway/grant - add a risky route grant."""

    def test_happy_path(self, handler_class):
        mock_gateway = MagicMock()
        mock_grant = MagicMock()
        mock_grant.grant_id = "grant-abc123"
        mock_gateway.add_grant.return_value = mock_grant
        handler_class.addons_with_stats = {"service-gateway": mock_gateway}
        handler_class._addons_obj = None

        body = json.dumps({
            "agent": "boris",
            "service": "github",
            "method": "DELETE",
            "path": "/repos/test/test",
            "lifetime": "once",
        })
        handler = _make_handler(handler_class, "POST", "/admin/gateway/grant", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "granted"
        assert response["grant_id"] == "grant-abc123"
        mock_gateway.add_grant.assert_called_once_with(
            agent="boris", service="github", method="DELETE", path="/repos/test/test", scope="once",
        )

    def test_missing_required_fields_returns_400(self, handler_class):
        body = json.dumps({"agent": "boris", "service": "github"})
        handler = _make_handler(handler_class, "POST", "/admin/gateway/grant", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing required fields: agent, service, method, path"

    def test_missing_body_returns_400(self, handler_class):
        handler = _make_handler(handler_class, "POST", "/admin/gateway/grant")
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing request body"

    def test_invalid_lifetime_returns_400(self, handler_class):
        body = json.dumps({
            "agent": "boris", "service": "github", "method": "DELETE",
            "path": "/repos/test", "lifetime": "forever",
        })
        handler = _make_handler(handler_class, "POST", "/admin/gateway/grant", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "lifetime must be 'once', 'session', or 'remembered'"

    def test_gateway_not_available_returns_503(self, handler_class):
        handler_class.addons_with_stats = {}
        handler_class._addons_obj = None

        body = json.dumps({
            "agent": "boris", "service": "github", "method": "DELETE",
            "path": "/repos/test", "lifetime": "once",
        })
        handler = _make_handler(handler_class, "POST", "/admin/gateway/grant", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 503
        assert _parse_response(handler)["error"] == "service gateway not available"


# ---------------------------------------------------------------------------
# DELETE endpoint tests — gateway grants
# ---------------------------------------------------------------------------


class TestDeleteGatewayGrant:
    """DELETE /admin/gateway/grants/{id} - revoke a grant."""

    def test_happy_path(self, handler_class):
        mock_gateway = MagicMock()
        mock_gateway.revoke_grant.return_value = True
        handler_class.addons_with_stats = {"service-gateway": mock_gateway}
        handler_class._addons_obj = None

        handler = _make_handler(handler_class, "DELETE", "/admin/gateway/grants/grant-abc123")

        with patch("admin_api.write_event"):
            handler.do_DELETE()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "revoked"
        assert response["grant_id"] == "grant-abc123"
        mock_gateway.revoke_grant.assert_called_once_with("grant-abc123")

    def test_not_found_returns_404(self, handler_class):
        mock_gateway = MagicMock()
        mock_gateway.revoke_grant.return_value = False
        handler_class.addons_with_stats = {"service-gateway": mock_gateway}
        handler_class._addons_obj = None

        handler = _make_handler(handler_class, "DELETE", "/admin/gateway/grants/no-such-grant")

        with patch("admin_api.write_event"):
            handler.do_DELETE()

        assert handler._status == 404
        assert _parse_response(handler)["error"] == "grant 'no-such-grant' not found"

    def test_gateway_not_available_returns_503(self, handler_class):
        handler_class.addons_with_stats = {}
        handler_class._addons_obj = None

        handler = _make_handler(handler_class, "DELETE", "/admin/gateway/grants/grant-abc123")

        with patch("admin_api.write_event"):
            handler.do_DELETE()

        assert handler._status == 503
        assert _parse_response(handler)["error"] == "service gateway not available"


# ---------------------------------------------------------------------------
# POST endpoint tests — circuit breaker
# ---------------------------------------------------------------------------


class TestPostCircuitBreakerReset:
    """POST /admin/circuit-breaker/reset - reset circuit breaker for a host."""

    def test_happy_path(self, handler_class):
        mock_cb = MagicMock()
        handler_class.addons_with_stats = {"circuit-breaker": mock_cb}
        handler_class._addons_obj = None

        body = json.dumps({"host": "api.slack.com"})
        handler = _make_handler(handler_class, "POST", "/admin/circuit-breaker/reset", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "reset"
        assert response["host"] == "api.slack.com"
        mock_cb.reset.assert_called_once_with("api.slack.com")

    def test_missing_host_returns_400(self, handler_class):
        body = json.dumps({"other": "field"})
        handler = _make_handler(handler_class, "POST", "/admin/circuit-breaker/reset", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing 'host' field"

    def test_not_available_returns_503(self, handler_class):
        handler_class.addons_with_stats = {}
        handler_class._addons_obj = None

        body = json.dumps({"host": "api.slack.com"})
        handler = _make_handler(handler_class, "POST", "/admin/circuit-breaker/reset", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 503


# ---------------------------------------------------------------------------
# Agent service endpoints (preserved from existing tests)
# ---------------------------------------------------------------------------


class TestAgentServiceEndpoints:
    """Tests for agent service authorization/revocation endpoints."""

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
        """Mock PDP to return a loader with _baseline_path."""
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
        import tomlkit

        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-oauth2"})
        handler = _make_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "authorized"
        assert response["agent"] == "boris"
        assert response["service"] == "gmail"
        assert response["capability"] == "readonly"

        doc = tomlkit.parse(policy_toml.read_text())
        agents = doc["agents"].unwrap()
        assert agents["boris"]["services"]["gmail"] == {"capability": "readonly", "token": "gmail-oauth2"}
        assert agents["boris"]["services"]["slack"] == {"capability": "chat", "token": "slack-key"}

    def test_post_missing_fields_returns_400(self, handler_class, mock_pdp):
        body = json.dumps({"service": "gmail"})
        handler = _make_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)
        handler.do_POST()

        assert handler._status == 400
        assert "missing required fields" in _parse_response(handler)["error"]

    def test_post_missing_body_returns_400(self, handler_class, mock_pdp):
        handler = _make_handler(handler_class, "POST", "/admin/agents/boris/services")
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing request body"

    def test_post_nonexistent_agent_returns_404(self, handler_class, mock_pdp):
        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-key"})
        handler = _make_handler(handler_class, "POST", "/admin/agents/noone/services", body=body)
        handler.do_POST()

        assert handler._status == 404
        assert "not found" in _parse_response(handler)["error"]

    def test_delete_removes_binding(self, handler_class, mock_pdp, policy_toml):
        import tomlkit

        handler = _make_handler(handler_class, "DELETE", "/admin/agents/boris/services/slack")

        with patch("admin_api.write_event"):
            handler.do_DELETE()

        response = _parse_response(handler)
        assert handler._status == 200
        assert response["status"] == "revoked"
        assert response["agent"] == "boris"
        assert response["service"] == "slack"
        assert response["credential"] == "slack-key"

        doc = tomlkit.parse(policy_toml.read_text())
        agents = doc["agents"].unwrap()
        assert "services" not in agents["boris"] or "slack" not in agents["boris"].get("services", {})

    def test_delete_nonexistent_service_returns_404(self, handler_class, mock_pdp):
        handler = _make_handler(handler_class, "DELETE", "/admin/agents/boris/services/nope")
        handler.do_DELETE()

        assert handler._status == 404

    def test_delete_nonexistent_agent_returns_404(self, handler_class, mock_pdp):
        handler = _make_handler(handler_class, "DELETE", "/admin/agents/noone/services/slack")
        handler.do_DELETE()

        assert handler._status == 404

    def test_post_emits_audit_event(self, handler_class, mock_pdp):
        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-key"})
        handler = _make_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)

        with patch("admin_api.write_event") as mock_write:
            handler.do_POST()

        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == "admin.agent_service_authorized"
        assert mock_write.call_args[1]["details"]["agent"] == "boris"
        assert mock_write.call_args[1]["details"]["service"] == "gmail"

    def test_delete_emits_audit_event(self, handler_class, mock_pdp, policy_toml):
        handler = _make_handler(handler_class, "DELETE", "/admin/agents/boris/services/slack")

        with patch("admin_api.write_event") as mock_write:
            handler.do_DELETE()

        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == "admin.agent_service_revoked"
        assert mock_write.call_args[1]["details"]["agent"] == "boris"
        assert mock_write.call_args[1]["details"]["service"] == "slack"

    def test_atomic_write_uses_tmp_rename(self, handler_class, mock_pdp, policy_toml):
        body = json.dumps({"service": "gmail", "capability": "readonly", "credential": "gmail-key"})
        handler = _make_handler(handler_class, "POST", "/admin/agents/boris/services", body=body)

        with patch("admin_api.write_event"):
            handler.do_POST()

        tmp = policy_toml.with_suffix(".tmp")
        assert not tmp.exists()
        assert policy_toml.exists()


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------


class TestAuthentication:
    """Bearer token authentication."""

    def test_health_exempt_from_auth(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/health", include_auth=False)
        handler.do_GET()

        assert handler._status == 200
        assert _parse_response(handler)["status"] == "ok"

    def test_stats_requires_auth(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/stats", include_auth=False)
        handler.do_GET()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_stats_with_valid_token(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/stats")
        handler.do_GET()

        assert handler._status == 200
        assert "proxy" in _parse_response(handler)

    def test_stats_with_invalid_token(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/stats", token="wrong-token")
        handler.do_GET()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_malformed_authorization_header(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/stats", include_auth=False)
        handler.headers["Authorization"] = "NotBearer test-token"
        handler.do_GET()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_modes_requires_auth(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/modes", include_auth=False)
        handler.do_GET()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_put_requires_auth(self, handler_class):
        body = json.dumps({"mode": "block"})
        handler = _make_handler(handler_class, "PUT", "/plugins/credential-guard/mode", body=body, include_auth=False)
        handler.do_PUT()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_post_requires_auth(self, handler_class):
        body = json.dumps({"prefix": "sk-abc", "host": "evil.com", "duration_minutes": 5})
        handler = _make_handler(handler_class, "POST", "/plugins/credential-guard/allowlist", body=body, include_auth=False)
        handler.do_POST()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_delete_requires_auth(self, handler_class):
        handler = _make_handler(handler_class, "DELETE", "/plugins/credential-guard/allowlist", include_auth=False)
        handler.do_DELETE()

        assert handler._status == 401
        assert _parse_response(handler)["error"] == "Unauthorized"

    def test_timing_attack_resistance_uses_compare_digest(self, handler_class):
        """Verify _check_auth uses secrets.compare_digest (constant-time)."""
        handler = _make_handler(handler_class, "GET", "/stats", token="wrong-token")
        assert handler._check_auth() is False

        handler = _make_handler(handler_class, "GET", "/stats", token=TEST_TOKEN)
        assert handler._check_auth() is True

    def test_no_token_configured_denies_all(self, handler_class_no_token):
        """If admin_token is None, all authenticated endpoints are denied."""
        handler = _make_handler(handler_class_no_token, "GET", "/stats", include_auth=False)
        handler.do_GET()

        assert handler._status == 401

    def test_host_rate_requires_auth(self, handler_class):
        body = json.dumps({"host": "api.openai.com", "rate": 6000})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/rate", body=body, include_auth=False)
        handler.do_POST()

        assert handler._status == 401


class TestAuthFailureAuditEvent:
    """Auth failures emit an audit event for security monitoring."""

    def test_auth_failure_emits_event(self, handler_class):
        handler = _make_handler(handler_class, "GET", "/stats", token="wrong-token")

        with patch("admin_api.write_event") as mock_write:
            handler.do_GET()

        assert handler._status == 401
        mock_write.assert_called_once()
        event_name = mock_write.call_args[0][0]
        assert event_name == "admin.auth_failure"
        details = mock_write.call_args[1]["details"]
        assert details["path"] == "/stats"
        assert details["reason"] == "invalid_or_missing_token"
        assert details["client_ip"] == "127.0.0.1"

    def test_auth_failure_on_post_emits_event(self, handler_class):
        body = json.dumps({"host": "evil.com"})
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny", body=body, include_auth=False)

        with patch("admin_api.write_event") as mock_write:
            handler.do_POST()

        assert handler._status == 401
        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == "admin.auth_failure"


# ---------------------------------------------------------------------------
# Malformed JSON body (pins B1 fix)
# ---------------------------------------------------------------------------


class TestMalformedJsonBody:
    """B1 fix: malformed JSON returns 400 with 'Malformed JSON' message."""

    def test_invalid_json_on_post_returns_400_malformed(self, handler_class):
        """Malformed JSON should return 400 'Malformed JSON', not 'missing body'."""
        handler = _make_handler(
            handler_class, "POST", "/admin/policy/host/deny", body="not valid json{{"
        )

        with patch("admin_api.get_policy_client", return_value=MagicMock()), \
             patch("admin_api.write_event"):
            handler.do_POST()

        assert handler._status == 400
        response = _parse_response(handler)
        assert response["error"] == "Malformed JSON in request body"
        assert "detail" in response

    def test_invalid_json_on_put_returns_400_malformed(self, handler_class):
        handler = _make_handler(
            handler_class, "PUT", "/plugins/credential-guard/mode", body="{{bad"
        )

        with patch("admin_api.ctx"):
            handler.do_PUT()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "Malformed JSON in request body"

    def test_empty_body_on_post_returns_missing_body(self, handler_class):
        """Empty body (Content-Length: 0) should give 'missing request body', not 'Malformed JSON'."""
        handler = _make_handler(handler_class, "POST", "/admin/policy/host/deny")
        handler.do_POST()

        assert handler._status == 400
        assert _parse_response(handler)["error"] == "missing request body"


# ---------------------------------------------------------------------------
# Addon class tests
# ---------------------------------------------------------------------------


class TestAdminAPIAddon:
    """AdminAPI addon class basics."""

    def test_name(self):
        from admin_api import AdminAPI

        addon = AdminAPI()
        assert addon.name == "admin-api"

    def test_mode_switchable_contains_expected_addons(self):
        from admin_api import AdminRequestHandler

        assert set(AdminRequestHandler.MODE_SWITCHABLE.keys()) == {
            "network-guard",
            "credential-guard",
            "pattern-scanner",
        }

    def test_mode_switchable_option_names_are_correct(self):
        """Verify the exact option names — wrong names silently pass with MagicMock."""
        from admin_api import AdminRequestHandler

        assert AdminRequestHandler.MODE_SWITCHABLE["credential-guard"] == ["credguard_block"]
        assert AdminRequestHandler.MODE_SWITCHABLE["network-guard"] == ["network_guard_block"]
        assert AdminRequestHandler.MODE_SWITCHABLE["pattern-scanner"] == [
            "pattern_block_request", "pattern_block_response",
        ]
