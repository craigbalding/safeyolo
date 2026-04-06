"""Tests for API client module."""

from unittest.mock import MagicMock

import httpx
import pytest

from safeyolo.api import AdminAPI, APIError, get_api


class TestAdminAPIInit:
    """Tests for AdminAPI initialization."""

    def test_default_url_from_config(self, tmp_config_dir):
        """Uses port from config for default URL."""
        api = AdminAPI()
        assert api.base_url == "http://localhost:9090"

    def test_custom_url(self, tmp_config_dir):
        """Accepts custom base URL."""
        api = AdminAPI(base_url="http://custom:8080")
        assert api.base_url == "http://custom:8080"

    def test_strips_trailing_slash(self, tmp_config_dir):
        """Strips trailing slash from URL."""
        api = AdminAPI(base_url="http://localhost:9090/")
        assert api.base_url == "http://localhost:9090"

    def test_token_from_param(self, tmp_config_dir):
        """Uses token from parameter."""
        api = AdminAPI(token="my-token")
        assert api.token == "my-token"


class TestAdminAPIHeaders:
    """Tests for _headers() method."""

    def test_includes_bearer_token(self, tmp_config_dir):
        """Includes Authorization header with token."""
        api = AdminAPI(token="test-token")
        headers = api._headers()
        assert headers["Authorization"] == "Bearer test-token"

    def test_empty_without_token(self, tmp_config_dir, monkeypatch):
        """Returns empty dict without token."""
        monkeypatch.delenv("SAFEYOLO_ADMIN_TOKEN", raising=False)
        api = AdminAPI(token=None)
        api.token = None
        headers = api._headers()
        assert headers == {}


class TestAdminAPIHealth:
    """Tests for health() endpoint."""

    def test_returns_healthy(self, tmp_config_dir, mock_httpx):
        """Returns health status."""
        mock_httpx["response"].json.return_value = {"status": "healthy"}

        api = AdminAPI()
        result = api.health()

        assert result == {"status": "healthy"}
        mock_httpx["client"].request.assert_called_once()
        call_args = mock_httpx["client"].request.call_args
        assert call_args[0] == ("GET", "http://localhost:9090/health")
        assert call_args[1]["headers"] == {}  # No auth required

    def test_handles_connection_error(self, tmp_config_dir, monkeypatch):
        """Raises APIError on connection failure."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.side_effect = httpx.ConnectError("Connection refused")
        monkeypatch.setattr("httpx.Client", MagicMock(return_value=mock_client))

        api = AdminAPI()
        with pytest.raises(APIError, match="Cannot connect"):
            api.health()


class TestAdminAPIStats:
    """Tests for stats() endpoint."""

    def test_returns_stats(self, tmp_config_dir, mock_httpx):
        """Returns stats dict."""
        mock_httpx["response"].json.return_value = {"proxy": "safeyolo", "requests": 100}

        api = AdminAPI(token="test")
        result = api.stats()

        assert result["proxy"] == "safeyolo"
        assert result["requests"] == 100

    def test_requires_auth(self, tmp_config_dir, mock_httpx):
        """Includes auth header."""
        api = AdminAPI(token="my-token")
        api.stats()

        call_args = mock_httpx["client"].request.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer my-token"

    def test_raises_on_401(self, tmp_config_dir, mock_httpx):
        """Raises APIError on auth failure."""
        mock_httpx["response"].status_code = 401

        api = AdminAPI(token="bad-token")
        with pytest.raises(APIError, match="Authentication failed"):
            api.stats()


class TestAdminAPIModes:
    """Tests for mode endpoints."""

    def test_get_modes(self, tmp_config_dir, mock_httpx):
        """Gets all addon modes."""
        mock_httpx["response"].json.return_value = {"modes": {"credential-guard": "block", "rate-limiter": "warn"}}

        api = AdminAPI(token="test")
        result = api.get_modes()

        assert "modes" in result
        call_args = mock_httpx["client"].request.call_args
        assert "/modes" in call_args[0][1]

    def test_set_mode(self, tmp_config_dir, mock_httpx):
        """Sets addon mode."""
        mock_httpx["response"].json.return_value = {"status": "updated"}

        api = AdminAPI(token="test")
        result = api.set_mode("credential-guard", "warn")

        assert result["status"] == "updated"
        call_args = mock_httpx["client"].request.call_args
        assert call_args[0] == ("PUT", "http://localhost:9090/plugins/credential-guard/mode")
        assert call_args[1]["json"] == {"mode": "warn"}


class TestAdminAPIApproval:
    """Tests for approval endpoints."""

    def test_add_approval(self, tmp_config_dir, mock_httpx):
        """Adds approval rule with specific cred_id."""
        mock_httpx["response"].json.return_value = {"status": "added"}

        api = AdminAPI(token="test")
        result = api.add_approval(
            destination="api.example.com",
            cred_id="hmac:abc123def456",
            tier="explicit",
        )

        assert result["status"] == "added"
        call_args = mock_httpx["client"].request.call_args
        assert "/admin/policy/baseline/approve" in call_args[0][1]
        assert call_args[1]["json"]["destination"] == "api.example.com"
        assert call_args[1]["json"]["cred_id"] == "hmac:abc123def456"

    def test_add_approval_minimal(self, tmp_config_dir, mock_httpx):
        """Adds approval with minimal params (tier defaults to explicit)."""
        mock_httpx["response"].json.return_value = {"status": "added"}

        api = AdminAPI(token="test")
        api.add_approval(destination="example.com", cred_id="hmac:xyz789")

        call_args = mock_httpx["client"].request.call_args
        payload = call_args[1]["json"]
        assert payload["destination"] == "example.com"
        assert payload["cred_id"] == "hmac:xyz789"
        assert payload["tier"] == "explicit"


class TestAdminAPIAllowlist:
    """Tests for allowlist endpoints."""

    def test_get_allowlist(self, tmp_config_dir, mock_httpx):
        """Gets temp allowlist."""
        mock_httpx["response"].json.return_value = []

        api = AdminAPI(token="test")
        result = api.get_allowlist()

        assert result == []

    def test_add_allowlist(self, tmp_config_dir, mock_httpx):
        """Adds temp allowlist entry."""
        mock_httpx["response"].json.return_value = {"status": "added"}

        api = AdminAPI(token="test")
        api.add_allowlist("sk-test", "api.openai.com", ttl_seconds=600)

        call_args = mock_httpx["client"].request.call_args
        assert call_args[1]["json"]["credential_prefix"] == "sk-test"
        assert call_args[1]["json"]["ttl_seconds"] == 600

    def test_clear_allowlist(self, tmp_config_dir, mock_httpx):
        """Clears all allowlist entries."""
        mock_httpx["response"].json.return_value = {"cleared": 5}

        api = AdminAPI(token="test")
        api.clear_allowlist()

        call_args = mock_httpx["client"].request.call_args
        assert call_args[0][0] == "DELETE"


class TestAPIError:
    """Tests for APIError exception."""

    def test_includes_status_code(self):
        """Stores status code."""
        err = APIError("Not found", status_code=404)
        assert err.status_code == 404
        assert "Not found" in str(err)

    def test_status_code_optional(self):
        """Status code is optional."""
        err = APIError("Connection failed")
        assert err.status_code is None


class TestAdminAPIAgentService:
    """Tests for authorize_service and revoke_service methods."""

    def test_authorize_service_sends_correct_post(self, tmp_config_dir, mock_httpx):
        """authorize_service sends POST to correct path with payload."""
        mock_httpx["response"].json.return_value = {
            "status": "authorized",
            "agent": "boris",
            "service": "gmail",
            "capability": "readonly",
        }

        api = AdminAPI(token="test")
        result = api.authorize_service(
            agent="boris",
            service="gmail",
            capability="readonly",
            credential="gmail-oauth2",
        )

        assert result["status"] == "authorized"
        call_args = mock_httpx["client"].request.call_args
        assert call_args[0] == ("POST", "http://localhost:9090/admin/agents/boris/services")
        assert call_args[1]["json"] == {
            "service": "gmail",
            "capability": "readonly",
            "credential": "gmail-oauth2",
        }

    def test_revoke_service_sends_correct_delete(self, tmp_config_dir, mock_httpx):
        """revoke_service sends DELETE to parameterized path."""
        mock_httpx["response"].json.return_value = {
            "status": "revoked",
            "agent": "boris",
            "service": "gmail",
            "credential": "gmail-oauth2",
        }

        api = AdminAPI(token="test")
        result = api.revoke_service(agent="boris", service="gmail")

        assert result["status"] == "revoked"
        assert result["credential"] == "gmail-oauth2"
        call_args = mock_httpx["client"].request.call_args
        assert call_args[0] == ("DELETE", "http://localhost:9090/admin/agents/boris/services/gmail")

    def test_authorize_service_raises_on_404(self, tmp_config_dir, mock_httpx):
        """authorize_service raises APIError on 404."""
        mock_httpx["response"].status_code = 404
        mock_httpx["response"].text = '{"error": "agent not found"}'

        api = AdminAPI(token="test")
        with pytest.raises(APIError):
            api.authorize_service(
                agent="noone",
                service="gmail",
                capability="readonly",
                credential="gmail-key",
            )

    def test_revoke_service_raises_on_404(self, tmp_config_dir, mock_httpx):
        """revoke_service raises APIError on 404."""
        mock_httpx["response"].status_code = 404
        mock_httpx["response"].text = '{"error": "not found"}'

        api = AdminAPI(token="test")
        with pytest.raises(APIError):
            api.revoke_service(agent="boris", service="nope")


class TestAdminAPIRequestErrors:
    """Tests for _request() error handling."""

    def test_request_403_raises_api_error(self, tmp_config_dir, mock_httpx):
        """403 status raises APIError with 'Permission denied' and status_code=403."""
        mock_httpx["response"].status_code = 403
        mock_httpx["response"].text = "Forbidden"

        api = AdminAPI(token="test")
        with pytest.raises(APIError, match="Permission denied") as exc_info:
            api.stats()
        assert exc_info.value.status_code == 403

    def test_request_timeout_raises_api_error(self, tmp_config_dir, monkeypatch):
        """Request timeout raises APIError with actionable message."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.side_effect = httpx.TimeoutException("timed out")
        monkeypatch.setattr("httpx.Client", MagicMock(return_value=mock_client))

        api = AdminAPI(timeout=5.0)
        with pytest.raises(APIError, match="timed out after 5.0s"):
            api.stats()

    def test_request_read_error_raises_api_error(self, tmp_config_dir, monkeypatch):
        """ReadError raises APIError with connection-lost message."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.request.side_effect = httpx.ReadError("connection reset")
        monkeypatch.setattr("httpx.Client", MagicMock(return_value=mock_client))

        api = AdminAPI()
        with pytest.raises(APIError, match="Connection lost"):
            api.health()

    def test_non_json_response_returns_text(self, tmp_config_dir, mock_httpx):
        """Non-JSON response returns response.text instead of calling .json()."""
        mock_httpx["response"].headers = {"content-type": "text/plain"}
        mock_httpx["response"].text = "# Prometheus metrics\nproxy_requests_total 42"

        api = AdminAPI(token="test")
        result = api.metrics()
        assert result == "# Prometheus metrics\nproxy_requests_total 42"

    def test_request_includes_auth_header(self, tmp_config_dir, mock_httpx):
        """Authenticated requests include Bearer token in Authorization header."""
        api = AdminAPI(token="secret-token-xyz")
        api.stats()

        call_args = mock_httpx["client"].request.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer secret-token-xyz"


class TestGetAPI:
    """Tests for get_api() helper."""

    def test_returns_api_instance(self, tmp_config_dir):
        """Returns configured AdminAPI instance."""
        api = get_api()
        assert isinstance(api, AdminAPI)
        assert api.base_url == "http://localhost:9090"
