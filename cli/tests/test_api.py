"""Tests for API client module."""

from unittest.mock import MagicMock, patch

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
        mock_httpx["response"].json.return_value = {
            "modes": {"credential-guard": "block", "rate-limiter": "warn"}
        }

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
        """Adds approval rule."""
        mock_httpx["response"].json.return_value = {"status": "approved"}

        api = AdminAPI(token="test")
        result = api.add_approval(
            project="default",
            token_hmac="abc123",
            hosts=["api.example.com"],
            paths=["/**"],
        )

        assert result["status"] == "approved"
        call_args = mock_httpx["client"].request.call_args
        assert "/admin/policy/default/approve" in call_args[0][1]
        assert call_args[1]["json"]["token_hmac"] == "abc123"
        assert call_args[1]["json"]["hosts"] == ["api.example.com"]

    def test_add_approval_minimal(self, tmp_config_dir, mock_httpx):
        """Adds approval with minimal params."""
        mock_httpx["response"].json.return_value = {"status": "approved"}

        api = AdminAPI(token="test")
        api.add_approval(project="default", token_hmac="xyz", hosts=["example.com"])

        call_args = mock_httpx["client"].request.call_args
        payload = call_args[1]["json"]
        assert "paths" not in payload
        assert "name" not in payload


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
        result = api.add_allowlist("sk-test", "api.openai.com", ttl_seconds=600)

        call_args = mock_httpx["client"].request.call_args
        assert call_args[1]["json"]["credential_prefix"] == "sk-test"
        assert call_args[1]["json"]["ttl_seconds"] == 600

    def test_clear_allowlist(self, tmp_config_dir, mock_httpx):
        """Clears all allowlist entries."""
        mock_httpx["response"].json.return_value = {"cleared": 5}

        api = AdminAPI(token="test")
        result = api.clear_allowlist()

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


class TestGetAPI:
    """Tests for get_api() helper."""

    def test_returns_api_instance(self, tmp_config_dir):
        """Returns configured AdminAPI instance."""
        api = get_api()
        assert isinstance(api, AdminAPI)
        assert api.base_url == "http://localhost:9090"
