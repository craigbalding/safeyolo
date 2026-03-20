"""Tests for cli/src/safeyolo/commands/_oauth2_flow.py — OAuth2 authorization code flow."""

import http.server

# Add CLI source to path for direct imports
import sys
import threading
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

cli_src = Path(__file__).parent.parent / "cli" / "src"
sys.path.insert(0, str(cli_src))

from safeyolo.commands._oauth2_flow import (
    PROVIDERS,
    OAuth2Error,
    _CallbackHandler,
    _extract_code_from_input,
    run_oauth2_flow,
    run_oauth2_flow_manual,
)


class TestProviderPresets:
    def test_google_preset_exists(self):
        assert "google" in PROVIDERS

    def test_google_preset_urls(self):
        google = PROVIDERS["google"]
        assert "accounts.google.com" in google["auth_url"]
        assert "googleapis.com/token" in google["token_url"]

    def test_google_preset_offline_access(self):
        google = PROVIDERS["google"]
        extra = google.get("extra_auth_params", {})
        assert extra.get("access_type") == "offline"
        assert extra.get("prompt") == "consent"


class TestCallbackHandler:
    """Test the localhost callback HTTP handler."""

    def _make_server(self, port=0):
        server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
        server.auth_code = None
        server.auth_error = None
        server.received_state = None
        return server

    def test_captures_auth_code(self):
        server = self._make_server()
        port = server.server_address[1]

        def handle():
            server.handle_request()

        t = threading.Thread(target=handle)
        t.start()

        resp = httpx.get(
            f"http://localhost:{port}/?code=test-auth-code&state=test-state",
            timeout=5.0,
        )

        t.join(timeout=5)
        server.server_close()

        assert resp.status_code == 200
        assert server.auth_code == "test-auth-code"
        assert server.received_state == "test-state"

    def test_captures_error(self):
        server = self._make_server()
        port = server.server_address[1]

        def handle():
            server.handle_request()

        t = threading.Thread(target=handle)
        t.start()

        resp = httpx.get(
            f"http://localhost:{port}/?error=access_denied&error_description=User+denied",
            timeout=5.0,
        )

        t.join(timeout=5)
        server.server_close()

        assert resp.status_code == 400
        assert "access_denied" in server.auth_error


def _send_callback_async(url: str, delay: float = 0.1):
    """Send a callback request in a background thread (simulates browser redirect).

    In real usage, webbrowser.open is non-blocking (launches browser process).
    The browser then redirects to localhost after user authorizes.
    We simulate this with a delayed thread.
    """
    import time

    def _send():
        time.sleep(delay)  # Let handle_request() start first
        try:
            httpx.get(url, timeout=5.0)
        except Exception:
            pass  # Server may close before response completes

    t = threading.Thread(target=_send, daemon=True)
    t.start()
    return t


class TestOAuth2Flow:
    """Test the full OAuth2 flow with mocked browser and token endpoint."""

    def test_successful_flow(self):
        """Simulate: browser opens -> user authorizes -> callback -> token exchange."""
        token_response = {
            "access_token": "ya29.test-access-token",
            "refresh_token": "1//test-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        def fake_browser_open(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            redirect_uri = params["redirect_uri"][0]
            state = params["state"][0]
            _send_callback_async(f"{redirect_uri}?code=fake-auth-code&state={state}")

        with patch("safeyolo.commands._oauth2_flow.webbrowser.open", side_effect=fake_browser_open):
            with patch("safeyolo.commands._oauth2_flow.httpx.post") as mock_post:
                mock_resp = MagicMock()
                mock_resp.json.return_value = token_response
                mock_resp.raise_for_status = MagicMock()
                mock_post.return_value = mock_resp

                result = run_oauth2_flow(
                    client_id="test-client-id",
                    client_secret="test-client-secret",
                    auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                    token_url="https://oauth2.googleapis.com/token",
                    scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                    extra_auth_params={"access_type": "offline", "prompt": "consent"},
                )

        assert result["access_token"] == "ya29.test-access-token"
        assert result["refresh_token"] == "1//test-refresh-token"
        assert result["expires_in"] == 3600

        # Verify token exchange was called correctly
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://oauth2.googleapis.com/token"
        post_data = call_kwargs[1]["data"]
        assert post_data["grant_type"] == "authorization_code"
        assert post_data["code"] == "fake-auth-code"
        assert post_data["client_id"] == "test-client-id"
        assert post_data["client_secret"] == "test-client-secret"

    def test_state_mismatch_raises(self):
        """CSRF protection: state mismatch should raise."""
        def fake_browser_open(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            redirect_uri = params["redirect_uri"][0]
            _send_callback_async(f"{redirect_uri}?code=test&state=wrong-state")

        with patch("safeyolo.commands._oauth2_flow.webbrowser.open", side_effect=fake_browser_open):
            with pytest.raises(OAuth2Error, match="State mismatch"):
                run_oauth2_flow(
                    client_id="cid",
                    client_secret="csec",
                    auth_url="https://example.com/auth",
                    token_url="https://example.com/token",
                    scopes=["read"],
                )

    def test_authorization_denied_raises(self):
        """User denies authorization should raise."""
        def fake_browser_open(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            redirect_uri = params["redirect_uri"][0]
            _send_callback_async(f"{redirect_uri}?error=access_denied")

        with patch("safeyolo.commands._oauth2_flow.webbrowser.open", side_effect=fake_browser_open):
            with pytest.raises(OAuth2Error, match="Authorization denied"):
                run_oauth2_flow(
                    client_id="cid",
                    client_secret="csec",
                    auth_url="https://example.com/auth",
                    token_url="https://example.com/token",
                    scopes=["read"],
                )

    def test_auth_url_includes_scopes(self):
        """Verify scopes are included in the authorization URL."""
        captured_url = None

        def fake_browser_open(url):
            nonlocal captured_url
            captured_url = url
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            redirect_uri = params["redirect_uri"][0]
            state = params["state"][0]
            _send_callback_async(f"{redirect_uri}?code=test&state={state}")

        with patch("safeyolo.commands._oauth2_flow.webbrowser.open", side_effect=fake_browser_open):
            with patch("safeyolo.commands._oauth2_flow.httpx.post") as mock_post:
                mock_resp = MagicMock()
                mock_resp.json.return_value = {"access_token": "tok"}
                mock_resp.raise_for_status = MagicMock()
                mock_post.return_value = mock_resp

                run_oauth2_flow(
                    client_id="cid",
                    client_secret="csec",
                    auth_url="https://example.com/auth",
                    token_url="https://example.com/token",
                    scopes=["scope1", "scope2"],
                )

        parsed = urllib.parse.urlparse(captured_url)
        params = urllib.parse.parse_qs(parsed.query)
        assert params["scope"] == ["scope1 scope2"]
        assert params["response_type"] == ["code"]

    def test_extra_auth_params_included(self):
        """Extra auth params (like access_type=offline) should be in the URL."""
        captured_url = None

        def fake_browser_open(url):
            nonlocal captured_url
            captured_url = url
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            redirect_uri = params["redirect_uri"][0]
            state = params["state"][0]
            _send_callback_async(f"{redirect_uri}?code=test&state={state}")

        with patch("safeyolo.commands._oauth2_flow.webbrowser.open", side_effect=fake_browser_open):
            with patch("safeyolo.commands._oauth2_flow.httpx.post") as mock_post:
                mock_resp = MagicMock()
                mock_resp.json.return_value = {"access_token": "tok"}
                mock_resp.raise_for_status = MagicMock()
                mock_post.return_value = mock_resp

                run_oauth2_flow(
                    client_id="cid",
                    client_secret="csec",
                    auth_url="https://example.com/auth",
                    token_url="https://example.com/token",
                    scopes=["read"],
                    extra_auth_params={"access_type": "offline", "prompt": "consent"},
                )

        parsed = urllib.parse.urlparse(captured_url)
        params = urllib.parse.parse_qs(parsed.query)
        assert params["access_type"] == ["offline"]
        assert params["prompt"] == ["consent"]


typer = pytest.importorskip("typer", reason="CLI dependency not available in addons test env")


class TestScopeExpansion:
    """Test Google scope shortcut expansion."""

    def test_gmail_readonly_expands(self):
        from safeyolo.commands.vault import _expand_scopes

        result = _expand_scopes(["gmail.readonly"], "google")
        assert result == ["https://www.googleapis.com/auth/gmail.readonly"]

    def test_full_url_unchanged(self):
        from safeyolo.commands.vault import _expand_scopes

        full = "https://www.googleapis.com/auth/gmail.readonly"
        result = _expand_scopes([full], "google")
        assert result == [full]

    def test_non_google_no_expansion(self):
        from safeyolo.commands.vault import _expand_scopes

        result = _expand_scopes(["gmail.readonly"], "slack")
        assert result == ["gmail.readonly"]

    def test_multiple_scopes(self):
        from safeyolo.commands.vault import _expand_scopes

        result = _expand_scopes(["gmail.readonly", "gmail.send"], "google")
        assert result == [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
        ]


class TestExtractCodeFromInput:
    """Test parsing user input in no-browser mode."""

    def test_bare_code(self):
        code = _extract_code_from_input("4/0AY0e-g7abc123")
        assert code == "4/0AY0e-g7abc123"

    def test_full_redirect_url(self):
        url = "http://localhost/?code=4/0AY0e-g7abc123&state=mystate"
        code = _extract_code_from_input(url, expected_state="mystate")
        assert code == "4/0AY0e-g7abc123"

    def test_url_with_wrong_state_raises(self):
        url = "http://localhost/?code=abc&state=wrong"
        with pytest.raises(OAuth2Error, match="State mismatch"):
            _extract_code_from_input(url, expected_state="correct")

    def test_url_with_error_raises(self):
        url = "http://localhost/?error=access_denied&error_description=User+denied"
        with pytest.raises(OAuth2Error, match="access_denied"):
            _extract_code_from_input(url)

    def test_url_without_code_raises(self):
        url = "http://localhost/?foo=bar"
        with pytest.raises(OAuth2Error, match="does not contain"):
            _extract_code_from_input(url)

    def test_empty_input_raises(self):
        with pytest.raises(OAuth2Error, match="No input"):
            _extract_code_from_input("")

    def test_whitespace_stripped(self):
        code = _extract_code_from_input("  abc123  \n")
        assert code == "abc123"

    def test_https_redirect_url(self):
        url = "https://localhost:8443/?code=mycode&state=s1"
        code = _extract_code_from_input(url, expected_state="s1")
        assert code == "mycode"

    def test_state_not_validated_when_not_expected(self):
        """When expected_state is None, don't check state."""
        url = "http://localhost/?code=abc&state=anything"
        code = _extract_code_from_input(url, expected_state=None)
        assert code == "abc"


class TestManualFlow:
    """Test the no-browser manual OAuth2 flow."""

    def test_manual_flow_with_url_paste(self):
        """User pastes back the full redirect URL."""
        token_response = {
            "access_token": "ya29.manual-token",
            "refresh_token": "1//manual-refresh",
            "expires_in": 3600,
        }

        captured_print_lines = []

        def fake_print(msg=""):
            captured_print_lines.append(msg)

        # We need to capture the state from the printed URL to build a valid response
        def fake_input(prompt):
            # Find the auth URL in printed output
            for line in captured_print_lines:
                if "accounts.google.com" in line:
                    parsed = urllib.parse.urlparse(line.strip())
                    params = urllib.parse.parse_qs(parsed.query)
                    state = params["state"][0]
                    return f"http://localhost/?code=manual-auth-code&state={state}"
            return "manual-auth-code"  # fallback: bare code

        with patch("safeyolo.commands._oauth2_flow.httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.json.return_value = token_response
            mock_resp.raise_for_status = MagicMock()
            mock_post.return_value = mock_resp

            result = run_oauth2_flow_manual(
                client_id="cid",
                client_secret="csec",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                extra_auth_params={"access_type": "offline"},
                input_fn=fake_input,
                print_fn=fake_print,
            )

        assert result["access_token"] == "ya29.manual-token"
        assert result["refresh_token"] == "1//manual-refresh"

        # Verify the URL was printed
        url_printed = any("accounts.google.com" in line for line in captured_print_lines)
        assert url_printed

    def test_manual_flow_with_bare_code(self):
        """User pastes just the authorization code."""
        token_response = {"access_token": "tok123"}

        with patch("safeyolo.commands._oauth2_flow.httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.json.return_value = token_response
            mock_resp.raise_for_status = MagicMock()
            mock_post.return_value = mock_resp

            result = run_oauth2_flow_manual(
                client_id="cid",
                client_secret="csec",
                auth_url="https://example.com/auth",
                token_url="https://example.com/token",
                scopes=["read"],
                input_fn=lambda _: "bare-code-123",
                print_fn=lambda *a: None,
            )

        assert result["access_token"] == "tok123"
        post_data = mock_post.call_args[1]["data"]
        assert post_data["code"] == "bare-code-123"

    def test_manual_flow_error_url_raises(self):
        """User pastes a URL containing an error."""
        with pytest.raises(OAuth2Error, match="access_denied"):
            run_oauth2_flow_manual(
                client_id="cid",
                client_secret="csec",
                auth_url="https://example.com/auth",
                token_url="https://example.com/token",
                scopes=["read"],
                input_fn=lambda _: "http://localhost/?error=access_denied",
                print_fn=lambda *a: None,
            )
