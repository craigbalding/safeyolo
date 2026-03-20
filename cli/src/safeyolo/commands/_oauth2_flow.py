"""
OAuth2 Authorization Code flow with localhost callback or manual copy-paste.

Two modes:
  - Browser mode (default): spins up localhost callback server, opens browser,
    catches the redirect automatically.
  - No-browser mode (--no-browser): prints the auth URL for the user to open
    on any machine, then prompts them to paste back the redirect URL or code.
    Works on headless servers.

Used by `safeyolo vault oauth2` for initial OAuth2 onboarding.
"""

import http.server
import secrets
import urllib.parse
import webbrowser

import httpx

# Known provider presets
PROVIDERS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        # Google requires access_type=offline + prompt=consent for refresh tokens
        "extra_auth_params": {
            "access_type": "offline",
            "prompt": "consent",
        },
    },
}


class OAuth2Error(Exception):
    """OAuth2 flow error."""

    pass


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth2 callback."""

    # Set by the server before handling requests
    auth_code: str | None = None
    auth_error: str | None = None
    received_state: str | None = None

    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)

        if "code" in params:
            self.server.auth_code = params["code"][0]
            self.server.received_state = params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:system-ui;text-align:center;padding:60px'>"
                b"<h1>&#9989; Authorization successful</h1>"
                b"<p>You can close this tab and return to the terminal.</p>"
                b"</body></html>"
            )
        elif "error" in params:
            error = params["error"][0]
            desc = params.get("error_description", [""])[0]
            self.server.auth_error = f"{error}: {desc}" if desc else error
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"<html><body style='font-family:system-ui;text-align:center;padding:60px'>"
                f"<h1>&#10060; Authorization failed</h1>"
                f"<p>{error}</p><p>{desc}</p>"
                f"</body></html>".encode()
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP server request logs


def _extract_code_from_input(user_input: str, expected_state: str | None = None) -> str:
    """Extract authorization code from user input.

    Accepts either:
      - A bare authorization code (e.g., "4/0AY0e-g...")
      - A full redirect URL (e.g., "http://localhost:8080/?code=4/0AY0e-g...&state=...")

    Args:
        user_input: What the user pasted
        expected_state: If set, validate state parameter from URL

    Returns:
        The authorization code

    Raises:
        OAuth2Error: If code can't be extracted or state doesn't match
    """
    user_input = user_input.strip()

    if not user_input:
        raise OAuth2Error("No input provided")

    # Try parsing as URL first
    if user_input.startswith("http://") or user_input.startswith("https://"):
        parsed = urllib.parse.urlparse(user_input)
        params = urllib.parse.parse_qs(parsed.query)

        if "error" in params:
            error = params["error"][0]
            desc = params.get("error_description", [""])[0]
            raise OAuth2Error(f"Authorization denied: {error}" + (f" ({desc})" if desc else ""))

        if "code" not in params:
            raise OAuth2Error("URL does not contain an authorization code (?code=...)")

        code = params["code"][0]

        # Validate state if present
        if expected_state and "state" in params:
            received_state = params["state"][0]
            if received_state != expected_state:
                raise OAuth2Error("State mismatch — possible CSRF attack")

        return code

    # Treat as bare code
    return user_input


def run_oauth2_flow(
    client_id: str,
    client_secret: str,
    auth_url: str,
    token_url: str,
    scopes: list[str],
    extra_auth_params: dict | None = None,
    port: int = 0,
    timeout: float = 120.0,
) -> dict:
    """Run the OAuth2 authorization code flow with localhost callback.

    1. Starts a localhost HTTP server to receive the callback
    2. Opens browser to the authorization URL
    3. Waits for the user to authorize
    4. Exchanges the auth code for tokens

    Args:
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        auth_url: Authorization endpoint URL
        token_url: Token endpoint URL
        scopes: List of OAuth2 scopes
        extra_auth_params: Additional authorization URL params (e.g., access_type)
        port: Localhost port for callback (0 = auto-pick)
        timeout: Seconds to wait for callback before timing out

    Returns:
        Token response dict with access_token, refresh_token, expires_in, etc.

    Raises:
        OAuth2Error: If authorization fails or times out
    """
    state = secrets.token_urlsafe(32)

    # Start callback server
    server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.auth_code = None
    server.auth_error = None
    server.received_state = None
    server.timeout = timeout

    actual_port = server.server_address[1]
    redirect_uri = f"http://localhost:{actual_port}"

    # Build authorization URL
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
    }
    if extra_auth_params:
        auth_params.update(extra_auth_params)

    full_url = f"{auth_url}?{urllib.parse.urlencode(auth_params)}"

    # Open browser
    webbrowser.open(full_url)

    # Wait for exactly one request (the callback)
    server.handle_request()
    server.server_close()

    # Check for errors
    if server.auth_error:
        raise OAuth2Error(f"Authorization denied: {server.auth_error}")

    if not server.auth_code:
        raise OAuth2Error("No authorization code received (timed out or unexpected request)")

    if server.received_state != state:
        raise OAuth2Error("State mismatch — possible CSRF attack")

    # Exchange code for tokens
    return _exchange_code(
        code=server.auth_code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        token_url=token_url,
    )


def run_oauth2_flow_manual(
    client_id: str,
    client_secret: str,
    auth_url: str,
    token_url: str,
    scopes: list[str],
    extra_auth_params: dict | None = None,
    redirect_uri: str = "http://localhost",
    input_fn=None,
    print_fn=None,
) -> dict:
    """Run the OAuth2 flow without a browser — print URL, paste code back.

    For headless servers where no browser is available. The user copies the
    URL to any browser (even on a different machine), authorizes, and pastes
    back either the redirect URL from the address bar or the bare code.

    Args:
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        auth_url: Authorization endpoint URL
        token_url: Token endpoint URL
        scopes: List of OAuth2 scopes
        extra_auth_params: Additional authorization URL params
        redirect_uri: Redirect URI registered with the provider
        input_fn: Custom input function (for testing). Default: builtin input()
        print_fn: Custom print function (for testing). Default: builtin print()

    Returns:
        Token response dict

    Raises:
        OAuth2Error: If authorization fails
    """
    if input_fn is None:
        input_fn = input
    if print_fn is None:
        print_fn = print

    state = secrets.token_urlsafe(32)

    # Build authorization URL
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
    }
    if extra_auth_params:
        auth_params.update(extra_auth_params)

    full_url = f"{auth_url}?{urllib.parse.urlencode(auth_params)}"

    print_fn("")
    print_fn("Open this URL in any browser:")
    print_fn("")
    print_fn(f"  {full_url}")
    print_fn("")
    print_fn("After authorizing, your browser will redirect to a localhost URL.")
    print_fn("The page won't load (that's expected). Copy the full URL from")
    print_fn("your browser's address bar and paste it below.")
    print_fn("")

    user_input = input_fn("Paste the redirect URL or authorization code: ")

    code = _extract_code_from_input(user_input, expected_state=state)

    return _exchange_code(
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        token_url=token_url,
    )


def _exchange_code(
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    token_url: str,
) -> dict:
    """Exchange an authorization code for tokens.

    Returns:
        Token response dict
    """
    try:
        response = httpx.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as e:
        try:
            error_body = e.response.json()
            error_desc = error_body.get("error_description", error_body.get("error", str(e)))
        except Exception:
            error_desc = str(e)
        raise OAuth2Error(f"Token exchange failed: {error_desc}") from e
    except httpx.RequestError as e:
        raise OAuth2Error(f"Token exchange request failed: {e}") from e
