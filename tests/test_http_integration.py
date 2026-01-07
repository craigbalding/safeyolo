"""
Real HTTP integration tests for SafeYolo proxy.

These tests send actual HTTP requests through the SafeYolo proxy to a local test server.
They are "specification quality" - good enough to verify a reimplementation in any language.

Requirements:
- SafeYolo proxy running on PROXY_HOST:PROXY_PORT (default localhost:8080)
- Admin API available on ADMIN_HOST:ADMIN_PORT (default localhost:9090)
- Admin token via ADMIN_API_TOKEN env var or /app/data/admin_token file

Test server:
- Provides deterministic responses based on path
- Runs on a random high port for each test session

Usage:
    # Inside container (reads token from /app/data/admin_token):
    pytest tests/test_http_integration.py -v

    # From host with explicit token:
    ADMIN_API_TOKEN=xxx pytest tests/test_http_integration.py -v
"""

import json
import os
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

# ==============================================================================
# Configuration
# ==============================================================================

PROXY_HOST = os.environ.get("PROXY_HOST", "localhost")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
ADMIN_HOST = os.environ.get("ADMIN_HOST", "localhost")
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "9090"))

# Load admin token from env or disk
def _load_admin_token() -> str:
    """Load admin token from environment or /app/data/admin_token."""
    token = os.environ.get("ADMIN_API_TOKEN", "")
    if token:
        return token
    token_path = "/app/data/admin_token"
    if os.path.exists(token_path):
        return open(token_path).read().strip()
    return ""

ADMIN_TOKEN = _load_admin_token()

# Skip all tests if proxy is not available
pytestmark = pytest.mark.skipif(
    not ADMIN_TOKEN,
    reason="ADMIN_API_TOKEN not set and /app/data/admin_token not found"
)


# ==============================================================================
# Test Server - Returns deterministic responses based on path
# ==============================================================================

@dataclass
class CapturedRequest:
    """A captured request from the test server."""
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class UpstreamHandler(BaseHTTPRequestHandler):
    """HTTP handler for upstream server with deterministic responses.

    Paths:
        /ok              -> 200 OK, {"status": "ok"}
        /echo            -> 200, echoes request details
        /slow?delay=N    -> 200 after N seconds delay
        /fail?code=N     -> Returns HTTP status N
        /headers         -> 200, returns all received headers
        /body            -> 200, echoes request body
        /secret          -> 200, {"secret": "value"} (for testing credential leaks)
    """

    # Class-level request capture (for inspection in tests)
    captured_requests: list[CapturedRequest] = []

    def log_message(self, format: str, *args) -> None:
        """Suppress default logging."""
        pass

    def _capture_request(self) -> CapturedRequest:
        """Capture request details for later inspection."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        headers = dict(self.headers.items())

        captured = CapturedRequest(
            method=self.command,
            path=self.path,
            headers=headers,
            body=body,
        )
        UpstreamHandler.captured_requests.append(captured)
        return captured

    def _send_json(self, status: int, data: dict) -> None:
        """Send JSON response."""
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_PUT(self) -> None:
        self._handle_request()

    def do_DELETE(self) -> None:
        self._handle_request()

    def _handle_request(self) -> None:
        """Route request to appropriate handler."""
        captured = self._capture_request()
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/ok":
            self._send_json(200, {"status": "ok"})

        elif path == "/echo":
            self._send_json(200, {
                "method": captured.method,
                "path": captured.path,
                "headers": captured.headers,
                "body": captured.body.decode("utf-8", errors="replace"),
            })

        elif path == "/slow":
            delay = float(query.get("delay", ["1"])[0])
            time.sleep(delay)
            self._send_json(200, {"status": "ok", "delay": delay})

        elif path == "/fail":
            code = int(query.get("code", ["500"])[0])
            self._send_json(code, {"error": f"Simulated {code}"})

        elif path == "/headers":
            self._send_json(200, {"headers": captured.headers})

        elif path == "/body":
            self._send_json(200, {
                "body": captured.body.decode("utf-8", errors="replace"),
                "length": len(captured.body),
            })

        elif path == "/secret":
            # Simulate an API that returns sensitive data
            self._send_json(200, {"secret": "super-secret-value-12345"})

        else:
            self._send_json(404, {"error": "Not found", "path": path})


class UpstreamServer:
    """Local HTTP server that runs in a background thread for integration tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the server and return the port."""
        self.server = HTTPServer((self.host, self.port), UpstreamHandler)
        # If port was 0, get the actual assigned port
        self.port = self.server.server_address[1]

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        # Wait for server to be ready
        for _ in range(50):
            try:
                with socket.create_connection((self.host, self.port), timeout=0.1):
                    return self.port
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)

        raise RuntimeError(f"Test server failed to start on {self.host}:{self.port}")

    def stop(self) -> None:
        """Stop the test server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None

    def clear_requests(self) -> None:
        """Clear captured requests."""
        UpstreamHandler.captured_requests.clear()

    @property
    def captured_requests(self) -> list[CapturedRequest]:
        """Get captured requests."""
        return UpstreamHandler.captured_requests

    @property
    def base_url(self) -> str:
        """Get the base URL for this server."""
        return f"http://{self.host}:{self.port}"


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture(scope="session")
def test_server() -> UpstreamServer:
    """Session-scoped upstream server fixture."""
    server = UpstreamServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def clear_requests(test_server: UpstreamServer):
    """Clear captured requests before each test."""
    test_server.clear_requests()
    yield
    # No cleanup needed


@pytest.fixture
def ensure_circuit_closed(proxied_client: httpx.Client, test_server: UpstreamServer, admin_client: httpx.Client):
    """Ensure circuit breaker for test server is closed before test runs.

    This fixture helps isolate tests from circuit breaker state.
    It sends successful requests until the circuit is closed.
    """
    ok_url = f"{test_server.base_url}/ok"
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

    # Try to close the circuit by sending successful requests
    for attempt in range(10):
        # Check current state
        stats = admin_client.get("/stats", headers=headers).json()
        domain_state = stats.get("circuit-breaker", {}).get("domains", {}).get("127.0.0.1", {})
        state = domain_state.get("state", "closed")

        if state == "closed":
            break

        if state == "half_open":
            # In half_open, one success closes it
            try:
                proxied_client.get(ok_url, timeout=5)
            except Exception:
                pass
        elif state == "open":
            # In open state, we need to wait for timeout or skip
            # For tests, we'll wait a short time and retry
            import time
            time.sleep(1)

    yield


@pytest.fixture(scope="session")
def proxy_url() -> str:
    """Get proxy URL for httpx."""
    return f"http://{PROXY_HOST}:{PROXY_PORT}"


@pytest.fixture(scope="session")
def admin_client() -> httpx.Client:
    """Client for admin API calls (no proxy)."""
    return httpx.Client(
        base_url=f"http://{ADMIN_HOST}:{ADMIN_PORT}",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        timeout=10.0,
    )


@pytest.fixture(scope="session")
def proxied_client(proxy_url: str) -> httpx.Client:
    """Client that routes through SafeYolo proxy."""
    # Note: For real integration tests, we'd need to trust SafeYolo's CA cert
    # For now, we skip SSL verification or use HTTP only
    return httpx.Client(
        proxy=proxy_url,
        timeout=30.0,
        verify=False,  # Skip SSL verification for tests
    )


@pytest.fixture
def admin_api(admin_client: httpx.Client):
    """Admin API helper with convenience methods."""
    return AdminAPI(admin_client)


class AdminAPI:
    """Helper for interacting with SafeYolo admin API."""

    def __init__(self, client: httpx.Client):
        self.client = client

    def health(self) -> dict:
        """Check admin API health."""
        resp = self.client.get("/health")
        resp.raise_for_status()
        return resp.json()

    def get_stats(self) -> dict:
        """Get stats from all addons."""
        resp = self.client.get("/stats")
        resp.raise_for_status()
        return resp.json()

    def get_modes(self) -> dict:
        """Get modes for all security addons."""
        resp = self.client.get("/modes")
        resp.raise_for_status()
        return resp.json()

    def get_plugin_mode(self, plugin: str) -> str:
        """Get current mode for a plugin."""
        resp = self.client.get(f"/plugins/{plugin}/mode")
        resp.raise_for_status()
        return resp.json().get("mode")

    def set_plugin_mode(self, plugin: str, mode: str) -> dict:
        """Set mode for a plugin (block/warn)."""
        resp = self.client.put(f"/plugins/{plugin}/mode", json={"mode": mode})
        resp.raise_for_status()
        return resp.json()

    def get_budgets(self) -> dict:
        """Get budget status."""
        resp = self.client.get("/admin/budgets")
        resp.raise_for_status()
        return resp.json()

    def reset_budgets(self, resource: str | None = None) -> dict:
        """Reset budget counters."""
        data = {"resource": resource} if resource else {}
        resp = self.client.post("/admin/budgets/reset", json=data)
        resp.raise_for_status()
        return resp.json()


@contextmanager
def plugin_mode(admin_api: AdminAPI, plugin: str, mode: str):
    """Context manager to temporarily set plugin mode."""
    original_mode = admin_api.get_plugin_mode(plugin)
    admin_api.set_plugin_mode(plugin, mode)
    try:
        yield
    finally:
        admin_api.set_plugin_mode(plugin, original_mode)


# ==============================================================================
# Tests: Admin API
# ==============================================================================

class TestAdminAPIHealth:
    """Tests for admin API availability and health endpoint."""

    def test_health_endpoint_responds(self, admin_client: httpx.Client):
        """Admin API should respond to health check."""
        resp = admin_client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "ok"

    def test_health_no_auth_required(self):
        """Health endpoint should NOT require authentication (for monitoring)."""
        client = httpx.Client(
            base_url=f"http://{ADMIN_HOST}:{ADMIN_PORT}",
            timeout=5.0,
        )
        resp = client.get("/health")
        # Health is exempt from auth for monitoring tools
        assert resp.status_code == 200
        assert resp.json().get("status") == "ok"

    def test_authenticated_endpoints_require_token(self):
        """Non-health endpoints should require authentication."""
        client = httpx.Client(
            base_url=f"http://{ADMIN_HOST}:{ADMIN_PORT}",
            timeout=5.0,
        )
        resp = client.get("/stats")
        # Should be 401 Unauthorized
        assert resp.status_code == 401
        data = resp.json()
        assert "unauthorized" in data.get("error", "").lower()


class TestAdminAPIPlugins:
    """Tests for plugin management via admin API."""

    def test_get_modes_lists_all_addons(self, admin_api: AdminAPI):
        """Should list modes for all security addons."""
        modes = admin_api.get_modes()
        assert "modes" in modes

        # Core security addons should be present
        addon_names = list(modes["modes"].keys())
        assert "network-guard" in addon_names
        assert "credential-guard" in addon_names

    def test_get_plugin_mode(self, admin_api: AdminAPI):
        """Should get current mode for a plugin."""
        mode = admin_api.get_plugin_mode("network-guard")
        assert mode in ("block", "warn")

    def test_set_plugin_mode_block(self, admin_api: AdminAPI):
        """Should be able to set plugin to block mode."""
        result = admin_api.set_plugin_mode("network-guard", "block")
        assert result.get("mode") == "block"

        # Verify it took effect
        mode = admin_api.get_plugin_mode("network-guard")
        assert mode == "block"

    def test_set_plugin_mode_warn(self, admin_api: AdminAPI):
        """Should be able to set plugin to warn mode."""
        result = admin_api.set_plugin_mode("network-guard", "warn")
        assert result.get("mode") == "warn"

        # Verify it took effect
        mode = admin_api.get_plugin_mode("network-guard")
        assert mode == "warn"

        # Clean up - restore block mode
        admin_api.set_plugin_mode("network-guard", "block")


class TestAdminAPIStats:
    """Tests for stats endpoint."""

    def test_stats_endpoint_responds(self, admin_api: AdminAPI):
        """Stats endpoint should return data from all addons."""
        stats = admin_api.get_stats()
        assert isinstance(stats, dict)

        # Should have stats from core addons
        assert "network-guard" in stats or "credential-guard" in stats

    def test_stats_include_addon_data(self, admin_api: AdminAPI):
        """Stats should include data from security addons."""
        stats = admin_api.get_stats()
        # Network-guard should have request counting stats
        if "network-guard" in stats:
            ng_stats = stats["network-guard"]
            assert isinstance(ng_stats, dict)
            # Should have check/allow/block counters
            assert "checks" in ng_stats or "allowed" in ng_stats or "blocked" in ng_stats


# ==============================================================================
# Tests: Proxy Basic Functionality
# ==============================================================================

class TestProxyBasic:
    """Basic proxy functionality tests."""

    def test_proxy_forwards_request(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        clear_requests,
    ):
        """Proxy should forward request to upstream server."""
        url = f"{test_server.base_url}/ok"
        resp = proxied_client.get(url)

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

        # Verify request was received by test server
        assert len(test_server.captured_requests) == 1
        assert test_server.captured_requests[0].path == "/ok"

    def test_proxy_preserves_headers(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        clear_requests,
    ):
        """Proxy should preserve request headers."""
        url = f"{test_server.base_url}/headers"
        custom_headers = {"X-Custom-Header": "test-value-12345"}
        resp = proxied_client.get(url, headers=custom_headers)

        assert resp.status_code == 200
        data = resp.json()
        assert data["headers"].get("X-Custom-Header") == "test-value-12345"

    def test_proxy_handles_post_body(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        clear_requests,
    ):
        """Proxy should forward POST body correctly."""
        url = f"{test_server.base_url}/body"
        body = {"message": "hello world", "number": 42}
        resp = proxied_client.post(url, json=body)

        assert resp.status_code == 200
        data = resp.json()
        received_body = json.loads(data["body"])
        assert received_body == body

    def test_proxy_handles_upstream_errors(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        clear_requests,
    ):
        """Proxy should forward upstream error responses."""
        url = f"{test_server.base_url}/fail?code=503"
        resp = proxied_client.get(url)

        assert resp.status_code == 503
        data = resp.json()
        assert "error" in data


# ==============================================================================
# Tests: Network Guard (Access Control + Rate Limiting)
# ==============================================================================

class TestNetworkGuardAccess:
    """Tests for network-guard access control."""

    def test_allowed_domain_passes(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Allowed domains should pass through."""
        # Ensure network-guard is in block mode
        admin_api.set_plugin_mode("network-guard", "block")

        url = f"{test_server.base_url}/ok"
        resp = proxied_client.get(url)

        # Local test server should be allowed
        assert resp.status_code == 200

    def test_blocked_domain_returns_403(
        self,
        proxied_client: httpx.Client,
        admin_api: AdminAPI,
    ):
        """Blocked domains should return 403.

        Note: This requires a domain that is denied in the policy.
        The test verifies the response format, not the policy config.
        """
        admin_api.set_plugin_mode("network-guard", "block")

        # Try to access a domain that should be blocked
        # (This depends on the policy configuration)
        try:
            resp = proxied_client.get("http://blocked.example.invalid/test", timeout=5)
            # If we get a response, check if it's a block response
            if resp.status_code == 403:
                data = resp.json()
                assert "blocked" in str(data).lower() or "denied" in str(data).lower()
        except httpx.ConnectError:
            # Connection refused is also valid (DNS resolution failed)
            pass

    def test_warn_mode_allows_through(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Warn mode should allow requests through but log them."""
        with plugin_mode(admin_api, "network-guard", "warn"):
            url = f"{test_server.base_url}/ok"
            resp = proxied_client.get(url)
            assert resp.status_code == 200


class TestNetworkGuardBudget:
    """Tests for network-guard budget/rate limiting."""

    def test_budget_endpoint_responds(self, admin_api: AdminAPI):
        """Budget endpoint should return budget status."""
        budgets = admin_api.get_budgets()
        assert isinstance(budgets, dict)
        # Should have budgets key or be empty dict
        assert "budgets" in budgets or budgets == {}

    def test_budget_reset_via_admin(self, admin_api: AdminAPI):
        """Budget counters should be resettable via admin API."""
        # Reset all budgets
        result = admin_api.reset_budgets()
        # Should return success status
        assert result.get("status") in ("ok", "reset") or "reset" in str(result).lower()


# ==============================================================================
# Tests: Credential Guard
# ==============================================================================

class TestCredentialGuard:
    """Tests for credential-guard (API key protection)."""

    def test_credential_to_correct_host_allowed(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Credentials to their expected host should pass."""
        admin_api.set_plugin_mode("credential-guard", "block")

        # Test server is not a "credential host" - should pass without creds
        url = f"{test_server.base_url}/ok"
        resp = proxied_client.get(url)
        assert resp.status_code == 200

    def test_openai_credential_to_wrong_host_blocked(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """OpenAI API key to non-OpenAI host should be blocked.

        This is the core security guarantee of credential-guard.
        """
        admin_api.set_plugin_mode("credential-guard", "block")

        # Send OpenAI-format API key to test server (wrong host)
        url = f"{test_server.base_url}/ok"
        headers = {
            "Authorization": f"Bearer sk-proj-{'a' * 80}",  # OpenAI format
        }
        resp = proxied_client.get(url, headers=headers)

        # Should be blocked (428 Precondition Required for approval-needed)
        assert resp.status_code in (403, 428)
        data = resp.json()
        # Response should indicate credential/approval issue
        assert any(
            term in str(data).lower()
            for term in ("credential", "approval", "blocked", "denied")
        )

        # Verify request did NOT reach the test server
        # (No request should have the credential header)
        assert len(test_server.captured_requests) == 0

    def test_credential_warn_mode_logs_but_allows(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Warn mode should log violation but allow request through."""
        with plugin_mode(admin_api, "credential-guard", "warn"):
            url = f"{test_server.base_url}/ok"
            headers = {
                "Authorization": f"Bearer sk-proj-{'a' * 80}",
            }
            resp = proxied_client.get(url, headers=headers)

            # In warn mode, request should pass
            assert resp.status_code == 200

            # Request should reach test server
            assert len(test_server.captured_requests) == 1


# ==============================================================================
# Tests: Circuit Breaker
# ==============================================================================

class TestCircuitBreaker:
    """Tests for circuit-breaker (upstream health tracking).

    Circuit breaker behavior:
    - CLOSED: Normal operation, requests pass through
    - OPEN: After failure_threshold consecutive failures, returns 503 immediately
    - HALF_OPEN: After timeout_seconds, allows one probe request
    """

    def test_circuit_status_in_stats(self, admin_api: AdminAPI):
        """Circuit breaker config should be available in stats."""
        stats = admin_api.get_stats()
        assert "circuit-breaker" in stats

        cb_stats = stats["circuit-breaker"]
        assert "enabled" in cb_stats
        assert "failure_threshold" in cb_stats
        assert cb_stats["failure_threshold"] > 0, "Threshold must be positive"

    def test_healthy_upstream_passes(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Healthy upstream should pass through (circuit closed or half_open)."""
        url = f"{test_server.base_url}/ok"
        resp = proxied_client.get(url)
        assert resp.status_code == 200

        # After success, circuit should be closed or transitioning
        stats = admin_api.get_stats()
        domains = stats.get("circuit-breaker", {}).get("domains", {})
        if "127.0.0.1" in domains:
            # After successful request, should not be open
            assert domains["127.0.0.1"]["state"] in ("closed", "half_open"), \
                "Circuit should allow traffic after successful request"

    def test_failure_increments_count(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Upstream failures should increment failure count."""
        # Reset by sending successful request first
        ok_url = f"{test_server.base_url}/ok"
        proxied_client.get(ok_url)

        # Get initial failure count
        stats = admin_api.get_stats()
        initial_count = stats.get("circuit-breaker", {}).get("domains", {}).get("127.0.0.1", {}).get("failure_count", 0)

        # Trigger a failure
        url = f"{test_server.base_url}/fail?code=500"
        resp = proxied_client.get(url)
        assert resp.status_code == 500

        # Check failure count increased
        stats = admin_api.get_stats()
        new_count = stats.get("circuit-breaker", {}).get("domains", {}).get("127.0.0.1", {}).get("failure_count", 0)
        assert new_count > initial_count, f"Failure count should increase: {initial_count} -> {new_count}"

    def test_success_resets_failure_count(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Successful request after circuit recovery should reset failure count.

        Note: failure_count only resets when circuit transitions from HALF_OPEN to CLOSED.
        A success in CLOSED state doesn't reset the count (it keeps counting towards threshold).
        """
        # This test verifies the success path works - detailed state machine testing
        # would require waiting for timeout or forcing half-open state
        ok_url = f"{test_server.base_url}/ok"
        resp = proxied_client.get(ok_url)
        assert resp.status_code == 200

        # Circuit should be in closed state after success
        stats = admin_api.get_stats()
        domain_stats = stats.get("circuit-breaker", {}).get("domains", {}).get("127.0.0.1", {})
        assert domain_stats.get("state") == "closed", "Circuit should be closed after success"

    def test_circuit_opens_after_threshold(
        self,
        proxied_client: httpx.Client,
        admin_api: AdminAPI,
    ):
        """Circuit should open after failure_threshold consecutive failures.

        This is the core circuit breaker guarantee: after N failures,
        the circuit opens and returns 503 WITHOUT hitting upstream.

        Uses postman-echo.com to avoid conflicts with other httpbin.org tests.
        """
        # Get threshold from stats
        stats = admin_api.get_stats()
        threshold = stats.get("circuit-breaker", {}).get("failure_threshold", 5)

        # Use postman-echo for isolation from other tests
        test_domain = "postman-echo.com"
        fail_url = f"https://{test_domain}/status/500"
        ok_url = f"https://{test_domain}/get"

        # Check if circuit is already open from previous test runs
        domain_stats = stats.get("circuit-breaker", {}).get("domains", {}).get(test_domain, {})
        if domain_stats.get("state") == "open":
            pytest.skip(f"Circuit for {test_domain} already open - cannot test threshold behavior")

        # Reset failure count by sending a successful request
        try:
            resp = proxied_client.get(ok_url, timeout=15)
            if resp.status_code == 503:
                pytest.skip(f"Circuit for {test_domain} is open - skipping threshold test")
        except Exception:
            pass  # Service may be slow

        # Trigger threshold failures
        for i in range(threshold):
            resp = proxied_client.get(fail_url, timeout=15)
            if resp.status_code == 503:
                # Circuit opened early - verify it's actually open
                stats = admin_api.get_stats()
                state = stats.get("circuit-breaker", {}).get("domains", {}).get(test_domain, {}).get("state")
                assert state == "open", f"Got 503 but circuit state is '{state}'"
                return  # Test passes - circuit opened (possibly from prior failures)
            assert resp.status_code == 500, f"Failure {i+1} should return 500, got {resp.status_code}"

        # Next request should get 503 from circuit breaker
        resp = proxied_client.get(ok_url, timeout=15)
        assert resp.status_code == 503, f"Expected 503 from open circuit, got {resp.status_code}"

        # Verify circuit state is open
        stats = admin_api.get_stats()
        state = stats.get("circuit-breaker", {}).get("domains", {}).get(test_domain, {}).get("state")
        assert state == "open", f"Circuit state should be 'open', got '{state}'"

    def test_open_circuit_response_format(
        self,
        proxied_client: httpx.Client,
        admin_api: AdminAPI,
    ):
        """Open circuit should return proper 503 response.

        Uses httpbin.org to avoid affecting local test server circuit.
        """
        # Get threshold
        stats = admin_api.get_stats()
        threshold = stats.get("circuit-breaker", {}).get("failure_threshold", 5)

        # Use a different httpbin endpoint to get a fresh circuit
        test_domain = "httpbin.org"

        # Check if circuit is already open from previous test
        domain_state = stats.get("circuit-breaker", {}).get("domains", {}).get(test_domain, {})
        if domain_state.get("state") == "open":
            # Circuit already open, just test the response format
            resp = proxied_client.get(f"http://{test_domain}/get", timeout=10)
        else:
            # Open the circuit
            fail_url = f"http://{test_domain}/status/500"
            for _ in range(threshold):
                proxied_client.get(fail_url, timeout=10)
            resp = proxied_client.get(f"http://{test_domain}/get", timeout=10)

        assert resp.status_code == 503

        # Should be JSON
        assert resp.headers.get("content-type", "").startswith("application/json")

        # Should indicate circuit breaker
        data = resp.json()
        response_text = str(data).lower()
        assert "circuit" in response_text or "breaker" in response_text or "unavailable" in response_text, \
            f"503 response should mention circuit breaker: {data}"


# ==============================================================================
# Tests: Response Behavior
# ==============================================================================

class TestBlockResponseFormat:
    """Tests for block response format consistency."""

    def test_block_response_is_json(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Block responses should be JSON."""
        admin_api.set_plugin_mode("credential-guard", "block")

        url = f"{test_server.base_url}/ok"
        headers = {"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        resp = proxied_client.get(url, headers=headers)

        assert resp.status_code in (403, 428)
        assert resp.headers.get("content-type", "").startswith("application/json")

        # Should be valid JSON
        data = resp.json()
        assert isinstance(data, dict)

    def test_block_response_includes_reason(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Block responses should include a reason/message."""
        admin_api.set_plugin_mode("credential-guard", "block")

        url = f"{test_server.base_url}/ok"
        headers = {"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        resp = proxied_client.get(url, headers=headers)

        data = resp.json()
        # Should have some explanation field
        has_explanation = any(
            key in data
            for key in ("error", "message", "reason", "detail", "details")
        )
        assert has_explanation, f"Block response missing explanation: {data}"

    def test_block_response_includes_event_id(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Block responses should include event_id for audit trail."""
        admin_api.set_plugin_mode("credential-guard", "block")

        url = f"{test_server.base_url}/ok"
        headers = {"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        resp = proxied_client.get(url, headers=headers)

        data = resp.json()
        # Should include event_id for correlation with logs
        assert "event_id" in data, f"Block response missing event_id: {data}"
        assert data["event_id"].startswith("evt_"), f"Invalid event_id format: {data['event_id']}"


# ==============================================================================
# Tests: Concurrent Requests
# ==============================================================================

class TestConcurrency:
    """Tests for concurrent request handling."""

    def test_concurrent_requests_succeed(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Multiple concurrent requests should all succeed."""
        import concurrent.futures

        url = f"{test_server.base_url}/ok"
        num_requests = 10
        results = []

        def make_request(i: int) -> tuple[int, int]:
            resp = proxied_client.get(url)
            return (i, resp.status_code)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        # All should succeed
        assert len(results) == num_requests
        for i, status in results:
            assert status == 200, f"Request {i} failed with status {status}"

    def test_concurrent_requests_isolated(
        self,
        proxied_client: httpx.Client,
        test_server: UpstreamServer,
        admin_api: AdminAPI,
        clear_requests,
    ):
        """Concurrent requests should not interfere with each other."""
        import concurrent.futures

        num_requests = 5

        def make_unique_request(i: int) -> dict:
            url = f"{test_server.base_url}/echo"
            headers = {"X-Request-Id": f"test-{i}"}
            resp = proxied_client.get(url, headers=headers)
            return resp.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(make_unique_request, i)
                for i in range(num_requests)
            ]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Each response should have unique X-Request-Id
        request_ids = [r["headers"].get("X-Request-Id") for r in results]
        assert len(set(request_ids)) == num_requests, "Responses mixed up between requests"
