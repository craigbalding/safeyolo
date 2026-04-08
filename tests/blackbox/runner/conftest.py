"""Pytest fixtures for black box tests.

These fixtures work both inside a microVM (production) and from the host
(development/debugging). All platform-specific details are configured
via environment variables set by the harness.

Environment variables:
    HTTP_PROXY / HTTPS_PROXY   - Proxy URL (set by guest-init from proxy.env)
    SAFEYOLO_GATEWAY_IP        - Host gateway IP (e.g., 192.168.65.1)
    ADMIN_API_TOKEN            - Token for admin API access
    SINKHOLE_API               - Sinkhole control API URL
    SSL_CERT_FILE              - Path to mitmproxy CA cert for TLS verification
"""

import os
import time

import httpx
import pytest
from sinkhole_client import SinkholeClient

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
_gateway = os.environ.get("SAFEYOLO_GATEWAY_IP", "127.0.0.1")
_proxy_port = os.environ.get("SAFEYOLO_PROXY_PORT", "8080")
_admin_port = os.environ.get("SAFEYOLO_ADMIN_PORT", "9090")

PROXY_URL = os.environ.get("HTTP_PROXY", f"http://{_gateway}:{_proxy_port}")
ADMIN_URL = os.environ.get("ADMIN_URL", f"http://{_gateway}:{_admin_port}")
ADMIN_TOKEN = os.environ.get("ADMIN_API_TOKEN", "test-token-for-blackbox-tests")
SINKHOLE_API = os.environ.get("SINKHOLE_API", f"http://{_gateway}:19999")

# CA cert installed by guest-init into the system trust store
_CA_CERT = os.environ.get(
    "SSL_CERT_FILE",
    "/usr/local/share/ca-certificates/safeyolo.crt",
)

# ---------------------------------------------------------------------------
# Test credentials — MUST match production detection patterns
# ---------------------------------------------------------------------------
# OpenAI pattern: sk-proj-[a-zA-Z0-9_-]{80,}
TEST_OPENAI_KEY = "sk-proj-" + "a1b2c3d4e5f6g7h8i9j0" * 4  # 80+ chars after prefix

# Anthropic pattern: sk-ant-api[a-zA-Z0-9-]{90,}
TEST_ANTHROPIC_KEY = "sk-ant-api03-" + "a1b2c3d4e5f6g7h8i9j0" * 5  # 90+ chars

# GitHub pattern: gh[ps]_[a-zA-Z0-9]{36}
TEST_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"  # 36 chars


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def sinkhole():
    """Sinkhole client for request inspection.

    Skips tests gracefully if sinkhole is not available (e.g., isolation-only runs).
    """
    client = SinkholeClient(SINKHOLE_API)
    try:
        client.wait_for_ready(timeout=10)
    except Exception:
        pytest.skip("Sinkhole not available — skipping proxy tests")
    yield client
    client.close()


@pytest.fixture(scope="session")
def admin_headers():
    """Headers for admin API authentication."""
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture(scope="session")
def admin_client(admin_headers):
    """HTTP client for admin API."""
    client = httpx.Client(
        base_url=ADMIN_URL,
        headers=admin_headers,
        timeout=10.0,
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def proxy_client():
    """HTTP client that routes through SafeYolo proxy.

    Uses the mitmproxy CA cert for TLS verification when available
    (ground truth — no ssl_insecure shortcuts). Falls back to unverified
    only when the CA cert is not installed (e.g., host-side debugging).
    """
    verify = _CA_CERT if os.path.exists(_CA_CERT) else False
    client = httpx.Client(
        proxy=PROXY_URL,
        verify=verify,
        timeout=30.0,
    )
    yield client
    client.close()


@pytest.fixture
def clear_sinkhole(sinkhole):
    """Clear sinkhole before each test for isolation."""
    sinkhole.clear_requests()
    yield


@pytest.fixture(scope="session")
def wait_for_safeyolo(admin_client):
    """Ensure SafeYolo is ready (no sinkhole dependency)."""
    for attempt in range(60):
        try:
            resp = admin_client.get("/health")
            if resp.status_code == 200:
                break
        except httpx.RequestError:
            pass
        time.sleep(1)
    else:
        pytest.fail("SafeYolo admin API not ready after 60 seconds")
    yield


@pytest.fixture(scope="session")
def wait_for_services(sinkhole, wait_for_safeyolo):
    """Ensure all services are ready before tests run."""
    yield
