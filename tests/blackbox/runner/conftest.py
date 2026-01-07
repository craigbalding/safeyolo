"""Pytest fixtures for black box tests."""

import os
import time

import httpx
import pytest
from sinkhole_client import SinkholeClient

# Environment configuration
PROXY_URL = os.environ.get("PROXY_URL", "http://safeyolo:8080")
ADMIN_URL = os.environ.get("ADMIN_URL", "http://safeyolo:9090")
ADMIN_TOKEN = os.environ.get("ADMIN_API_TOKEN", "test-token-for-blackbox-tests")
SINKHOLE_API = os.environ.get("SINKHOLE_API", "http://sinkhole:9999")

# =============================================================================
# Test credentials - MUST match production detection patterns
# =============================================================================
# OpenAI pattern: sk-proj-[a-zA-Z0-9_-]{80,}
TEST_OPENAI_KEY = "sk-proj-" + "a1b2c3d4e5f6g7h8i9j0" * 4  # 80+ chars after prefix

# Anthropic pattern: sk-ant-api[a-zA-Z0-9-]{90,}
TEST_ANTHROPIC_KEY = "sk-ant-api03-" + "a1b2c3d4e5f6g7h8i9j0" * 5  # 90+ chars after prefix

# GitHub pattern: gh[ps]_[a-zA-Z0-9]{36}
TEST_GITHUB_TOKEN = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"  # 36 chars after prefix


@pytest.fixture(scope="session")
def sinkhole():
    """Sinkhole client for request inspection."""
    client = SinkholeClient(SINKHOLE_API)
    client.wait_for_ready(timeout=60)
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

    IMPORTANT: SSL verification is disabled because we're using mitmproxy's
    dynamically generated certificates. In the test network, this is safe
    because all traffic goes through the controlled sinkhole.
    """
    client = httpx.Client(
        proxy=PROXY_URL,
        verify=False,  # Trust mitmproxy CA
        timeout=30.0,
    )
    yield client
    client.close()


@pytest.fixture(autouse=True)
def clear_sinkhole(sinkhole):
    """Clear sinkhole before each test for isolation."""
    sinkhole.clear_requests()
    yield


@pytest.fixture(scope="session")
def wait_for_services(sinkhole, admin_client):
    """Ensure all services are ready before tests run."""
    # Sinkhole ready (handled by sinkhole fixture)

    # SafeYolo admin API ready
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
