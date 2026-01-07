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
