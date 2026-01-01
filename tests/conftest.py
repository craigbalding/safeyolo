"""
Pytest fixtures for SafeYolo addon tests.

Uses mitmproxy.test.tflow for creating test flows and
mitmproxy.test.taddons for testing addons with proper context.

Key pattern: Use taddons.context() to set up ctx.options properly.
See: https://snyk.io/advisor/python/mitmproxy/functions/mitmproxy.test.taddons.context
"""

import pytest
import sys
from pathlib import Path

# Add project root to path so we can import addons as a package
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def make_flow():
    """Factory for creating test flows."""
    from mitmproxy.test import tflow

    def _make_flow(
        method: str = "GET",
        url: str = "http://example.com/",
        content: bytes | str = b"",
        headers: dict | None = None,
    ):
        """Create a test flow with customized request."""
        flow = tflow.tflow()
        flow.request.method = method
        flow.request.url = url

        if isinstance(content, str):
            content = content.encode()
        flow.request.content = content

        if headers:
            for name, value in headers.items():
                flow.request.headers[name] = value

        return flow

    return _make_flow


@pytest.fixture
def make_response():
    """Factory for creating test responses."""
    from mitmproxy import http

    def _make_response(
        status_code: int = 200,
        content: bytes | str = b"",
        headers: dict | None = None,
    ):
        """Create a test HTTP response."""
        if isinstance(content, str):
            content = content.encode()

        return http.Response.make(
            status_code,
            content,
            headers or {},
        )

    return _make_response


@pytest.fixture
def taddons_ctx():
    """Provide taddons.context for tests that need ctx.options."""
    from mitmproxy.test import taddons
    return taddons.context


@pytest.fixture
def credential_guard():
    """Create a fresh CredentialGuard instance with blocking enabled."""
    from addons.credential_guard import CredentialGuard, DEFAULT_RULES

    addon = CredentialGuard()
    addon.rules = list(DEFAULT_RULES)
    # Default to blocking mode for tests (production default is warn-only)
    addon._should_block = lambda: True
    return addon


@pytest.fixture
def rate_limiter():
    """Create a fresh RateLimiter instance with blocking enabled."""
    from addons.rate_limiter import RateLimiter

    addon = RateLimiter()
    # Default to blocking mode for tests (production default is warn-only)
    addon._should_block = lambda: True
    return addon


@pytest.fixture
def circuit_breaker():
    """Create a fresh CircuitBreaker instance."""
    from addons.circuit_breaker import CircuitBreaker

    addon = CircuitBreaker()
    return addon
