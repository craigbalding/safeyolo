"""
Pytest fixtures for SafeYolo addon tests.

Uses mitmproxy.test.tflow for creating test flows and
mitmproxy.test.taddons for testing addons with proper context.

Key pattern: Use taddons.context() to set up ctx.options properly.
See: https://snyk.io/advisor/python/mitmproxy/functions/mitmproxy.test.taddons.context
"""

import sys
from pathlib import Path

import pytest

# Add addons directory to path for standalone imports
# This matches how mitmproxy loads addons via -s flag
addons_dir = Path(__file__).parent.parent / "addons"
sys.path.insert(0, str(addons_dir))

# Also add project root for any remaining package imports during transition
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
def policy_engine_initialized(tmp_path):
    """Initialize PolicyEngine with test baseline for credential_guard tests."""
    import policy_engine as pe
    from policy_engine import init_policy_engine

    # Save existing engine
    old_engine = pe._policy_engine

    # Create test baseline
    baseline = tmp_path / "baseline.yaml"
    baseline.write_text("""
metadata:
  version: "1.0"
  description: "Test baseline"

permissions:
  # OpenAI credentials to OpenAI endpoints
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit
    condition:
      credential: ["openai:*"]

  # Unknown destinations require approval
  - action: credential:use
    resource: "*"
    effect: prompt
    tier: explicit

budgets: {}
required: []
addons:
  credential_guard:
    enabled: true
""")

    engine = init_policy_engine(baseline_path=baseline)
    yield engine

    # Restore
    pe._policy_engine = old_engine


@pytest.fixture
def credential_guard(policy_engine_initialized):
    """Create a fresh CredentialGuard instance with proper mitmproxy context."""
    from credential_guard import DEFAULT_RULES, CredentialGuard
    from mitmproxy.test import taddons

    addon = CredentialGuard()

    # Set up proper mitmproxy context with options
    with taddons.context(addon) as tctx:
        # Configure options
        tctx.options.credguard_block = True
        tctx.options.credguard_scan_urls = False
        tctx.options.credguard_scan_bodies = True  # Enable for integration tests

        # Load rules
        addon.rules = list(DEFAULT_RULES)

        # v2 initialization
        addon.hmac_secret = b"test-secret-for-hmac-fingerprinting-in-tests"
        addon.config = {}
        addon.safe_headers_config = {}
        # default_policy already initialized in __init__

        yield addon  # Keep context alive during test


@pytest.fixture
def network_guard():
    """Create a fresh NetworkGuard instance with blocking enabled."""
    from network_guard import NetworkGuard

    addon = NetworkGuard()
    # Default to blocking mode for tests
    addon.should_block = lambda: True
    return addon


@pytest.fixture
def circuit_breaker():
    """Create a fresh CircuitBreaker instance."""
    from circuit_breaker import CircuitBreaker

    addon = CircuitBreaker()
    return addon


@pytest.fixture
def make_flow_with_request_id(make_flow):
    """Factory for creating test flows with request_id pre-set.

    Simulates what request_id.py addon does in production.
    """
    import time

    def _make_flow(request_id: str = "req-test123abc", **kwargs):
        flow = make_flow(**kwargs)
        flow.metadata["request_id"] = request_id
        flow.metadata["start_time"] = time.time()
        return flow

    return _make_flow
