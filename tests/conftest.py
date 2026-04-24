"""
Pytest fixtures for SafeYolo addon tests.

Uses mitmproxy.test.tflow for creating test flows and
mitmproxy.test.taddons for testing addons with proper context.

Key pattern: Use taddons.context() to set up ctx.options properly.
See: https://snyk.io/advisor/python/mitmproxy/functions/mitmproxy.test.taddons.context
"""

import os
import sys
import tempfile
from pathlib import Path

# Set log path to temp directory BEFORE utils.py is imported
# (AUDIT_LOG_PATH is evaluated at module import time)
os.environ.setdefault(
    "SAFEYOLO_LOG_PATH",
    str(Path(tempfile.gettempdir()) / "safeyolo-test.jsonl"),
)

import pytest

# Post-#200-phase-5: addons live under the installed `safeyolo` package,
# not as top-level modules in `addons/`. Tests can import via
# `from safeyolo.mitm_addons.foo import ...`. We also keep the
# mitm_addons directory on sys.path so the older "bare" pattern
# (`from pid_writer import ...`) still resolves — matching how
# mitmproxy's `-s` loader exposes siblings at runtime.
_MITM_ADDONS_DIR = Path(__file__).parent.parent / "cli" / "src" / "safeyolo" / "mitm_addons"
sys.path.insert(0, str(_MITM_ADDONS_DIR))

# Project root remains on sys.path for `from pdp import ...` and
# `from audit_schema import ...` (both live at the repo root).
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def _reset_config_cache():
    """Reset the sensor_config cache between tests.

    `config_cache` is a module-level singleton (same as in production).
    Tests that mock PolicyClient behaviour need to start from a clean
    state, otherwise a prior test's stubbed config bleeds into the
    next. Invalidate before AND after so fresh mocks are picked up on
    the next `get()` and the singleton doesn't leak into later
    sessions either.
    """
    try:
        import safeyolo.core.config_cache as config_cache
        config_cache._cache._config = None
        config_cache._cache._callback_registered = False
    except ImportError:  # pragma: no cover — addon path issue
        pass
    yield
    try:
        import safeyolo.core.config_cache as config_cache
        config_cache._cache._config = None
        config_cache._cache._callback_registered = False
    except ImportError:
        pass


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
    """Initialize PDP with test baseline for credential_guard tests.

    Uses PDPCore as the authority - tests configure policy through PDP,
    not the legacy init_policy_engine() path.
    """
    from pdp import PolicyClientConfig, configure_policy_client, get_policy_client, reset_policy_client

    # Reset any existing client
    reset_policy_client()

    # Create test baseline
    baseline = tmp_path / "policy.yaml"
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

  # Default-allow for network requests (explicit catch-all required
  # since evaluate_request defaults to deny)
  - action: network:request
    resource: "*"
    effect: allow
    tier: explicit

budgets: {}
required: []
addons:
  credential_guard:
    enabled: true

credential_rules:
  - name: openai
    patterns:
      - "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"
      - "sk-proj-[a-zA-Z0-9_-]{80,}"
    allowed_hosts:
      - api.openai.com
  - name: anthropic
    patterns:
      - "sk-ant-api[a-zA-Z0-9-]{90,}"
    allowed_hosts:
      - api.anthropic.com
  - name: github
    patterns:
      - "gh[ps]_[a-zA-Z0-9]{36}"
    allowed_hosts:
      - api.github.com
      - github.com
""")

    # Configure PolicyClient with the test baseline
    config = PolicyClientConfig(baseline_path=baseline)
    configure_policy_client(config)
    client = get_policy_client()

    yield client

    # Cleanup
    reset_policy_client()


@pytest.fixture
def credential_guard(policy_engine_initialized):
    """Create a fresh CredentialGuard instance with proper mitmproxy context.

    Rules are loaded from PolicyClient via get_sensor_config() - no manual setup needed.
    """
    from credential_guard import CredentialGuard
    from mitmproxy.test import taddons

    addon = CredentialGuard()

    # Set up proper mitmproxy context with options
    with taddons.context(addon) as tctx:
        # Configure options
        tctx.options.credguard_block = True
        tctx.options.credguard_scan_urls = False
        tctx.options.credguard_scan_bodies = True  # Enable for integration tests

        # Test initialization - rules load from PolicyClient.get_sensor_config()
        addon.hmac_secret = b"test-secret-for-hmac-fingerprinting-in-tests"
        addon.config = {}
        addon.safe_headers_config = {}

        yield addon  # Keep context alive during test


@pytest.fixture
def network_guard(tmp_path):
    """Create a fresh NetworkGuard instance with blocking enabled and default policy."""
    from network_guard import NetworkGuard

    from pdp import PolicyClientConfig, configure_policy_client, reset_policy_client

    # Reset PDP client for fresh state
    reset_policy_client()

    # Create permissive baseline for network_guard tests
    baseline = tmp_path / "policy.yaml"
    baseline.write_text("""
metadata:
  version: "1.0"
permissions:
  - action: network:request
    resource: "*"
    effect: allow
budgets: {}
required: []
addons: {}
domains: {}
""")

    # Initialize PolicyClient with baseline
    config = PolicyClientConfig(baseline_path=baseline)
    configure_policy_client(config)

    addon = NetworkGuard()
    # Default to blocking mode for tests
    addon.should_block = lambda: True

    yield addon

    # Cleanup
    reset_policy_client()


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
