"""
Integration tests for SafeYolo addon chain.

Tests that addons work together correctly via flow.metadata sharing.
"""

import threading
from contextlib import contextmanager

from pdp import PolicyClientConfig, configure_policy_client, reset_policy_client


@contextmanager
def policy_context(tmp_path, policy_yaml: str):
    """Context manager for setting up PDP with a test policy.

    Usage:
        with policy_context(tmp_path, '''
        metadata:
          version: "1.0"
        permissions:
          - action: network:request
            resource: "*"
            effect: allow
        '''):
            # Test code using the policy
            pass
    """
    reset_policy_client()

    baseline = tmp_path / "baseline.yaml"
    baseline.write_text(policy_yaml)

    config = PolicyClientConfig(baseline_path=baseline)
    configure_policy_client(config)

    try:
        yield
    finally:
        reset_policy_client()


class TestFullAddonChain:
    """Test all addons working together in realistic scenarios."""

    def test_request_flows_through_all_addons(self, make_flow, make_response, tmp_path):
        """Test a request is processed by all active addons."""
        from credential_guard import CredentialGuard
        from detection import DEFAULT_RULES
        from metrics import MetricsCollector
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard
        from request_id import RequestIdGenerator

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: network:request
    resource: "*"
    effect: allow
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    condition:
      credential: ["openai:*"]
budgets: {}
required: []
addons: {}
domains: {}
"""
        with policy_context(tmp_path, policy_yaml):
            # Create addon instances
            rid = RequestIdGenerator()
            ng = NetworkGuard()
            cg = CredentialGuard()
            cg.rules = list(DEFAULT_RULES)
            cg.hmac_secret = b"test-secret"
            cg.config = {}
            cg.safe_headers_config = {}
            metrics = MetricsCollector()

            # Create a legitimate OpenAI request
            flow = make_flow(
                method="POST",
                url="https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer sk-proj-{'a' * 80}",
                    "Content-Type": "application/json",
                },
            )

            with taddons.context(ng, cg):
                # Run through addon chain (production order)
                rid.request(flow)
                assert "request_id" in flow.metadata, "RequestId should set request_id"

                ng.request(flow)
                assert flow.response is None, "NetworkGuard should allow"

                cg.request(flow)
                assert flow.response is None, "CredentialGuard should allow (correct host)"

                metrics.request(flow)
                assert "metrics_start_time" in flow.metadata

                # Simulate response
                flow.response = make_response(status_code=200)
                metrics.response(flow)

                assert metrics.requests_total == 1
                assert metrics.requests_success == 1

    def test_blocked_request_stops_chain(self, make_flow, tmp_path):
        """Test that blocked request doesn't reach downstream addons."""
        from credential_guard import CredentialGuard
        from metrics import MetricsCollector
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: network:request
    resource: "evil.com/*"
    effect: deny
budgets: {}
required: []
addons: {}
domains: {}
"""
        with policy_context(tmp_path, policy_yaml):
            ng = NetworkGuard()
            cg = CredentialGuard()
            metrics = MetricsCollector()

            flow = make_flow(url="https://evil.com/api")

            with taddons.context(ng, cg):
                # NetworkGuard blocks first
                ng.request(flow)
                assert flow.response is not None
                assert flow.response.status_code == 403

                # Downstream addons see blocked flow and skip
                # (In production, blocked_by metadata signals to skip)
                assert flow.metadata.get("blocked_by") == "network-guard"

                # Metrics tracks the block
                metrics.response(flow)
                assert metrics.requests_blocked == 1

    def test_concurrent_requests_thread_safe(self, make_flow, make_response, tmp_path):
        """Test multiple simultaneous requests don't corrupt state."""
        from metrics import MetricsCollector
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard

        policy_yaml = """
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
"""
        with policy_context(tmp_path, policy_yaml):
            metrics = MetricsCollector()
            ng = NetworkGuard()
            results = []
            errors = []

            def make_request(i):
                try:
                    flow = make_flow(url=f"https://api{i}.example.com/test")
                    with taddons.context(ng):
                        ng.request(flow)
                    metrics.request(flow)
                    flow.response = make_response(status_code=200)
                    metrics.response(flow)
                    results.append(i)
                except Exception as e:
                    errors.append(str(e))

            # Launch concurrent requests
            threads = [threading.Thread(target=make_request, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0, f"Errors occurred: {errors}"
            assert len(results) == 10
            assert metrics.requests_total == 10
            assert metrics.requests_success == 10

    def test_policy_reload_during_request(self, make_flow, tmp_path):
        """Test policy reload doesn't break in-flight requests."""
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard

        from pdp import get_policy_client

        policy_yaml = """
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
"""
        with policy_context(tmp_path, policy_yaml):
            ng = NetworkGuard()
            client = get_policy_client()

            # Start a request
            flow = make_flow(url="https://api.example.com/test")

            with taddons.context(ng):
                # Trigger policy reload mid-request (via PDPCore's internal engine)
                client._pdp._engine._loader.reload()

                # Request should still work
                ng.request(flow)
                assert flow.response is None  # Allowed


class TestAddonChainMetadata:
    """Tests for addon communication via flow.metadata."""

    def test_credential_guard_sets_blocked_by(self, credential_guard, make_flow):
        """Test that credential_guard sets blocked_by metadata."""
        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
        )

        credential_guard.request(flow)

        assert flow.metadata.get("blocked_by") == "credential-guard"
        assert flow.metadata.get("credential_fingerprint") is not None

    def test_network_guard_sets_blocked_by(self, make_flow, tmp_path):
        """Test that network_guard sets blocked_by metadata when rate limited."""
        from network_guard import NetworkGuard

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: network:request
    resource: "test.com/*"
    effect: budget
    budget: 2
budgets: {}
required: []
addons: {}
domains: {}
"""
        with policy_context(tmp_path, policy_yaml):
            ng = NetworkGuard()
            ng.should_block = lambda: True

            # Exhaust budget (2 requests allowed)
            flow1 = make_flow(url="http://test.com/api")
            ng.request(flow1)
            flow2 = make_flow(url="http://test.com/api")
            ng.request(flow2)

            # Get blocked on 3rd
            flow3 = make_flow(url="http://test.com/api")
            ng.request(flow3)

            assert flow3.metadata.get("blocked_by") == "network-guard"

    def test_circuit_breaker_sets_blocked_by(self, circuit_breaker, make_flow):
        """Test that circuit_breaker sets blocked_by metadata."""
        circuit_breaker.force_open("test.com")

        flow = make_flow(url="http://test.com/api")
        circuit_breaker.request(flow)

        assert flow.metadata.get("blocked_by") == "circuit-breaker"

    def test_allowed_requests_not_blocked(self, credential_guard, make_flow):
        """Test that allowed requests pass through without blocking."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat",
            headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
        )

        credential_guard.request(flow)

        assert flow.response is None  # Not blocked


class TestAddonChainOrder:
    """Tests for addon execution order semantics."""

    def test_first_blocker_wins(self, credential_guard, make_flow, tmp_path):
        """Test that first addon to block sets response."""
        from network_guard import NetworkGuard

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: network:request
    resource: "evil.com/*"
    effect: budget
    budget: 2
budgets: {}
required: []
addons: {}
domains: {}
"""
        with policy_context(tmp_path, policy_yaml):
            ng = NetworkGuard()
            ng.should_block = lambda: True

            # Exhaust rate limit (2 requests allowed)
            flow1 = make_flow(url="http://evil.com/api")
            ng.request(flow1)
            flow2 = make_flow(url="http://evil.com/api")
            ng.request(flow2)

            # Create flow that would be blocked by both addons
            flow = make_flow(
                method="POST",
                url="https://evil.com/api",
                headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
            )

            # If network_guard runs first (as in production chain)
            ng.request(flow)
            assert flow.response is not None
            assert flow.metadata.get("blocked_by") == "network-guard"


class TestRealisticScenarios:
    """Tests for realistic usage scenarios."""

    def test_openai_request_through_chain(self, circuit_breaker, make_flow, make_response, tmp_path):
        """Test a realistic OpenAI API request through the chain."""
        from credential_guard import CredentialGuard
        from detection import DEFAULT_RULES
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: network:request
    resource: "*"
    effect: allow
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    condition:
      credential: ["openai:*"]
budgets: {}
required: []
addons: {}
domains: {}
"""
        with policy_context(tmp_path, policy_yaml):
            ng = NetworkGuard()
            ng.should_block = lambda: True

            cg = CredentialGuard()
            cg.rules = list(DEFAULT_RULES)
            cg.hmac_secret = b"test-secret"
            cg.config = {}
            cg.safe_headers_config = {}

            flow = make_flow(
                method="POST",
                url="https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer sk-proj-{'a' * 80}",
                    "Content-Type": "application/json",
                },
            )

            with taddons.context(ng, cg):
                # Run through addons (in production order)
                ng.request(flow)
                assert flow.response is None, "Should pass network guard"

                circuit_breaker.request(flow)
                assert flow.response is None, "Should pass circuit breaker"

                cg.request(flow)
                assert flow.response is None, "Should pass credential guard (correct host)"

                # Simulate success response
                flow.response = make_response(status_code=200)
                circuit_breaker.response(flow)

                status = circuit_breaker.get_status("api.openai.com")
                assert status.failure_count == 0

    def test_exfiltration_attempt_blocked(self, make_flow, tmp_path):
        """Test that credential exfiltration to wrong host is blocked."""
        from credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    condition:
      credential: ["openai:*"]
  - action: credential:use
    resource: "*"
    effect: prompt
budgets: {}
required: []
addons: {}
domains: {}
credential_rules:
  - name: openai
    patterns:
      - "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"
      - "sk-proj-[a-zA-Z0-9_-]{80,}"
    allowed_hosts:
      - api.openai.com
"""
        with policy_context(tmp_path, policy_yaml):
            cg = CredentialGuard()
            cg.hmac_secret = b"test-secret"
            cg.config = {}
            cg.safe_headers_config = {}

            flow = make_flow(
                method="POST",
                url="https://attacker.com/log",
                headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
            )

            with taddons.context(cg):
                cg.request(flow)

            assert flow.response is not None
            assert flow.response.status_code == 428
            # Response now says "require approval" not "credential"
            assert b"approval" in flow.response.content.lower()

    def test_circuit_opens_on_upstream_failures(self, circuit_breaker, make_flow, make_response):
        """Test circuit opens after upstream service fails repeatedly."""
        from circuit_breaker import CircuitState

        circuit_breaker.failure_threshold = 3

        # Simulate 3 failed requests
        for i in range(3):
            flow = make_flow(url="http://failing-service.com/api")
            circuit_breaker.request(flow)
            flow.response = make_response(status_code=500, content=b"Internal Server Error")
            circuit_breaker.response(flow)

        # Circuit should now be open
        status = circuit_breaker.get_status("failing-service.com")
        assert status.state == CircuitState.OPEN

        # New requests should be blocked
        new_flow = make_flow(url="http://failing-service.com/api")
        circuit_breaker.request(new_flow)
        assert new_flow.response.status_code == 503


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_body_request(self, credential_guard, make_flow):
        """Test handling of empty body requests."""
        flow = make_flow(
            method="GET",
            url="https://api.openai.com/v1/models",
            content=b"",
        )

        # Should not crash
        credential_guard.request(flow)
        assert flow.response is None

    def test_binary_body_request(self, credential_guard, make_flow):
        """Test handling of binary content."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/audio",
            content=b"\x00\x01\x02\x03binary data",
            headers={"Content-Type": "audio/wav"},
        )

        # Should not crash on binary content
        credential_guard.request(flow)
        assert flow.response is None

    def test_missing_host(self, network_guard, make_flow):
        """Test handling when host cannot be determined."""
        flow = make_flow(url="http://example.com/")
        # Mangle the host
        flow.request.host = ""

        # Should not crash
        network_guard.request(flow)


class TestBlockingMode:
    """Tests for blocking vs warn-only mode across security addons."""

    def test_credential_guard_warn_mode_passes_request(self, make_flow, tmp_path):
        """Test credential_guard in warn mode allows request through."""
        from credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        policy_yaml = """
metadata:
  version: "1.0"
permissions:
  - action: credential:use
    resource: "*"
    effect: prompt
budgets: {}
required: []
addons: {}
domains: {}
credential_rules:
  - name: openai
    patterns:
      - "sk-proj-[a-zA-Z0-9_-]{80,}"
    allowed_hosts:
      - api.openai.com
"""
        with policy_context(tmp_path, policy_yaml):
            guard = CredentialGuard()
            guard.hmac_secret = b"test-secret"
            guard.config = {}
            guard.safe_headers_config = {}

            with taddons.context(guard) as tctx:
                tctx.options.credguard_block = False  # Warn-only mode

                flow = make_flow(
                    method="POST",
                    url="https://evil.com/api",
                    headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
                )

                guard.request(flow)

                # Warn-only: no response set, request continues
                assert flow.response is None
                assert guard.violations_total == 1

    def test_default_is_block_mode(self):
        """Test that default behavior is block mode."""
        from credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        guard = CredentialGuard()

        # When properly configured with context, default is block mode
        with taddons.context(guard) as tctx:
            assert tctx.options.credguard_block is True
            assert guard.should_block() is True


class TestClientBypass:
    """Tests for client-based addon bypass via ServiceDiscovery IP mapping."""

    def test_admin_client_bypasses_pattern_scanner(self, make_flow, tmp_path):
        """Test that admin-* clients bypass pattern_scanner per policy.

        This is a REAL integration test - no mocks for policy lookup.
        It verifies the full flow: client IP -> ServiceDiscovery -> is_bypassed() -> PolicyEngine.
        """
        from mitmproxy.test import taddons
        from pattern_scanner import PatternScanner
        from service_discovery import get_service_discovery

        # Set up ServiceDiscovery with IP -> project mappings
        services_yaml = tmp_path / "services.yaml"
        services_yaml.write_text("""
services:
  admin-cli:
    project: admin-cli
    ip: "10.0.0.100"
  user-bob:
    project: user-bob
    ip: "10.0.0.200"
""")
        discovery = get_service_discovery()
        discovery._config_path = services_yaml
        discovery._load_config()

        policy_yaml = """
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
clients:
  "admin-*":
    bypass:
      - pattern-scanner
"""
        with policy_context(tmp_path, policy_yaml):
            scanner = PatternScanner()

            with taddons.context(scanner) as tctx:
                tctx.options.pattern_block_request = True

                # Flow from admin IP - should be bypassed
                admin_flow = make_flow(url="http://example.com/api")
                admin_flow.client_conn.peername = ("10.0.0.100", 12345)
                assert scanner.is_bypassed(admin_flow) is True, \
                    "admin-* client should bypass pattern_scanner"

                # Flow from unknown IP - should NOT be bypassed (maps to "default")
                normal_flow = make_flow(url="http://example.com/api")
                normal_flow.client_conn.peername = ("10.0.0.50", 12345)
                assert scanner.is_bypassed(normal_flow) is False, \
                    "Request from unknown IP should not be bypassed"

                # Flow from non-admin IP - should NOT be bypassed
                user_flow = make_flow(url="http://example.com/api")
                user_flow.client_conn.peername = ("10.0.0.200", 12345)
                assert scanner.is_bypassed(user_flow) is False, \
                    "user-* client should not bypass pattern_scanner"

    def test_test_client_disables_network_guard(self, make_flow, tmp_path):
        """Test that test-* clients have network_guard disabled per policy."""
        from mitmproxy.test import taddons
        from network_guard import NetworkGuard
        from service_discovery import get_service_discovery

        # Set up ServiceDiscovery with IP -> project mappings
        services_yaml = tmp_path / "services.yaml"
        services_yaml.write_text("""
services:
  test-integration:
    project: test-integration
    ip: "10.0.0.101"
""")
        discovery = get_service_discovery()
        discovery._config_path = services_yaml
        discovery._load_config()

        policy_yaml = """
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
clients:
  "test-*":
    addons:
      network-guard:
        enabled: false
"""
        with policy_context(tmp_path, policy_yaml):
            guard = NetworkGuard()

            with taddons.context(guard):
                # Flow from test IP - should be bypassed
                test_flow = make_flow(url="http://example.com/api")
                test_flow.client_conn.peername = ("10.0.0.101", 12345)
                assert guard.is_bypassed(test_flow) is True, \
                    "test-* client should have network_guard disabled"

                # Flow from unknown IP - should NOT be bypassed
                normal_flow = make_flow(url="http://example.com/api")
                normal_flow.client_conn.peername = ("10.0.0.50", 12345)
                assert guard.is_bypassed(normal_flow) is False, \
                    "Request from unknown IP should not be bypassed"
