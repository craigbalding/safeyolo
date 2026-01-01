"""
Tests for circuit_breaker.py addon.

Tests circuit state transitions, failure detection, and recovery.
"""

import pytest
import time


class TestCircuitStates:
    """Tests for circuit state machine."""

    def test_starts_closed(self, circuit_breaker):
        """Test that circuits start in closed state."""
        from addons.circuit_breaker import CircuitState

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.CLOSED
        assert status.failure_count == 0

    def test_opens_after_threshold(self, circuit_breaker):
        """Test that circuit opens after failure threshold."""
        from addons.circuit_breaker import CircuitState

        circuit_breaker.failure_threshold = 3

        # Record failures up to threshold
        circuit_breaker.record_failure("test.com", "error 1")
        circuit_breaker.record_failure("test.com", "error 2")

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.CLOSED  # Not yet

        circuit_breaker.record_failure("test.com", "error 3")

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.OPEN

    def test_half_open_after_timeout(self, circuit_breaker):
        """Test that circuit transitions to half-open after timeout."""
        from addons.circuit_breaker import CircuitState

        circuit_breaker.failure_threshold = 1
        circuit_breaker.timeout_seconds = 0.1  # 100ms for testing

        # Open the circuit
        circuit_breaker.record_failure("test.com", "error")
        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.OPEN

        # Wait for timeout
        time.sleep(0.15)

        # Should transition to half-open
        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.HALF_OPEN

    def test_closes_after_success_threshold(self, circuit_breaker):
        """Test that circuit closes after success threshold in half-open."""
        from addons.circuit_breaker import CircuitState

        circuit_breaker.failure_threshold = 1
        circuit_breaker.success_threshold = 2
        circuit_breaker.timeout_seconds = 0.05

        # Open the circuit
        circuit_breaker.record_failure("test.com", "error")
        time.sleep(0.1)  # Wait for half-open

        # Record successes
        circuit_breaker.record_success("test.com")
        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.HALF_OPEN  # Not yet closed

        circuit_breaker.record_success("test.com")
        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.CLOSED

    def test_reopens_on_failure_in_half_open(self, circuit_breaker):
        """Test that circuit reopens on failure during half-open."""
        from addons.circuit_breaker import CircuitState

        circuit_breaker.failure_threshold = 1
        circuit_breaker.timeout_seconds = 0.05

        # Open the circuit
        circuit_breaker.record_failure("test.com", "error 1")
        time.sleep(0.1)  # Wait for half-open

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.HALF_OPEN

        # Fail during half-open
        circuit_breaker.record_failure("test.com", "error 2")

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.OPEN
        assert status.failure_streak == 1  # Streak incremented


class TestCircuitBreakerBlocking:
    """Tests for request blocking behavior."""

    def test_allows_requests_when_closed(self, circuit_breaker, make_flow):
        """Test that closed circuit allows requests."""
        flow = make_flow(url="http://test.com/api")

        allowed, status = circuit_breaker.should_allow_request("test.com")
        assert allowed is True

    def test_blocks_requests_when_open(self, circuit_breaker, make_flow):
        """Test that open circuit blocks requests."""
        from addons.circuit_breaker import CircuitState

        # Force open
        circuit_breaker.force_open("test.com")

        allowed, status = circuit_breaker.should_allow_request("test.com")
        assert allowed is False
        assert status.state == CircuitState.OPEN

    def test_request_hook_blocks_with_503(self, circuit_breaker, make_flow):
        """Test that request hook returns 503 when circuit is open."""
        circuit_breaker.force_open("test.com")

        flow = make_flow(url="http://test.com/api")
        circuit_breaker.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 503
        assert "Retry-After" in flow.response.headers
        assert flow.metadata.get("blocked_by") == "circuit-breaker"

    def test_limited_requests_in_half_open(self, circuit_breaker, make_flow):
        """Test that half-open allows limited requests."""
        circuit_breaker.failure_threshold = 1
        circuit_breaker.timeout_seconds = 0.05
        circuit_breaker.half_open_max_requests = 2

        # Open then wait for half-open
        circuit_breaker.record_failure("test.com", "error")
        time.sleep(0.1)

        # First two requests allowed in half-open
        allowed1, _ = circuit_breaker.should_allow_request("test.com")
        allowed2, _ = circuit_breaker.should_allow_request("test.com")
        assert allowed1 is True
        assert allowed2 is True

        # Third request blocked
        allowed3, _ = circuit_breaker.should_allow_request("test.com")
        assert allowed3 is False


class TestResponseHandling:
    """Tests for response-based success/failure recording."""

    def test_records_failure_on_5xx(self, circuit_breaker, make_flow, make_response):
        """Test that 5xx responses record failures."""
        flow = make_flow(url="http://test.com/api")
        flow.response = make_response(status_code=500)

        circuit_breaker.response(flow)

        status = circuit_breaker.get_status("test.com")
        assert status.failure_count == 1

    def test_skips_proxy_blocked_requests(self, circuit_breaker, make_flow, make_response):
        """Test that proxy-blocked requests don't count as upstream failures."""
        flow = make_flow(url="http://test.com/api")
        flow.response = make_response(status_code=429)  # Would normally be a failure
        flow.metadata["blocked_by"] = "rate-limiter"  # Blocked by another addon

        circuit_breaker.response(flow)

        status = circuit_breaker.get_status("test.com")
        assert status.failure_count == 0  # Should NOT count as upstream failure

    def test_records_failure_on_429(self, circuit_breaker, make_flow, make_response):
        """Test that 429 responses record failures."""
        flow = make_flow(url="http://test.com/api")
        flow.response = make_response(status_code=429)

        circuit_breaker.response(flow)

        status = circuit_breaker.get_status("test.com")
        assert status.failure_count == 1

    def test_records_success_on_2xx(self, circuit_breaker, make_flow, make_response):
        """Test that 2xx responses record success."""
        # First create some failure state
        circuit_breaker.record_failure("test.com", "previous error")

        flow = make_flow(url="http://test.com/api")
        flow.response = make_response(status_code=200)

        circuit_breaker.response(flow)

        status = circuit_breaker.get_status("test.com")
        # Failure count should decay
        assert status.failure_count == 0


class TestExponentialBackoff:
    """Tests for exponential backoff on repeated failures."""

    def test_timeout_increases_on_reopen(self, circuit_breaker):
        """Test that timeout increases with failure streak."""
        circuit_breaker.failure_threshold = 1
        circuit_breaker.timeout_seconds = 1.0
        circuit_breaker.use_exponential_backoff = True
        circuit_breaker.backoff_multiplier = 2.0
        circuit_breaker.jitter_factor = 0  # Disable jitter for predictability

        # First open
        circuit_breaker.record_failure("test.com", "error 1")
        status = circuit_breaker.get_status("test.com")
        assert status.current_timeout == 1.0  # Base timeout

        # Force to half-open, then fail again
        circuit_breaker._state.get("test.com")["opened_at"] = 0  # Force timeout
        circuit_breaker.get_status("test.com")  # Trigger half-open
        circuit_breaker.record_failure("test.com", "error 2")

        status = circuit_breaker.get_status("test.com")
        assert status.failure_streak == 1
        # With backoff: 1.0 * 2^1 = 2.0
        assert 1.5 < status.current_timeout < 2.5


class TestManualControl:
    """Tests for manual circuit control."""

    def test_reset_closes_circuit(self, circuit_breaker):
        """Test that reset closes an open circuit."""
        from addons.circuit_breaker import CircuitState

        circuit_breaker.force_open("test.com")
        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.OPEN

        circuit_breaker.reset("test.com")

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.CLOSED
        assert status.failure_count == 0

    def test_force_open_works(self, circuit_breaker):
        """Test that force_open immediately opens circuit."""
        from addons.circuit_breaker import CircuitState

        circuit_breaker.force_open("healthy.com")

        status = circuit_breaker.get_status("healthy.com")
        assert status.state == CircuitState.OPEN


class TestStats:
    """Tests for statistics tracking."""

    def test_stats_tracking(self, circuit_breaker):
        """Test that stats are tracked correctly."""
        circuit_breaker.failure_threshold = 1
        circuit_breaker.timeout_seconds = 0.05

        assert circuit_breaker.opens_total == 0
        assert circuit_breaker.recoveries_total == 0

        # Open circuit
        circuit_breaker.record_failure("test.com", "error")
        assert circuit_breaker.opens_total == 1

        # Wait for half-open
        time.sleep(0.1)
        circuit_breaker.get_status("test.com")  # Trigger transition
        assert circuit_breaker.half_opens_total == 1

        # Recover
        circuit_breaker.success_threshold = 1
        circuit_breaker.record_success("test.com")
        assert circuit_breaker.recoveries_total == 1

    def test_get_stats_returns_dict(self, circuit_breaker):
        """Test that get_stats returns proper structure."""
        stats = circuit_breaker.get_stats()

        assert "enabled" in stats
        assert "failure_threshold" in stats
        assert "timeout_seconds" in stats
        assert "checks_total" in stats
        assert "opens_total" in stats
        assert "domains" in stats
