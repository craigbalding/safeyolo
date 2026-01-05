"""
Tests for circuit_breaker.py addon.

Tests circuit state transitions, failure detection, and recovery.
"""

import time


class TestCircuitStates:
    """Tests for circuit state machine."""

    def test_starts_closed(self, circuit_breaker):
        """Test that circuits start in closed state."""
        from circuit_breaker import CircuitState

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.CLOSED
        assert status.failure_count == 0

    def test_opens_after_threshold(self, circuit_breaker):
        """Test that circuit opens after failure threshold."""
        from circuit_breaker import CircuitState

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
        from circuit_breaker import CircuitState

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
        from circuit_breaker import CircuitState

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
        from circuit_breaker import CircuitState

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
        _ = make_flow(url="http://test.com/api")  # Fixture invoked for setup

        allowed, status = circuit_breaker.should_allow_request("test.com")
        assert allowed is True

    def test_blocks_requests_when_open(self, circuit_breaker, make_flow):
        """Test that open circuit blocks requests."""
        from circuit_breaker import CircuitState

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
        from circuit_breaker import CircuitState

        circuit_breaker.force_open("test.com")
        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.OPEN

        circuit_breaker.reset("test.com")

        status = circuit_breaker.get_status("test.com")
        assert status.state == CircuitState.CLOSED
        assert status.failure_count == 0

    def test_force_open_works(self, circuit_breaker):
        """Test that force_open immediately opens circuit."""
        from circuit_breaker import CircuitState

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


class TestCircuitBreakerStatePersistence:
    """Tests for circuit breaker state file persistence across restarts."""

    def test_saves_state_to_file(self, tmp_path):
        """Verify circuit states are saved to file."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "circuit_breaker_state.json"
        state = InMemoryCircuitState(state_file=state_file)

        # Create some circuit states
        state.set("api.example.com", {"state": "open", "failure_count": 5})
        state.set("api.openai.com", {"state": "closed", "failure_count": 0})

        # Stop background thread to avoid race condition with manual save
        state.stop_snapshots()

        # Verify file exists and contains states (final save on stop)
        assert state_file.exists()

        import json
        with open(state_file) as f:
            data = json.load(f)

        assert "states" in data
        assert "saved_at" in data
        assert "api.example.com" in data["states"]
        assert "api.openai.com" in data["states"]
        assert data["states"]["api.example.com"]["state"] == "open"

    def test_loads_state_on_startup(self, tmp_path):
        """Verify circuit states are restored from file."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "circuit_breaker_state.json"

        # First instance - create state
        state1 = InMemoryCircuitState(state_file=state_file)
        state1.set("test.com", {"state": "open", "failure_count": 3, "opened_at": 1234567890.0})
        state1._save_state()
        state1.stop_snapshots()

        # Second instance - should load state
        state2 = InMemoryCircuitState(state_file=state_file)

        loaded_data = state2.get("test.com")
        assert loaded_data["state"] == "open"
        assert loaded_data["failure_count"] == 3

    def test_atomic_write_cleanup(self, tmp_path):
        """Verify temp files are cleaned up after atomic writes."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "circuit_breaker_state.json"
        state = InMemoryCircuitState(state_file=state_file)

        # Trigger multiple saves
        for i in range(5):
            state._save_state()

        # No temp files should exist
        temp_files = list(tmp_path.glob("*.tmp"))
        assert len(temp_files) == 0

    def test_snapshot_worker_starts_and_stops(self, tmp_path):
        """Verify snapshot worker lifecycle."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "circuit_breaker_state.json"
        state = InMemoryCircuitState(state_file=state_file)

        assert state._worker is not None

        # Stop snapshots
        state.stop_snapshots()

        # Worker should be stopped and set to None
        assert state._worker is None

        # Final state should be saved
        assert state_file.exists()

    def test_graceful_shutdown_saves_final_state(self, tmp_path):
        """Verify final state is saved on shutdown."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "circuit_breaker_state.json"

        state = InMemoryCircuitState(state_file=state_file)
        state.set("final.com", {"state": "half_open", "success_count": 1})

        # Stop snapshots (simulates shutdown)
        state.stop_snapshots()

        # Verify state was saved
        import json
        with open(state_file) as f:
            data = json.load(f)

        assert "final.com" in data["states"]

    def test_handles_missing_state_file_gracefully(self, tmp_path):
        """Verify state starts empty if file doesn't exist."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "nonexistent.json"
        state = InMemoryCircuitState(state_file=state_file)

        # Should start with empty states
        assert len(state.all_domains()) == 0

    def test_handles_corrupted_state_file_gracefully(self, tmp_path):
        """Verify state handles corrupted file gracefully."""
        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "corrupted.json"
        state_file.write_text("not valid json {{{")

        state = InMemoryCircuitState(state_file=state_file)

        # Should start with empty states despite corrupt file
        assert len(state.all_domains()) == 0

    def test_circuit_breaker_addon_cleanup_on_done(self, tmp_path):
        """Verify CircuitBreaker addon calls stop_snapshots on done()."""
        from circuit_breaker import CircuitBreaker, InMemoryCircuitState

        circuit_breaker = CircuitBreaker()

        # Create state with file
        state_file = tmp_path / "state.json"
        circuit_breaker._state = InMemoryCircuitState(state_file=state_file)

        assert circuit_breaker._state._worker is not None

        # Call done() (simulates mitmproxy shutdown)
        circuit_breaker.done()

        # Worker should be stopped and set to None
        assert circuit_breaker._state._worker is None

    def test_concurrent_access_thread_safety(self, tmp_path):
        """Verify concurrent access to state is thread-safe."""
        import threading

        from circuit_breaker import InMemoryCircuitState

        state_file = tmp_path / "concurrent.json"
        state_obj = InMemoryCircuitState(state_file=state_file)

        # Spawn multiple threads making concurrent updates
        def worker(domain_id):
            for i in range(10):
                state_obj.set(f"domain-{domain_id}.com", {"state": "open", "failure_count": i})

        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Verify all domains were tracked
        assert len(state_obj.all_domains()) == 5

        # Cleanup
        state_obj.stop_snapshots()

    def test_state_persists_across_restart_integration(self, tmp_path):
        """Integration test: State persists through simulated restart."""
        from circuit_breaker import CircuitBreaker, CircuitState, InMemoryCircuitState

        state_file = tmp_path / "persist_test.json"

        # First instance - open a circuit
        cb1 = CircuitBreaker()
        cb1.failure_threshold = 2
        cb1._state = InMemoryCircuitState(state_file=state_file)

        cb1.record_failure("api.example.com", "error 1")
        cb1.record_failure("api.example.com", "error 2")

        status1 = cb1.get_status("api.example.com")
        assert status1.state == CircuitState.OPEN

        # Save and cleanup
        cb1._state._save_state()
        cb1.done()

        # Second instance - should restore open circuit
        cb2 = CircuitBreaker()
        cb2.failure_threshold = 2
        cb2._state = InMemoryCircuitState(state_file=state_file)

        status2 = cb2.get_status("api.example.com")
        assert status2.state == CircuitState.OPEN
        assert status2.failure_count == 2

        # Cleanup
        cb2.done()


class TestRequestIdPropagation:
    """Tests for request_id propagation in circuit breaker logging."""

    def test_log_event_includes_request_id(self, circuit_breaker, make_flow_with_request_id, tmp_path):
        """Verify _log_event includes request_id from flow metadata."""
        import json
        from unittest.mock import patch

        log_path = tmp_path / "test.jsonl"

        # Force circuit open
        circuit_breaker.force_open("test.com")

        with patch("utils.AUDIT_LOG_PATH", log_path):
            flow = make_flow_with_request_id(
                request_id="req-circuit123",
                url="http://test.com/api"
            )

            circuit_breaker.request(flow)

            # Verify circuit event was logged with request_id
            if log_path.exists():
                lines = log_path.read_text().strip().split("\n")
                for line in lines:
                    entry = json.loads(line)
                    if entry.get("event") == "security.circuit":
                        assert entry.get("request_id") == "req-circuit123"
                        break

    def test_metadata_preserved_on_circuit_block(self, circuit_breaker, make_flow_with_request_id):
        """Verify request_id is preserved when request is blocked by open circuit."""
        circuit_breaker.force_open("blocked.com")

        flow = make_flow_with_request_id(
            request_id="req-circuitblock789",
            url="http://blocked.com/api"
        )

        circuit_breaker.request(flow)

        # Request ID should still be in metadata after processing
        assert flow.metadata.get("request_id") == "req-circuitblock789"
        assert flow.response is not None
        assert flow.response.status_code == 503
        assert flow.metadata.get("blocked_by") == "circuit-breaker"

    def test_response_handler_uses_request_id(self, circuit_breaker, make_flow_with_request_id, make_response, tmp_path):
        """Verify response handler logs with request_id on failure."""
        from unittest.mock import patch

        log_path = tmp_path / "test.jsonl"

        with patch("utils.AUDIT_LOG_PATH", log_path):
            flow = make_flow_with_request_id(
                request_id="req-respfail123",
                url="http://failing.com/api"
            )
            flow.response = make_response(status_code=500)

            circuit_breaker.response(flow)

            # Request ID should still be in metadata
            assert flow.metadata.get("request_id") == "req-respfail123"
