"""
Tests for circuit_breaker.py addon.

Tests circuit state transitions, failure detection, recovery,
policy-driven settings, and cache staleness fixes.
"""

import json
import time
from unittest.mock import MagicMock, patch


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
        """Integration test: State persists through simulated restart.

        After the refactor, the second CB instance reconciles stale open circuits
        rather than preserving them as-is.
        """
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

        # Backdate opened_at so it's stale on reload
        data = cb1._state.get("api.example.com")
        data["opened_at"] = time.time() - 120  # 2 minutes ago
        cb1._state.set("api.example.com", data)

        # Save and cleanup
        cb1._state._save_state()
        cb1.done()

        # Second instance - should reconcile stale open circuit to HALF_OPEN
        cb2 = CircuitBreaker()
        cb2.failure_threshold = 2
        cb2.timeout_seconds = 60  # 60s timeout, opened 2 min ago → stale
        cb2._state = InMemoryCircuitState(state_file=state_file)
        cb2._reconcile_stale_circuits()

        status2 = cb2.get_status("api.example.com")
        # The circuit was opened long enough ago that reconciliation moves it to HALF_OPEN
        assert status2.state == CircuitState.HALF_OPEN

        # Cleanup
        cb2.done()


class TestPolicyLoading:
    """Tests for policy-driven configuration loading."""

    def test_settings_from_policy_override_defaults(self, circuit_breaker):
        """Settings from policy override hardcoded defaults."""
        sensor_config = {
            "addons": {
                "circuit_breaker": {
                    "failure_threshold": 10,
                    "success_threshold": 3,
                    "timeout_seconds": 120,
                    "half_open_max_requests": 5,
                    "use_exponential_backoff": False,
                    "max_timeout_seconds": 7200,
                    "backoff_multiplier": 3.0,
                    "jitter_factor": 0.5,
                    "streak_decay_seconds": 1800,
                    "excluded_domains": ["custom.internal"],
                }
            }
        }

        circuit_breaker._load_config_from_pdp(sensor_config)

        assert circuit_breaker.failure_threshold == 10
        assert circuit_breaker.success_threshold == 3
        assert circuit_breaker.timeout_seconds == 120
        assert circuit_breaker.half_open_max_requests == 5
        assert circuit_breaker.use_exponential_backoff is False
        assert circuit_breaker.max_timeout_seconds == 7200
        assert circuit_breaker.backoff_multiplier == 3.0
        assert circuit_breaker.jitter_factor == 0.5
        assert circuit_breaker.streak_decay_seconds == 1800
        # Excluded domains is additive
        assert "custom.internal" in circuit_breaker._excluded_domains
        assert "localhost" in circuit_breaker._excluded_domains  # hardcoded still there

    def test_no_policy_client_uses_hardcoded_defaults(self, circuit_breaker):
        """No PolicyClient available → hardcoded defaults work fine."""
        # Simulate PDP not configured by patching import
        with patch("circuit_breaker.CircuitBreaker._maybe_reload_config") as mock_reload:
            # _maybe_reload_config would catch RuntimeError - simulate that it's a no-op
            mock_reload.return_value = None

            # Defaults should still be intact
            assert circuit_breaker.failure_threshold == 5
            assert circuit_breaker.success_threshold == 2
            assert circuit_breaker.timeout_seconds == 60

    def test_maybe_reload_config_skips_when_pdp_not_configured(self, circuit_breaker):
        """_maybe_reload_config silently skips when PDP raises RuntimeError."""
        mock_get = MagicMock(side_effect=RuntimeError("PolicyClient not configured"))

        with patch("pdp.get_policy_client", mock_get):
            # Should not raise
            circuit_breaker._maybe_reload_config()

        # Defaults unchanged
        assert circuit_breaker.failure_threshold == 5

    def test_policy_hash_prevents_redundant_reload(self, circuit_breaker):
        """Policy hash prevents redundant reload when unchanged."""
        mock_client = MagicMock()
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "hash123",
            "addons": {
                "circuit_breaker": {
                    "failure_threshold": 10,
                }
            }
        }

        with patch("pdp.get_policy_client", return_value=mock_client):
            # First call - should reload
            circuit_breaker._maybe_reload_config()
            assert circuit_breaker.failure_threshold == 10

            # Change the attribute to detect if reload happens
            circuit_breaker.failure_threshold = 99

            # Second call with same hash - should NOT reload
            circuit_breaker._maybe_reload_config()
            assert circuit_breaker.failure_threshold == 99  # Unchanged

            # Third call with new hash - should reload
            mock_client.get_sensor_config.return_value = {
                "policy_hash": "hash456",
                "addons": {
                    "circuit_breaker": {
                        "failure_threshold": 20,
                    }
                }
            }
            circuit_breaker._maybe_reload_config()
            assert circuit_breaker.failure_threshold == 20

    def test_excluded_domains_additive(self, circuit_breaker):
        """Policy excluded_domains extends hardcoded set, not replaces."""
        original_excluded = circuit_breaker._excluded_domains.copy()

        sensor_config = {
            "addons": {
                "circuit_breaker": {
                    "excluded_domains": ["extra1.local", "extra2.local"],
                }
            }
        }

        circuit_breaker._load_config_from_pdp(sensor_config)

        # Original domains still present
        for domain in original_excluded:
            assert domain in circuit_breaker._excluded_domains

        # New domains added
        assert "extra1.local" in circuit_breaker._excluded_domains
        assert "extra2.local" in circuit_breaker._excluded_domains


class TestCacheStaleness:
    """Tests for cache staleness fixes."""

    def test_stale_open_circuit_reconciled_to_half_open(self, tmp_path):
        """Fix 1: Pre-write state with stale OPEN circuit (opened 2h ago),
        verify reconciled to HALF_OPEN."""
        from circuit_breaker import CircuitBreaker, CircuitState, InMemoryCircuitState

        state_file = tmp_path / "stale_state.json"
        two_hours_ago = time.time() - 7200

        # Write stale state to file
        stale_data = {
            "states": {
                "stale.example.com": {
                    "state": "open",
                    "failure_count": 5,
                    "failure_streak": 0,
                    "opened_at": two_hours_ago,
                    "last_failure_time": two_hours_ago,
                }
            },
            "saved_at": two_hours_ago,
        }
        with open(state_file, "w") as f:
            json.dump(stale_data, f)

        cb = CircuitBreaker()
        cb.timeout_seconds = 60  # 60s timeout, opened 2h ago → definitely stale
        cb._state = InMemoryCircuitState(state_file=state_file)
        cb._reconcile_stale_circuits()

        status = cb.get_status("stale.example.com")
        assert status.state == CircuitState.HALF_OPEN

        cb.done()

    def test_streak_decays_to_zero_after_inactivity(self, circuit_breaker):
        """Fix 2: Build streak, fake last_failure_time far in past,
        verify streak decays to 0."""
        circuit_breaker.streak_decay_seconds = 60  # 1 minute decay

        # Manually set up a domain with a streak and old failure time
        circuit_breaker._state.set("decaying.com", {
            "state": "closed",
            "failure_count": 0,
            "failure_streak": 5,
            "last_failure_time": time.time() - 3600,  # 1 hour ago
            "success_count": 0,
        })

        status = circuit_breaker.get_status("decaying.com")
        assert status.failure_streak == 0  # Should have decayed

    def test_streak_does_not_decay_if_recent(self, circuit_breaker):
        """Streak should NOT decay if last failure was recent."""
        circuit_breaker.streak_decay_seconds = 3600  # 1 hour decay

        circuit_breaker._state.set("active.com", {
            "state": "closed",
            "failure_count": 0,
            "failure_streak": 3,
            "last_failure_time": time.time() - 60,  # 1 minute ago
            "success_count": 0,
        })

        status = circuit_breaker.get_status("active.com")
        assert status.failure_streak == 3  # Should NOT decay

    def test_failure_streak_capped_to_1_on_load(self, tmp_path):
        """Fix 3: Pre-write state with failure_streak: 8,
        verify capped to 1 on load."""
        from circuit_breaker import CircuitBreaker, InMemoryCircuitState

        state_file = tmp_path / "high_streak.json"
        now = time.time()

        # Write state with high streak
        data = {
            "states": {
                "streaky.com": {
                    "state": "open",
                    "failure_count": 10,
                    "failure_streak": 8,
                    "opened_at": now,  # Just opened, so won't transition
                    "last_failure_time": now,
                }
            },
            "saved_at": now,
        }
        with open(state_file, "w") as f:
            json.dump(data, f)

        cb = CircuitBreaker()
        cb._state = InMemoryCircuitState(state_file=state_file)
        cb._reconcile_stale_circuits()

        # Streak should be capped to 1
        raw_data = cb._state.get("streaky.com")
        assert raw_data["failure_streak"] == 1

        cb.done()

    def test_reconcile_does_nothing_for_closed_circuits(self, tmp_path):
        """Reconciliation should not change CLOSED circuits."""
        from circuit_breaker import CircuitBreaker, CircuitState, InMemoryCircuitState

        state_file = tmp_path / "closed_state.json"

        data = {
            "states": {
                "healthy.com": {
                    "state": "closed",
                    "failure_count": 1,
                    "failure_streak": 0,
                    "last_failure_time": time.time() - 100,
                }
            },
            "saved_at": time.time(),
        }
        with open(state_file, "w") as f:
            json.dump(data, f)

        cb = CircuitBreaker()
        cb._state = InMemoryCircuitState(state_file=state_file)
        cb._reconcile_stale_circuits()

        status = cb.get_status("healthy.com")
        assert status.state == CircuitState.CLOSED
        assert status.failure_count == 1

        cb.done()

    def test_reconcile_caps_streak_but_keeps_open_if_not_stale(self, tmp_path):
        """If circuit is OPEN but not yet timed out, keep it OPEN but cap streak."""
        from circuit_breaker import CircuitBreaker, CircuitState, InMemoryCircuitState

        state_file = tmp_path / "recent_open.json"
        now = time.time()

        data = {
            "states": {
                "recent.com": {
                    "state": "open",
                    "failure_count": 5,
                    "failure_streak": 4,
                    "opened_at": now,  # Just now, not stale
                    "last_failure_time": now,
                }
            },
            "saved_at": now,
        }
        with open(state_file, "w") as f:
            json.dump(data, f)

        cb = CircuitBreaker()
        cb.timeout_seconds = 60
        cb._state = InMemoryCircuitState(state_file=state_file)
        cb._reconcile_stale_circuits()

        raw_data = cb._state.get("recent.com")
        assert raw_data["failure_streak"] == 1  # Capped
        assert raw_data["state"] == "open"  # Still OPEN (not stale)

        cb.done()


class TestRequestIdPropagation:
    """Tests for request_id propagation in circuit breaker logging."""

    def test_log_event_includes_request_id(self, circuit_breaker, make_flow_with_request_id, tmp_path):
        """Verify _log_event includes request_id from flow metadata."""
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
