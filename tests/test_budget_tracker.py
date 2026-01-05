"""
Tests for budget_tracker.py - GCRA-based budget tracking.

Tests rate limiting algorithm, state persistence, and thread safety.
"""

import json
import pytest
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch


class TestGCRABasics:
    """Basic GCRA budget tracking tests."""

    def test_allows_initial_request(self):
        """Test first request is always allowed."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()
        allowed, remaining = tracker.check_and_consume("test-key", 100)

        assert allowed is True
        assert remaining >= 0

    def test_allows_requests_within_budget(self):
        """Test requests within budget are allowed."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # With 6000 req/min budget, we should be able to do several quick requests
        for _ in range(5):
            allowed, remaining = tracker.check_and_consume("test-key", 6000)
            assert allowed is True

    def test_blocks_when_budget_exceeded(self):
        """Test requests are blocked when budget exceeded."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # Very low budget: 1 req/min, burst_capacity=1
        # GCRA allows burst_capacity+1 immediate requests (burst window)
        allowed, _ = tracker.check_and_consume("test-key", 1)
        assert allowed is True

        # Second request still allowed (within burst window)
        allowed, _ = tracker.check_and_consume("test-key", 1)
        assert allowed is True

        # Third request should be blocked (burst exhausted)
        allowed, remaining = tracker.check_and_consume("test-key", 1)
        assert allowed is False
        assert remaining == 0

    def test_different_keys_independent(self):
        """Test different keys have independent budgets."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # Exhaust budget for key1 (need 3 requests to exceed burst)
        tracker.check_and_consume("key1", 1)
        tracker.check_and_consume("key1", 1)
        allowed1, _ = tracker.check_and_consume("key1", 1)
        assert allowed1 is False

        # key2 should still have budget
        allowed2, _ = tracker.check_and_consume("key2", 1)
        assert allowed2 is True


class TestGCRARemaining:
    """Tests for remaining budget calculation."""

    def test_get_remaining_without_consuming(self):
        """Test get_remaining doesn't consume budget."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()
        budget = 100

        remaining1 = tracker.get_remaining("test-key", budget)
        remaining2 = tracker.get_remaining("test-key", budget)

        # Should be the same since we didn't consume
        assert remaining1 == remaining2
        assert remaining1 > 0

    def test_get_remaining_for_new_key(self):
        """Test get_remaining for new key returns full burst capacity."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()
        budget = 100

        # For new key, should return burst capacity (10% of budget)
        remaining = tracker.get_remaining("new-key", budget)
        assert remaining == budget // 10


class TestGCRAReset:
    """Tests for budget reset functionality."""

    def test_reset_clears_key(self):
        """Test reset() clears budget for specific key."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # Exhaust budget (3 requests to exceed burst)
        tracker.check_and_consume("test-key", 1)
        tracker.check_and_consume("test-key", 1)
        allowed, _ = tracker.check_and_consume("test-key", 1)
        assert allowed is False

        # Reset and try again
        tracker.reset("test-key")
        allowed, _ = tracker.check_and_consume("test-key", 1)
        assert allowed is True

    def test_reset_only_affects_specified_key(self):
        """Test reset() only affects the specified key."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # Use both keys
        tracker.check_and_consume("key1", 1)
        tracker.check_and_consume("key2", 1)

        # Reset key1
        tracker.reset("key1")

        stats = tracker.get_stats()
        assert "key2" in stats["keys"]
        assert "key1" not in stats["keys"]

    def test_reset_all_clears_everything(self):
        """Test reset_all() clears all budgets."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # Use multiple keys
        tracker.check_and_consume("key1", 1)
        tracker.check_and_consume("key2", 1)
        tracker.check_and_consume("key3", 1)

        assert tracker.get_stats()["tracked_keys"] == 3

        tracker.reset_all()
        assert tracker.get_stats()["tracked_keys"] == 0


class TestGCRAStats:
    """Tests for budget stats."""

    def test_stats_tracks_keys(self):
        """Test get_stats() returns tracked key info."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        tracker.check_and_consume("api.openai.com", 100)
        tracker.check_and_consume("api.anthropic.com", 100)

        stats = tracker.get_stats()
        assert stats["tracked_keys"] == 2
        assert "api.openai.com" in stats["keys"]
        assert "api.anthropic.com" in stats["keys"]


class TestGCRAPersistence:
    """Tests for state persistence."""

    def test_save_and_load_state(self):
        """Test state is saved and loaded correctly."""
        from addons.budget_tracker import GCRABudgetTracker

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "budget_state.json"

            # Create tracker and add some state
            tracker1 = GCRABudgetTracker(state_file=state_file)
            tracker1.check_and_consume("key1", 100)
            tracker1.check_and_consume("key2", 100)
            tracker1._save_state()  # Force save
            tracker1.stop()

            # Verify state file exists
            assert state_file.exists()

            # Load in new tracker
            tracker2 = GCRABudgetTracker(state_file=state_file)
            stats = tracker2.get_stats()
            tracker2.stop()

            assert stats["tracked_keys"] == 2
            assert "key1" in stats["keys"]
            assert "key2" in stats["keys"]

    def test_handles_missing_state_file(self):
        """Test tracker handles missing state file gracefully."""
        from addons.budget_tracker import GCRABudgetTracker

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "nonexistent.json"

            # Should not raise error
            tracker = GCRABudgetTracker(state_file=state_file)
            stats = tracker.get_stats()
            tracker.stop()

            assert stats["tracked_keys"] == 0

    def test_handles_corrupted_state_file(self):
        """Test tracker handles corrupted state file gracefully."""
        from addons.budget_tracker import GCRABudgetTracker

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "corrupted.json"
            state_file.write_text("not valid json {{{")

            # Should not raise error, just start empty
            tracker = GCRABudgetTracker(state_file=state_file)
            stats = tracker.get_stats()
            tracker.stop()

            assert stats["tracked_keys"] == 0


class TestGCRAThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_access(self):
        """Test concurrent access from multiple threads."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()
        results = []
        errors = []

        def worker(thread_id):
            try:
                for _ in range(100):
                    allowed, remaining = tracker.check_and_consume(
                        f"thread-{thread_id}", 10000
                    )
                    results.append((thread_id, allowed))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0

        # Should have results from all threads
        assert len(results) == 500  # 5 threads * 100 iterations

    def test_concurrent_reset(self):
        """Test concurrent reset operations don't cause errors."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()
        errors = []

        def writer():
            try:
                for _ in range(50):
                    tracker.check_and_consume("shared-key", 10000)
            except Exception as e:
                errors.append(e)

        def resetter():
            try:
                for _ in range(50):
                    tracker.reset("shared-key")
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=resetter)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0


class TestGCRACostParameter:
    """Tests for cost parameter in check_and_consume."""

    def test_higher_cost_consumes_more_budget(self):
        """Test that higher cost consumes more budget."""
        from addons.budget_tracker import GCRABudgetTracker

        tracker = GCRABudgetTracker()

        # Consume with cost=10 on a budget of 20/min
        allowed1, _ = tracker.check_and_consume("test-key", 20, cost=10)
        assert allowed1 is True

        # Next request should be blocked since we consumed half
        allowed2, _ = tracker.check_and_consume("test-key", 20, cost=10)
        assert allowed2 is False
