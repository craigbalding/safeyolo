"""
budget_tracker.py - GCRA-based budget tracking for rate limiting

Provides smooth rate limiting using Generic Cell Rate Algorithm (GCRA).
Prevents thundering herd problems with virtual scheduling.

Usage:
    from budget_tracker import GCRABudgetTracker

    tracker = GCRABudgetTracker(state_file=Path("/app/data/budget_state.json"))
    allowed, remaining = tracker.check_and_consume("api.openai.com", 3000)  # 3000 req/min
"""

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    from .utils import atomic_write_json, BackgroundWorker
except ImportError:
    from utils import atomic_write_json, BackgroundWorker

log = logging.getLogger("safeyolo.budget-tracker")


@dataclass
class BudgetState:
    """GCRA-based budget tracking for a resource."""
    tat: float = 0.0  # Theoretical Arrival Time in milliseconds
    last_check: float = 0.0


class GCRABudgetTracker:
    """
    GCRA-based budget tracking with per-minute windows.

    Uses "virtual scheduling" - tracks TAT (Theoretical Arrival Time)
    for smooth rate limiting without thundering herd problems.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self._budgets: dict[str, BudgetState] = {}  # key -> state
        self._state_file = state_file
        self._lock = threading.RLock()
        self._worker: Optional[BackgroundWorker] = None

        if self._state_file and self._state_file.exists():
            self._load_state()

        if self._state_file:
            self._start_snapshots()

    def check_and_consume(
        self,
        key: str,
        budget_per_minute: int,
        cost: int = 1,
    ) -> tuple[bool, int]:
        """
        Check if budget allows request and consume if so.

        Args:
            key: Budget key (e.g., "network:request:api.openai.com")
            budget_per_minute: Max requests per minute
            cost: Cost of this request (default 1)

        Returns:
            (allowed, remaining) tuple
        """
        with self._lock:
            now_ms = time.time() * 1000
            state = self._budgets.get(key)

            if state is None:
                state = BudgetState(tat=now_ms, last_check=now_ms)
                self._budgets[key] = state

            # GCRA calculation
            emission_interval_ms = 60000.0 / budget_per_minute  # ms between requests
            burst_capacity = max(1, budget_per_minute // 10)  # 10% burst
            burst_offset = emission_interval_ms * burst_capacity
            allow_at = state.tat - burst_offset

            if now_ms < allow_at:
                # Budget exceeded
                remaining = 0
                return False, remaining

            # Allowed - update TAT
            new_tat = max(state.tat, now_ms) + (emission_interval_ms * cost)
            state.tat = new_tat
            state.last_check = now_ms

            # Calculate remaining
            remaining = int((now_ms - (new_tat - burst_offset)) / emission_interval_ms)
            remaining = max(0, min(burst_capacity, remaining))

            return True, remaining

    def get_remaining(self, key: str, budget_per_minute: int) -> int:
        """Get remaining budget without consuming."""
        with self._lock:
            now_ms = time.time() * 1000
            state = self._budgets.get(key)

            if state is None:
                return budget_per_minute // 10  # Full burst capacity

            emission_interval_ms = 60000.0 / budget_per_minute
            burst_capacity = max(1, budget_per_minute // 10)
            burst_offset = emission_interval_ms * burst_capacity

            remaining = int((now_ms - (state.tat - burst_offset)) / emission_interval_ms)
            return max(0, min(burst_capacity, remaining))

    def reset(self, key: str) -> None:
        """Reset budget for a key."""
        with self._lock:
            self._budgets.pop(key, None)

    def reset_all(self) -> None:
        """Reset all budgets."""
        with self._lock:
            self._budgets.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get budget tracking statistics."""
        with self._lock:
            return {
                "tracked_keys": len(self._budgets),
                "keys": list(self._budgets.keys()),
            }

    def _load_state(self) -> None:
        """Load state from file."""
        try:
            with open(self._state_file) as f:
                data = json.load(f)

            for key, state_data in data.get("budgets", {}).items():
                self._budgets[key] = BudgetState(
                    tat=state_data.get("tat", 0.0),
                    last_check=state_data.get("last_check", 0.0),
                )

            log.info(f"Loaded {len(self._budgets)} budget states from {self._state_file}")
        except Exception as e:
            log.error(f"Failed to load budget state: {type(e).__name__}: {e}")
            self._budgets = {}

    def _save_state(self) -> None:
        """Save state to file (atomic write)."""
        if not self._state_file:
            return

        try:
            with self._lock:
                data = {
                    "budgets": {
                        key: {"tat": state.tat, "last_check": state.last_check}
                        for key, state in self._budgets.items()
                    },
                    "saved_at": time.time(),
                }

            atomic_write_json(self._state_file, data)
        except Exception as e:
            log.error(f"Failed to save budget state: {type(e).__name__}: {e}")

    def _start_snapshots(self) -> None:
        """Start background snapshot worker."""
        self._worker = BackgroundWorker(
            self._save_state,
            interval_sec=10.0,
            name="policy-budget-snapshot"
        )
        self._worker.start()
        log.info("Started policy budget state snapshots (10s interval)")

    def stop(self) -> None:
        """Stop snapshot worker and save final state."""
        if self._worker:
            self._worker.stop()
            self._save_state()
            self._worker = None
