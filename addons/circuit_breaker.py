"""
circuit_breaker.py - Native mitmproxy addon for circuit breaker pattern

Prevents cascade failures by stopping requests to unhealthy upstreams.
Auto-recovers when services become healthy again.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Service unhealthy, requests fail fast (503)
- HALF_OPEN: Testing recovery, limited requests allowed

Settings are read from config/baseline.yaml under addons.circuit_breaker
and hot-reload when the file changes (via the policy engine).

Based on: https://martinfowler.com/bliki/CircuitBreaker.html
"""

import json
import logging
import math
import random
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from base import SecurityAddon
from mitmproxy import ctx, http
from utils import BackgroundWorker, atomic_write_json, make_block_response, sanitize_for_log

log = logging.getLogger("safeyolo.circuit-breaker")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitStatus:
    """Current status of a circuit."""
    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: float | None
    last_success_time: float | None
    opened_at: float | None
    failure_streak: int
    current_timeout: float

    @property
    def time_until_half_open(self) -> float | None:
        """Seconds until circuit transitions to half-open."""
        if self.state != CircuitState.OPEN or self.opened_at is None:
            return None
        elapsed = time.time() - self.opened_at
        remaining = self.current_timeout - elapsed
        return max(0, remaining)


class InMemoryCircuitState:
    """In-memory state storage with optional file-backed persistence."""

    def __init__(self, state_file: Path | None = None):
        self._states: dict[str, dict] = {}
        self._state_file = state_file
        self._lock = threading.RLock()
        self._worker: BackgroundWorker | None = None

        if self._state_file and self._state_file.exists():
            self._load_state()

        if self._state_file:
            self._start_snapshots()

    def _load_state(self):
        """Load circuit states from state file on startup."""
        try:
            with open(self._state_file) as f:
                data = json.load(f)

            with self._lock:
                self._states = data.get("states", {})

            log.info(f"Loaded {len(self._states)} circuit states from {self._state_file}")
        except Exception as e:
            log.error(f"Failed to load circuit state: {type(e).__name__}: {e}")
            self._states = {}

    def _save_state(self):
        """Save circuit states to state file (atomic write)."""
        if not self._state_file:
            return

        try:
            with self._lock:
                data = {"states": self._states.copy(), "saved_at": time.time()}
            atomic_write_json(self._state_file, data)
        except Exception as e:
            log.error(f"Failed to save circuit state: {type(e).__name__}: {e}")

    def _start_snapshots(self):
        """Start background worker to snapshot state every 10 seconds."""
        self._worker = BackgroundWorker(
            self._save_state, interval_sec=10.0, name="circuit-breaker-snapshot"
        )
        self._worker.start()
        log.info("Started circuit breaker state snapshots (10s interval)")

    def stop_snapshots(self):
        """Stop snapshot worker and save final state."""
        if self._worker:
            self._worker.stop()
            self._save_state()
            self._worker = None
            log.info("Stopped circuit breaker state snapshots")

    def get(self, domain: str) -> dict:
        with self._lock:
            return self._states.get(domain, {})

    def set(self, domain: str, data: dict):
        with self._lock:
            self._states[domain] = data

    def delete(self, domain: str):
        with self._lock:
            self._states.pop(domain, None)

    def all_domains(self) -> list[str]:
        with self._lock:
            return list(self._states.keys())


class CircuitBreaker(SecurityAddon):
    """
    Native mitmproxy addon for circuit breaker pattern.

    Tracks failures per domain and opens circuit when threshold is reached.
    Automatically recovers after timeout period.

    Settings are loaded from baseline.yaml via the policy engine and
    hot-reload when the file changes.
    """

    name = "circuit-breaker"

    def __init__(self):
        # Don't call super().__init__() - we have custom stats
        self._state = InMemoryCircuitState()

        # Default config (fallback when PDP isn't loaded)
        self.failure_threshold = 5
        self.success_threshold = 2
        self.timeout_seconds = 60
        self.half_open_max_requests = 3
        self.use_exponential_backoff = True
        self.max_timeout_seconds = 3600
        self.backoff_multiplier = 2.0
        self.jitter_factor = 0.3
        self.streak_decay_seconds: float = 3600

        # Policy reload tracking
        self._last_policy_hash: str = ""

        # Domains excluded from circuit breaking (local infrastructure)
        self._excluded_domains: set[str] = {
            "localhost",
            "127.0.0.1",
            "host.docker.internal",
        }

        # Circuit-specific stats (different from base AddonStats)
        self.checks_total = 0
        self.opens_total = 0
        self.half_opens_total = 0
        self.recoveries_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="circuit_state_file",
            typespec=Optional[str],
            default="/safeyolo/data/circuit_breaker_state.json",
            help="Path to circuit breaker state file for persistence",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "circuit_state_file" in updates or not hasattr(self, "_state"):
            state_path = ctx.options.circuit_state_file
            self._state = InMemoryCircuitState(
                state_file=Path(state_path) if state_path else None
            )
            if state_path:
                log.info(f"Circuit breaker state persistence enabled: {state_path}")
            self._reconcile_stale_circuits()

    def _load_config_from_pdp(self, sensor_config: dict):
        """Load settings from policy engine sensor config."""
        cb_config = sensor_config.get("addons", {}).get("circuit_breaker", {})

        self.failure_threshold = cb_config.get("failure_threshold", self.failure_threshold)
        self.success_threshold = cb_config.get("success_threshold", self.success_threshold)
        self.timeout_seconds = cb_config.get("timeout_seconds", self.timeout_seconds)
        self.half_open_max_requests = cb_config.get("half_open_max_requests", self.half_open_max_requests)
        self.use_exponential_backoff = cb_config.get("use_exponential_backoff", self.use_exponential_backoff)
        self.max_timeout_seconds = cb_config.get("max_timeout_seconds", self.max_timeout_seconds)
        self.backoff_multiplier = cb_config.get("backoff_multiplier", self.backoff_multiplier)
        self.jitter_factor = cb_config.get("jitter_factor", self.jitter_factor)
        self.streak_decay_seconds = cb_config.get("streak_decay_seconds", self.streak_decay_seconds)

        # Excluded domains: policy extends the hardcoded set
        extra_excluded = cb_config.get("excluded_domains", [])
        if extra_excluded:
            self._excluded_domains.update(extra_excluded)

    def _maybe_reload_config(self):
        """Reload settings from policy engine if policy hash changed."""
        from pdp import get_policy_client

        try:
            client = get_policy_client()
            config = client.get_sensor_config()
            policy_hash = config.get("policy_hash", "")

            if policy_hash != self._last_policy_hash:
                self._load_config_from_pdp(config)
                self._last_policy_hash = policy_hash
        except RuntimeError:
            # PolicyClient not configured yet - skip reload
            pass
        except Exception as e:
            log.warning("Failed to reload circuit breaker config: %s: %s", type(e).__name__, e)

    def _reconcile_stale_circuits(self):
        """Reconcile stale circuit states after loading from disk.

        - Caps failure_streak to 1 (mild memory, not exponential punishment)
        - Transitions stale OPEN circuits to HALF_OPEN if timeout has elapsed
        """
        now = time.time()
        for domain in self._state.all_domains():
            data = self._state.get(domain)
            if not data:
                continue

            changed = False

            # Fix 3: Cap streak on restart
            streak = data.get("failure_streak", 0)
            if streak > 1:
                data["failure_streak"] = 1
                changed = True
                log.info("Reconcile: capped failure_streak %d -> 1 for %s", streak, sanitize_for_log(domain))

            # Fix 1: Transition stale OPEN to HALF_OPEN
            state = data.get("state")
            if state == CircuitState.OPEN.value:
                opened_at = data.get("opened_at", 0)
                capped_streak = data.get("failure_streak", 0)
                timeout = self._calculate_timeout(capped_streak)
                if now - opened_at >= timeout:
                    data["state"] = CircuitState.HALF_OPEN.value
                    data["success_count"] = 0
                    data["half_open_requests"] = 0
                    changed = True
                    self.half_opens_total += 1
                    log.info("Reconcile: stale OPEN -> HALF_OPEN for %s "
                             "(opened %.0fs ago, timeout was %.0fs)",
                             sanitize_for_log(domain), now - opened_at, timeout)

            if changed:
                self._state.set(domain, data)

    def _calculate_timeout(self, streak: int) -> float:
        """Calculate timeout with exponential backoff and jitter."""
        if not self.use_exponential_backoff or streak == 0:
            return self.timeout_seconds

        # Cap streak to prevent OverflowError in exponentiation.
        # max_streak is the point where timeout >= max_timeout_seconds.
        if self.backoff_multiplier > 1:
            max_streak = math.ceil(math.log(self.max_timeout_seconds / self.timeout_seconds,
                                            self.backoff_multiplier))
            streak = min(streak, max_streak)

        timeout = self.timeout_seconds * (self.backoff_multiplier**streak)
        timeout = min(timeout, self.max_timeout_seconds)

        jitter_range = timeout * self.jitter_factor
        timeout += random.uniform(-jitter_range, jitter_range)

        return max(self.timeout_seconds, timeout)

    def block(self, flow: http.HTTPFlow, status: int, body: dict, extra_headers: dict = None):
        """Override base block() - circuit breaker has its own stats."""
        flow.metadata["blocked_by"] = self.name
        flow.response = make_block_response(status, body, self.name, extra_headers)

    def _log_circuit_event(self, event: str, domain: str, flow: http.HTTPFlow | None = None, **extra):
        """Log circuit breaker event."""
        self.log_decision(
            flow if flow else type("Flow", (), {"metadata": {}})(),
            event,
            domain=domain,
            **extra,
        )

    def get_status(self, domain: str) -> CircuitStatus:
        """Get current circuit status for domain."""
        data = self._state.get(domain)

        if not data:
            return CircuitStatus(
                state=CircuitState.CLOSED,
                failure_count=0,
                success_count=0,
                last_failure_time=None,
                last_success_time=None,
                opened_at=None,
                failure_streak=0,
                current_timeout=self.timeout_seconds,
            )

        state = CircuitState(data.get("state", "closed"))
        failure_streak = data.get("failure_streak", 0)

        # Fix 2: Streak decay at runtime
        if failure_streak > 0:
            last_failure_time = data.get("last_failure_time")
            if last_failure_time and (time.time() - last_failure_time) > self.streak_decay_seconds:
                failure_streak = 0
                data["failure_streak"] = 0
                self._state.set(domain, data)
                log.info("Streak decayed to 0 for %s (last failure > %ss ago)", sanitize_for_log(domain), self.streak_decay_seconds)

        current_timeout = self._calculate_timeout(failure_streak)

        if state == CircuitState.OPEN:
            opened_at = data.get("opened_at", 0)
            if time.time() - opened_at >= current_timeout:
                state = CircuitState.HALF_OPEN
                data["state"] = state.value
                data["success_count"] = 0
                data["half_open_requests"] = 0
                self._state.set(domain, data)
                self.half_opens_total += 1
                self._log_circuit_event("half_open", domain)
                log.info(f"Circuit half-open: {domain}")

        return CircuitStatus(
            state=state,
            failure_count=data.get("failure_count", 0),
            success_count=data.get("success_count", 0),
            last_failure_time=data.get("last_failure_time"),
            last_success_time=data.get("last_success_time"),
            opened_at=data.get("opened_at"),
            failure_streak=failure_streak,
            current_timeout=current_timeout,
        )

    def should_allow_request(self, domain: str) -> tuple[bool, CircuitStatus]:
        """Check if request should be allowed."""
        self.checks_total += 1
        status = self.get_status(domain)

        if status.state == CircuitState.CLOSED:
            return True, status

        if status.state == CircuitState.OPEN:
            return False, status

        data = self._state.get(domain)
        half_open_requests = data.get("half_open_requests", 0)

        if half_open_requests >= self.half_open_max_requests:
            return False, status

        data["half_open_requests"] = half_open_requests + 1
        self._state.set(domain, data)

        return True, status

    def record_failure(self, domain: str, error: str | None = None,
                       flow: http.HTTPFlow | None = None) -> CircuitStatus:
        """Record a failure for domain."""
        data = self._state.get(domain)
        now = time.time()

        current_state = CircuitState(data.get("state", "closed"))
        failure_count = data.get("failure_count", 0) + 1
        failure_streak = data.get("failure_streak", 0)

        new_data = {
            **data,
            "failure_count": failure_count,
            "last_failure_time": now,
            "last_error": error or "",
        }

        if current_state == CircuitState.CLOSED:
            if failure_count >= self.failure_threshold:
                new_data["state"] = CircuitState.OPEN.value
                new_data["opened_at"] = now
                new_data["success_count"] = 0
                self.opens_total += 1
                self._log_circuit_event("open", domain, flow=flow, failure_count=failure_count, error=error)
                log.warning(f"Circuit OPEN: {domain} (failures: {failure_count})")
            else:
                new_data["state"] = CircuitState.CLOSED.value

        elif current_state == CircuitState.HALF_OPEN:
            new_data["state"] = CircuitState.OPEN.value
            new_data["opened_at"] = now
            new_data["failure_streak"] = failure_streak + 1
            new_data["success_count"] = 0
            self.opens_total += 1
            self._log_circuit_event("reopen", domain, flow=flow, streak=failure_streak + 1, error=error)
            log.warning(f"Circuit REOPENED: {domain} (streak: {failure_streak + 1})")

        self._state.set(domain, new_data)
        return self.get_status(domain)

    def record_success(self, domain: str,
                       flow: http.HTTPFlow | None = None) -> CircuitStatus:
        """Record a success for domain."""
        status = self.get_status(domain)
        data = self._state.get(domain)
        now = time.time()

        if not data:
            return status

        current_state = status.state
        success_count = data.get("success_count", 0) + 1

        new_data = {
            **data,
            "success_count": success_count,
            "last_success_time": now,
        }

        if current_state == CircuitState.HALF_OPEN:
            if success_count >= self.success_threshold:
                new_data["state"] = CircuitState.CLOSED.value
                new_data["failure_count"] = 0
                new_data["failure_streak"] = 0
                self.recoveries_total += 1
                self._log_circuit_event("close", domain, flow=flow, success_count=success_count)
                log.info(f"Circuit CLOSED: {domain} (recovered)")
            else:
                new_data["state"] = CircuitState.HALF_OPEN.value

        elif current_state == CircuitState.CLOSED:
            failure_count = data.get("failure_count", 0)
            if failure_count > 0:
                new_data["failure_count"] = failure_count - 1

        self._state.set(domain, new_data)
        return self.get_status(domain)

    def reset(self, domain: str):
        """Manually reset circuit to closed state."""
        self._state.delete(domain)
        self._log_circuit_event("reset", domain)
        log.info(f"Circuit RESET: {domain}")

    def force_open(self, domain: str):
        """Manually open circuit."""
        self._state.set(
            domain,
            {
                "state": CircuitState.OPEN.value,
                "opened_at": time.time(),
                "failure_count": self.failure_threshold,
                "success_count": 0,
                "failure_streak": 0,
                "manual_open": True,
            },
        )
        self._log_circuit_event("force_open", domain)
        log.info(f"Circuit FORCE OPEN: {domain}")

    def request(self, flow: http.HTTPFlow):
        """Check circuit before request."""
        if not self.is_enabled():
            return

        if self.is_bypassed(flow):
            return

        self._maybe_reload_config()

        domain = flow.request.host
        if domain in self._excluded_domains:
            return

        allowed, status = self.should_allow_request(domain)

        if not allowed:
            retry_after = int(status.time_until_half_open or self.timeout_seconds)
            self.log_decision(
                flow,
                "block",
                domain=domain,
                circuit_state=status.state.value,
                failure_count=status.failure_count,
                retry_after=retry_after,
                path=flow.request.path,
            )
            log.warning(
                f"Circuit BLOCKED: {domain}{flow.request.path} "
                f"(state: {status.state.value}, failures: {status.failure_count})"
            )
            self.block(
                flow,
                503,
                {
                    "error": f"Service temporarily unavailable: {domain}",
                    "domain": domain,
                    "circuit_state": status.state.value,
                    "retry_after_seconds": retry_after,
                    "message": f"Circuit breaker open for {domain}. "
                    f"Service has failed {status.failure_count} times. "
                    f"Will retry in {retry_after} seconds.",
                },
                {
                    "Retry-After": str(retry_after),
                    "X-Circuit-State": status.state.value,
                },
            )

    def response(self, flow: http.HTTPFlow):
        """Record success/failure based on response."""
        if not self.is_enabled():
            return

        self._maybe_reload_config()

        if flow.metadata.get("blocked_by"):
            return

        if not flow.response:
            return

        domain = flow.request.host
        if domain in self._excluded_domains:
            return
        status_code = flow.response.status_code

        if status_code >= 500 or status_code == 429:
            self.record_failure(domain, f"HTTP {status_code}", flow=flow)
        elif status_code < 400:
            self.record_success(domain, flow=flow)

    def get_stats(self) -> dict:
        """Get circuit breaker statistics."""
        domains = self._state.all_domains()
        domain_status = {}

        for domain in domains:
            status = self.get_status(domain)
            domain_status[domain] = {
                "state": status.state.value,
                "failure_count": status.failure_count,
                "failure_streak": status.failure_streak,
                "time_until_half_open": status.time_until_half_open,
            }

        return {
            "enabled": self.is_enabled(),
            "failure_threshold": self.failure_threshold,
            "timeout_seconds": self.timeout_seconds,
            "checks_total": self.checks_total,
            "opens_total": self.opens_total,
            "half_opens_total": self.half_opens_total,
            "recoveries_total": self.recoveries_total,
            "domains": domain_status,
        }

    def done(self):
        """Cleanup on shutdown."""
        if hasattr(self, "_state") and self._state:
            self._state.stop_snapshots()
            log.info("Circuit breaker shutdown complete")


addons = [CircuitBreaker()]
