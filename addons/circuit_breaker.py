"""
circuit_breaker.py - Native mitmproxy addon for circuit breaker pattern

Prevents cascade failures by stopping requests to unhealthy upstreams.
Auto-recovers when services become healthy again.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Service unhealthy, requests fail fast (503)
- HALF_OPEN: Testing recovery, limited requests allowed

Usage:
    mitmdump -s addons/circuit_breaker.py \
        --set circuit_failure_threshold=5 \
        --set circuit_timeout=60

Based on: https://martinfowler.com/bliki/CircuitBreaker.html
"""

import json
import logging
import random
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

try:
    from .utils import make_block_response, write_event
except ImportError:
    from utils import make_block_response, write_event

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
    last_failure_time: Optional[float]
    last_success_time: Optional[float]
    opened_at: Optional[float]
    failure_streak: int
    current_timeout: float

    @property
    def time_until_half_open(self) -> Optional[float]:
        """Seconds until circuit transitions to half-open."""
        if self.state != CircuitState.OPEN or self.opened_at is None:
            return None
        elapsed = time.time() - self.opened_at
        remaining = self.current_timeout - elapsed
        return max(0, remaining)


class InMemoryCircuitState:
    """In-memory state storage with optional file-backed persistence.

    Periodically snapshots circuit states to JSON file for restart recovery.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self._states: dict[str, dict] = {}
        self._state_file = state_file
        self._snapshot_thread: Optional[threading.Thread] = None
        self._snapshot_stop = threading.Event()
        self._lock = threading.RLock()

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

            log.info(f"Loaded {len(self._states)} circuit breaker states from {self._state_file}")
        except Exception as e:
            log.error(f"Failed to load circuit breaker state: {type(e).__name__}: {e}")
            self._states = {}

    def _save_state(self):
        """Save circuit states to state file (atomic write)."""
        if not self._state_file:
            return

        try:
            tmp_file = self._state_file.with_suffix('.tmp')

            with self._lock:
                data = {
                    "states": self._states.copy(),
                    "saved_at": time.time()
                }

            with open(tmp_file, 'w') as f:
                json.dump(data, f, indent=2)

            tmp_file.rename(self._state_file)
        except Exception as e:
            log.error(f"Failed to save circuit breaker state: {type(e).__name__}: {e}")

    def _start_snapshots(self):
        """Start background thread to snapshot state every 10 seconds."""
        def snapshot_loop():
            while not self._snapshot_stop.is_set():
                self._save_state()
                self._snapshot_stop.wait(timeout=10.0)

        self._snapshot_thread = threading.Thread(target=snapshot_loop, daemon=True, name="circuit-breaker-snapshot")
        self._snapshot_thread.start()
        log.info("Started circuit breaker state snapshots (10s interval)")

    def stop_snapshots(self):
        """Stop snapshot thread and save final state."""
        if self._snapshot_thread:
            self._snapshot_stop.set()
            self._snapshot_thread.join(timeout=2.0)
            if self._snapshot_thread.is_alive():
                log.warning("Circuit breaker snapshot thread didn't stop within timeout")
            self._save_state()
            self._snapshot_thread = None
            self._snapshot_stop.clear()
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


class CircuitBreaker:
    """
    Native mitmproxy addon for circuit breaker pattern.

    Tracks failures per domain and opens circuit when threshold is reached.
    Automatically recovers after timeout period.
    """

    name = "circuit-breaker"

    def __init__(self):
        self._state = InMemoryCircuitState()
        self.log_path: Optional[Path] = None

        # Default config
        self.failure_threshold = 5
        self.success_threshold = 2
        self.timeout_seconds = 60
        self.half_open_max_requests = 3
        self.use_exponential_backoff = True
        self.max_timeout_seconds = 3600
        self.backoff_multiplier = 2.0
        self.jitter_factor = 0.3

        # Per-domain config overrides
        self._domain_configs: dict[str, dict] = {}

        # Stats
        self.checks_total = 0
        self.opens_total = 0
        self.half_opens_total = 0
        self.recoveries_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="circuit_enabled",
            typespec=bool,
            default=True,
            help="Enable circuit breaker",
        )
        loader.add_option(
            name="circuit_failure_threshold",
            typespec=int,
            default=5,
            help="Failures before opening circuit",
        )
        loader.add_option(
            name="circuit_success_threshold",
            typespec=int,
            default=2,
            help="Successes in half-open to close circuit",
        )
        loader.add_option(
            name="circuit_timeout",
            typespec=int,
            default=60,
            help="Seconds before open -> half-open",
        )
        loader.add_option(
            name="circuit_config",
            typespec=Optional[str],
            default=None,
            help="Path to circuit breaker config JSON",
        )
        loader.add_option(
            name="circuit_log_path",
            typespec=Optional[str],
            default=None,
            help="Path for JSONL circuit events log",
        )
        loader.add_option(
            name="circuit_state_file",
            typespec=Optional[str],
            default="/app/data/circuit_breaker_state.json",
            help="Path to circuit breaker state file for persistence",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "circuit_failure_threshold" in updates:
            self.failure_threshold = ctx.options.circuit_failure_threshold

        if "circuit_success_threshold" in updates:
            self.success_threshold = ctx.options.circuit_success_threshold

        if "circuit_timeout" in updates:
            self.timeout_seconds = ctx.options.circuit_timeout

        if "circuit_config" in updates:
            config_path = ctx.options.circuit_config
            if config_path and Path(config_path).exists():
                self._load_config(config_path)

        if "circuit_log_path" in updates:
            path = ctx.options.circuit_log_path
            self.log_path = Path(path) if path else None

        if "circuit_state_file" in updates or not hasattr(self, '_state'):
            state_path = ctx.options.circuit_state_file
            self._state = InMemoryCircuitState(
                state_file=Path(state_path) if state_path else None
            )

            if state_path:
                log.info(f"Circuit breaker state persistence enabled: {state_path}")

    def _load_config(self, config_path: str):
        """Load per-domain config from JSON."""
        try:
            with open(config_path) as f:
                data = json.load(f)

            # Global defaults
            if "default" in data:
                d = data["default"]
                self.failure_threshold = d.get("failure_threshold", self.failure_threshold)
                self.success_threshold = d.get("success_threshold", self.success_threshold)
                self.timeout_seconds = d.get("timeout_seconds", self.timeout_seconds)

            # Per-domain overrides
            self._domain_configs = data.get("domains", {})

            log.info(f"Circuit breaker loaded config: {len(self._domain_configs)} domain overrides")

        except Exception as e:
            log.error(f"Failed to load circuit config: {type(e).__name__}: {e}")

    def _get_config(self, domain: str) -> dict:
        """Get config for domain."""
        base = {
            "failure_threshold": self.failure_threshold,
            "success_threshold": self.success_threshold,
            "timeout_seconds": self.timeout_seconds,
            "half_open_max_requests": self.half_open_max_requests,
        }

        # Check for domain override
        if domain in self._domain_configs:
            base.update(self._domain_configs[domain])

        # Check wildcard patterns
        for pattern, config in self._domain_configs.items():
            if pattern.startswith("*.") and domain.endswith(pattern[1:]):
                base.update(config)
                break

        return base

    def _calculate_timeout(self, streak: int) -> float:
        """Calculate timeout with exponential backoff and jitter."""
        if not self.use_exponential_backoff or streak == 0:
            return self.timeout_seconds

        timeout = self.timeout_seconds * (self.backoff_multiplier ** streak)
        timeout = min(timeout, self.max_timeout_seconds)

        # Add jitter
        jitter_range = timeout * self.jitter_factor
        timeout += random.uniform(-jitter_range, jitter_range)

        return max(self.timeout_seconds, timeout)

    def _log_event(self, event: str, domain: str, flow: Optional[http.HTTPFlow] = None, **extra):
        """Log circuit breaker event.

        Args:
            event: Event type (open, close, half_open, block)
            domain: The domain affected
            flow: Optional HTTP flow for request_id correlation
            **extra: Additional fields
        """
        write_event(
            "security.circuit",
            request_id=flow.metadata.get("request_id") if flow else None,
            addon=self.name,
            circuit_event=event,
            domain=domain,
            **extra
        )

    def get_status(self, domain: str) -> CircuitStatus:
        """Get current circuit status for domain."""
        config = self._get_config(domain)
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
                current_timeout=config["timeout_seconds"],
            )

        state = CircuitState(data.get("state", "closed"))
        failure_streak = data.get("failure_streak", 0)
        current_timeout = self._calculate_timeout(failure_streak)

        # Check for automatic state transitions
        if state == CircuitState.OPEN:
            opened_at = data.get("opened_at", 0)
            if time.time() - opened_at >= current_timeout:
                # Transition to half-open
                state = CircuitState.HALF_OPEN
                data["state"] = state.value
                data["success_count"] = 0
                data["half_open_requests"] = 0
                self._state.set(domain, data)
                self.half_opens_total += 1
                self._log_event("half_open", domain)
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
        config = self._get_config(domain)

        if status.state == CircuitState.CLOSED:
            return True, status

        if status.state == CircuitState.OPEN:
            return False, status

        # Half-open: allow limited requests
        data = self._state.get(domain)
        half_open_requests = data.get("half_open_requests", 0)

        if half_open_requests >= config["half_open_max_requests"]:
            return False, status

        # Increment half-open request count
        data["half_open_requests"] = half_open_requests + 1
        self._state.set(domain, data)

        return True, status

    def record_failure(self, domain: str, error: Optional[str] = None) -> CircuitStatus:
        """Record a failure for domain."""
        config = self._get_config(domain)
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
            if failure_count >= config["failure_threshold"]:
                # Open the circuit
                new_data["state"] = CircuitState.OPEN.value
                new_data["opened_at"] = now
                new_data["success_count"] = 0
                self.opens_total += 1
                self._log_event("open", domain, failure_count=failure_count, error=error)
                log.warning(f"Circuit OPEN: {domain} (failures: {failure_count})")
            else:
                new_data["state"] = CircuitState.CLOSED.value

        elif current_state == CircuitState.HALF_OPEN:
            # Any failure in half-open reopens circuit
            new_data["state"] = CircuitState.OPEN.value
            new_data["opened_at"] = now
            new_data["failure_streak"] = failure_streak + 1
            new_data["success_count"] = 0
            self.opens_total += 1
            self._log_event("reopen", domain, streak=failure_streak + 1, error=error)
            log.warning(f"Circuit REOPENED: {domain} (streak: {failure_streak + 1})")

        self._state.set(domain, new_data)
        return self.get_status(domain)

    def record_success(self, domain: str) -> CircuitStatus:
        """Record a success for domain."""
        config = self._get_config(domain)
        # Get status first to trigger any state transitions (e.g., OPEN -> HALF_OPEN)
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
            if success_count >= config["success_threshold"]:
                # Close the circuit
                new_data["state"] = CircuitState.CLOSED.value
                new_data["failure_count"] = 0
                new_data["failure_streak"] = 0
                self.recoveries_total += 1
                self._log_event("close", domain, success_count=success_count)
                log.info(f"Circuit CLOSED: {domain} (recovered)")
            else:
                new_data["state"] = CircuitState.HALF_OPEN.value

        elif current_state == CircuitState.CLOSED:
            # Decay failure count on success
            failure_count = data.get("failure_count", 0)
            if failure_count > 0:
                new_data["failure_count"] = failure_count - 1

        self._state.set(domain, new_data)
        return self.get_status(domain)

    def reset(self, domain: str):
        """Manually reset circuit to closed state."""
        self._state.delete(domain)
        self._log_event("reset", domain)
        log.info(f"Circuit RESET: {domain}")

    def force_open(self, domain: str):
        """Manually open circuit."""
        self._state.set(domain, {
            "state": CircuitState.OPEN.value,
            "opened_at": time.time(),
            "failure_count": self.failure_threshold,
            "success_count": 0,
            "failure_streak": 0,
            "manual_open": True,
        })
        self._log_event("force_open", domain)
        log.info(f"Circuit FORCE OPEN: {domain}")

    def request(self, flow: http.HTTPFlow):
        """Check circuit before request."""
        try:
            if not ctx.options.circuit_enabled:
                return
        except AttributeError:
            pass  # ctx.options not available in tests

        domain = flow.request.host
        allowed, status = self.should_allow_request(domain)

        if not allowed:
            retry_after = int(status.time_until_half_open or self.timeout_seconds)
            flow.metadata["blocked_by"] = self.name
            log.warning(f"Circuit BLOCKED: {domain}{flow.request.path} (state: {status.state.value}, failures: {status.failure_count})")
            self._log_event("block", domain, flow=flow,
                decision="block",
                circuit_state=status.state.value,
                failure_count=status.failure_count,
                retry_after=retry_after,
                path=flow.request.path
            )
            flow.response = make_block_response(
                503,
                {
                    "error": "Service temporarily unavailable",
                    "domain": domain,
                    "circuit_state": status.state.value,
                    "retry_after_seconds": retry_after,
                    "message": f"Circuit breaker open for {domain}. "
                               f"Service has failed {status.failure_count} times. "
                               f"Will retry in {retry_after} seconds.",
                },
                self.name,
                {
                    "Retry-After": str(retry_after),
                    "X-Circuit-State": status.state.value,
                },
            )

    def response(self, flow: http.HTTPFlow):
        """Record success/failure based on response."""
        try:
            if not ctx.options.circuit_enabled:
                return
        except AttributeError:
            pass  # ctx.options not available in tests

        # Skip if any addon blocked it (not an upstream failure)
        if flow.metadata.get("blocked_by"):
            return

        if not flow.response:
            return

        domain = flow.request.host
        status_code = flow.response.status_code

        # Record failure on 5xx or 429
        if status_code >= 500 or status_code == 429:
            error = f"HTTP {status_code}"
            self.record_failure(domain, error)
        elif status_code < 400:
            self.record_success(domain)

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

        # Safe access to ctx.options for testing
        try:
            enabled = ctx.options.circuit_enabled
        except AttributeError:
            enabled = True

        return {
            "enabled": enabled,
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
        if hasattr(self, '_state') and self._state:
            self._state.stop_snapshots()
            log.info("Circuit breaker shutdown complete")


# mitmproxy addon instance
addons = [CircuitBreaker()]
