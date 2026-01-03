"""
rate_limiter.py - Native mitmproxy addon for per-domain rate limiting

Uses GCRA (Generic Cell Rate Algorithm) for smooth rate limiting.
Prevents IP blacklisting from aggressive LLM API calls.

Supports hot reload via:
- File watching (checks every 5 seconds)
- SIGHUP signal

Usage:
    mitmdump -s addons/rate_limiter.py \
        --set ratelimit_config=/path/to/rates.json

Config format (rates.json):
{
    "default": {"rps": 0.5, "burst": 3},
    "domains": {
        "api.openai.com": {"rps": 1.0, "burst": 5},
        "api.anthropic.com": {"rps": 1.0, "burst": 5}
    }
}
"""

import json
import logging
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

try:
    from .utils import make_block_response, write_event
except ImportError:
    from utils import make_block_response, write_event

log = logging.getLogger("safeyolo.rate-limiter")


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""
    requests_per_second: float  # e.g., 1.0 = 1 req/sec, 0.5 = 1 req/2sec
    burst_capacity: int  # Max requests in a burst

    @property
    def emission_interval_ms(self) -> float:
        """Milliseconds between requests at steady state."""
        return 1000.0 / self.requests_per_second


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    wait_ms: float  # How long to wait if not allowed
    remaining: int  # Remaining burst capacity


class InMemoryGCRA:
    """
    In-memory GCRA (Generic Cell Rate Algorithm) rate limiter with optional file-backed persistence.

    GCRA uses "virtual scheduling" - it tracks a TAT (Theoretical Arrival Time)
    representing when the next request should ideally arrive. This creates
    smooth rate limiting without the "thundering herd" problem of fixed windows.

    Periodically snapshots TAT state to JSON file for restart recovery.
    For single-instance proxy deployments. Use Redis-backed version for
    multi-instance.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self._tats: dict[str, float] = {}  # domain -> TAT in ms
        self._state_file = state_file
        self._snapshot_thread: Optional[threading.Thread] = None
        self._snapshot_stop = threading.Event()
        self._lock = threading.RLock()  # Protect concurrent access

        # Load state on startup
        if self._state_file and self._state_file.exists():
            self._load_state()

        # Start snapshot thread
        if self._state_file:
            self._start_snapshots()

    def check(self, domain: str, config: RateLimitConfig, cost: int = 1) -> RateLimitResult:
        """Check if request is allowed, update state if so."""
        with self._lock:
            now_ms = time.time() * 1000
            tat = self._tats.get(domain, now_ms)

            burst_offset = config.emission_interval_ms * config.burst_capacity
            allow_at = tat - burst_offset

            if now_ms < allow_at:
                # Rate limited
                wait_ms = allow_at - now_ms
                return RateLimitResult(
                    allowed=False,
                    wait_ms=wait_ms,
                    remaining=0,
                )

            # Allowed - update TAT
            new_tat = max(tat, now_ms) + (config.emission_interval_ms * cost)
            self._tats[domain] = new_tat

            # Calculate remaining burst
            remaining = int((now_ms - (new_tat - burst_offset)) / config.emission_interval_ms)
            remaining = max(0, min(config.burst_capacity, remaining))

            return RateLimitResult(
                allowed=True,
                wait_ms=0,
                remaining=remaining,
            )

    def reset(self, domain: str) -> None:
        """Reset rate limit for a domain."""
        self._tats.pop(domain, None)

    def get_status(self) -> dict[str, float]:
        """Get current TAT values for all domains."""
        return dict(self._tats)

    def _load_state(self):
        """Load TATs from state file on startup."""
        try:
            with open(self._state_file) as f:
                data = json.load(f)

            raw_tats = data.get("tats", {})
            self._tats = {domain: float(tat) for domain, tat in raw_tats.items()}

            log.info(f"Loaded {len(self._tats)} rate limiter TATs from {self._state_file}")
        except Exception as e:
            log.error(f"Failed to load rate limiter state: {type(e).__name__}: {e}")
            self._tats = {}

    def _save_state(self):
        """Save TATs to state file (atomic write)."""
        if not self._state_file:
            return

        try:
            tmp_file = self._state_file.with_suffix('.tmp')

            with self._lock:
                data = {
                    "tats": self._tats.copy(),
                    "saved_at": time.time()
                }

            with open(tmp_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Atomic rename
            tmp_file.rename(self._state_file)
        except Exception as e:
            log.error(f"Failed to save rate limiter state: {type(e).__name__}: {e}")

    def _start_snapshots(self):
        """Start background thread to snapshot state every 10 seconds."""
        def snapshot_loop():
            while not self._snapshot_stop.is_set():
                self._save_state()
                self._snapshot_stop.wait(timeout=10.0)

        self._snapshot_thread = threading.Thread(target=snapshot_loop, daemon=True, name="rate-limiter-snapshot")
        self._snapshot_thread.start()
        log.info("Started rate limiter state snapshots (10s interval)")

    def stop_snapshots(self):
        """Stop snapshot thread and save final state."""
        if self._snapshot_thread:
            self._snapshot_stop.set()
            self._snapshot_thread.join(timeout=2.0)
            if self._snapshot_thread.is_alive():
                log.warning("Rate limiter snapshot thread didn't stop within timeout")
            self._save_state()  # Final snapshot
            self._snapshot_thread = None
            self._snapshot_stop.clear()
            log.info("Stopped rate limiter state snapshots")


class RateLimiter:
    """
    Native mitmproxy addon for per-domain rate limiting.

    Prevents IP blacklisting by enforcing conservative request rates
    to external APIs.

    Supports hot reload via file watching and SIGHUP signal.
    """

    name = "rate-limiter"

    def __init__(self):
        self._gcra = InMemoryGCRA()
        self._configs: dict[str, RateLimitConfig] = {}
        self._default_config = RateLimitConfig(
            requests_per_second=0.5,  # Conservative: 1 req per 2 seconds
            burst_capacity=3,
        )
        self.log_path: Optional[Path] = None
        self.config_path: Optional[Path] = None

        # File watcher state
        self._watcher_thread: Optional[threading.Thread] = None
        self._watcher_stop = threading.Event()
        self._last_mtime: float = 0

        # Stats
        self.checks_total = 0
        self.allowed_total = 0
        self.limited_total = 0
        self.reloads_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="ratelimit_config",
            typespec=Optional[str],
            default=None,
            help="Path to rate limit config JSON",
        )
        loader.add_option(
            name="ratelimit_default_rps",
            typespec=float,
            default=0.5,
            help="Default requests per second for unconfigured domains",
        )
        loader.add_option(
            name="ratelimit_default_burst",
            typespec=int,
            default=3,
            help="Default burst capacity for unconfigured domains",
        )
        loader.add_option(
            name="ratelimit_enabled",
            typespec=bool,
            default=True,
            help="Enable rate limiting",
        )
        loader.add_option(
            name="ratelimit_block",
            typespec=bool,
            default=True,
            help="Block rate-limited requests (default: block mode)",
        )
        loader.add_option(
            name="ratelimit_log_path",
            typespec=Optional[str],
            default=None,
            help="Path for JSONL rate limit log",
        )
        loader.add_option(
            name="ratelimit_watch",
            typespec=bool,
            default=True,
            help="Watch config file for changes (hot reload)",
        )
        loader.add_option(
            name="ratelimit_state_file",
            typespec=Optional[str],
            default="/app/data/rate_limiter_state.json",
            help="Path to rate limiter state file for persistence",
        )

    def configure(self, updates):
        """Handle option changes."""
        # Initialize GCRA with state file if config or state file updated
        if "ratelimit_config" in updates or "ratelimit_state_file" in updates:
            # Stop existing GCRA snapshots if any
            if hasattr(self, '_gcra') and self._gcra:
                self._gcra.stop_snapshots()

            # Initialize new GCRA with state file
            state_path = ctx.options.ratelimit_state_file
            self._gcra = InMemoryGCRA(
                state_file=Path(state_path) if state_path else None
            )

            if state_path:
                log.info(f"Rate limiter state persistence enabled: {state_path}")

            # Load config if exists
            config_path = ctx.options.ratelimit_config
            if config_path and Path(config_path).exists():
                self.config_path = Path(config_path)
                self._load_config(config_path)

        if "ratelimit_default_rps" in updates or "ratelimit_default_burst" in updates:
            self._default_config = RateLimitConfig(
                requests_per_second=ctx.options.ratelimit_default_rps,
                burst_capacity=ctx.options.ratelimit_default_burst,
            )

        if "ratelimit_log_path" in updates:
            path = ctx.options.ratelimit_log_path
            self.log_path = Path(path) if path else None

        if "ratelimit_watch" in updates:
            try:
                watch = ctx.options.ratelimit_watch
            except AttributeError:
                watch = True
            if watch and self.config_path:
                self._start_watcher()
            else:
                self._stop_watcher()

        # Setup SIGHUP handler for hot reload
        self._setup_signal_handler()

    def _load_config(self, config_path: str):
        """Load rate limit config from JSON file (initial load)."""
        try:
            path = Path(config_path)
            with open(path) as f:
                data = json.load(f)

            # Load default
            if "default" in data:
                default = data["default"]
                self._default_config = RateLimitConfig(
                    requests_per_second=default.get("rps", 0.5),
                    burst_capacity=default.get("burst", 3),
                )

            # Load per-domain configs
            self._configs = {}
            for domain, cfg in data.get("domains", {}).items():
                self._configs[domain] = RateLimitConfig(
                    requests_per_second=cfg.get("rps", self._default_config.requests_per_second),
                    burst_capacity=cfg.get("burst", self._default_config.burst_capacity),
                )

            # Track mtime for file watcher
            self._last_mtime = path.stat().st_mtime

            log.info(f"Rate limiter loaded config: {len(self._configs)} domains configured")

        except Exception as e:
            log.error(f"Failed to load rate limit config: {type(e).__name__}: {e}")

    def _get_config(self, domain: str) -> RateLimitConfig:
        """Get config for domain, with wildcard and default fallback."""
        # Exact match
        if domain in self._configs:
            return self._configs[domain]

        # Wildcard match (*.example.com)
        parts = domain.split(".")
        for i in range(len(parts)):
            wildcard = "*." + ".".join(parts[i:])
            if wildcard in self._configs:
                return self._configs[wildcard]

        return self._default_config

    def _setup_signal_handler(self):
        """Setup SIGHUP handler for hot reload."""
        try:
            signal.signal(signal.SIGHUP, self._handle_sighup)
        except (ValueError, OSError):
            pass  # Not main thread or not supported

    def _handle_sighup(self, signum, frame):
        """Handle SIGHUP signal."""
        log.info("Received SIGHUP, reloading rate limit config...")
        if self.config_path:
            self._reload_config()

    def _start_watcher(self):
        """Start background thread to watch for config file changes."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    if self.config_path and self.config_path.exists():
                        mtime = self.config_path.stat().st_mtime
                        if mtime > self._last_mtime:
                            log.info("Rate limit config file changed, reloading...")
                            self._reload_config()
                except Exception as e:
                    log.warning(f"Error checking config file: {type(e).__name__}: {e}")

                self._watcher_stop.wait(timeout=5.0)

        self._watcher_thread = threading.Thread(target=watch_loop, daemon=True)
        self._watcher_thread.start()
        log.info(f"Started rate limit config watcher for {self.config_path}")

    def _stop_watcher(self):
        """Stop the file watcher thread."""
        if self._watcher_thread:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
            self._watcher_stop.clear()

    def _reload_config(self) -> bool:
        """Reload config from file (hot reload)."""
        if not self.config_path or not self.config_path.exists():
            return False

        try:
            with open(self.config_path) as f:
                data = json.load(f)

            # Load default
            if "default" in data:
                default = data["default"]
                self._default_config = RateLimitConfig(
                    requests_per_second=default.get("rps", 0.5),
                    burst_capacity=default.get("burst", 3),
                )

            # Load per-domain configs
            self._configs = {}
            for domain, cfg in data.get("domains", {}).items():
                self._configs[domain] = RateLimitConfig(
                    requests_per_second=cfg.get("rps", self._default_config.requests_per_second),
                    burst_capacity=cfg.get("burst", self._default_config.burst_capacity),
                )

            self._last_mtime = self.config_path.stat().st_mtime
            self.reloads_total += 1

            log.info(f"Rate limiter config reloaded: {len(self._configs)} domains configured")
            return True

        except Exception as e:
            log.error(f"Failed to reload rate limit config: {type(e).__name__}: {e}")
            return False

    def _log_limited(self, flow: http.HTTPFlow, decision: str, domain: str, wait_ms: float):
        """Log rate limit decision.

        Args:
            flow: HTTP flow for request_id correlation
            decision: "block" or "warn"
            domain: The rate-limited domain
            wait_ms: Time until next allowed request
        """
        write_event(
            "security.ratelimit",
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            decision=decision,
            domain=domain,
            wait_ms=round(wait_ms, 1)
        )

    def _should_block(self) -> bool:
        """Check if blocking is enabled."""
        try:
            return ctx.options.ratelimit_block
        except AttributeError:
            return False

    def request(self, flow: http.HTTPFlow):
        """Check rate limit before request."""
        try:
            if not ctx.options.ratelimit_enabled:
                return
        except AttributeError:
            pass  # ctx.options not available in tests

        domain = flow.request.host
        config = self._get_config(domain)

        self.checks_total += 1
        result = self._gcra.check(domain, config)

        if result.allowed:
            self.allowed_total += 1
            # Store for metrics
            flow.metadata["ratelimit_remaining"] = result.remaining
        else:
            self.limited_total += 1
            client = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

            if self._should_block():
                log.warning(
                    f"BLOCKED: {domain}{flow.request.path} from {client} "
                    f"(wait {result.wait_ms:.0f}ms, limit: {config.requests_per_second} rps)"
                )
                self._log_limited(flow, "block", domain, result.wait_ms)
                # Block with 429 and Retry-After header
                retry_after = int(result.wait_ms / 1000) + 1
                flow.metadata["blocked_by"] = self.name
                flow.response = make_block_response(
                    429,
                    {
                        "error": "Rate limited by proxy",
                        "domain": domain,
                        "retry_after_seconds": retry_after,
                        "message": f"Too many requests to {domain}. "
                                   f"Limit: {config.requests_per_second} req/sec with burst of {config.burst_capacity}.",
                    },
                    self.name,
                    {
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(config.requests_per_second),
                        "X-RateLimit-Remaining": "0",
                    },
                )
            else:
                log.warning(
                    f"WARN: {domain}{flow.request.path} from {client} "
                    f"(wait {result.wait_ms:.0f}ms, limit: {config.requests_per_second} rps)"
                )
                self._log_limited(flow, "warn", domain, result.wait_ms)

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        # Safe access to ctx.options for testing
        try:
            enabled = ctx.options.ratelimit_enabled
        except AttributeError:
            enabled = True

        return {
            "enabled": enabled,
            "checks_total": self.checks_total,
            "allowed_total": self.allowed_total,
            "limited_total": self.limited_total,
            "reloads_total": self.reloads_total,
            "default_rps": self._default_config.requests_per_second,
            "default_burst": self._default_config.burst_capacity,
            "configured_domains": list(self._configs.keys()),
        }

    def get_domain_status(self) -> dict:
        """Get current rate limit status per domain."""
        now_ms = time.time() * 1000
        status = {}

        for domain, tat in self._gcra.get_status().items():
            config = self._get_config(domain)
            burst_offset = config.emission_interval_ms * config.burst_capacity

            if now_ms < tat - burst_offset:
                wait_ms = (tat - burst_offset) - now_ms
                remaining = 0
            else:
                wait_ms = 0
                remaining = int((now_ms - (tat - burst_offset)) / config.emission_interval_ms)
                remaining = max(0, min(config.burst_capacity, remaining))

            status[domain] = {
                "rps": config.requests_per_second,
                "burst": config.burst_capacity,
                "remaining": remaining,
                "wait_ms": round(wait_ms, 1) if wait_ms > 0 else 0,
            }

        return status

    def done(self):
        """Cleanup on shutdown."""
        if hasattr(self, '_gcra') and self._gcra:
            self._gcra.stop_snapshots()
            log.info("Rate limiter shutdown complete")


# mitmproxy addon instance
addons = [RateLimiter()]
