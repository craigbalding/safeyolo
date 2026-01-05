"""
rate_limiter.py - Native mitmproxy addon for per-domain rate limiting

Uses PolicyEngine's GCRA-based budget tracking for smooth rate limiting.
Prevents IP blacklisting from aggressive LLM API calls.

Rate limits are configured in baseline.yaml as permissions with effect: budget.

Usage:
    mitmdump -s addons/rate_limiter.py -s addons/policy_engine.py

Example baseline.yaml:
permissions:
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 3000  # requests per minute (50 rps)
"""

import logging
from typing import Optional

from mitmproxy import ctx, http

try:
    from .utils import make_block_response, write_event, get_client_ip, get_option_safe
    from .policy_engine import get_policy_engine
except ImportError:
    from utils import make_block_response, write_event, get_client_ip, get_option_safe
    from policy_engine import get_policy_engine

log = logging.getLogger("safeyolo.rate-limiter")


class RateLimiter:
    """
    Native mitmproxy addon for per-domain rate limiting.

    Delegates to PolicyEngine for budget/rate limit configuration and enforcement.
    Rate limits are defined as permissions with effect: budget in baseline.yaml.
    """

    name = "rate-limiter"

    def __init__(self):
        # Stats
        self.checks_total = 0
        self.allowed_total = 0
        self.limited_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
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

    def _log_limited(self, flow: http.HTTPFlow, decision: str, domain: str):
        """Log rate limit decision."""
        write_event(
            "security.ratelimit",
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            decision=decision,
            domain=domain,
        )

    def _should_block(self) -> bool:
        """Check if blocking is enabled."""
        return get_option_safe("ratelimit_block", True)

    def request(self, flow: http.HTTPFlow):
        """Check rate limit before request using PolicyEngine."""
        if not get_option_safe("ratelimit_enabled", True):
            return

        domain = flow.request.host
        path = flow.request.path
        method = flow.request.method

        # Get PolicyEngine
        engine = get_policy_engine()
        if engine is None:
            # PolicyEngine not initialized - allow request
            return

        self.checks_total += 1

        # Evaluate request budget
        decision = engine.evaluate_request(domain, path, method)

        if decision.effect == "budget_exceeded":
            self.limited_total += 1
            client = get_client_ip(flow)

            if self._should_block():
                log.warning(
                    f"BLOCKED: {domain}{path} from {client} - budget exceeded"
                )
                self._log_limited(flow, "block", domain)

                # Block with 429 and Retry-After header
                flow.metadata["blocked_by"] = self.name
                flow.response = make_block_response(
                    429,
                    {
                        "error": "Rate limited by proxy",
                        "domain": domain,
                        "reason": decision.reason,
                        "message": f"Too many requests to {domain}. Please slow down.",
                    },
                    self.name,
                    {
                        "Retry-After": "60",
                        "X-RateLimit-Remaining": "0",
                    },
                )
            else:
                log.warning(
                    f"WARN: {domain}{path} from {client} - budget exceeded"
                )
                self._log_limited(flow, "warn", domain)
        else:
            self.allowed_total += 1
            # Store remaining budget for metrics
            if decision.budget_remaining is not None:
                flow.metadata["ratelimit_remaining"] = decision.budget_remaining

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        # Get budget stats from PolicyEngine
        engine = get_policy_engine()
        budget_stats = engine.get_budget_stats() if engine else {}

        return {
            "enabled": get_option_safe("ratelimit_enabled", True),
            "checks_total": self.checks_total,
            "allowed_total": self.allowed_total,
            "limited_total": self.limited_total,
            "budget_stats": budget_stats,
        }

    def done(self):
        """Cleanup on shutdown."""
        log.info("Rate limiter shutdown complete")


# mitmproxy addon instance
addons = [RateLimiter()]
