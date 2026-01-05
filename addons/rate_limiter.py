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

from mitmproxy import http

try:
    from .base import SecurityAddon
    from .utils import get_client_ip
    from .policy_engine import get_policy_engine
except ImportError:
    from base import SecurityAddon
    from utils import get_client_ip
    from policy_engine import get_policy_engine

log = logging.getLogger("safeyolo.rate-limiter")


class RateLimiter(SecurityAddon):
    """
    Native mitmproxy addon for per-domain rate limiting.

    Delegates to PolicyEngine for budget/rate limit configuration and enforcement.
    Rate limits are defined as permissions with effect: budget in baseline.yaml.
    """

    name = "rate-limiter"

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

    # Compatibility properties for existing interfaces
    @property
    def checks_total(self) -> int:
        return self.stats.checks

    @property
    def allowed_total(self) -> int:
        return self.stats.allowed

    @property
    def limited_total(self) -> int:
        return self.stats.blocked + self.stats.warned

    def request(self, flow: http.HTTPFlow):
        """Check rate limit before request using PolicyEngine."""
        if not self.is_enabled():
            return

        domain = flow.request.host
        path = flow.request.path
        method = flow.request.method

        engine = get_policy_engine()
        if engine is None:
            return

        self.stats.checks += 1

        decision = engine.evaluate_request(domain, path, method)

        if decision.effect == "budget_exceeded":
            client = get_client_ip(flow)

            if self.should_block():
                log.warning(f"BLOCKED: {domain}{path} from {client} - budget exceeded")
                self.log_decision(flow, "block", domain=domain)
                self.block(
                    flow,
                    429,
                    {
                        "error": "Rate limited by proxy",
                        "domain": domain,
                        "reason": decision.reason,
                        "message": f"Too many requests to {domain}. Please slow down.",
                    },
                    {
                        "Retry-After": "60",
                        "X-RateLimit-Remaining": "0",
                    },
                )
            else:
                log.warning(f"WARN: {domain}{path} from {client} - budget exceeded")
                self.log_decision(flow, "warn", domain=domain)
                self.warn(flow)
        else:
            self.stats.allowed += 1
            if decision.budget_remaining is not None:
                flow.metadata["ratelimit_remaining"] = decision.budget_remaining

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        engine = get_policy_engine()
        budget_stats = engine.get_budget_stats() if engine else {}

        return {
            "enabled": self.is_enabled(),
            "checks_total": self.stats.checks,
            "allowed_total": self.stats.allowed,
            "limited_total": self.stats.blocked + self.stats.warned,
            "budget_stats": budget_stats,
        }

    def done(self):
        """Cleanup on shutdown."""
        log.info("Rate limiter shutdown complete")


addons = [RateLimiter()]
