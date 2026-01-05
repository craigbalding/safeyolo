"""
base.py - Base class for security-focused mitmproxy addons

Provides common functionality for addons that make security decisions:
- Stats tracking (checks, allowed, blocked, warned)
- Option checking (enabled, block mode)
- Decision logging
- Block response generation

Usage:
    from .base import SecurityAddon

    class MyAddon(SecurityAddon):
        name = "my-addon"

        def request(self, flow):
            if not self.is_enabled() or self.is_bypassed(flow):
                return

            self.stats.checks += 1
            # ... evaluation logic ...

            if should_block:
                self.log_decision(flow, "block", reason="...")
                self.block(flow, 403, {"error": "Blocked", ...})
            else:
                self.stats.allowed += 1
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from mitmproxy import http

try:
    from .utils import make_block_response, write_event, get_option_safe
    from .policy_engine import get_policy_engine
except ImportError:
    from utils import make_block_response, write_event, get_option_safe
    from policy_engine import get_policy_engine


@dataclass
class AddonStats:
    """Common stats for security addons."""
    checks: int = 0
    allowed: int = 0
    blocked: int = 0
    warned: int = 0


class SecurityAddon:
    """
    Base class for security-decision addons.

    Subclasses must define:
        name: str  - addon identifier (e.g., "rate-limiter")

    Convention for mitmproxy options (auto-derived from name):
        {name}_enabled  - enable/disable addon
        {name}_block    - block vs warn mode

    Example:
        name = "rate-limiter" -> ratelimit_enabled, ratelimit_block
        name = "access-control" -> access_control_enabled, access_control_block
    """

    name: str  # Subclass must define

    def __init__(self):
        self.stats = AddonStats()

    def _option_prefix(self) -> str:
        """Convert addon name to option prefix (e.g., 'rate-limiter' -> 'ratelimit')."""
        return self.name.replace("-", "_")

    def is_enabled(self) -> bool:
        """Check if addon is enabled via mitmproxy option."""
        option = f"{self._option_prefix()}_enabled"
        return get_option_safe(option, True)

    def should_block(self) -> bool:
        """Check if addon should block (vs warn)."""
        option = f"{self._option_prefix()}_block"
        return get_option_safe(option, True)

    def is_bypassed(self, flow: http.HTTPFlow) -> bool:
        """Check if addon is bypassed for this request.

        Returns True if:
        - Flow already has a response (another addon blocked it)
        - PolicyEngine says addon is disabled for this domain
        """
        if flow.response:
            return True

        engine = get_policy_engine()
        if engine:
            domain = flow.request.host
            return not engine.is_addon_enabled(self.name, domain)

        return False

    def log_decision(
        self,
        flow: http.HTTPFlow,
        decision: str,
        **data: Any,
    ) -> None:
        """Log security decision to audit log.

        Args:
            flow: HTTP flow for request_id correlation
            decision: Decision type (e.g., "block", "warn", "allow")
            **data: Additional fields (domain, reason, etc.)
        """
        # Convert name to event type: "rate-limiter" -> "security.ratelimit"
        event_type = f"security.{self._option_prefix()}"

        write_event(
            event_type,
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            decision=decision,
            **data,
        )

    def block(
        self,
        flow: http.HTTPFlow,
        status: int,
        body: dict,
        extra_headers: Optional[dict] = None,
    ) -> None:
        """Block request with standard response.

        Args:
            flow: HTTP flow to block
            status: HTTP status code (403, 429, 503, etc.)
            body: Response body as dict
            extra_headers: Additional headers (e.g., Retry-After)
        """
        self.stats.blocked += 1
        flow.metadata["blocked_by"] = self.name
        flow.response = make_block_response(status, body, self.name, extra_headers)

    def warn(self, flow: http.HTTPFlow) -> None:
        """Record a warning (would-block in warn mode)."""
        self.stats.warned += 1

    def get_stats(self) -> dict[str, Any]:
        """Return stats dict for admin API."""
        return {
            "enabled": self.is_enabled(),
            "checks_total": self.stats.checks,
            "allowed_total": self.stats.allowed,
            "blocked_total": self.stats.blocked,
            "warned_total": self.stats.warned,
        }
