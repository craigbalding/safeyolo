"""
access_control.py - Network access control addon for client internet reach limits

Enforces allow/deny rules for network:request permissions from PolicyEngine.
Use this to restrict which domains coding agents can access.

Load BEFORE rate_limiter.py in the addon chain - this blocks denied requests
before rate limiting is applied.

Usage:
    mitmdump -s addons/access_control.py -s addons/rate_limiter.py ...

Example baseline.yaml:
permissions:
  # Allowlist mode: allow specific, deny rest
  - action: network:request
    resource: "api.openai.com/*"
    effect: allow
    tier: explicit

  - action: network:request
    resource: "api.anthropic.com/*"
    effect: allow
    tier: explicit

  - action: network:request
    resource: "*"
    effect: deny  # Catch-all deny
    tier: explicit

  # Or denylist mode: deny specific domains
  - action: network:request
    resource: "malware.com/*"
    effect: deny
    tier: explicit
"""

import logging
from mitmproxy import ctx, http

try:
    from .utils import make_block_response, write_event, get_client_ip, get_option_safe
    from .policy_engine import get_policy_engine
except ImportError:
    from utils import make_block_response, write_event, get_client_ip, get_option_safe
    from policy_engine import get_policy_engine

log = logging.getLogger("safeyolo.access-control")


class AccessControl:
    """
    Network access control based on PolicyEngine allow/deny rules.

    Evaluates network:request permissions and blocks requests with effect: deny.
    Requests with effect: allow or effect: budget pass through to other addons.
    """

    name = "access-control"

    def __init__(self):
        self.checks_total = 0
        self.allowed_total = 0
        self.denied_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="access_control_enabled",
            typespec=bool,
            default=True,
            help="Enable network access control",
        )
        loader.add_option(
            name="access_control_block",
            typespec=bool,
            default=True,
            help="Block denied requests (False = warn only)",
        )

    def _should_block(self) -> bool:
        """Check if blocking is enabled."""
        return get_option_safe("access_control_block", True)

    def _log_decision(self, flow: http.HTTPFlow, decision: str, domain: str, reason: str):
        """Log access control decision."""
        write_event(
            "security.access_control",
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            decision=decision,
            domain=domain,
            reason=reason,
        )

    def request(self, flow: http.HTTPFlow):
        """Check network access permissions before request."""
        if not get_option_safe("access_control_enabled", True):
            return

        domain = flow.request.host
        path = flow.request.path
        method = flow.request.method

        engine = get_policy_engine()
        if engine is None:
            return

        self.checks_total += 1

        decision = engine.evaluate_request(domain, path, method)

        # Only act on explicit deny - allow and budget pass through
        if decision.effect == "deny":
            self.denied_total += 1
            client = get_client_ip(flow)
            reason = decision.reason or f"Access denied to {domain}"

            if self._should_block():
                log.warning(f"BLOCKED: {method} {domain}{path} from {client} - access denied")
                self._log_decision(flow, "block", domain, reason)

                flow.metadata["blocked_by"] = self.name
                flow.response = make_block_response(
                    403,
                    {
                        "error": "Access denied by proxy",
                        "domain": domain,
                        "reason": reason,
                        "message": f"Network access to {domain} is not permitted.",
                    },
                    self.name,
                )
            else:
                log.warning(f"WARN: {method} {domain}{path} from {client} - would be denied")
                self._log_decision(flow, "warn", domain, reason)
        else:
            self.allowed_total += 1

    def get_stats(self) -> dict:
        """Get access control statistics."""
        return {
            "enabled": get_option_safe("access_control_enabled", True),
            "checks_total": self.checks_total,
            "allowed_total": self.allowed_total,
            "denied_total": self.denied_total,
        }


addons = [AccessControl()]
