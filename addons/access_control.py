"""
access_control.py - Network access control addon for client internet reach limits

Enforces allow/deny rules for network:request permissions from PolicyEngine.
Use this to restrict which domains coding agents can access.

Also detects homoglyph attacks (mixed-script domain spoofing like api.οpenai.com
with Cyrillic 'o') to prevent phishing via lookalike domains.

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
from typing import Optional

from mitmproxy import ctx, http

try:
    from confusable_homoglyphs import confusables
    HOMOGLYPH_ENABLED = True
except ImportError:
    HOMOGLYPH_ENABLED = False
    confusables = None

try:
    from .base import SecurityAddon
    from .utils import get_client_ip
    from .policy_engine import get_policy_engine
except ImportError:
    from base import SecurityAddon
    from utils import get_client_ip
    from policy_engine import get_policy_engine

log = logging.getLogger("safeyolo.access-control")


def detect_homoglyph_attack(text: str) -> Optional[dict]:
    """Detect mixed-script homoglyph attacks in domain names.

    Catches spoofing attempts like 'api.οpenai.com' where 'ο' is Cyrillic.
    """
    if not HOMOGLYPH_ENABLED or not confusables:
        return None

    try:
        result = confusables.is_dangerous(text)
        if result:
            return {"dangerous": True, "domain": text, "message": f"Mixed scripts detected in '{text}'"}
    except Exception:
        pass
    return None


class AccessControl(SecurityAddon):
    """
    Network access control based on PolicyEngine allow/deny rules.

    Evaluates network:request permissions and blocks requests with effect: deny.
    Requests with effect: allow or effect: budget pass through to other addons.
    """

    name = "access-control"

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
        loader.add_option(
            name="access_control_homoglyph",
            typespec=bool,
            default=True,
            help="Block homoglyph/mixed-script domain attacks",
        )

    def _check_homoglyph(self) -> bool:
        """Check if homoglyph detection is enabled."""
        try:
            return ctx.options.access_control_homoglyph
        except AttributeError:
            return True  # Default on

    def request(self, flow: http.HTTPFlow):
        """Check network access permissions before request."""
        if not self.is_enabled():
            return

        domain = flow.request.host
        path = flow.request.path
        method = flow.request.method

        self.stats.checks += 1

        # Check for homoglyph attacks first (before policy)
        if self._check_homoglyph():
            homoglyph = detect_homoglyph_attack(domain)
            if homoglyph:
                client = get_client_ip(flow)
                reason = f"Homoglyph attack detected: {homoglyph['message']}"

                if self.should_block():
                    log.warning(f"BLOCKED: {method} {domain}{path} from {client} - {reason}")
                    self.log_decision(flow, "block", domain=domain, reason=reason, attack_type="homoglyph")
                    self.block(
                        flow,
                        403,
                        {
                            "error": "Domain blocked by proxy",
                            "domain": domain,
                            "reason": reason,
                            "attack_type": "homoglyph",
                            "message": "This domain contains mixed-script characters that may indicate a spoofing attempt.",
                        },
                    )
                else:
                    log.warning(f"WARN: {method} {domain}{path} from {client} - {reason}")
                    self.log_decision(flow, "warn", domain=domain, reason=reason, attack_type="homoglyph")
                    self.warn(flow)
                return

        # Check policy engine rules
        engine = get_policy_engine()
        if engine is None:
            self.stats.allowed += 1
            return

        decision = engine.evaluate_request(domain, path, method)

        # Only act on explicit deny - allow and budget pass through
        if decision.effect == "deny":
            client = get_client_ip(flow)
            reason = decision.reason or f"Access denied to {domain}"

            if self.should_block():
                log.warning(f"BLOCKED: {method} {domain}{path} from {client} - access denied")
                self.log_decision(flow, "block", domain=domain, reason=reason)
                self.block(
                    flow,
                    403,
                    {
                        "error": "Access denied by proxy",
                        "domain": domain,
                        "reason": reason,
                        "message": f"Network access to {domain} is not permitted.",
                    },
                )
            else:
                log.warning(f"WARN: {method} {domain}{path} from {client} - would be denied")
                self.log_decision(flow, "warn", domain=domain, reason=reason)
                self.warn(flow)
        else:
            self.stats.allowed += 1

    def get_stats(self) -> dict:
        """Get access control statistics."""
        return {
            "enabled": self.is_enabled(),
            **self.stats.__dict__,
        }


addons = [AccessControl()]
