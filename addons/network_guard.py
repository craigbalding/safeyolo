"""
network_guard.py - Unified network policy enforcement

Combines access control (deny rules) and rate limiting (budget enforcement)
into a single addon with one PolicyEngine evaluation per request.

Handles:
- Homoglyph detection (mixed-script domain spoofing) → 403
- Access denial (effect: deny) → 403
- Rate limiting (effect: budget_exceeded) → 429

Load order: Layer 1 (after policy_engine, before credential_guard)

Usage:
    mitmdump -s addons/network_guard.py ...

Example baseline.yaml:
permissions:
  # Deny specific domains
  - action: network:request
    resource: "malware.com/*"
    effect: deny

  # Rate limit API domains
  - action: network:request
    resource: "api.openai.com/*"
    effect: budget
    budget: 3000  # requests per minute

  # Allow everything else (or use effect: deny for allowlist mode)
  - action: network:request
    resource: "*"
    effect: allow
"""

import logging

from mitmproxy import ctx, http

try:
    from confusable_homoglyphs import confusables
    HOMOGLYPH_ENABLED = True
except ImportError:
    HOMOGLYPH_ENABLED = False
    confusables = None

from base import SecurityAddon
from policy_engine import get_policy_engine
from utils import get_client_ip

log = logging.getLogger("safeyolo.network-guard")


def detect_homoglyph_attack(text: str) -> dict | None:
    """Detect mixed-script homoglyph attacks in domain names.

    Catches spoofing attempts like 'api.οpenai.com' where 'ο' is Cyrillic.
    """
    if not HOMOGLYPH_ENABLED or not confusables:
        return None

    try:
        result = confusables.is_dangerous(text)
        if result:
            return {"dangerous": True, "domain": text, "message": f"Mixed scripts detected in '{text}'"}
    except Exception as e:
        log.warning(f"Homoglyph detection failed for '{text}': {type(e).__name__}: {e}")
    return None


class NetworkGuard(SecurityAddon):
    """
    Unified network policy enforcement.

    Single PolicyEngine evaluation per request handles:
    - Access control (deny → 403)
    - Rate limiting (budget_exceeded → 429)
    - Homoglyph detection (mixed scripts → 403)

    Replaces separate access_control + rate_limiter addons to fix
    double budget consumption bug.
    """

    name = "network-guard"

    def __init__(self):
        super().__init__()
        # Additional stats for rate limiting
        self.rate_limited = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="network_guard_enabled",
            typespec=bool,
            default=True,
            help="Enable network guard (access control + rate limiting)",
        )
        loader.add_option(
            name="network_guard_block",
            typespec=bool,
            default=True,
            help="Block violations (False = warn only)",
        )
        loader.add_option(
            name="network_guard_homoglyph",
            typespec=bool,
            default=True,
            help="Block homoglyph/mixed-script domain attacks",
        )

    def _check_homoglyph(self) -> bool:
        """Check if homoglyph detection is enabled."""
        try:
            return ctx.options.network_guard_homoglyph
        except AttributeError:
            return True  # Default on

    def request(self, flow: http.HTTPFlow):
        """Enforce network policy: homoglyphs, access control, rate limits."""
        if not self.is_enabled():
            return

        domain = flow.request.host
        path = flow.request.path
        method = flow.request.method

        self.stats.checks += 1

        # 1. Check for homoglyph attacks first (before policy)
        if self._check_homoglyph():
            homoglyph = detect_homoglyph_attack(domain)
            if homoglyph:
                self._handle_homoglyph(flow, domain, path, method, homoglyph)
                return

        # 2. Single PolicyEngine evaluation for access + rate limiting
        engine = get_policy_engine()
        if engine is None:
            self.stats.allowed += 1
            return

        decision = engine.evaluate_request(domain, path, method)

        # 3. Handle deny → 403
        if decision.effect == "deny":
            self._handle_deny(flow, domain, path, method, decision.reason)
            return

        # 4. Handle budget_exceeded → 429
        if decision.effect == "budget_exceeded":
            self._handle_rate_limit(flow, domain, path, method, decision.reason)
            return

        # 5. Allowed - track remaining budget if present
        self.stats.allowed += 1
        if decision.budget_remaining is not None:
            flow.metadata["ratelimit_remaining"] = decision.budget_remaining

    def _handle_homoglyph(self, flow, domain, path, method, homoglyph):
        """Handle homoglyph attack detection."""
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

    def _handle_deny(self, flow, domain, path, method, reason):
        """Handle access denial."""
        client = get_client_ip(flow)
        reason = reason or f"Access denied to {domain}"

        if self.should_block():
            log.warning(f"BLOCKED: {method} {domain}{path} from {client} - access denied")
            self.log_decision(flow, "block", domain=domain, reason=reason, decision_type="access_denied")
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
            self.log_decision(flow, "warn", domain=domain, reason=reason, decision_type="access_denied")
            self.warn(flow)

    def _handle_rate_limit(self, flow, domain, path, method, reason):
        """Handle rate limit exceeded."""
        client = get_client_ip(flow)
        self.rate_limited += 1

        if self.should_block():
            log.warning(f"BLOCKED: {method} {domain}{path} from {client} - budget exceeded")
            self.log_decision(flow, "block", domain=domain, reason=reason, decision_type="rate_limited")
            self.block(
                flow,
                429,
                {
                    "error": "Rate limited by proxy",
                    "domain": domain,
                    "reason": reason,
                    "message": f"Too many requests to {domain}. Please slow down.",
                },
                {
                    "Retry-After": "60",
                    "X-RateLimit-Remaining": "0",
                },
            )
        else:
            log.warning(f"WARN: {method} {domain}{path} from {client} - budget exceeded")
            self.log_decision(flow, "warn", domain=domain, reason=reason, decision_type="rate_limited")
            self.warn(flow)

    def get_stats(self) -> dict:
        """Get network guard statistics."""
        engine = get_policy_engine()
        budget_stats = engine.get_budget_stats() if engine else {}

        return {
            "enabled": self.is_enabled(),
            "checks": self.stats.checks,
            "allowed": self.stats.allowed,
            "blocked": self.stats.blocked,
            "warned": self.stats.warned,
            "rate_limited": self.rate_limited,
            "budget_stats": budget_stats,
        }


addons = [NetworkGuard()]
