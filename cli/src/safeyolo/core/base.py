"""
base.py - Base class for security-focused mitmproxy addons

Provides common functionality for addons that make security decisions:
- Stats tracking (checks, allowed, blocked, warned)
- Option checking (enabled, block mode)
- Decision logging
- Block response generation

Usage:
    from safeyolo.core.base import SecurityAddon

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

from dataclasses import dataclass
from typing import Any

from mitmproxy import http
from service_discovery import get_service_discovery

from pdp import get_policy_client
from safeyolo.core.audit_schema import ApprovalRequest, Decision, EventKind, Severity
from safeyolo.core.trace import (
    REASON_POLICY_DISABLED,
    STATE_BYPASSED,
    STATE_ERROR,
    STATE_EVALUATED,
    _elapsed_us_from,
    record_step,
    register_expected_addon,
)
from safeyolo.core.utils import (
    find_addon,
    get_client_ip,
    get_option_safe,
    make_block_response,
    write_event,
)


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

    # Set True on addons that a normal outbound request should always traverse.
    # `TraceStore` uses this to synthesise `state=not_loaded` entries at read
    # time for expected addons that did not appear in the trace (issue #213).
    # Left False on addons that only fire on special paths (virtual hosts,
    # port 9090 admin, response-only observability) so absence from a normal
    # request's trace isn't misreported as a failure.
    trace_expected: bool = False

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        name = getattr(cls, "name", None)
        if isinstance(name, str) and name and getattr(cls, "trace_expected", False):
            register_expected_addon(name)

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

    def _resolve_service_discovery(self):
        """Resolve the live service-discovery addon for client-id mapping.

        Prefer the master addon registry. Only fall back to the module-level
        singleton when there is no running master at all (e.g. unit tests): when
        a master exists its registry is authoritative, so an absent addon means
        "unresolved" rather than a reason to consult a possibly-stale singleton.
        """
        try:
            from mitmproxy import ctx
            master = getattr(ctx, "master", None)
        except Exception:  # pragma: no cover - defensive
            master = None

        if master is not None:
            # A running master's addon registry is authoritative: return the live
            # instance (or None if it isn't registered) and never consult the
            # possibly-stale module singleton.
            return find_addon("service-discovery")

        # No running master at all (e.g. unit tests): fall back to the singleton.
        return get_service_discovery()

    def is_bypassed(self, flow: http.HTTPFlow) -> bool:
        """Check if addon is bypassed for this request.

        Returns True if:
        - Flow already has a response (another addon blocked it)
        - Policy says addon is disabled for this domain/client

        Only records `policy_disabled` here; `prior_response` is emitted by
        `@trace_addon_hook` before the addon body runs, so recording it here
        too would double-count. `is_bypassed` is still called by the addon
        body when the decorator has not preempted, e.g. undecorated call
        sites; the prior_response branch is left as a safety net returning
        True without duplicate recording.
        """
        if flow.response:
            return True

        try:
            client = get_policy_client()
        except RuntimeError:
            # PolicyClient not configured — default to not bypassed
            return False

        domain = flow.request.host

        # Get client_id from ServiceDiscovery IP mapping. Resolve the addon via
        # the master registry first; the module-level singleton can be a distinct
        # object that is None under the addon loader, which would silently drop
        # per-client policy resolution (client_id stays None) proxy-wide.
        discovery = self._resolve_service_discovery()
        if discovery:
            client_ip = get_client_ip(flow)
            client_id = discovery.get_client_for_ip(client_ip)
            # Non-identities are not project scopes: "default" (no specific
            # project) and "unknown" (unmapped source) both resolve to None so
            # per-client rules aren't evaluated against a literal placeholder.
            if not client_id or client_id in ("unknown", "default"):
                client_id = None
        else:
            client_id = None

        if not client.is_addon_enabled(self.name, domain, client_id):
            self._trace_bypassed(flow, reason=REASON_POLICY_DISABLED)
            return True
        return False

    def log_decision(
        self,
        flow: http.HTTPFlow,
        decision: Decision,
        *,
        severity: Severity,
        summary: str,
        host: str | None = None,
        approval: ApprovalRequest | None = None,
        **details: Any,
    ) -> None:
        """Log security decision to audit log.

        Args:
            flow: HTTP flow for request_id correlation
            decision: Decision enum value
            severity: Event severity
            summary: Human-readable one-liner
            host: Destination hostname
            approval: Approval request metadata
            **details: Additional addon-specific fields
        """
        event_type = f"security.{self._option_prefix()}"

        write_event(
            event_type,
            kind=EventKind.SECURITY,
            severity=severity,
            summary=summary,
            decision=decision,
            host=host,
            request_id=flow.metadata.get("request_id"),
            agent=flow.metadata.get("agent"),
            addon=self.name,
            approval=approval,
            details=details if details else None,
        )

    def block(
        self,
        flow: http.HTTPFlow,
        status: int,
        body: dict,
        extra_headers: dict | None = None,
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
        flow.response = make_block_response(
            status,
            body,
            self.name,
            extra_headers,
            request_id=flow.metadata.get("request_id"),
        )
        self._trace_evaluated(flow, outcome="blocked", status=status)

    def warn(self, flow: http.HTTPFlow) -> None:
        """Record a warning (would-block in warn mode)."""
        self.stats.warned += 1
        self._trace_evaluated(flow, outcome="warned")

    # -- trace helpers ----------------------------------------------------
    # No-op unless the flow opted into tracing (issue #213). Addons that
    # want to record `state=evaluated` on their allow/no-detection path
    # call `_trace_evaluated(flow, outcome=...)` directly; the base class
    # already records blocked/warned/bypassed automatically.

    def _trace_evaluated(
        self,
        flow: http.HTTPFlow,
        *,
        outcome: str,
        hook: str = "request",
        duration_us: int | None = None,
        **details: Any,
    ) -> None:
        if duration_us is None:
            duration_us = _elapsed_us_from(flow, self.name, hook)
        record_step(
            flow,
            addon=self.name,
            hook=hook,
            state=STATE_EVALUATED,
            outcome=outcome,
            duration_us=duration_us,
            details=details or None,
        )

    def _trace_bypassed(
        self,
        flow: http.HTTPFlow,
        *,
        reason: str,
        hook: str = "request",
    ) -> None:
        # No duration for bypassed steps — either the hook was preempted
        # before entering (prior_response) or the addon short-circuited on
        # a policy/option check, neither of which is meaningful runtime.
        record_step(
            flow,
            addon=self.name,
            hook=hook,
            state=STATE_BYPASSED,
            reason=reason,
        )

    def _trace_error(
        self,
        flow: http.HTTPFlow,
        *,
        exc: BaseException,
        hook: str = "request",
    ) -> None:
        # Record the exception TYPE only. The message can carry request-derived
        # content (URL fragments, header values) and must not leak into trace.
        record_step(
            flow,
            addon=self.name,
            hook=hook,
            state=STATE_ERROR,
            reason=type(exc).__name__,
            duration_us=_elapsed_us_from(flow, self.name, hook),
        )

    def get_stats(self) -> dict[str, Any]:
        """Return stats dict for admin API."""
        return {
            "enabled": self.is_enabled(),
            "checks_total": self.stats.checks,
            "allowed_total": self.stats.allowed,
            "blocked_total": self.stats.blocked,
            "warned_total": self.stats.warned,
        }
