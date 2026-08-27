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

from pdp import get_policy_client
from safeyolo.core.audit_schema import ApprovalRequest, Decision, EventKind, Severity
from safeyolo.core.identity import AgentIdentity, IdentityStatus, resolve_agent_identity
from safeyolo.core.trace import (
    REASON_POLICY_DISABLED,
    REASON_PRIOR_RESPONSE,
    STATE_BYPASSED,
    STATE_ERROR,
    STATE_EVALUATED,
    _elapsed_us_from,
    record_step,
)
from safeyolo.core.utils import (
    find_addon,
    get_option_safe,
    make_block_response,
    write_event,
)
from safeyolo.mitm_addons.service_discovery import get_service_discovery


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

    # Documentation-only marker: True on addons that a normal outbound request
    # should always traverse. Not a functional registry — the source of truth
    # is `safeyolo.core.trace.EXPECTED_ADDONS` (issue #213 second-pass review:
    # a manifest independent of module import so a truly absent addon is still
    # reportable).
    trace_expected: bool = False

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

    def resolve_agent_identity(self, flow: http.HTTPFlow) -> AgentIdentity:
        """Resolve and stamp this flow's identity from trusted sources."""
        return resolve_agent_identity(flow, self._resolve_service_discovery())

    def is_bypassed(self, flow: http.HTTPFlow) -> bool:
        """Check if addon is bypassed for this request.

        Returns True if:
        - Flow already has a response (another addon blocked it)
        - Policy says addon is disabled for this domain/client

        Both branches emit their own trace evidence so callers can
        distinguish `prior_response` from `policy_disabled`. The decorator
        is observation-only and does NOT emit `bypassed/*` on the addon's
        behalf (issue #213 second-pass review: tracing must not alter which
        code executes; the addon owns its short-circuit decision AND its
        trace evidence).
        """
        if flow.response:
            self._trace_bypassed(flow, reason=REASON_PRIOR_RESPONSE)
            return True

        identity = self.resolve_agent_identity(flow)
        if identity.status is IdentityStatus.CONFLICT:
            # A disagreement must be evaluated and denied by the security
            # addon, never converted into an unscoped policy bypass.
            return False

        try:
            client = get_policy_client()
        except RuntimeError:
            # PolicyClient not configured — default to not bypassed
            return False

        domain = flow.request.host

        # Identity conflicts and unavailable identities never become policy
        # scopes. The resolver also prevents untrusted metadata from supplying
        # a scope when the connection has no trusted identity.
        client_id = identity.agent if identity.is_resolved else None

        # Policy files use Python/config-style addon keys (``network_guard``),
        # while runtime/audit labels use kebab case (``network-guard``).
        # Options already use this normalized prefix; policy lookups must use
        # the same key or configured bypasses are silently ignored.
        policy_addon_name = self._option_prefix()
        if not client.is_addon_enabled(policy_addon_name, domain, client_id):
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
        # Surface the PDP / addon-specific deny reason to downstream readers
        # (request_logger, traffic view, `safeyolo logs`) via the same
        # metadata channel as `blocked_by`, so operators don't have to
        # correlate the security event by request_id (issue #337). Every
        # existing block() caller passes the reason in `body["reason"]` —
        # promote it here rather than change every caller.
        reason = body.get("reason") if isinstance(body, dict) else None
        if reason:
            flow.metadata["block_reason"] = reason
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
