"""
test_context.py - Link HTTP traffic to test activities

Requires operator-declared test target hosts to include an
X-SafeYolo-Test-Context header. Valid headers on any host opt that request
into test provenance and FlowStore recording, even when the host is not an
enforcement target.

Requests without the header to non-target hosts pass through untouched.

Declared context (mobile / header-less traffic):
- Native apps cannot attach X-SafeYolo-Test-Context. When enabled, the
  operating agent can declare its current test context out-of-band via the
  Agent API. A target-host request that arrives WITHOUT a usable header then
  inherits the caller's active declaration (bound to (source_id,
  trusted_agent), monotonic TTL) and is recorded exactly as a valid-header
  flow would be.
- A valid explicit header always wins. The declaration fallback is never used
  for a non-empty malformed header. When neither a usable header nor an
  applicable declaration is present, ordinary block/warn policy applies (428 in
  block mode; warn + forward, unrecorded, in warn mode) — unchanged by this
  feature.

Design:
- Active when target_hosts is non-empty in policy.yaml (no separate enable flag)
- Soft-reject (428) for missing/malformed context headers on target hosts
- Logs structured events for request and response with parsed context
- Body capture: first 4KB head + tail lines for truncated bodies

Usage:
    mitmdump -s addons/test_context.py --set test_context_block=true
"""

import logging
import math
import threading
import time

from mitmproxy import http

from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.base import SecurityAddon
from safeyolo.core.trace import REASON_PRIOR_RESPONSE, trace_addon_hook
from safeyolo.core.utils import (
    get_client_ip,
    get_option_safe,
    matches_host_pattern,
    sanitize_for_log,
    write_event,
)
from safeyolo.test_context_contract import (
    MAX_CONTEXT_PAIRS,
    TEST_CONTEXT_HEADER,
    TestContextError,
    parse_test_context,
)

log = logging.getLogger("safeyolo.test-context")


# =============================================================================
# Trace outcome vocabulary (issue #213)
# =============================================================================
OUTCOME_ALLOWED = "allowed"
# Emitted for requests to hosts NOT in target_hosts and with no context
# header — proves the addon ran and correctly decided not to enforce, rather
# than showing as `not_loaded` (which would be the false-not-loaded pattern
# the #213 review flagged).
OUTCOME_NOT_TARGET_HOST = "not_target_host"
# Response-hook outcomes.
OUTCOME_RESPONSE_RECORDED = "response_recorded"     # captured response event for a tracked flow
OUTCOME_NOT_APPLICABLE = "not_applicable"           # response hook ran; no test_context on flow

_MAX_CONTEXT_PAIRS = MAX_CONTEXT_PAIRS

# Fallback TTL ceiling if neither policy config nor the mitmproxy option yields
# a usable positive integer.
_DEFAULT_DECLARED_TTL = 900

_LIVE_METADATA_FIELDS = {
    "run": "test_run",
    "agent": "test_agent",
    "role": "test_role",
    "suite": "test_suite",
    "subject": "test_subject",
    "step": "test_step",
    "test": "test_id",
    "intent": "test_intent",
    "expect": "test_expect",
}


def _parse_context_header(value: str) -> dict | None:
    """Compatibility wrapper returning ``None`` for invalid context.

    The reusable parser and formatter live in ``safeyolo.test_context_contract``.
    """
    try:
        return parse_test_context(value)
    except TestContextError:
        return None


def _capture_body(content: bytes, max_head: int = 4096, tail_lines: int = 5) -> str:
    """Capture body content with truncation for large bodies.

    Returns first max_head bytes as string, plus tail lines if truncated.
    """
    if not content:
        return ""

    total_size = len(content)
    text = content[:max_head].decode("utf-8", errors="replace")

    if total_size <= max_head:
        return text

    # Decode only the last 8KB for tail extraction (not the entire body)
    tail_chunk = content[-8192:]
    tail_text = tail_chunk.decode("utf-8", errors="replace")
    lines = tail_text.rstrip("\n").split("\n")
    tail = "\n".join(lines[-tail_lines:]) if len(lines) > tail_lines else ""

    result = text + f"\n...[truncated, {total_size} bytes total]...\n"
    if tail:
        result += tail

    return result


def _promote_live_metadata(flow: http.HTTPFlow, context: dict[str, str]) -> bool | None:
    """Expose canonical context fields without replacing trusted identity."""
    for context_key, metadata_key in _LIVE_METADATA_FIELDS.items():
        if context_key in context:
            flow.metadata[metadata_key] = context[context_key]

    trusted_agent = flow.metadata.get("agent")
    declared_agent = context.get("agent")
    if trusted_agent is None or declared_agent is None:
        return None

    agent_matches = trusted_agent == declared_agent
    flow.metadata["test_agent_match"] = agent_matches
    return agent_matches


class TestContext(SecurityAddon):
    """Link test HTTP traffic to test activities via X-SafeYolo-Test-Context header."""

    name = "test-context"
    trace_expected = True

    def __init__(self):
        super().__init__()
        self._target_hosts: list[str] = []
        self._last_policy_hash: str = ""

        # Declared-context state (mobile / header-less traffic). Owned here so a
        # single component enforces the TTL and its maximum. In-memory only: a
        # proxy restart invalidates every declaration by design.
        # source_id -> (trusted_agent, context, expires_at_monotonic)
        self._declarations: dict[str, tuple[str, dict[str, str], float]] = {}
        self._declared_lock = threading.Lock()
        self._declared_injections_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="test_context_block",
            typespec=bool,
            default=True,
            help="Block (428) requests to target hosts missing context header",
        )
        loader.add_option(
            name="test_context_inject_declared",
            typespec=bool,
            default=False,
            help=(
                "Allow target-host header-less traffic to inherit the operating "
                "agent's declared test context (fallback default; may be "
                "overridden by addons.test_context.inject_declared)"
            ),
        )
        loader.add_option(
            name="test_context_declared_ttl",
            typespec=int,
            default=_DEFAULT_DECLARED_TTL,
            help=(
                "Maximum TTL (seconds) for a declared test context (fallback "
                "default; may be overridden by addons.test_context.declared_ttl_max)"
            ),
        )

    def _maybe_reload_config(self):
        """Reload target_hosts from PDP if policy changed."""
        import safeyolo.core.config_cache as config_cache
        try:
            sensor_config = config_cache.get_or_raise()
        except RuntimeError:
            # PolicyClient not configured yet
            return
        except Exception as exc:
            log.warning(f"Failed to reload test context config: {type(exc).__name__}: {exc}")
            return
        policy_hash = sensor_config.get("policy_hash", "")
        if policy_hash != self._last_policy_hash:
            pc_config = sensor_config.get("addons", {}).get("test_context", {})
            self._target_hosts = pc_config.get("target_hosts", [])
            self._last_policy_hash = policy_hash
            if self._target_hosts:
                log.info(f"Loaded {len(self._target_hosts)} test target hosts")

    def _is_target_host(self, host: str) -> bool:
        """Check if host matches any configured target host pattern."""
        for pattern in self._target_hosts:
            if matches_host_pattern(host, pattern):
                return True
        return False

    # ------------------------------------------------------------------
    # Declared-context: effective configuration (single source of truth)
    # ------------------------------------------------------------------

    def _inject_declared_enabled(self) -> bool:
        """Whether declared-context injection is active.

        Dynamic addon config wins over the mitmproxy option; a malformed config
        value falls back to the option rather than failing open/closed randomly.
        """
        import safeyolo.core.config_cache as config_cache

        section = config_cache.addon_section("test_context")
        if "inject_declared" in section:
            value = section["inject_declared"]
            if isinstance(value, bool):
                return value
            log.warning("Invalid test_context.inject_declared; using mitmproxy option")

        return bool(get_option_safe("test_context_inject_declared", False))

    def _declared_ttl_max(self) -> int:
        """The single authoritative maximum TTL for a declaration (seconds)."""
        import safeyolo.core.config_cache as config_cache

        option_default = get_option_safe("test_context_declared_ttl", _DEFAULT_DECLARED_TTL)

        section = config_cache.addon_section("test_context")
        value = section.get("declared_ttl_max", option_default)

        # Reject non-int (incl. bool) and non-positive values; fall back safely.
        if type(value) is not int or value <= 0:
            log.warning("Invalid test_context.declared_ttl_max; using fallback")
            value = option_default

        if type(value) is not int or value <= 0:
            return _DEFAULT_DECLARED_TTL

        return value

    # ------------------------------------------------------------------
    # Declared-context: store operations (thread-safe)
    # ------------------------------------------------------------------

    def set_declaration(
        self,
        source_id: str,
        trusted_agent: str,
        context: dict[str, str],
        ttl_s: int | None,
    ) -> int:
        """Store the caller's current declared context. Returns granted TTL.

        Raises ValueError on an unusable identity or an invalid explicit TTL.
        """
        if not source_id or source_id == "unknown":
            raise ValueError("invalid source identity")
        if not trusted_agent or trusted_agent in ("unknown", "default"):
            raise ValueError("invalid trusted agent")

        ttl_max = self._declared_ttl_max()

        if ttl_s is None:
            granted = ttl_max
        else:
            # bool is a subclass of int; `type(...) is not int` rejects it.
            if type(ttl_s) is not int or ttl_s <= 0:
                raise ValueError("ttl must be a positive integer")
            granted = min(ttl_s, ttl_max)

        expires_at = time.monotonic() + granted
        with self._declared_lock:
            self._declarations[source_id] = (trusted_agent, dict(context), expires_at)
        return granted

    def get_declaration(
        self,
        source_id: str,
        trusted_agent: str,
    ) -> tuple[dict[str, str], int] | None:
        """Return (context_copy, expires_in_seconds) or None.

        Expiry inspection and deletion happen inside a single lock acquisition
        so a concurrently-replaced declaration is never removed by a stale read.
        Agent mismatch invalidates the stale declaration immediately — this is
        the network-slot reuse guard.
        """
        now = time.monotonic()
        with self._declared_lock:
            rec = self._declarations.get(source_id)
            if rec is None:
                return None

            agent, context, expires_at = rec

            if agent != trusted_agent:
                self._declarations.pop(source_id, None)
                return None

            if now >= expires_at:
                self._declarations.pop(source_id, None)
                return None

            expires_in = max(1, math.ceil(expires_at - now))
            return dict(context), expires_in

    def clear_declaration(self, source_id: str) -> bool:
        """Remove the caller's declaration. Returns whether one existed."""
        with self._declared_lock:
            return self._declarations.pop(source_id, None) is not None

    def _declared_active_count(self) -> int:
        """Count of currently-unexpired declarations, lazily evicting expired."""
        now = time.monotonic()
        with self._declared_lock:
            expired = [k for k, (_a, _c, exp) in self._declarations.items() if now >= exp]
            for k in expired:
                self._declarations.pop(k, None)
            return len(self._declarations)

    def _trusted_agent(self, flow: http.HTTPFlow) -> str | None:
        """Resolve the trusted agent for the injection path, self-sufficiently.

        Does not depend on service_discovery.request() having already stamped
        flow.metadata["agent"]; ensures flow_recorder later sees the same
        trusted identity that authorized the declaration. Resolution uses the
        inherited SecurityAddon._resolve_service_discovery() (master registry
        authoritative; singleton fallback only when there is no running master).
        """
        identity = self.resolve_agent_identity(flow)
        if not identity.is_resolved:
            log.warning(
                "Trusted agent identity unavailable for source %s: %s",
                sanitize_for_log(get_client_ip(flow)),
                identity.reason,
            )
            return None
        return identity.agent

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    def _apply_context(
        self,
        flow: http.HTTPFlow,
        context: dict[str, str],
        *,
        source: str,
    ) -> bool | None:
        """Apply a validated context (explicit or declared) to a flow.

        Sets flow.metadata["test_context"] (the flow_recorder recording gate),
        promotes live metadata, and emits the request security.test_context
        audit event with honest provenance. `source` is one of
        "header" | "declared".

        Response duration is calculated from flow.metadata["start_time"]
        (stamped by the request_id addon before test_context runs), so this
        method does not store a separate request-time key.
        """
        flow.metadata["test_context"] = dict(context)
        # Internal correlation only — NOT a FlowStore field. response() reads it
        # back to stamp the same provenance on the response audit event.
        flow.metadata["test_context_source"] = source

        test_agent_match = _promote_live_metadata(flow, context)

        request_body = _capture_body(flow.request.content or b"")

        write_event(
            "security.test_context",
            kind=EventKind.SECURITY,
            severity=Severity.LOW,
            summary=(
                f"Test context request: {flow.request.method} "
                f"{sanitize_for_log(flow.request.host)}{sanitize_for_log(flow.request.path)}"
            ),
            host=flow.request.host,
            request_id=flow.metadata.get("request_id"),
            agent=flow.metadata.get("agent"),
            addon=self.name,
            details={
                "phase": "request",
                "method": flow.request.method,
                "path": flow.request.path,
                "context": context,
                "trusted_agent": flow.metadata.get("agent"),
                "test_agent_match": test_agent_match,
                "test_context_source": source,
                "request_body_snippet": request_body[:512] if request_body else "",
            },
        )

        self.stats.allowed += 1
        if source == "declared":
            self._declared_injections_total += 1
        self._trace_evaluated(flow, outcome=OUTCOME_ALLOWED, context_source=source)

        return test_agent_match

    def _reject_missing_or_malformed(self, flow: http.HTTPFlow, reason: str):
        """Apply existing block/warn policy for a missing/malformed target-host
        request. Does not touch the reserved header (callers strip it first)."""
        if self.should_block():
            self.log_decision(
                flow,
                Decision.DENY,
                severity=Severity.HIGH,
                summary=f"Test context {reason} for {sanitize_for_log(flow.request.host)}",
                host=flow.request.host,
                reason=reason,
                path=flow.request.path,
                method=flow.request.method,
            )
            body = {
                "error": "Test context required",
                "type": reason,
                "destination": flow.request.host,
                "action": "add_header",
                "header": TEST_CONTEXT_HEADER,
                "format": "run=<run_id>;agent=<agent_id>;test=<test_id>",
                "example": f"{TEST_CONTEXT_HEADER}: run=sec1;agent=idor;test=IDOR-003",
                "reflection": f"Add {TEST_CONTEXT_HEADER} header to link this request to your test activity.",
            }
            self.block(flow, 428, body)
        else:
            self.log_decision(
                flow,
                Decision.WARN,
                severity=Severity.HIGH,
                summary=f"Test context {reason} for {sanitize_for_log(flow.request.host)} (warn)",
                host=flow.request.host,
                reason=reason,
                path=flow.request.path,
                method=flow.request.method,
            )
            self.warn(flow)

    @trace_addon_hook("request")
    def request(self, flow: http.HTTPFlow):
        """Check requests to target hosts for context header.

        Active when target_hosts is non-empty in policy.yaml.
        No separate enable flag - add target hosts to activate, remove to deactivate.
        """
        if flow.response:
            self._trace_bypassed(flow, reason=REASON_PRIOR_RESPONSE)
            return

        self._maybe_reload_config()

        is_target = self._is_target_host(flow.request.host)
        header_present = TEST_CONTEXT_HEADER in flow.request.headers
        header_value = flow.request.headers.get(TEST_CONTEXT_HEADER, "")

        # An explicitly empty reserved header is semantically "missing", but the
        # reserved header must never leak upstream — strip it now.
        if header_present and not header_value:
            del flow.request.headers[TEST_CONTEXT_HEADER]

        # Optional provenance is inert unless the caller supplies a usable header.
        if not is_target and not header_value:
            # Emit evidence we ran and chose not to enforce. Absent this the
            # addon would look identical to `not_loaded` for every non-target
            # host, which is the false-not-loaded pattern #213 exists to fix.
            self._trace_evaluated(flow, outcome=OUTCOME_NOT_TARGET_HOST)
            return

        self.stats.checks += 1

        # Parse context header
        context = _parse_context_header(header_value)

        if context is None:
            if not is_target:
                # Non-empty invalid optional annotation on a non-target host: the
                # reserved header must not leak upstream, but an invalid optional
                # annotation must not turn an ordinary host into an enforcement
                # target.
                if TEST_CONTEXT_HEADER in flow.request.headers:
                    del flow.request.headers[TEST_CONTEXT_HEADER]
                self.log_decision(
                    flow,
                    Decision.WARN,
                    severity=Severity.MEDIUM,
                    summary=(
                        "Malformed optional test context for "
                        f"{sanitize_for_log(flow.request.host)}"
                    ),
                    host=flow.request.host,
                    reason="malformed_optional_context",
                    path=flow.request.path,
                    method=flow.request.method,
                )
                self.warn(flow)
                return

            if header_value:
                # Non-empty malformed header on a target host. The declaration
                # fallback is NEVER used here (broken explicit instrumentation
                # must not be masked); ordinary block/warn policy applies below.
                # Strip the reserved header before block/warn so it never leaks
                # upstream (fixes a warn-mode leak in the previous behavior).
                if TEST_CONTEXT_HEADER in flow.request.headers:
                    del flow.request.headers[TEST_CONTEXT_HEADER]
                self._reject_missing_or_malformed(flow, "malformed_context")
                return

            # Missing or explicitly empty header on a target host: try to inherit
            # the operating agent's declared context.
            if self._inject_declared_enabled():
                source_id = get_client_ip(flow)
                agent = self._trusted_agent(flow)
                if agent is not None:
                    rec = self.get_declaration(source_id, agent)
                    if rec is not None:
                        declared_context, _expires_in = rec
                        self._apply_context(flow, declared_context, source="declared")
                        return

            self._reject_missing_or_malformed(flow, "missing_context")
            return

        # Valid context - strip before sending upstream, then apply + record.
        del flow.request.headers[TEST_CONTEXT_HEADER]
        self._apply_context(flow, context, source="header")

    @trace_addon_hook("response")
    def response(self, flow: http.HTTPFlow):
        """Log response for requests that had valid context."""
        context = flow.metadata.get("test_context")
        if context is None:
            self._trace_evaluated(flow, outcome=OUTCOME_NOT_APPLICABLE, hook="response")
            return

        # Response duration comes from the request_id addon's start_time stamp
        # (set before test_context runs). No separate request-time key needed.
        start_time = flow.metadata.get("start_time", 0)
        duration_ms = int((time.time() - start_time) * 1000) if start_time else 0

        response_body = _capture_body(flow.response.content or b"") if flow.response else ""

        write_event(
            "security.test_context",
            kind=EventKind.SECURITY,
            severity=Severity.LOW,
            summary=f"Test context response: {flow.response.status_code if flow.response else 0} {sanitize_for_log(flow.request.host)}{sanitize_for_log(flow.request.path)}",
            host=flow.request.host,
            request_id=flow.metadata.get("request_id"),
            # Attribute to the resolved agent so /explain's strict scope
            # filter (issue #213) doesn't drop this response-side event.
            # The matching request-side event already carries this — the
            # omission here was the false-scope leak the reviewer caught.
            agent=flow.metadata.get("agent"),
            addon=self.name,
            details={
                "phase": "response",
                "method": flow.request.method,
                "path": flow.request.path,
                "context": context,
                "trusted_agent": flow.metadata.get("agent"),
                "test_agent_match": flow.metadata.get("test_agent_match"),
                "test_context_source": flow.metadata.get("test_context_source"),
                "status_code": flow.response.status_code if flow.response else 0,
                "response_body_snippet": response_body[:512] if response_body else "",
                "duration_ms": duration_ms,
            },
        )
        self._trace_evaluated(
            flow,
            outcome=OUTCOME_RESPONSE_RECORDED,
            hook="response",
            status_code=flow.response.status_code if flow.response else 0,
        )

    def get_stats(self) -> dict:
        """Return stats for admin API."""
        return {
            "active": len(self._target_hosts) > 0,
            "target_hosts": len(self._target_hosts),
            "checks_total": self.stats.checks,
            "allowed_total": self.stats.allowed,
            "blocked_total": self.stats.blocked,
            "warned_total": self.stats.warned,
            "declared_injections_total": self._declared_injections_total,
            "declared_active": self._declared_active_count(),
        }


addons = [TestContext()]
