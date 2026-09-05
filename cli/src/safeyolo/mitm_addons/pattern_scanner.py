"""
pattern_scanner.py - User-configurable pattern scanning

A framework for security-conscious users to define custom patterns for detecting
sensitive data crossing the proxy boundary. Scans URLs, headers, HTTP bodies,
and complete WebSocket messages.

Complements credential_guard:
  credential_guard: Credential ROUTING (is this key going to the right host?)
  pattern_scanner: Pattern DETECTION (should this content be blocked/logged?)

The scanner starts empty until policy is loaded. SafeYolo's shipped addon
configuration enables the `secrets` set; operators can configure it via:

    # Enable optional builtin pattern sets
    pattern_scanner:
      builtin_sets: [secrets]  # Available: secrets, pii

    # Add custom patterns
    scan_patterns:
      - name: internal-project-ids
        pattern: "PROJ-[0-9]{5}"
        target: request        # request | response | both
        scope: [body, url]     # url | headers | body (default: [body])
        action: block          # block | log
        message: "Internal project ID detected"

Usage:
    mitmdump -s addons/pattern_scanner.py --set pattern_block_request=true
    mitmdump -s addons/pattern_scanner.py --set pattern_block_websocket_request=true
"""

import logging
from dataclasses import dataclass
from urllib.parse import unquote

from mitmproxy import ctx, http
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode

from safeyolo.core.audit_schema import Decision, Severity
from safeyolo.core.base import SecurityAddon
from safeyolo.core.trace import trace_addon_hook
from safeyolo.core.utils import make_block_response, sanitize_for_log
from safeyolo.detection.patterns import (
    PatternRule,
    load_builtin_set,
    load_patterns_from_config,
)

log = logging.getLogger("safeyolo.pattern-scanner")


# =============================================================================
# Trace outcome vocabulary (issue #213)
# =============================================================================
OUTCOME_NO_RULES = "no_rules"
OUTCOME_NO_MATCH = "no_match"
OUTCOME_MATCH_LOGGED = "match_logged"     # rule matched, warn-only mode
OUTCOME_MATCH_BLOCKED = "match_blocked"   # rule matched and produced a block

WEBSOCKET_MESSAGE_TYPES = (Opcode.TEXT, Opcode.BINARY)

# URL inspection is deliberately bounded independently from FlowStore.  The
# latter retains the original request for its scoped evidence contract; this
# hot-path representation is only for matching and must not become an
# unbounded allocation or an operational publication surface.
MAX_URL_SCAN_BYTES = 16 * 1024
# Public alias for callers/tests that describe the bound in characters.  The
# actual limit is applied to UTF-8 bytes so malformed Unicode is deterministic.
MAX_URL_SCAN_LENGTH = MAX_URL_SCAN_BYTES

URL_INSPECTION_OK = "ok"
URL_INSPECTION_OVERFLOW = "url_inspection_overflow"
URL_INSPECTION_ERROR = "url_inspection_error"

_SAFE_ACTIONS = frozenset({"block", "log"})
_SAFE_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True, slots=True)
class _URLInspection:
    """Bounded URL representations and the result of inspecting their input."""

    raw: str = ""
    decoded: str = ""
    status: str = URL_INSPECTION_OK

    @property
    def inspectable(self) -> bool:
        return self.status == URL_INSPECTION_OK


def _bounded_source_bytes(value: object) -> tuple[bytes | None, bool]:
    """Capture at most the URL budget and report whether the source overflowed."""
    if isinstance(value, bytes):
        bounded = value[: MAX_URL_SCAN_BYTES + 1]
        return bounded[:MAX_URL_SCAN_BYTES], len(bounded) > MAX_URL_SCAN_BYTES

    if isinstance(value, str):
        result = bytearray()
        for character in value:
            encoded = character.encode("utf-8", errors="surrogatepass")
            if len(result) + len(encoded) > MAX_URL_SCAN_BYTES:
                return bytes(result), True
            result.extend(encoded)
        return bytes(result), False

    # Do not call an attacker-controlled __str__: it can allocate an unbounded
    # value or raise an exception carrying inspected data.
    return None, False


def _bounded_text(value: str) -> str | None:
    """Normalize text and reject UTF-8 expansion instead of truncating it."""
    try:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) > MAX_URL_SCAN_BYTES:
            return None
        return encoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _bounded_url_representations(value: object) -> _URLInspection:
    """Return the bounded raw URL and one canonical, non-recursive decode.

    ``urllib.parse.unquote`` decodes each ``%HH`` sequence once.  It leaves
    malformed/truncated escapes alone and, with replacement errors, gives
    invalid UTF-8 bytes a deterministic representation.  Normalising to a
    bounded UTF-8 byte string before calling it also handles duck-typed test
    flows and lone surrogate values without exposing an exception message.

    Fragments are not sent in HTTP requests and therefore are excluded from
    URL scope.  No parsed query structure is built: encoded delimiters,
    duplicate parameters, and their ordering remain visible to the matcher in
    both representations without changing request semantics.
    """
    try:
        raw_bytes, overflowed = _bounded_source_bytes(value)
        if raw_bytes is None:
            return _URLInspection(status=URL_INSPECTION_ERROR)
        if overflowed:
            return _URLInspection(status=URL_INSPECTION_OVERFLOW)

        raw = _bounded_text(raw_bytes.decode("utf-8", errors="replace"))
        if raw is None:
            return _URLInspection(status=URL_INSPECTION_OVERFLOW)
    except Exception:
        # The request hook must not publish exception text containing an input
        # value.  This is a deterministic, content-free inspection failure.
        return _URLInspection(status=URL_INSPECTION_ERROR)

    # A literal fragment is never part of the request target.  A percent-
    # encoded '#' is intentionally retained and decoded in the second pass.
    raw = raw.split("#", 1)[0]
    try:
        decoded = _bounded_text(unquote(raw, encoding="utf-8", errors="replace"))
        if decoded is None:
            return _URLInspection(status=URL_INSPECTION_OVERFLOW)
    except Exception:
        # Defensive only: the normalised raw value above is accepted by
        # unquote.  Keeping this branch content-free preserves fail-closed
        # diagnostics if that implementation ever changes.
        return _URLInspection(status=URL_INSPECTION_ERROR)
    return _URLInspection(raw=raw, decoded=decoded)


def _safe_value(value: object, *, max_len: int, fallback: str) -> str:
    """Return bounded evidence without allowing conversion errors to escape."""
    try:
        value = sanitize_for_log(value, max_len=max_len)
    except Exception:
        return fallback[:max_len]
    # sanitize_for_log appends an ellipsis after max_len characters. Slice the
    # result as well so this helper's bound is exact at publication time.
    return value[:max_len] or fallback[:max_len]


def _safe_exception_type(exc: BaseException) -> str:
    """Return bounded exception identity without its potentially sensitive text."""
    return _safe_value(type(exc).__name__, max_len=64, fallback="Exception")


def _safe_rule_name(rule: PatternRule) -> str:
    """Return bounded, log-safe rule identity (never a match or pattern)."""
    try:
        name = rule.name
    except Exception:
        name = None
    return _safe_value(name, max_len=128, fallback="unnamed")


def _safe_rule_id(rule: PatternRule, safe_name: str) -> str:
    """Preserve the normal rule ID while constraining unusual policy values."""
    try:
        rule_id = rule.rule_id
    except Exception:
        rule_id = f"scan:{safe_name}"
    return _safe_value(rule_id, max_len=128, fallback=f"scan:{safe_name}")


def _safe_rule_action(rule: PatternRule) -> str:
    """Return only the policy actions understood by the scanner."""
    try:
        action = rule.action
    except Exception:
        action = None
    return action if isinstance(action, str) and action in _SAFE_ACTIONS else "unknown"


def _safe_rule_severity(rule: PatternRule) -> str:
    """Return only the policy severities understood by the audit contract."""
    try:
        severity = rule.severity
    except Exception:
        severity = None
    return severity if isinstance(severity, str) and severity in _SAFE_SEVERITIES else "medium"


def _safe_location(location: str) -> str:
    """Retain only the scanner's bounded location vocabulary."""
    if location in {"url", "body"}:
        return location
    if location.startswith("header:"):
        return "header:" + _safe_value(location[7:], max_len=64, fallback="unknown")
    return "unknown"


def _safe_host(flow: http.HTTPFlow) -> str:
    """Return bounded host evidence without carrying URL/user input through."""
    try:
        host = flow.request.host
    except Exception:
        host = None
    return _safe_value(host, max_len=253, fallback="unknown")


class PatternScanner(SecurityAddon):
    """User-configurable scanner for URLs, headers, and message bodies.

    Scans HTTP and WebSocket content for policy-defined patterns. The object
    starts empty and is populated from user rules and enabled builtin sets.
    """

    name = "pattern-scanner"
    trace_expected = True

    def __init__(self):
        super().__init__()
        self.rules: list[PatternRule] = []
        self.scans_total = 0
        self.matches_total = 0
        self.blocks_total = 0
        self._last_policy_hash: str = ""

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="pattern_block_request",
            typespec=bool,
            default=False,
            help="Block requests matching patterns (default: log only)",
        )
        loader.add_option(
            name="pattern_block_response",
            typespec=bool,
            default=False,
            help="Block responses matching patterns (default: log only)",
        )
        loader.add_option(
            name="pattern_block_websocket_request",
            typespec=bool,
            default=False,
            help="Block matching WebSocket client messages (default: log only)",
        )
        loader.add_option(
            name="pattern_block_websocket_response",
            typespec=bool,
            default=False,
            help="Block matching WebSocket server messages (default: log only)",
        )

    @staticmethod
    def _websocket_block_enabled(direction: str) -> bool:
        """Return the effective block mode for one WebSocket direction.

        The WebSocket options are independent from HTTP options, so operators
        can block one transport without blocking the other. ``getattr`` keeps
        direct/unit callers that provide only the original options compatible
        while older addon fixtures are migrated.
        """
        generic_name = (
            "pattern_block_request"
            if direction == "request"
            else "pattern_block_response"
        )
        websocket_name = (
            "pattern_block_websocket_request"
            if direction == "request"
            else "pattern_block_websocket_response"
        )
        websocket_value = getattr(ctx.options, websocket_name, None)
        if websocket_value is None:
            return bool(getattr(ctx.options, generic_name, False))
        return bool(websocket_value)

    def _load_patterns_from_config(self, sensor_config: dict):
        """Load scan patterns from sensor configuration.

        Args:
            sensor_config: Dict from PolicyClient.get_sensor_config() with:
                - scan_patterns: List of user-defined pattern configs
                - addons.pattern_scanner.builtin_sets: List of builtin set names
        """
        all_pattern_configs = []

        # Load builtin sets if enabled (from addons config)
        addon_config = sensor_config.get("addons", {}).get("pattern_scanner", {})
        builtin_sets = addon_config.get("builtin_sets", [])
        for set_name in builtin_sets:
            builtin_patterns = load_builtin_set(set_name)
            all_pattern_configs.extend(builtin_patterns)
            if builtin_patterns:
                log.debug("Loaded %d patterns from a builtin set", len(builtin_patterns))

        # Load user-defined patterns from policy
        user_patterns = sensor_config.get("scan_patterns", [])
        all_pattern_configs.extend(user_patterns)

        # Compile all patterns
        self.rules = load_patterns_from_config(all_pattern_configs)

        if self.rules:
            log.info(f"Pattern scanner ready: {len(self.rules)} total patterns")
        else:
            log.debug("No scan patterns configured (add patterns to policy)")

    def load_policy_config(self, config: dict):
        """Public method for loading patterns (for tests and direct configuration).

        Args:
            config: Dict with scan_patterns list
        """
        self._load_patterns_from_config(config)

    def _maybe_reload_patterns(self):
        """Reload patterns if policy changed."""
        import safeyolo.core.config_cache as config_cache
        try:
            config = config_cache.get_or_raise()
        except RuntimeError:
            # PolicyClient not configured yet - skip reload
            return
        except Exception as e:
            # Configuration/parser exceptions can echo policy-controlled
            # values.  The type is sufficient operational evidence.
            log.warning("Failed to reload patterns (%s)", _safe_exception_type(e))
            return
        policy_hash = config.get("policy_hash", "")
        if policy_hash != self._last_policy_hash:
            try:
                self._load_patterns_from_config(config)
            except Exception as exc:
                # Pattern configuration is policy-controlled. Never let a
                # parser exception (which may echo it) reach mitmproxy's
                # diagnostics or the tracing decorator.
                log.warning("Failed to load patterns (%s)", _safe_exception_type(exc))
                return
            self._last_policy_hash = policy_hash

    def block(
        self,
        flow: http.HTTPFlow,
        status: int,
        body: dict,
        extra_headers: dict = None,
        *,
        trace_reason: str | None = None,
    ):
        """Block request/response with error."""
        self.blocks_total += 1
        flow.metadata["blocked_by"] = self.name
        flow.response = make_block_response(
            status,
            body,
            self.name,
            extra_headers,
            request_id=flow.metadata.get("request_id"),
        )
        trace_details = {}
        if trace_reason in {URL_INSPECTION_OVERFLOW, URL_INSPECTION_ERROR}:
            trace_details = {"reason": trace_reason, "location": "url"}
        self._trace_evaluated(flow, outcome="blocked", status=status, **trace_details)

    @staticmethod
    def _has_url_rules(rules: list[PatternRule], direction: str) -> bool:
        return any(
            rule.target in {direction, "both"} and "url" in rule.scope
            for rule in rules
        )

    def _block_url_inspection_failure(self, flow: http.HTTPFlow, reason: str) -> None:
        """Fail closed when URL-scoped request content was not fully inspected."""
        if reason not in {URL_INSPECTION_OVERFLOW, URL_INSPECTION_ERROR}:
            reason = URL_INSPECTION_ERROR
        safe_host = _safe_host(flow)
        flow.metadata["pattern_scan_failure"] = reason
        flow.metadata["pattern_location"] = "url"
        log.warning(
            "BLOCKED: Pattern URL inspection failed (%s) -> %s",
            reason,
            safe_host,
        )
        self.log_decision(
            flow,
            Decision.DENY,
            severity=Severity.HIGH,
            summary=f"Pattern URL inspection blocked request to {safe_host}",
            host=safe_host,
            direction="request",
            location="url",
            action="block",
            reason=reason,
        )
        self.block(
            flow,
            403,
            {
                "error": "Request blocked because URL inspection failed",
                "location": "url",
                "action": "block",
                "reason": reason,
            },
            trace_reason=reason,
        )

    def _scan_for_scope(
        self,
        rules: list[PatternRule],
        scope: str,
        text: str,
        direction: str,
    ) -> PatternRule | None:
        """Scan text for patterns that include the given scope.

        Args:
            rules: Pattern rules to check
            scope: The scope being scanned ("url", "headers", "body")
            text: Text to scan
            direction: "request" or "response"

        Returns:
            First matching rule, or None
        """
        self.scans_total += 1

        for rule in rules:
            # Check direction match
            if rule.target != direction and rule.target != "both":
                continue

            # Check scope match
            if scope not in rule.scope:
                continue

            if rule.matches(text):
                self.matches_total += 1
                return rule

        return None

    def _scan_url_scope(
        self,
        rules: list[PatternRule],
        inspection: _URLInspection,
        direction: str,
    ) -> PatternRule | None:
        """Scan raw URL text and exactly one canonical decoded form.

        Rule order remains the precedence order across both representations.
        A match is counted once even when the same rule matches raw and decoded
        text, while both forms are evaluated so the decoded pass is never
        accidentally skipped by a raw match.
        """
        self.scans_total += 2

        for rule in rules:
            if rule.target != direction and rule.target != "both":
                continue
            if "url" not in rule.scope:
                continue

            matched = False
            for text in (inspection.raw, inspection.decoded):
                if rule.matches(text):
                    matched = True
            if matched:
                self.matches_total += 1
                return rule
        return None

    def _scan_request_content(
        self,
        flow: http.HTTPFlow,
    ) -> tuple[PatternRule | None, str, str | None]:
        """Scan request URL, headers, and body based on rule scopes.

        Returns:
            (matched_rule, location, failure) - location is "url",
            "header:<name>", or "body"; failure is a stable URL inspection
            reason when the request target could not be completely inspected.
        """
        # Scan the bounded raw path/query and exactly one percent-decoded form.
        # This is inspection-only; the request target is never rewritten.
        if self._has_url_rules(self.rules, "request"):
            inspection = _bounded_url_representations(flow.request.path)
            if not inspection.inspectable:
                return None, "", inspection.status
            rule = self._scan_url_scope(self.rules, inspection, "request")
        else:
            rule = None
        if rule:
            return rule, "url", None

        # Scan headers
        for header_name, header_value in flow.request.headers.items():
            rule = self._scan_for_scope(self.rules, "headers", header_value, "request")
            if rule:
                return rule, _safe_location(f"header:{header_name}"), None

        # Scan body
        body = flow.request.get_text(strict=False)
        if body:
            rule = self._scan_for_scope(self.rules, "body", body, "request")
            if rule:
                return rule, "body", None

        return None, "", None

    def _scan_response_content(
        self,
        flow: http.HTTPFlow,
    ) -> tuple[PatternRule | None, str]:
        """Scan response headers and body based on rule scopes.

        Returns:
            (matched_rule, location) - location is "header:<name>" or "body"
        """
        if not flow.response:
            return None, ""

        # Scan headers
        for header_name, header_value in flow.response.headers.items():
            rule = self._scan_for_scope(self.rules, "headers", header_value, "response")
            if rule:
                return rule, _safe_location(f"header:{header_name}")

        # Scan body
        body = flow.response.get_text(strict=False)
        if body:
            rule = self._scan_for_scope(self.rules, "body", body, "response")
            if rule:
                return rule, "body"

        return None, ""

    def _scan_websocket_message(
        self,
        message: WebSocketMessage,
    ) -> tuple[PatternRule | None, str, str]:
        """Scan one reassembled WebSocket message as body content.

        Mitmproxy exposes complete text and binary messages here, including
        messages that arrived in multiple frames. Request rules apply to
        client messages. Response rules apply to server messages.
        """
        if message.type not in WEBSOCKET_MESSAGE_TYPES:
            raise ValueError("unsupported WebSocket message type")

        direction = "request" if message.from_client else "response"
        message_type = "text" if message.type == Opcode.TEXT else "binary"
        if message.type == Opcode.TEXT:
            text = message.content.decode("utf-8")
        else:
            # Latin-1 gives each byte a stable code point. This lets existing
            # ASCII-oriented body rules inspect binary messages without
            # changing or logging the original content.
            text = message.content.decode("latin-1")

        rule = self._scan_for_scope(self.rules, "body", text, direction)
        return rule, direction, message_type

    def _drop_websocket_message(
        self,
        flow: http.HTTPFlow,
        message: WebSocketMessage,
        *,
        direction: str,
        message_type: str,
        rule: PatternRule | None = None,
        error_type: str | None = None,
    ) -> None:
        """Drop one message and emit content-free audit evidence."""
        message.drop()
        self.blocks_total += 1
        self.stats.blocked += 1
        flow.metadata["websocket_pattern_dropped"] = True

        if rule is not None:
            safe_name = _safe_rule_name(rule)
            safe_host = _safe_host(flow)
            safe_rule_id = _safe_rule_id(rule, safe_name)
            summary = (
                f"Pattern '{safe_name}' blocked in "
                f"WebSocket {direction} message for "
                f"{safe_host}"
            )
            details = {
                "direction": direction,
                "rule_name": safe_name,
                "rule_id": safe_rule_id,
                "pattern_action": _safe_rule_action(rule),
                "pattern_severity": _safe_rule_severity(rule),
                "location": "websocket_message",
                "message_type": message_type,
            }
        else:
            safe_host = _safe_host(flow)
            summary = (
                f"WebSocket {direction} message dropped because pattern "
                f"inspection failed for {safe_host}"
            )
            details = {
                "direction": direction,
                "location": "websocket_message",
                "message_type": message_type,
                "reason": "inspection_error",
                "error_type": _safe_value(error_type, max_len=64, fallback="Exception"),
            }

        self.log_decision(
            flow,
            Decision.DENY,
            severity=Severity.HIGH,
            summary=summary,
            host=safe_host,
            **details,
        )

    @trace_addon_hook("request")
    def request(self, flow: http.HTTPFlow):
        """Scan request for user-defined patterns."""
        # Reload patterns if policy changed
        self._maybe_reload_patterns()

        if not self.rules:
            self._trace_evaluated(flow, outcome=OUTCOME_NO_RULES)
            return

        rule, location, inspection_failure = self._scan_request_content(flow)
        if inspection_failure:
            self._block_url_inspection_failure(flow, inspection_failure)
            return
        if not rule:
            self._trace_evaluated(flow, outcome=OUTCOME_NO_MATCH, rules_evaluated=len(self.rules))
            return

        safe_name = _safe_rule_name(rule)
        safe_host = _safe_host(flow)
        safe_rule_id = _safe_rule_id(rule, safe_name)
        flow.metadata["pattern_matched"] = safe_name
        flow.metadata["pattern_location"] = location

        match_fields = {
            "direction": "request",
            "rule_name": safe_name,
            "rule_id": safe_rule_id,
            "pattern_action": _safe_rule_action(rule),
            "pattern_severity": _safe_rule_severity(rule),
            "location": location,
        }

        if rule.should_block and ctx.options.pattern_block_request:
            log.warning(
                "BLOCKED: Pattern '%s' matched in %s -> %s",
                safe_name,
                location,
                safe_host,
            )
            self.log_decision(
                flow, Decision.DENY,
                severity=Severity.HIGH,
                summary=f"Pattern '{safe_name}' blocked in request {location} to {safe_host}",
                host=safe_host,
                **match_fields,
            )
            # self.block() records the trace step via base wrapper; the extra
            # outcome tag here would double-count. Base emits outcome=blocked.
            self.block(flow, 403, {
                "error": "Request blocked by pattern policy",
                "rule": safe_name,
                "location": location,
                "action": _safe_rule_action(rule),
            })
        else:
            log.info(
                "MATCH: Pattern '%s' matched in %s -> %s",
                safe_name,
                location,
                safe_host,
            )
            self.log_decision(
                flow, Decision.LOG,
                severity=Severity.MEDIUM,
                summary=f"Pattern '{safe_name}' matched in request {location} to {safe_host}",
                host=safe_host,
                **match_fields,
            )
            self._trace_evaluated(
                flow,
                outcome=OUTCOME_MATCH_LOGGED,
                rule_name=safe_name,
                location=location,
            )

    @trace_addon_hook("response")
    def response(self, flow: http.HTTPFlow):
        """Scan response for user-defined patterns."""
        # Reload patterns if policy changed
        self._maybe_reload_patterns()

        if not self.rules:
            self._trace_evaluated(flow, outcome=OUTCOME_NO_RULES, hook="response")
            return

        if not flow.response:
            return

        rule, location = self._scan_response_content(flow)
        if not rule:
            self._trace_evaluated(
                flow,
                outcome=OUTCOME_NO_MATCH,
                hook="response",
                rules_evaluated=len(self.rules),
            )
            return

        safe_name = _safe_rule_name(rule)
        safe_host = _safe_host(flow)
        safe_rule_id = _safe_rule_id(rule, safe_name)
        flow.metadata["pattern_matched_response"] = safe_name
        flow.metadata["pattern_location_response"] = location

        match_fields = {
            "direction": "response",
            "rule_name": safe_name,
            "rule_id": safe_rule_id,
            "pattern_action": _safe_rule_action(rule),
            "pattern_severity": _safe_rule_severity(rule),
            "location": location,
        }

        if rule.should_block and ctx.options.pattern_block_response:
            log.warning(
                "BLOCKED: Pattern '%s' matched in %s <- %s",
                safe_name,
                location,
                safe_host,
            )
            self.log_decision(
                flow, Decision.DENY,
                severity=Severity.HIGH,
                summary=f"Pattern '{safe_name}' blocked in response {location} from {safe_host}",
                host=safe_host,
                **match_fields,
            )
            self.block(flow, 502, {
                "error": "Response blocked by pattern policy",
                "rule": safe_name,
                "location": location,
                "action": _safe_rule_action(rule),
            })
        else:
            log.info(
                "MATCH: Pattern '%s' matched in %s <- %s",
                safe_name,
                location,
                safe_host,
            )
            self.log_decision(
                flow, Decision.LOG,
                severity=Severity.MEDIUM,
                summary=f"Pattern '{safe_name}' matched in response {location} from {safe_host}",
                host=safe_host,
                **match_fields,
            )
            self._trace_evaluated(
                flow,
                outcome=OUTCOME_MATCH_LOGGED,
                hook="response",
                rule_name=safe_name,
                location=location,
            )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Inspect the newest reassembled WebSocket message."""
        websocket = flow.websocket
        if websocket is None or not websocket.messages:
            return
        message = websocket.messages[-1]

        direction = "request" if message.from_client else "response"
        try:
            message_type = getattr(message.type, "name", "unknown").lower()
        except Exception:
            message_type = "unknown"
        message_type = _safe_value(message_type, max_len=32, fallback="unknown")
        try:
            self._maybe_reload_patterns()
            if not self.rules:
                return
            rule, direction, message_type = self._scan_websocket_message(message)
        except Exception as exc:
            # An inspection error must not turn into uninspected delivery. Log
            # only the exception type; its message can contain inspected data.
            log.error(
                "DROPPED: WebSocket %s message for %s because pattern "
                "inspection failed (%s)",
                direction,
                _safe_host(flow),
                _safe_exception_type(exc),
            )
            self._drop_websocket_message(
                flow,
                message,
                direction=direction,
                message_type=message_type,
                error_type=_safe_exception_type(exc),
            )
            return

        if rule is None:
            return

        safe_name = _safe_rule_name(rule)
        safe_host = _safe_host(flow)
        safe_rule_id = _safe_rule_id(rule, safe_name)
        flow.metadata["websocket_pattern_matched"] = safe_name
        flow.metadata["websocket_pattern_direction"] = direction
        flow.metadata["websocket_pattern_message_type"] = message_type

        block_enabled = self._websocket_block_enabled(direction)
        if rule.should_block and block_enabled:
            log.warning(
                "DROPPED: Pattern '%s' matched in WebSocket %s message for %s",
                safe_name,
                direction,
                safe_host,
            )
            self._drop_websocket_message(
                flow,
                message,
                direction=direction,
                message_type=message_type,
                rule=rule,
            )
            return

        log.info(
            "MATCH: Pattern '%s' matched in WebSocket %s message for %s",
            safe_name,
            direction,
            safe_host,
        )
        self.log_decision(
            flow,
            Decision.LOG,
            severity=Severity.MEDIUM,
            summary=(
                f"Pattern '{safe_name}' matched in "
                f"WebSocket {direction} message for "
                f"{safe_host}"
            ),
            host=safe_host,
            direction=direction,
            rule_name=safe_name,
            rule_id=safe_rule_id,
            pattern_action=_safe_rule_action(rule),
            pattern_severity=_safe_rule_severity(rule),
            location="websocket_message",
            message_type=message_type,
        )

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "rules_total": len(self.rules),
            "scans_total": self.scans_total,
            "matches_total": self.matches_total,
            "blocks_total": self.blocks_total,
        }


addons = [PatternScanner()]
