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
                log.debug(f"Loaded {len(builtin_patterns)} patterns from builtin set '{set_name}'")

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
            log.warning(f"Failed to reload patterns: {type(e).__name__}: {e}")
            return
        policy_hash = config.get("policy_hash", "")
        if policy_hash != self._last_policy_hash:
            self._load_patterns_from_config(config)
            self._last_policy_hash = policy_hash

    def block(self, flow: http.HTTPFlow, status: int, body: dict, extra_headers: dict = None):
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
        self._trace_evaluated(flow, outcome="blocked", status=status)

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

    def _scan_request_content(
        self,
        flow: http.HTTPFlow,
    ) -> tuple[PatternRule | None, str]:
        """Scan request URL, headers, and body based on rule scopes.

        Returns:
            (matched_rule, location) - location is "url", "header:<name>", or "body"
        """
        # Scan URL (path + query)
        url_text = flow.request.path
        rule = self._scan_for_scope(self.rules, "url", url_text, "request")
        if rule:
            return rule, "url"

        # Scan headers
        for header_name, header_value in flow.request.headers.items():
            rule = self._scan_for_scope(self.rules, "headers", header_value, "request")
            if rule:
                return rule, f"header:{header_name}"

        # Scan body
        body = flow.request.get_text(strict=False)
        if body:
            rule = self._scan_for_scope(self.rules, "body", body, "request")
            if rule:
                return rule, "body"

        return None, ""

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
                return rule, f"header:{header_name}"

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
            summary = (
                f"Pattern '{sanitize_for_log(rule.name)}' blocked in "
                f"WebSocket {direction} message for "
                f"{sanitize_for_log(flow.request.host)}"
            )
            details = {
                "direction": direction,
                "rule_name": rule.name,
                "rule_id": rule.rule_id,
                "pattern_action": rule.action,
                "pattern_severity": rule.severity,
                "location": "websocket_message",
                "message_type": message_type,
            }
        else:
            summary = (
                f"WebSocket {direction} message dropped because pattern "
                f"inspection failed for {sanitize_for_log(flow.request.host)}"
            )
            details = {
                "direction": direction,
                "location": "websocket_message",
                "message_type": message_type,
                "reason": "inspection_error",
                "error_type": error_type or "Exception",
            }

        self.log_decision(
            flow,
            Decision.DENY,
            severity=Severity.HIGH,
            summary=summary,
            host=flow.request.host,
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

        rule, location = self._scan_request_content(flow)
        if not rule:
            self._trace_evaluated(flow, outcome=OUTCOME_NO_MATCH, rules_evaluated=len(self.rules))
            return

        flow.metadata["pattern_matched"] = rule.name
        flow.metadata["pattern_location"] = location

        match_fields = {
            "direction": "request",
            "rule_name": rule.name,
            "rule_id": rule.rule_id,
            "pattern_action": rule.action,
            "pattern_severity": rule.severity,
            "location": location,
            "path": flow.request.path,
        }

        if rule.should_block and ctx.options.pattern_block_request:
            log.warning(f"BLOCKED: Pattern '{rule.name}' matched in {location} -> {flow.request.host}{flow.request.path}")
            self.log_decision(
                flow, Decision.DENY,
                severity=Severity.HIGH,
                summary=f"Pattern '{rule.name}' blocked in request {location} to {sanitize_for_log(flow.request.host)}",
                host=flow.request.host,
                **match_fields,
            )
            # self.block() records the trace step via base wrapper; the extra
            # outcome tag here would double-count. Base emits outcome=blocked.
            self.block(flow, 403, {
                "error": "Request blocked by pattern policy",
                "rule": rule.name,
                "location": location,
                "message": rule.message,
            })
        else:
            log.info(f"MATCH: Pattern '{rule.name}' matched in {location} -> {flow.request.host}{flow.request.path}")
            self.log_decision(
                flow, Decision.LOG,
                severity=Severity.MEDIUM,
                summary=f"Pattern '{rule.name}' matched in request {location} to {sanitize_for_log(flow.request.host)}",
                host=flow.request.host,
                **match_fields,
            )
            self._trace_evaluated(
                flow,
                outcome=OUTCOME_MATCH_LOGGED,
                rule_name=rule.name,
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

        flow.metadata["pattern_matched_response"] = rule.name
        flow.metadata["pattern_location_response"] = location

        match_fields = {
            "direction": "response",
            "rule_name": rule.name,
            "rule_id": rule.rule_id,
            "pattern_action": rule.action,
            "pattern_severity": rule.severity,
            "location": location,
            "path": flow.request.path,
        }

        if rule.should_block and ctx.options.pattern_block_response:
            log.warning(f"BLOCKED: Pattern '{rule.name}' matched in {location} <- {flow.request.host}{flow.request.path}")
            self.log_decision(
                flow, Decision.DENY,
                severity=Severity.HIGH,
                summary=f"Pattern '{rule.name}' blocked in response {location} from {sanitize_for_log(flow.request.host)}",
                host=flow.request.host,
                **match_fields,
            )
            self.block(flow, 502, {
                "error": "Response blocked by pattern policy",
                "rule": rule.name,
                "location": location,
                "message": rule.message,
            })
        else:
            log.info(f"MATCH: Pattern '{rule.name}' matched in {location} <- {flow.request.host}{flow.request.path}")
            self.log_decision(
                flow, Decision.LOG,
                severity=Severity.MEDIUM,
                summary=f"Pattern '{rule.name}' matched in response {location} from {sanitize_for_log(flow.request.host)}",
                host=flow.request.host,
                **match_fields,
            )
            self._trace_evaluated(
                flow,
                outcome=OUTCOME_MATCH_LOGGED,
                hook="response",
                rule_name=rule.name,
                location=location,
            )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Inspect the newest reassembled WebSocket message."""
        websocket = flow.websocket
        if websocket is None or not websocket.messages:
            return
        message = websocket.messages[-1]

        direction = "request" if message.from_client else "response"
        message_type = getattr(message.type, "name", "unknown").lower()
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
                sanitize_for_log(flow.request.host),
                type(exc).__name__,
            )
            self._drop_websocket_message(
                flow,
                message,
                direction=direction,
                message_type=message_type,
                error_type=type(exc).__name__,
            )
            return

        if rule is None:
            return

        flow.metadata["websocket_pattern_matched"] = rule.name
        flow.metadata["websocket_pattern_direction"] = direction
        flow.metadata["websocket_pattern_message_type"] = message_type

        block_enabled = self._websocket_block_enabled(direction)
        if rule.should_block and block_enabled:
            log.warning(
                "DROPPED: Pattern '%s' matched in WebSocket %s message for %s",
                sanitize_for_log(rule.name),
                direction,
                sanitize_for_log(flow.request.host),
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
            sanitize_for_log(rule.name),
            direction,
            sanitize_for_log(flow.request.host),
        )
        self.log_decision(
            flow,
            Decision.LOG,
            severity=Severity.MEDIUM,
            summary=(
                f"Pattern '{sanitize_for_log(rule.name)}' matched in "
                f"WebSocket {direction} message for "
                f"{sanitize_for_log(flow.request.host)}"
            ),
            host=flow.request.host,
            direction=direction,
            rule_name=rule.name,
            rule_id=rule.rule_id,
            pattern_action=rule.action,
            pattern_severity=rule.severity,
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
