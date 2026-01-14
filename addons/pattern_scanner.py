"""
pattern_scanner.py - User-configurable pattern scanning

A framework for security-conscious users to define custom patterns for detecting
sensitive data crossing the proxy boundary. Scans URLs, headers, and/or bodies.

Complements credential_guard:
  credential_guard: Credential ROUTING (is this key going to the right host?)
  pattern_scanner: Pattern DETECTION (should this content be blocked/logged?)

By default, pattern_scanner has NO patterns loaded. Configure via policy:

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
"""

import logging
from pathlib import Path
from typing import Optional

from base import SecurityAddon
from detection.patterns import (
    PatternRule,
    load_builtin_set,
    load_patterns_from_config,
)
from mitmproxy import ctx, http
from utils import make_block_response

log = logging.getLogger("safeyolo.pattern-scanner")


class PatternScanner(SecurityAddon):
    """User-configurable pattern scanner for URLs, headers, and bodies.

    Scans request/response content for user-defined patterns. Empty by default -
    users configure patterns via policy or enable builtin pattern sets.
    """

    name = "pattern-scanner"

    def __init__(self):
        self.rules: list[PatternRule] = []
        self.log_path: Path | None = None
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
            name="pattern_log_path",
            typespec=Optional[str],
            default=None,
            help="Path for JSONL match log",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "pattern_log_path" in updates:
            path = ctx.options.pattern_log_path
            self.log_path = Path(path) if path else None

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
        from pdp import get_policy_client

        try:
            client = get_policy_client()
            config = client.get_sensor_config()
            policy_hash = config.get("policy_hash", "")

            if policy_hash != self._last_policy_hash:
                self._load_patterns_from_config(config)
                self._last_policy_hash = policy_hash
        except RuntimeError:
            # PolicyClient not configured yet - skip reload
            pass
        except Exception as e:
            log.warning(f"Failed to reload patterns: {type(e).__name__}: {e}")

    def block(self, flow: http.HTTPFlow, status: int, body: dict, extra_headers: dict = None):
        """Block request/response with error."""
        self.blocks_total += 1
        flow.metadata["blocked_by"] = self.name
        flow.response = make_block_response(status, body, self.name, extra_headers)

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

    def request(self, flow: http.HTTPFlow):
        """Scan request for user-defined patterns."""
        # Reload patterns if policy changed
        self._maybe_reload_patterns()

        if not self.rules:
            return

        rule, location = self._scan_request_content(flow)
        if not rule:
            return

        flow.metadata["pattern_matched"] = rule.name
        flow.metadata["pattern_location"] = location

        match_fields = {
            "direction": "request",
            "rule_name": rule.name,
            "rule_id": rule.rule_id,
            "action": rule.action,
            "severity": rule.severity,
            "location": location,
            "host": flow.request.host,
            "path": flow.request.path,
        }

        if rule.should_block and ctx.options.pattern_block_request:
            log.warning(f"BLOCKED: Pattern '{rule.name}' matched in {location} -> {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "block", **match_fields)
            self.block(flow, 403, {
                "error": "Request blocked by pattern policy",
                "rule": rule.name,
                "location": location,
                "message": rule.message,
            })
        else:
            log.info(f"MATCH: Pattern '{rule.name}' matched in {location} -> {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "log", **match_fields)

    def response(self, flow: http.HTTPFlow):
        """Scan response for user-defined patterns."""
        # Reload patterns if policy changed
        self._maybe_reload_patterns()

        if not self.rules:
            return

        if not flow.response or not flow.response.content:
            return

        rule, location = self._scan_response_content(flow)
        if not rule:
            return

        flow.metadata["pattern_matched_response"] = rule.name
        flow.metadata["pattern_location_response"] = location

        match_fields = {
            "direction": "response",
            "rule_name": rule.name,
            "rule_id": rule.rule_id,
            "action": rule.action,
            "severity": rule.severity,
            "location": location,
            "host": flow.request.host,
            "path": flow.request.path,
        }

        if rule.should_block and ctx.options.pattern_block_response:
            log.warning(f"BLOCKED: Pattern '{rule.name}' matched in {location} <- {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "block", **match_fields)
            self.block(flow, 502, {
                "error": "Response blocked by pattern policy",
                "rule": rule.name,
                "location": location,
                "message": rule.message,
            })
        else:
            log.info(f"MATCH: Pattern '{rule.name}' matched in {location} <- {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "log", **match_fields)

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "rules_total": len(self.rules),
            "scans_total": self.scans_total,
            "matches_total": self.matches_total,
            "blocks_total": self.blocks_total,
        }


addons = [PatternScanner()]
