"""
pattern_scanner.py - Native mitmproxy addon for regex-based scanning

Fast pattern matching for:
- Secrets/credentials in responses (API keys, tokens, passwords)
- Jailbreak/injection attempts in requests
- Custom patterns

Lighter weight than YARA, runs on all requests.

Usage:
    mitmdump -s addons/pattern_scanner.py --set pattern_block_input=true
"""

import logging
from pathlib import Path
from typing import Optional

from base import SecurityAddon
from detection import PatternRule, compile_rules
from mitmproxy import ctx, http
from utils import make_block_response

log = logging.getLogger("safeyolo.pattern-scanner")


class PatternScanner(SecurityAddon):
    """
    Native mitmproxy addon for regex-based scanning.

    Fast pattern matching for secrets and jailbreak attempts.
    """

    name = "pattern-scanner"

    def __init__(self):
        # Custom stats - don't call super().__init__()
        self.rules: list[PatternRule] = []
        self.log_path: Path | None = None
        self.scans_total = 0
        self.matches_total = 0
        self.blocks_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="pattern_block_input",
            typespec=bool,
            default=False,
            help="Block requests matching input patterns (default: warn only)",
        )
        loader.add_option(
            name="pattern_block_output",
            typespec=bool,
            default=False,
            help="Block responses matching output patterns (default: warn only)",
        )
        loader.add_option(
            name="pattern_redact_secrets",
            typespec=bool,
            default=False,
            help="Redact secrets instead of blocking",
        )
        loader.add_option(
            name="pattern_log_path",
            typespec=Optional[str],
            default=None,
            help="Path for JSONL match log",
        )

    def configure(self, updates):
        """Handle option changes."""
        if not self.rules:
            self.rules = compile_rules()
            log.info(f"Pattern scanner loaded {len(self.rules)} rules")

        if "pattern_log_path" in updates:
            path = ctx.options.pattern_log_path
            self.log_path = Path(path) if path else None

    def block(self, flow: http.HTTPFlow, status: int, body: dict, extra_headers: dict = None):
        """Override base block() - pattern scanner has custom stats."""
        self.blocks_total += 1
        flow.metadata["blocked_by"] = self.name
        flow.response = make_block_response(status, body, self.name, extra_headers)

    def _scan_text(self, text: str, target: str) -> PatternRule | None:
        """Scan text for matching patterns."""
        self.scans_total += 1

        for rule in self.rules:
            if rule.target != target and rule.target != "both":
                continue

            if rule.matches(text):
                self.matches_total += 1
                return rule

        return None

    def request(self, flow: http.HTTPFlow):
        """Scan request for jailbreak patterns."""
        scan_parts = []

        body = flow.request.get_text(strict=False)
        if body:
            scan_parts.append(body)

        for header in ["User-Agent", "Referer", "X-Custom-Prompt"]:
            value = flow.request.headers.get(header)
            if value:
                scan_parts.append(value)

        if not scan_parts:
            return

        scan_text = "\n".join(scan_parts)
        rule = self._scan_text(scan_text, "input")

        if not rule:
            return

        flow.metadata["pattern_matched"] = rule.rule_id

        match_fields = {
            "direction": "request",
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "category": rule.category,
            "host": flow.request.host,
            "path": flow.request.path,
        }

        if rule.should_block and ctx.options.pattern_block_input:
            log.warning(f"BLOCKED: Pattern matched INPUT {rule.rule_id} ({rule.name}) -> {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "block", **match_fields)
            self.block(flow, 403, {
                "error": "Request blocked by security policy",
                "rule": rule.rule_id,
                "category": rule.category,
            })
        else:
            log.warning(f"WARN: Pattern matched INPUT {rule.rule_id} ({rule.name}) -> {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "warn", **match_fields)

    def response(self, flow: http.HTTPFlow):
        """Scan response for leaked secrets."""
        if not flow.response or not flow.response.content:
            return

        body = flow.response.get_text(strict=False)
        if not body:
            return

        rule = self._scan_text(body, "output")

        if not rule:
            return

        flow.metadata["pattern_matched_response"] = rule.rule_id

        match_fields = {
            "direction": "response",
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "category": rule.category,
            "host": flow.request.host,
            "path": flow.request.path,
        }

        if ctx.options.pattern_redact_secrets and rule.category == "secret":
            redacted = rule.pattern.sub("[REDACTED]", body)
            flow.response.text = redacted
            flow.response.headers["X-Secrets-Redacted"] = "true"
            log.warning(f"REDACTED: Pattern matched OUTPUT {rule.rule_id} ({rule.name}) <- {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "redact", **match_fields)
            return

        if rule.should_block and ctx.options.pattern_block_output:
            log.warning(f"BLOCKED: Pattern matched OUTPUT {rule.rule_id} ({rule.name}) <- {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "block", **match_fields)
            self.block(flow, 500, {"error": "Response blocked: potential credential leak detected"})
        else:
            log.warning(f"WARN: Pattern matched OUTPUT {rule.rule_id} ({rule.name}) <- {flow.request.host}{flow.request.path}")
            self.log_decision(flow, "warn", **match_fields)

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "rules_total": len(self.rules),
            "scans_total": self.scans_total,
            "matches_total": self.matches_total,
            "blocks_total": self.blocks_total,
        }


addons = [PatternScanner()]
