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
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

try:
    from .utils import make_block_response, write_event
except ImportError:
    from utils import make_block_response, write_event

log = logging.getLogger("safeyolo.pattern-scanner")


@dataclass
class PatternRule:
    """A pattern detection rule."""
    rule_id: str
    name: str
    pattern: re.Pattern
    target: str  # "input", "output", "both"
    severity: int  # 1-5
    category: str  # "secret", "jailbreak", "pii"

    def matches(self, text: str) -> Optional[re.Match]:
        return self.pattern.search(text)

    @property
    def should_block(self) -> bool:
        return self.severity >= 4


# Built-in secret patterns (scan output/responses)
BUILTIN_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{48}", "openai_api_key", "OpenAI API Key", 5),
    (r"sk-ant-[a-zA-Z0-9-]{95}", "anthropic_api_key", "Anthropic API Key", 5),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "AWS Access Key ID", 5),
    (r"AIza[0-9A-Za-z-_]{35}", "google_api_key", "Google API Key", 5),
    (r"ghp_[a-zA-Z0-9]{36}", "github_pat", "GitHub Personal Access Token", 5),
    (r"gho_[a-zA-Z0-9]{36}", "github_oauth", "GitHub OAuth Token", 5),
    (r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})", "generic_api_key", "Generic API Key", 4),
    (r"(?i)bearer\s+[a-zA-Z0-9_-]{20,}", "bearer_token", "Bearer Token", 4),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key", "Private Key", 5),
    (r"(?i)(postgres|mysql|mongodb)://[^\s]+:[^\s]+@", "db_connection_string", "Database Connection String", 5),
]

# Built-in jailbreak patterns (scan input/requests)
BUILTIN_JAILBREAK_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "ignore_instructions", "Instruction override", 4),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "disregard_instructions", "Instruction override", 4),
    (r"forget\s+(everything|all)\s+(you|that)\s+(know|learned|were)", "forget_training", "Memory reset attempt", 4),
    (r"you\s+are\s+(now\s+)?(?:DAN|jailbroken|unrestricted|unfiltered)", "dan_jailbreak", "DAN jailbreak", 5),
    (r"pretend\s+(you\s+)?(are|to\s+be)\s+(a|an)?\s*(evil|malicious|unrestricted)", "evil_roleplay", "Malicious roleplay", 4),
    (r"developer\s+mode\s+(enabled?|activated?|on)", "developer_mode", "Fake developer mode", 4),
    (r"enable\s+(developer|debug|admin)\s+mode", "enable_mode", "Privileged mode attempt", 4),
    (r"(what|show|tell|reveal|repeat|print)\s+(is\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)", "prompt_extraction", "System prompt extraction", 3),
    (r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", "instruction_markers", "LLM instruction markers", 4),
    (r"<<SYS>>|<</SYS>>", "llama_system", "Llama system markers", 4),
]


def _compile_rules() -> list[PatternRule]:
    """Compile built-in patterns into rules."""
    rules = []

    for pattern_str, rule_id, desc, severity in BUILTIN_SECRET_PATTERNS:
        try:
            rules.append(PatternRule(
                rule_id=f"secret:{rule_id}",
                name=desc,
                pattern=re.compile(pattern_str, re.IGNORECASE),
                target="output",
                severity=severity,
                category="secret",
            ))
        except re.error as e:
            log.warning(f"Invalid pattern {rule_id}: {e}")

    for pattern_str, rule_id, desc, severity in BUILTIN_JAILBREAK_PATTERNS:
        try:
            rules.append(PatternRule(
                rule_id=f"jailbreak:{rule_id}",
                name=desc,
                pattern=re.compile(pattern_str, re.IGNORECASE),
                target="input",
                severity=severity,
                category="jailbreak",
            ))
        except re.error as e:
            log.warning(f"Invalid pattern {rule_id}: {e}")

    return rules


class PatternScanner:
    """
    Native mitmproxy addon for regex-based scanning.

    Fast pattern matching for secrets and jailbreak attempts.
    """

    name = "pattern-scanner"

    def __init__(self):
        self.rules: list[PatternRule] = []
        self.log_path: Optional[Path] = None

        # Stats
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
            self.rules = _compile_rules()
            log.info(f"Pattern scanner loaded {len(self.rules)} rules")

        if "pattern_log_path" in updates:
            path = ctx.options.pattern_log_path
            self.log_path = Path(path) if path else None

    def _log_match(self, flow: http.HTTPFlow, decision: str, **data):
        """Write pattern match to JSONL audit log.

        Args:
            flow: HTTP flow for request_id correlation
            decision: "block", "warn", or "redact"
            **data: Match details (rule_id, name, category, etc.)
        """
        write_event(
            "security.pattern",
            request_id=flow.metadata.get("request_id"),
            addon=self.name,
            decision=decision,
            **data
        )

    def _scan_text(self, text: str, target: str) -> Optional[PatternRule]:
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
        # Build text to scan
        scan_parts = []

        body = flow.request.get_text(strict=False)
        if body:
            scan_parts.append(body)

        # Check relevant headers
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

        match_fields = dict(
            direction="request",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            category=rule.category,
            host=flow.request.host,
            path=flow.request.path,
        )

        if rule.should_block and ctx.options.pattern_block_input:
            self.blocks_total += 1
            flow.metadata["blocked_by"] = self.name
            log.warning(f"BLOCKED: Pattern matched INPUT {rule.rule_id} ({rule.name}) -> {flow.request.host}{flow.request.path}")
            self._log_match(flow, "block", **match_fields)
            flow.response = make_block_response(
                403,
                {
                    "error": "Request blocked by security policy",
                    "rule": rule.rule_id,
                    "category": rule.category,
                },
                self.name,
            )
        else:
            log.warning(f"WARN: Pattern matched INPUT {rule.rule_id} ({rule.name}) -> {flow.request.host}{flow.request.path}")
            self._log_match(flow, "warn", **match_fields)

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

        match_fields = dict(
            direction="response",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            category=rule.category,
            host=flow.request.host,
            path=flow.request.path,
        )

        if ctx.options.pattern_redact_secrets and rule.category == "secret":
            # Redact instead of blocking
            redacted = rule.pattern.sub("[REDACTED]", body)
            flow.response.text = redacted
            flow.response.headers["X-Secrets-Redacted"] = "true"
            log.warning(f"REDACTED: Pattern matched OUTPUT {rule.rule_id} ({rule.name}) <- {flow.request.host}{flow.request.path}")
            self._log_match(flow, "redact", **match_fields)
            return

        if rule.should_block and ctx.options.pattern_block_output:
            self.blocks_total += 1
            flow.metadata["blocked_by"] = self.name
            log.warning(f"BLOCKED: Pattern matched OUTPUT {rule.rule_id} ({rule.name}) <- {flow.request.host}{flow.request.path}")
            self._log_match(flow, "block", **match_fields)
            flow.response = make_block_response(
                500,
                {"error": "Response blocked: potential credential leak detected"},
                self.name,
            )
        else:
            log.warning(f"WARN: Pattern matched OUTPUT {rule.rule_id} ({rule.name}) <- {flow.request.host}{flow.request.path}")
            self._log_match(flow, "warn", **match_fields)

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "rules_total": len(self.rules),
            "scans_total": self.scans_total,
            "matches_total": self.matches_total,
            "blocks_total": self.blocks_total,
        }


# mitmproxy addon instance
addons = [PatternScanner()]
