"""
yara_scanner.py - Native mitmproxy addon for YARA-based threat detection

Scans requests and responses using YARA rules for:
- Credential patterns (API keys, tokens, private keys)
- Jailbreak attempts (DAN, instruction override)
- PII detection (SSN, credit cards)
- Injection markers (LLM instruction tokens)

Usage:
    mitmdump -s addons/yara_scanner.py --set yara_rules=/path/to/custom.yar

Requires: yara-python (`pip install yara-python`)
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

try:
    from .utils import make_block_response, write_jsonl
except ImportError:
    from utils import make_block_response, write_jsonl

log = logging.getLogger("safeyolo.yara-scanner")

# Try to import yara
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None


# Built-in YARA rules
BUILTIN_YARA_RULES = '''
/*
 * Built-in YARA rules for proxy security scanning.
 */

rule Credential_AWS_AccessKey {
    meta:
        description = "AWS Access Key ID"
        severity = 5
        category = "credential"
    strings:
        $key = /AKIA[0-9A-Z]{16}/ ascii wide
    condition:
        $key
}

rule Credential_OpenAI_Key {
    meta:
        description = "OpenAI API Key"
        severity = 5
        category = "credential"
    strings:
        $key = /sk-[a-zA-Z0-9]{48}/ ascii
    condition:
        $key
}

rule Credential_Anthropic_Key {
    meta:
        description = "Anthropic API Key"
        severity = 5
        category = "credential"
    strings:
        $key = /sk-ant-[a-zA-Z0-9\\-]{90,100}/ ascii
    condition:
        $key
}

rule Credential_GitHub_Token {
    meta:
        description = "GitHub Personal Access Token"
        severity = 5
        category = "credential"
    strings:
        $pat = /ghp_[a-zA-Z0-9]{36}/ ascii
        $oauth = /gho_[a-zA-Z0-9]{36}/ ascii
    condition:
        any of them
}

rule Credential_PrivateKey {
    meta:
        description = "Private Key (RSA/EC/DSA)"
        severity = 5
        category = "credential"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $generic = "-----BEGIN PRIVATE KEY-----"
    condition:
        any of them
}

rule Credential_JWT {
    meta:
        description = "JSON Web Token"
        severity = 4
        category = "credential"
    strings:
        $jwt = /eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*/ ascii
    condition:
        $jwt
}

rule Jailbreak_IgnoreInstructions {
    meta:
        description = "Attempt to ignore system instructions"
        severity = 4
        category = "jailbreak"
    strings:
        $ignore1 = /ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|prompts?|rules?)/ nocase
        $ignore2 = /disregard\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|prompts?)/ nocase
        $forget = /forget\\s+(everything|all)\\s+(you|that)\\s+(know|learned)/ nocase
    condition:
        any of them
}

rule Jailbreak_DAN {
    meta:
        description = "DAN (Do Anything Now) jailbreak attempt"
        severity = 5
        category = "jailbreak"
    strings:
        $dan1 = "you are now DAN" nocase
        $dan2 = "DAN Mode" nocase
        $dan3 = "jailbroken" nocase
        $dan4 = "you are DAN" nocase
    condition:
        any of them
}

rule Jailbreak_DeveloperMode {
    meta:
        description = "Fake developer/debug mode activation"
        severity = 4
        category = "jailbreak"
    strings:
        $dev1 = /developer\\s+mode\\s+(enabled?|activated?|on)/ nocase
        $dev2 = /enable\\s+(developer|debug|admin)\\s+mode/ nocase
        $sudo = "sudo mode" nocase
    condition:
        any of them
}

rule Jailbreak_InstructionMarkers {
    meta:
        description = "LLM instruction markers in user input"
        severity = 4
        category = "injection"
    strings:
        $inst1 = "[INST]"
        $inst2 = "[/INST]"
        $im_start = "<|im_start|>"
        $im_end = "<|im_end|>"
        $sys1 = "<<SYS>>"
        $sys2 = "<</SYS>>"
    condition:
        any of them
}

rule PII_SSN {
    meta:
        description = "US Social Security Number"
        severity = 4
        category = "pii"
    strings:
        $ssn = /\\b\\d{3}-\\d{2}-\\d{4}\\b/ ascii
    condition:
        $ssn
}

rule PII_CreditCard {
    meta:
        description = "Credit Card Number (Visa/MC/Amex)"
        severity = 4
        category = "pii"
    strings:
        $visa = /4[0-9]{15}/ ascii
        $mc = /5[1-5][0-9]{14}/ ascii
        $amex = /3[47][0-9]{13}/ ascii
    condition:
        any of them
}
'''


@dataclass
class YARAMatch:
    """Result of a YARA rule match."""
    rule_name: str
    tags: list[str]
    meta: dict
    severity: int
    category: str

    @property
    def should_block(self) -> bool:
        return self.severity >= 4 or "block" in self.tags


class YARAScanner:
    """
    Native mitmproxy addon for YARA-based scanning.

    Scans request/response bodies for threats using YARA rules.
    """

    name = "yara-scanner"

    def __init__(self):
        self.rules: Optional[yara.Rules] = None
        self.rule_sources: list[str] = []
        self.log_path: Optional[Path] = None

        # Stats
        self.scans_total = 0
        self.matches_total = 0
        self.blocks_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="yara_rules",
            typespec=Optional[str],
            default=None,
            help="Path to additional YARA rules file",
        )
        loader.add_option(
            name="yara_scan_requests",
            typespec=bool,
            default=True,
            help="Scan request bodies",
        )
        loader.add_option(
            name="yara_scan_responses",
            typespec=bool,
            default=True,
            help="Scan response bodies",
        )
        loader.add_option(
            name="yara_block_on_match",
            typespec=bool,
            default=False,
            help="Block on high-severity matches (default: warn only)",
        )
        loader.add_option(
            name="yara_max_scan_size",
            typespec=int,
            default=10 * 1024 * 1024,
            help="Maximum bytes to scan",
        )
        loader.add_option(
            name="yara_log_path",
            typespec=Optional[str],
            default=None,
            help="Path for JSONL match log",
        )

    def configure(self, updates):
        """Handle option changes."""
        if not YARA_AVAILABLE:
            log.warning("yara-python not installed - YARA scanner disabled")
            return

        if "yara_rules" in updates or not self.rules:
            self._compile_rules()

        if "yara_log_path" in updates:
            path = ctx.options.yara_log_path
            self.log_path = Path(path) if path else None

    def _compile_rules(self):
        """Compile YARA rules."""
        if not YARA_AVAILABLE:
            return

        sources = [BUILTIN_YARA_RULES]

        # Load custom rules if specified
        custom_path = ctx.options.yara_rules
        if custom_path and Path(custom_path).exists():
            try:
                sources.append(Path(custom_path).read_text())
                log.info(f"Loaded custom YARA rules from {custom_path}")
            except Exception as e:
                log.error(f"Failed to load YARA rules from {custom_path}: {type(e).__name__}: {e}")

        try:
            combined = "\n\n".join(sources)
            self.rules = yara.compile(source=combined)
            self.rule_sources = sources
            log.info(f"YARA scanner compiled {len(sources)} rule sources")
        except yara.SyntaxError as e:
            log.error(f"YARA compilation error: {type(e).__name__}: {e}")
            self.rules = None

    def _log_match(self, **data):
        """Write match to JSONL log."""
        write_jsonl(self.log_path, "yara_match", log, **data)

    def _scan_data(self, data: bytes) -> list[YARAMatch]:
        """Scan data with YARA rules."""
        if not YARA_AVAILABLE or not self.rules:
            return []

        self.scans_total += 1

        # Truncate if too large
        max_size = ctx.options.yara_max_scan_size
        if len(data) > max_size:
            data = data[:max_size]

        try:
            yara_matches = self.rules.match(data=data)
        except Exception as e:
            log.warning(f"YARA scan error: {type(e).__name__}: {e}")
            return []

        if not yara_matches:
            return []

        matches = []
        for m in yara_matches:
            meta = dict(m.meta)
            matches.append(YARAMatch(
                rule_name=m.rule,
                tags=list(m.tags),
                meta=meta,
                severity=int(meta.get("severity", 3)),
                category=meta.get("category", "unknown"),
            ))

        self.matches_total += len(matches)
        return matches

    def _create_block_response(self, matches: list[YARAMatch], location: str) -> http.Response:
        """Create block response for YARA matches."""
        rule_names = [m.rule_name for m in matches]
        categories = list(set(m.category for m in matches))

        return make_block_response(
            403,
            {
                "error": "Request blocked by security scan",
                "rules": rule_names,
                "categories": categories,
            },
            self.name,
            {
                "X-Block-Reason": "yara-match",
                "X-YARA-Rules": ",".join(rule_names),
            },
        )

    def request(self, flow: http.HTTPFlow):
        """Scan request body."""
        if not ctx.options.yara_scan_requests:
            return

        if not flow.request.content:
            return

        matches = self._scan_data(flow.request.content)
        if not matches:
            return

        blocking = [m for m in matches if m.should_block]
        rule_names = [m.rule_name for m in matches]

        self._log_match(
            location="request",
            rules=rule_names,
            host=flow.request.host,
            request_path=flow.request.path,
        )

        flow.metadata["yara_matched"] = rule_names

        if blocking and ctx.options.yara_block_on_match:
            self.blocks_total += 1
            flow.metadata["blocked_by"] = self.name
            log.warning(f"BLOCKED: YARA matched {rule_names} -> {flow.request.host}{flow.request.path}")
            flow.response = self._create_block_response(blocking, "request")
        else:
            log.warning(f"WARN: YARA matched {rule_names} -> {flow.request.host}{flow.request.path}")

    def response(self, flow: http.HTTPFlow):
        """Scan response body."""
        if not ctx.options.yara_scan_responses:
            return

        if not flow.response or not flow.response.content:
            return

        matches = self._scan_data(flow.response.content)
        if not matches:
            return

        blocking = [m for m in matches if m.should_block]
        rule_names = [m.rule_name for m in matches]

        self._log_match(
            location="response",
            rules=rule_names,
            host=flow.request.host,
            request_path=flow.request.path,
        )

        flow.metadata["yara_matched_response"] = rule_names

        if blocking and ctx.options.yara_block_on_match:
            self.blocks_total += 1
            flow.metadata["blocked_by"] = self.name
            log.warning(f"BLOCKED: YARA matched {rule_names} <- {flow.request.host}{flow.request.path}")
            # Replace response with error
            flow.response = make_block_response(
                500,
                {"error": "Response blocked: sensitive content detected"},
                self.name,
            )
        else:
            log.warning(f"WARN: YARA matched {rule_names} <- {flow.request.host}{flow.request.path}")

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "yara_available": YARA_AVAILABLE,
            "rules_compiled": self.rules is not None,
            "scans_total": self.scans_total,
            "matches_total": self.matches_total,
            "blocks_total": self.blocks_total,
        }


# mitmproxy addon instance
addons = [YARAScanner()]
