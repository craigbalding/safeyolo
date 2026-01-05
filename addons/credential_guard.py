"""
credential_guard.py - Credential protection for AI coding agents

Detects credentials in HTTP requests and validates they're going to
authorized destinations. Emits structured events to JSONL for external
processing (approval workflow, notifications, alerting).

Design:
- ~500 lines focused on detect/validate/decide
- No notification code (handled by external safeyolo CLI)
- Read-only policy (writes via admin API)
- All decisions logged to JSONL for correlation

Usage:
    mitmdump -s addons/credential_guard.py --set credguard_block=true
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http

try:
    from .base import SecurityAddon
    from .utils import (
        make_block_response, load_config_file, get_client_ip,
        looks_like_secret, load_hmac_secret, hmac_fingerprint,
    )
except ImportError:
    from base import SecurityAddon
    from utils import (
        make_block_response, load_config_file, get_client_ip,
        looks_like_secret, load_hmac_secret, hmac_fingerprint,
    )

try:
    from .policy_engine import get_policy_engine
except ImportError:
    from policy_engine import get_policy_engine

log = logging.getLogger("safeyolo.credential-guard")


# =============================================================================
# Header Analysis Utilities
# =============================================================================

def is_safe_header(header_name: str, safe_config: dict) -> bool:
    """Check if header is known-safe (trace IDs, etc.)."""
    header_lower = header_name.lower()
    safe_patterns = safe_config.get("safe_patterns", [])
    for pattern in safe_patterns:
        if pattern.lower() in header_lower:
            return True
    return False


def extract_bearer_token(auth_value: str) -> str:
    """Extract token from Bearer auth header."""
    if auth_value.lower().startswith("bearer "):
        return auth_value[7:].strip()
    return auth_value


# =============================================================================
# Credential Rules
# =============================================================================

@dataclass
class CredentialRule:
    """A credential detection rule."""
    name: str
    patterns: list[str]
    allowed_hosts: list[str]
    header_names: list[str] = None
    suggested_url: str = ""

    def __post_init__(self):
        if self.header_names is None:
            self.header_names = ["authorization", "x-api-key"]
        self._compiled = [re.compile(p) for p in self.patterns]

    def matches(self, value: str) -> Optional[str]:
        """Check if value matches any pattern, return matched portion."""
        for pattern in self._compiled:
            match = pattern.search(value)
            if match:
                return match.group(0)
        return None


DEFAULT_RULES = [
    CredentialRule(
        name="openai",
        patterns=[r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", r"sk-proj-[a-zA-Z0-9_-]{80,}"],
        allowed_hosts=["api.openai.com"],
    ),
    CredentialRule(
        name="anthropic",
        patterns=[r"sk-ant-api[a-zA-Z0-9-]{90,}"],
        allowed_hosts=["api.anthropic.com"],
    ),
    CredentialRule(
        name="github",
        patterns=[r"gh[ps]_[a-zA-Z0-9]{36}"],
        allowed_hosts=["api.github.com", "github.com"],
    ),
]


def detect_credential_type(value: str, rules: list[CredentialRule] = None) -> Optional[str]:
    """Detect credential type from value using pattern matching."""
    if rules is None:
        rules = DEFAULT_RULES

    for rule in rules:
        if rule.matches(value):
            return rule.name

    return None


# =============================================================================
# Header Analysis
# =============================================================================

def analyze_headers(
    headers: dict,
    rules: list[CredentialRule],
    safe_headers_config: dict,
    entropy_config: dict,
    standard_auth_headers: list[str],
    detection_level: str = "standard"
) -> list[dict]:
    """Analyze headers for credentials."""
    detections = []

    for header_name, header_value in headers.items():
        header_lower = header_name.lower()

        if is_safe_header(header_name, safe_headers_config):
            continue

        value = header_value
        if header_lower == "authorization":
            value = extract_bearer_token(header_value)

        if header_lower in standard_auth_headers:
            for rule in rules:
                matched = rule.matches(value)
                if matched:
                    detections.append({
                        "credential": matched,
                        "rule_name": rule.name,
                        "header_name": header_name,
                        "confidence": "high",
                        "tier": 1,
                        "allowed_hosts": rule.allowed_hosts,
                        "suggested_url": rule.suggested_url,
                    })
                    break
            else:
                if detection_level in ("standard", "paranoid") and looks_like_secret(value, entropy_config):
                    detections.append({
                        "credential": value,
                        "rule_name": "unknown_secret",
                        "header_name": header_name,
                        "confidence": "medium",
                        "tier": 2,
                        "allowed_hosts": [],
                        "suggested_url": "",
                    })

        elif detection_level == "paranoid":
            if looks_like_secret(value, entropy_config):
                detections.append({
                    "credential": value,
                    "rule_name": "unknown_secret",
                    "header_name": header_name,
                    "confidence": "low",
                    "tier": 2,
                    "allowed_hosts": [],
                    "suggested_url": "",
                })

    return detections


# =============================================================================
# Decision Engine
# =============================================================================

def determine_decision_with_policy_engine(
    credential: str,
    rule_name: str,
    host: str,
    path: str,
    rules: list[CredentialRule],
    hmac_secret: bytes,
) -> tuple[str, dict]:
    """Determine credential decision using PolicyEngine."""
    policy_engine = get_policy_engine()

    if policy_engine is None:
        raise RuntimeError("PolicyEngine not initialized.")

    credential_type = detect_credential_type(credential, rules)
    if credential_type is None:
        credential_type = "unknown"

    fingerprint = hmac_fingerprint(credential, hmac_secret)

    decision = policy_engine.evaluate_credential(
        credential_type=credential_type,
        destination=host,
        path=path,
        credential_hmac=fingerprint,
    )

    if decision.effect == "allow":
        return "allow", {}
    elif decision.effect == "deny":
        expected_hosts = []
        for rule in rules:
            if rule.name == credential_type:
                expected_hosts = rule.allowed_hosts
                break
        return "greylist_mismatch", {"expected_hosts": expected_hosts, "suggested_url": ""}
    elif decision.effect == "prompt":
        return "greylist_approval", {"reason": "requires_approval"}
    elif decision.effect == "budget_exceeded":
        return "greylist_approval", {"reason": "budget_exceeded"}
    else:
        return "greylist_approval", {"reason": decision.reason or "unknown"}


# =============================================================================
# Response Builders
# =============================================================================

def create_mismatch_response(
    credential_type: str,
    host: str,
    expected_hosts: list[str],
    fingerprint: str,
    path: str,
    suggested_url: str = ""
) -> http.Response:
    """Create 428 response for destination mismatch."""
    body = {
        "error": "Credential routing error",
        "type": "destination_mismatch",
        "credential_type": credential_type,
        "destination": host,
        "expected_hosts": expected_hosts,
        "credential_fingerprint": fingerprint,
        "action": "self_correct",
        "reflection": f"You sent a {credential_type} credential to {host}, but it should go to {expected_hosts}. Please verify the URL.",
    }
    if suggested_url:
        body["suggested_url"] = suggested_url
    return make_block_response(428, body, "credential-guard")


def create_approval_response(
    credential_type: str,
    host: str,
    fingerprint: str,
    path: str,
    reason: str
) -> http.Response:
    """Create 428 response for approval required."""
    body = {
        "error": "Credential requires approval",
        "type": "requires_approval",
        "credential_type": credential_type,
        "destination": host,
        "credential_fingerprint": fingerprint,
        "reason": reason,
        "action": "wait_for_approval",
        "reflection": "This credential requires human approval before use.",
    }
    return make_block_response(428, body, "credential-guard")


# =============================================================================
# Main Addon
# =============================================================================

class CredentialGuard(SecurityAddon):
    """Credential protection addon - detect, validate, decide, emit."""

    name = "credential-guard"

    def __init__(self):
        # Custom stats - don't call super().__init__()
        self.rules: list[CredentialRule] = []
        self.config: dict = {}
        self.safe_headers_config: dict = {}
        self.hmac_secret: bytes = b""
        self.violations_total = 0
        self.violations_by_type: dict[str, int] = {}

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option("credguard_rules", Optional[str], None, "Path to rules JSON")
        loader.add_option("credguard_block", bool, True, "Block violations (default: true)")
        loader.add_option("credguard_scan_urls", bool, False, "Scan URLs for credentials")
        loader.add_option("credguard_scan_bodies", bool, False, "Scan request bodies")
        loader.add_option("credguard_log_path", Optional[str], None, "JSONL log path")

    def configure(self, updates):
        """Handle configuration updates."""
        if not self.config:
            self._load_config()
        if "credguard_rules" in updates:
            self._load_rules()

    def _load_config(self):
        """Load configuration files."""
        config_dir = Path(__file__).parent.parent / "config"
        self.config = load_config_file(config_dir / "credential_guard.yaml")
        self.safe_headers_config = load_config_file(config_dir / "safe_headers.yaml")
        self.hmac_secret = load_hmac_secret(Path("/app/data/hmac_secret"))

    def _load_rules(self):
        """Load credential rules."""
        rules_path = ctx.options.credguard_rules
        if rules_path and Path(rules_path).exists():
            try:
                with open(rules_path) as f:
                    data = json.load(f)
                self.rules = [
                    CredentialRule(
                        name=r["name"],
                        patterns=r.get("patterns", [r.get("pattern")]),
                        allowed_hosts=r.get("allowed_hosts", []),
                        suggested_url=r.get("suggested_url", ""),
                    )
                    for r in data.get("credentials", [])
                ]
                log.info(f"Loaded {len(self.rules)} rules from {rules_path}")
            except Exception as e:
                log.error(f"Failed to load rules: {type(e).__name__}: {e}")
                self.rules = list(DEFAULT_RULES)
        else:
            self.rules = list(DEFAULT_RULES)

    def should_block(self) -> bool:
        """Override base - uses credguard_block option."""
        return ctx.options.credguard_block

    def _get_project_id(self, flow: http.HTTPFlow) -> str:
        """Get project ID from service discovery."""
        client_ip = get_client_ip(flow)
        if client_ip == "unknown":
            return "default"

        try:
            from .service_discovery import get_service_discovery
            sd = get_service_discovery()
            if sd:
                return sd.get_project_for_ip(client_ip)
        except Exception as e:
            log.debug(f"Service discovery lookup failed: {type(e).__name__}: {e}")
        return "default"

    def _record_violation(self, rule: str, host: str):
        """Record violation for stats."""
        self.violations_total += 1
        self.violations_by_type[rule] = self.violations_by_type.get(rule, 0) + 1

    def request(self, flow: http.HTTPFlow):
        """Inspect request for credential leakage."""
        policy = flow.metadata.get("policy")
        if policy and not policy.is_addon_enabled("credential-guard"):
            return

        host = flow.request.host.lower()
        path = flow.request.path
        project_id = self._get_project_id(flow)

        entropy_config = self.config.get("entropy", {
            "min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5
        })
        detection_level = self.config.get("detection_level", "standard")
        standard_auth_headers = self.config.get("standard_auth_headers", [
            "authorization", "x-api-key", "api-key", "x-auth-token", "apikey"
        ])

        detections = analyze_headers(
            headers=dict(flow.request.headers),
            rules=self.rules,
            safe_headers_config=self.safe_headers_config,
            entropy_config=entropy_config,
            standard_auth_headers=standard_auth_headers,
            detection_level=detection_level
        )

        for det in detections:
            credential = det["credential"]
            rule_name = det["rule_name"]
            header = det["header_name"]
            confidence = det["confidence"]
            tier = det["tier"]
            fp = hmac_fingerprint(credential, self.hmac_secret)

            decision, context = determine_decision_with_policy_engine(
                credential=credential,
                rule_name=rule_name,
                host=host,
                path=path,
                rules=self.rules,
                hmac_secret=self.hmac_secret,
            )

            log_data = {
                "rule": rule_name, "host": host, "location": f"header:{header}",
                "fingerprint": f"hmac:{fp}", "confidence": confidence, "tier": tier,
                "project_id": project_id
            }

            if decision == "allow":
                self.log_decision(flow, "allow", **log_data)
                continue

            self._record_violation(rule_name, host)
            flow.metadata["blocked_by"] = self.name
            flow.metadata["credential_fingerprint"] = f"hmac:{fp}"

            if decision == "greylist_mismatch":
                log_data["reason"] = "destination_mismatch"
                log_data["expected_hosts"] = context.get("expected_hosts", [])

                if self.should_block():
                    self.log_decision(flow, "block", **log_data)
                    flow.response = create_mismatch_response(
                        rule_name, host, context.get("expected_hosts", []),
                        f"hmac:{fp}", path, context.get("suggested_url", "")
                    )
                    return
                else:
                    self.log_decision(flow, "warn", **log_data)

            elif decision == "greylist_approval":
                log_data["reason"] = "requires_approval"

                if self.should_block():
                    self.log_decision(flow, "block", **log_data)
                    flow.response = create_approval_response(
                        rule_name, host, f"hmac:{fp}", path, "unknown_credential"
                    )
                    return
                else:
                    self.log_decision(flow, "warn", **log_data)

    def get_stats(self) -> dict:
        """Get stats for admin API."""
        return {
            "violations_total": self.violations_total,
            "violations_by_type": self.violations_by_type,
            "rules_count": len(self.rules),
        }


addons = [CredentialGuard()]
