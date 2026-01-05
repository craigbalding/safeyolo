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

import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from mitmproxy import ctx, http
from yarl import URL

try:
    from confusable_homoglyphs import confusables as homoglyph_confusables
    HOMOGLYPH_ENABLED = True
except ImportError:
    HOMOGLYPH_ENABLED = False
    homoglyph_confusables = None

try:
    from .utils import write_event, make_block_response
except ImportError:
    from utils import write_event, make_block_response

try:
    from .policy_engine import get_policy_engine, PolicyDecision
except ImportError:
    from policy_engine import get_policy_engine, PolicyDecision

log = logging.getLogger("safeyolo.credential-guard")


# =============================================================================
# Configuration & Utilities
# =============================================================================

def load_yaml_config(path: Path, default=None) -> dict:
    """Load YAML config file, return default if not found."""
    if not path.exists():
        return default or {}
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.error(f"Failed to load {path}: {type(e).__name__}: {e}")
        return default or {}


def load_hmac_secret(secret_path: Path) -> bytes:
    """Load or generate HMAC secret for credential fingerprinting."""
    env_secret = os.environ.get("CREDGUARD_HMAC_SECRET")
    if env_secret:
        return env_secret.encode()

    if secret_path.exists():
        return secret_path.read_bytes().strip()

    # Generate new secret
    secret = secrets.token_hex(32).encode()
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_bytes(secret)
    secret_path.chmod(0o600)
    log.info(f"Generated new HMAC secret at {secret_path}")
    return secret


def hmac_fingerprint(credential: str, secret: bytes) -> str:
    """Generate HMAC fingerprint for a credential (never log raw)."""
    h = hmac.new(secret, credential.encode(), hashlib.sha256)
    return h.hexdigest()[:16]


def normalize_path(path: str) -> str:
    """Normalize URL path for consistent matching."""
    path = unicodedata.normalize("NFKC", path)
    normalized = URL("http://x" + path).path
    normalized = re.sub(r"/+", "/", normalized)
    return normalized.rstrip("/") or "/"


# =============================================================================
# Validation: Host & Path Matching
# =============================================================================

def matches_host_pattern(host: str, pattern: str) -> bool:
    """Check if host matches pattern (supports wildcards)."""
    host = host.lower()
    pattern = pattern.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) or host == pattern[2:]

    return host == pattern


def path_matches_pattern(path: str, pattern: str) -> bool:
    """Check if path matches pattern (supports * and **)."""
    path = normalize_path(path)
    pattern = normalize_path(pattern)

    if pattern == "/*" or pattern == "/**":
        return True

    if "**" in pattern:
        prefix = pattern.split("**")[0].rstrip("/")
        return path.startswith(prefix) or path == prefix.rstrip("/")

    if pattern.endswith("/*"):
        prefix = pattern[:-2]
        return path.startswith(prefix + "/") or path == prefix

    return path == pattern


def detect_homoglyph_attack(text: str) -> Optional[dict]:
    """Detect mixed-script homoglyph attacks."""
    if not HOMOGLYPH_ENABLED or not homoglyph_confusables:
        return None

    try:
        result = homoglyph_confusables.is_dangerous(text)
        if result:
            return {
                "dangerous": True,
                "message": f"Mixed scripts detected in '{text}'"
            }
    except Exception:
        pass
    return None


# =============================================================================
# Detection: Entropy & Pattern Analysis
# =============================================================================

def calculate_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def looks_like_secret(value: str, entropy_config: dict) -> bool:
    """Check if value looks like a secret based on entropy heuristics."""
    min_length = entropy_config.get("min_length", 20)
    min_diversity = entropy_config.get("min_charset_diversity", 0.5)
    min_entropy = entropy_config.get("min_shannon_entropy", 3.5)

    if len(value) < min_length:
        return False

    unique_chars = len(set(value))
    diversity = unique_chars / len(value)
    if diversity < min_diversity:
        return False

    entropy = calculate_shannon_entropy(value)
    return entropy >= min_entropy


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


# Default rules for common providers
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
    """
    Detect credential type from value using pattern matching.

    This maps raw credential values to human-readable types for policy evaluation.
    HMAC fingerprinting is still used for logging (never log raw credentials).

    Args:
        value: The credential value to analyze
        rules: Optional list of rules (defaults to DEFAULT_RULES)

    Returns:
        Credential type name (e.g., "openai", "anthropic") or None if unknown
    """
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
    """Analyze headers for credentials.

    Returns list of detections with:
    - credential: the detected value
    - rule_name: matched rule or "unknown_secret"
    - header_name: source header
    - confidence: high/medium/low
    - tier: 1 (pattern) or 2 (entropy)
    """
    detections = []

    for header_name, header_value in headers.items():
        header_lower = header_name.lower()

        # Skip safe headers
        if is_safe_header(header_name, safe_headers_config):
            continue

        # Extract token if Bearer auth
        value = header_value
        if header_lower == "authorization":
            value = extract_bearer_token(header_value)

        # Tier 1: Pattern matching (standard auth headers)
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
                # No pattern match - check entropy for unknown secrets
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

        # Tier 2: All headers (paranoid mode)
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
    """
    Determine credential decision using PolicyEngine.

    Uses the unified policy system for credential authorization.
    Supports both type-based matching (e.g., "openai:*") and HMAC-based
    matching (e.g., "hmac:a1b2c3d4") in policy conditions.

    Args:
        credential: Raw credential value
        rule_name: Detected rule name (from pattern matching)
        host: Target host
        path: Request path
        rules: Credential rules (for expected hosts in error messages)
        hmac_secret: HMAC secret for fingerprinting

    Returns:
        (decision_type, context) where decision_type is:
        - "allow": credential approved for destination
        - "greylist_mismatch": known credential, wrong destination
        - "greylist_approval": unknown credential, needs approval
    """
    policy_engine = get_policy_engine()

    if policy_engine is None:
        raise RuntimeError("PolicyEngine not initialized. Call init_policy_engine() first.")

    # Detect credential type
    credential_type = detect_credential_type(credential, rules)
    if credential_type is None:
        credential_type = "unknown"

    # Calculate HMAC fingerprint for policy matching
    fingerprint = hmac_fingerprint(credential, hmac_secret)

    # Evaluate with PolicyEngine (destination-first matching)
    decision = policy_engine.evaluate_credential(
        credential_type=credential_type,
        destination=host,
        path=path,
        credential_hmac=fingerprint,
    )

    # Map PolicyEngine decision to response format
    if decision.effect == "allow":
        return "allow", {}
    elif decision.effect == "deny":
        # Find expected hosts from rules for error message
        expected_hosts = []
        for rule in rules:
            if rule.name == credential_type:
                expected_hosts = rule.allowed_hosts
                break
        return "greylist_mismatch", {
            "expected_hosts": expected_hosts,
            "suggested_url": "",
        }
    elif decision.effect == "prompt":
        return "greylist_approval", {"reason": "requires_approval"}
    elif decision.effect == "budget_exceeded":
        return "greylist_approval", {"reason": "budget_exceeded"}
    else:
        # Unknown effect - default to require approval
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
        "reflection": f"This credential requires human approval before use. The request has been logged for review.",
    }
    return make_block_response(428, body, "credential-guard")




# =============================================================================
# Main Addon
# =============================================================================

class CredentialGuard:
    """Credential protection addon - detect, validate, decide, emit."""

    name = "credential-guard"

    def __init__(self):
        self.rules: list[CredentialRule] = []
        self.config: dict = {}
        self.safe_headers_config: dict = {}
        self.hmac_secret: bytes = b""

        # Stats
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

        self.config = load_yaml_config(config_dir / "credential_guard.yaml")
        self.safe_headers_config = load_yaml_config(config_dir / "safe_headers.yaml")
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

    def _should_block(self) -> bool:
        return ctx.options.credguard_block

    def _get_project_id(self, flow: http.HTTPFlow) -> str:
        """Get project ID from service discovery."""
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        if not client_ip:
            return "default"

        try:
            from .service_discovery import get_service_discovery
            sd = get_service_discovery()
            if sd:
                return sd.get_project_for_ip(client_ip)
        except Exception:
            pass
        return "default"

    def _record_violation(self, rule: str, host: str):
        """Record violation for stats."""
        self.violations_total += 1
        self.violations_by_type[rule] = self.violations_by_type.get(rule, 0) + 1

    def request(self, flow: http.HTTPFlow):
        """Inspect request for credential leakage."""
        # Check policy bypass
        policy = flow.metadata.get("policy")
        if policy and not policy.is_addon_enabled("credential-guard"):
            return

        host = flow.request.host.lower()
        path = flow.request.path
        project_id = self._get_project_id(flow)

        # Config
        entropy_config = self.config.get("entropy", {
            "min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5
        })
        detection_level = self.config.get("detection_level", "standard")
        standard_auth_headers = self.config.get("standard_auth_headers", [
            "authorization", "x-api-key", "api-key", "x-auth-token", "apikey"
        ])

        # Analyze headers
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

            # Get decision using PolicyEngine
            decision, context = determine_decision_with_policy_engine(
                credential=credential,
                rule_name=rule_name,
                host=host,
                path=path,
                rules=self.rules,
                hmac_secret=self.hmac_secret,
            )

            # Log decision
            log_data = {
                "rule": rule_name, "host": host, "location": f"header:{header}",
                "fingerprint": f"hmac:{fp}", "confidence": confidence, "tier": tier,
                "project_id": project_id
            }

            if decision == "allow":
                write_event("security.credential", request_id=flow.metadata.get("request_id"),
                           addon=self.name, decision="allow", **log_data)
                continue

            # Violation
            self._record_violation(rule_name, host)
            flow.metadata["blocked_by"] = self.name
            flow.metadata["credential_fingerprint"] = f"hmac:{fp}"

            if decision == "greylist_mismatch":
                log_data["reason"] = "destination_mismatch"
                log_data["expected_hosts"] = context.get("expected_hosts", [])

                if self._should_block():
                    write_event("security.credential", request_id=flow.metadata.get("request_id"),
                               addon=self.name, decision="block", **log_data)
                    flow.response = create_mismatch_response(
                        rule_name, host, context.get("expected_hosts", []),
                        f"hmac:{fp}", path, context.get("suggested_url", "")
                    )
                    return
                else:
                    write_event("security.credential", request_id=flow.metadata.get("request_id"),
                               addon=self.name, decision="warn", **log_data)

            elif decision == "greylist_approval":
                log_data["reason"] = "requires_approval"

                if self._should_block():
                    write_event("security.credential", request_id=flow.metadata.get("request_id"),
                               addon=self.name, decision="block", **log_data)
                    flow.response = create_approval_response(
                        rule_name, host, f"hmac:{fp}", path, "unknown_credential"
                    )
                    return
                else:
                    write_event("security.credential", request_id=flow.metadata.get("request_id"),
                               addon=self.name, decision="warn", **log_data)

    def get_stats(self) -> dict:
        """Get stats for admin API."""
        return {
            "violations_total": self.violations_total,
            "violations_by_type": self.violations_by_type,
            "rules_count": len(self.rules),
        }


# mitmproxy addon registration
addons = [CredentialGuard()]
