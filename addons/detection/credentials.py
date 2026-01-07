"""
credentials.py - Credential detection and header analysis
"""

import math
import re
from dataclasses import dataclass


# =============================================================================
# Entropy Functions
# =============================================================================

def calculate_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy suggests more randomness (potential secret).
    Typical thresholds: <3.0 low, 3.0-4.0 medium, >4.0 high.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def looks_like_secret(value: str, entropy_config: dict | None = None) -> bool:
    """Check if value looks like a secret based on entropy heuristics.

    Uses length, character diversity, and Shannon entropy to detect
    potential secrets without pattern matching.

    Args:
        value: String to analyze
        entropy_config: Optional config dict with keys:
            - min_length: Minimum string length (default: 20)
            - min_charset_diversity: Unique chars / length ratio (default: 0.5)
            - min_shannon_entropy: Minimum entropy bits (default: 3.5)

    Returns:
        True if value appears to be a high-entropy secret
    """
    if entropy_config is None:
        entropy_config = {}

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


# =============================================================================
# Header Utilities
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

    def matches(self, value: str) -> str | None:
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


def detect_credential_type(value: str, rules: list[CredentialRule] = None) -> str | None:
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
    """Analyze headers for credentials.

    Args:
        headers: Dict of header name -> value
        rules: List of CredentialRule objects to match
        safe_headers_config: Config for safe header patterns
        entropy_config: Config for entropy-based detection
        standard_auth_headers: List of header names that typically contain auth
        detection_level: "standard" or "paranoid"

    Returns:
        List of detection dicts with credential info
    """
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
