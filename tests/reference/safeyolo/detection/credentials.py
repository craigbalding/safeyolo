"""
credentials.py - Credential detection and header analysis

Detects credentials in HTTP headers and validates routing to authorized
destinations. Body/URL scanning for arbitrary patterns is handled by
pattern_scanner.py.
"""

import base64
import binascii
import logging
import math
from dataclasses import dataclass

from .credential_catalog import build_default_rule_configs

log = logging.getLogger("safeyolo.credentials")

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


def looks_like_secret(value: str, entropy_config: dict | None = None) -> bool:  # DOC: SECURITY.md
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


def extract_basic_credential(auth_value: str) -> str | None:
    """Extract the credential half of an `Authorization: Basic <b64>` header.

    Basic auth transports credentials as `base64(userinfo:credential)`.
    The credential half is where the useful classifier signal lives --
    for example git-over-HTTPS via `gh auth git-credential fill` sends
    `Authorization: Basic <base64(oauth:gho_...)>`, so the underlying
    GitHub token is invisible to a pattern classifier that only looks at
    the raw header value.

    Returns the credential (everything after the first `:`) if the value
    is a decodable Basic header, else None. Callers should treat None as
    "not applicable, fall through to other extraction paths."
    """
    if not auth_value.lower().startswith("basic "):
        return None
    encoded = auth_value[6:].strip()
    if not encoded:
        return None
    try:
        # RFC 7617 says the payload is base64. Strict decoding rejects
        # values that a client would never actually send.
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    _userinfo, sep, credential = decoded.partition(":")
    if not sep:
        # No colon: not a well-formed userinfo pair.
        return None
    return credential


# =============================================================================
# Credential Rules
# =============================================================================

@dataclass
class CredentialRule:  # DOC: SECURITY.md
    """A credential detection rule."""
    name: str
    patterns: list[str]
    allowed_hosts: list[str]
    header_names: list[str] = None
    suggested_url: str = ""

    def __post_init__(self):
        if self.header_names is None:
            self.header_names = ["authorization", "x-api-key"]
        else:
            self.header_names = [name.lower() for name in self.header_names]
        # Relative import so this module works whether it was loaded
        # as `safeyolo.detection.credentials` (installed package) or as
        # top-level `detection.credentials` (fuzz harness that puts
        # cli/src/safeyolo on sys.path).
        from .patterns import compile_pattern

        self._compiled = []
        for p in self.patterns:
            compiled = compile_pattern(p)
            if compiled is not None:
                self._compiled.append(compiled)
            else:
                log.warning("Skipping invalid credential pattern for %s: %s", self.name, p[:60])

    def matches(self, value: str) -> str | None:
        """Check if value matches any pattern, return matched portion."""
        for pattern in self._compiled:
            match = pattern.search(value)
            if match:
                return match.group(0)
        return None


DEFAULT_RULES = [CredentialRule(**config) for config in build_default_rule_configs()]


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
            lowered = header_value.lower()
            if lowered.startswith("bearer "):
                value = extract_bearer_token(header_value)
            elif lowered.startswith("basic "):
                # Git-over-HTTPS via gh's credential helper sends
                # `Basic <b64(oauth:gho_...)>`. Decode and classify the
                # password half so the underlying token matches the
                # github rule instead of falling to entropy fallback.
                basic_credential = extract_basic_credential(header_value)
                if basic_credential is not None:
                    value = basic_credential

        if header_lower in standard_auth_headers:
            for rule in rules:
                if header_lower not in rule.header_names:
                    continue
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
