"""
detection - Pattern and credential detection logic

Regex-based pattern matching for secrets, jailbreaks, and credentials.
Pure functions suitable for testing and fuzzing.
"""

from .credentials import (
    CredentialRule,
    DEFAULT_RULES,
    analyze_headers,
    calculate_shannon_entropy,
    detect_credential_type,
    extract_bearer_token,
    is_safe_header,
    looks_like_secret,
)
from .patterns import (
    BUILTIN_JAILBREAK_PATTERNS,
    BUILTIN_SECRET_PATTERNS,
    PatternRule,
    compile_rules,
    scan_text,
)

__all__ = [
    # Patterns
    "PatternRule",
    "BUILTIN_SECRET_PATTERNS",
    "BUILTIN_JAILBREAK_PATTERNS",
    "compile_rules",
    "scan_text",
    # Credentials
    "CredentialRule",
    "DEFAULT_RULES",
    "is_safe_header",
    "extract_bearer_token",
    "detect_credential_type",
    "analyze_headers",
    "looks_like_secret",
    "calculate_shannon_entropy",
]
