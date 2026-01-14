"""
detection - Pattern and credential detection logic

Pure functions suitable for testing and fuzzing.

Modules:
- credentials: Credential detection in headers, routing validation
- patterns: User-configurable pattern scanning framework
- matching: Host/resource pattern matching utilities
"""

from .credentials import (
    DEFAULT_RULES,
    CredentialRule,
    analyze_headers,
    calculate_shannon_entropy,
    detect_credential_type,
    extract_bearer_token,
    is_safe_header,
    looks_like_secret,
)
from .matching import (
    hmac_fingerprint,
    matches_host_pattern,
    matches_resource_pattern,
    normalize_path,
)
from .patterns import (
    BUILTIN_PATTERN_SETS,
    PatternRule,
    compile_pattern,
    load_builtin_set,
    load_patterns_from_config,
    scan_text,
)

__all__ = [
    # Credentials (header detection + routing)
    "CredentialRule",
    "DEFAULT_RULES",
    "is_safe_header",
    "extract_bearer_token",
    "detect_credential_type",
    "analyze_headers",
    "looks_like_secret",
    "calculate_shannon_entropy",
    # User-configurable patterns
    "PatternRule",
    "compile_pattern",
    "load_patterns_from_config",
    "load_builtin_set",
    "BUILTIN_PATTERN_SETS",
    "scan_text",
    # Matching utilities
    "hmac_fingerprint",
    "matches_host_pattern",
    "matches_resource_pattern",
    "normalize_path",
]
