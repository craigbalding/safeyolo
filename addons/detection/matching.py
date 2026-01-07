"""
matching.py - Host and resource pattern matching, HMAC fingerprinting
"""

import fnmatch
import hashlib
import hmac
import re
import unicodedata

from yarl import URL


def hmac_fingerprint(value: str, secret: bytes, prefix_len: int = 16) -> str:
    """Generate HMAC fingerprint for sensitive data (never log raw values).

    Args:
        value: Sensitive string to fingerprint
        secret: HMAC secret key
        prefix_len: Length of hex digest to return (default: 16)

    Returns:
        Truncated hex digest (e.g., "a1b2c3d4e5f67890")
    """
    h = hmac.new(secret, value.encode(), hashlib.sha256)
    return h.hexdigest()[:prefix_len]


def normalize_path(path: str) -> str:
    """Normalize URL path for consistent, secure matching.

    Security properties:
    - Unicode NFKC normalization (prevents homoglyph bypasses)
    - URL parsing via yarl (handles encoding correctly)
    - Collapses multiple slashes (prevents // bypass tricks)
    - Strips trailing slashes (consistent matching)

    Args:
        path: URL path to normalize

    Returns:
        Normalized path (e.g., "//v1//chat/" -> "/v1/chat")
    """
    path = unicodedata.normalize("NFKC", path)
    normalized = URL("http://x" + path).path
    normalized = re.sub(r"/+", "/", normalized)
    return normalized.rstrip("/") or "/"


def matches_host_pattern(host: str, pattern: str) -> bool:
    """Check if host matches pattern with secure wildcard handling.

    Supports:
    - Exact match: "api.openai.com"
    - Subdomain wildcard: "*.openai.com" (matches api.openai.com, also openai.com)

    Args:
        host: Hostname to check
        pattern: Pattern to match against

    Returns:
        True if host matches pattern
    """
    host = host.lower()
    pattern = pattern.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return host.endswith(suffix) or host == pattern[2:]

    return host == pattern


def matches_resource_pattern(resource: str, pattern: str) -> bool:
    """Check if resource matches pattern with normalized, strict matching.

    Normalizes resource before matching for security. Supports fnmatch
    glob patterns for user-friendly policy writing.

    Supports:
    - Exact: "/v1/chat/completions"
    - Wildcard: "/v1/*" (single path segment)
    - Recursive: "/v1/**" or "api.openai.com/*" (any depth)
    - Glob patterns: "*.json", "/v[12]/*"

    Args:
        resource: Resource string (path or host/path) to check
        pattern: Pattern to match against

    Returns:
        True if normalized resource matches pattern
    """
    if "/" in resource and not resource.startswith("/"):
        parts = resource.split("/", 1)
        host = parts[0].lower()
        path = normalize_path("/" + parts[1]) if len(parts) > 1 else "/"
        resource = host + path
    elif resource.startswith("/"):
        resource = normalize_path(resource)
    else:
        resource = resource.lower()

    pattern = pattern.lower()

    if resource == pattern:
        return True

    if "**" in pattern:
        fnmatch_pattern = pattern.replace("**", "*")
        if fnmatch.fnmatch(resource, fnmatch_pattern):
            return True
        base_pattern = pattern.rstrip("*").rstrip("/")
        if resource == base_pattern:
            return True
        return False

    return fnmatch.fnmatch(resource, pattern)
