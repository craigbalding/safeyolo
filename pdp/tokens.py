"""
tokens.py - Readonly token creation and validation for agent relay

Token format: <base64_payload>.<hmac_signature>
  Payload: {"scope": "readonly", "exp": unix_timestamp, "jti": hex_id}
  Signature: HMAC-SHA256 with admin token as key

Single-token model: only one token exists at a time, stored in a plain file.
Validation checks signature, expiry, AND exact match against the on-disk token.
Token survives restarts and expires after TTL (default: 1h).

Rotating the admin token automatically invalidates all relay tokens.

No external dependencies (stdlib only).
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

DEFAULT_TTL_SECONDS = 3600  # 1 hour


def create_readonly_token(admin_token: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """Create a readonly relay token signed with the admin token.

    Args:
        admin_token: The SafeYolo admin API token (used as HMAC key)
        ttl_seconds: Token time-to-live in seconds (default: 1h)

    Returns:
        Token string in format: <base64_payload>.<hex_signature>
    """
    payload = {
        "scope": "readonly",
        "exp": int(time.time()) + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode()

    sig = hmac.new(
        admin_token.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()

    return f"{payload_b64}.{sig}"


def validate_readonly_token(token: str, admin_token: str) -> dict | None:
    """Validate a readonly relay token (signature + expiry only).

    Args:
        token: Token string to validate
        admin_token: The SafeYolo admin API token (used as HMAC key)

    Returns:
        Decoded payload dict if valid, None if invalid or expired
    """
    parts = token.split(".")
    if len(parts) != 2:
        return None

    payload_b64, sig = parts

    # Verify signature
    expected_sig = hmac.new(
        admin_token.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        return None

    # Decode payload
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None

    # Check scope
    if payload.get("scope") != "readonly":
        return None

    # Check expiry
    exp = payload.get("exp", 0)
    if time.time() > exp:
        return None

    return payload


def read_active_token(token_path: Path) -> str | None:
    """Read the active token from disk.

    Returns None if the file doesn't exist or is empty.
    Reads directly without exists() check to avoid TOCTOU race.
    """
    try:
        content = token_path.read_text().strip()
        return content if content else None
    except FileNotFoundError:
        return None
    except OSError:
        return None


def delete_token_file(token_path: Path) -> bool:
    """Delete the token file. Returns True if a file was removed."""
    try:
        if token_path.exists():
            token_path.unlink()
            return True
    except OSError:
        pass
    return False
