"""Token creation/validation - thin wrapper around pdp.tokens.

When pdp is on PYTHONPATH (inside the proxy container, or when running
from the workspace root), imports from pdp.tokens directly.

When running as standalone CLI (pip-installed), provides the same
implementation inline. pdp.tokens uses only stdlib, so this is safe.
"""

try:
    from pdp.tokens import create_readonly_token, validate_readonly_token
except ImportError:
    # Standalone CLI mode - pdp not on PYTHONPATH
    # Inline the pure-stdlib implementation from pdp/tokens.py
    import base64
    import hashlib
    import hmac
    import json
    import secrets
    import time

    def create_readonly_token(admin_token: str, ttl_seconds: int = 3600) -> str:
        """Create a readonly relay token signed with the admin token."""
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
        """Validate a readonly relay token."""
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        expected_sig = hmac.new(
            admin_token.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes)
        except (ValueError, json.JSONDecodeError):
            return None
        if payload.get("scope") != "readonly":
            return None
        if time.time() > payload.get("exp", 0):
            return None
        return payload


__all__ = ["create_readonly_token", "validate_readonly_token"]
