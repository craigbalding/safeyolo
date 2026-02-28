"""Tests for pdp/tokens.py - readonly token creation and validation."""


from pdp.tokens import create_readonly_token, validate_readonly_token

ADMIN_TOKEN = "test-admin-token-for-hmac-signing"


class TestCreateToken:
    def test_creates_token_string(self):
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        assert isinstance(token, str)
        assert "." in token

    def test_token_has_two_parts(self):
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        parts = token.split(".")
        assert len(parts) == 2

    def test_different_tokens_have_different_jtis(self):
        token1 = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        token2 = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        assert token1 != token2


class TestValidateToken:
    def test_valid_token_returns_payload(self):
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        payload = validate_readonly_token(token, ADMIN_TOKEN)
        assert payload is not None
        assert payload["scope"] == "readonly"
        assert "jti" in payload
        assert "exp" in payload

    def test_expired_token_returns_none(self):
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=-1)
        payload = validate_readonly_token(token, ADMIN_TOKEN)
        assert payload is None

    def test_wrong_admin_token_returns_none(self):
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        payload = validate_readonly_token(token, "wrong-admin-token")
        assert payload is None

    def test_tampered_payload_returns_none(self):
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        # Tamper with payload
        parts = token.split(".")
        tampered = "dGFtcGVyZWQ" + parts[0][10:]
        tampered_token = f"{tampered}.{parts[1]}"
        payload = validate_readonly_token(tampered_token, ADMIN_TOKEN)
        assert payload is None

    def test_invalid_format_returns_none(self):
        assert validate_readonly_token("not-a-token", ADMIN_TOKEN) is None
        assert validate_readonly_token("", ADMIN_TOKEN) is None
        assert validate_readonly_token("a.b.c", ADMIN_TOKEN) is None

    def test_rotating_admin_token_invalidates(self):
        """Changing the admin token invalidates all existing tokens."""
        token = create_readonly_token(ADMIN_TOKEN, ttl_seconds=3600)
        # Valid with original admin token
        assert validate_readonly_token(token, ADMIN_TOKEN) is not None
        # Invalid with rotated admin token
        assert validate_readonly_token(token, "new-admin-token") is None
