"""
Tests for credential_guard.py addon.

Tests credential detection, host authorization, and blocking behavior.
"""

import json
import pytest
import tempfile
from pathlib import Path


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

        assert rule.matches("sk-ant-abc123xyz456def789ghi01")
        assert rule.matches("sk-ant-api03-abcdefghij-1234567890")

        assert rule.matches("sk-ant-short") is None
        assert rule.matches("sk-abc123xyz456def789ghi") is None


class TestHostMatching:
    """Tests for host pattern matching."""

    def test_exact_match(self):
        from addons.credential_guard import matches_host_pattern

        assert matches_host_pattern("api.openai.com", "api.openai.com")
        assert not matches_host_pattern("api.openai.com", "openai.com")

    def test_wildcard_match(self):
        from addons.credential_guard import matches_host_pattern

        assert matches_host_pattern("api.example.com", "*.example.com")
        assert matches_host_pattern("sub.api.example.com", "*.example.com")
        assert matches_host_pattern("example.com", "*.example.com")
        assert not matches_host_pattern("example.org", "*.example.com")

    def test_case_insensitive(self):
        from addons.credential_guard import matches_host_pattern

        assert matches_host_pattern("API.OpenAI.com", "api.openai.com")
        assert matches_host_pattern("api.openai.com", "API.OPENAI.COM")


class TestPathMatching:
    """Tests for path pattern matching."""

    def test_path_wildcard_suffix(self):
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/v1/chat", "/v1/*")
        assert path_matches_pattern("/v1/chat/completions", "/v1/*")
        assert not path_matches_pattern("/v2/chat", "/v1/*")

    def test_path_double_wildcard(self):
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/api/v1/anything", "/api/**")
        assert path_matches_pattern("/api", "/api/**")
        assert not path_matches_pattern("/other/path", "/api/**")

    def test_path_exact_match(self):
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/v1/models", "/v1/models")
        assert not path_matches_pattern("/v1/models/extra", "/v1/models")

    def test_path_full_wildcard(self):
        from addons.credential_guard import path_matches_pattern

        assert path_matches_pattern("/any/path", "/**")
        assert path_matches_pattern("/", "/**")
        assert path_matches_pattern("/any/path", "/*")

    def test_path_normalization(self):
        from addons.credential_guard import path_matches_pattern

        # Double slash normalized
        assert path_matches_pattern("//v1//models", "/v1/models")
        # Trailing slash normalized
        assert path_matches_pattern("/v1/models/", "/v1/models")


class TestShannonEntropy:
    """Tests for entropy calculation."""

    def test_empty_string(self):
        from addons.credential_guard import calculate_shannon_entropy

        assert calculate_shannon_entropy("") == 0.0

    def test_single_char(self):
        from addons.credential_guard import calculate_shannon_entropy

        assert calculate_shannon_entropy("a") == 0.0
        assert calculate_shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        from addons.credential_guard import calculate_shannon_entropy

        entropy = calculate_shannon_entropy("ab")
        assert abs(entropy - 1.0) < 0.01

    def test_high_entropy_string(self):
        from addons.credential_guard import calculate_shannon_entropy

        # Random-looking string should have high entropy
        entropy = calculate_shannon_entropy("sk-proj-abc123XYZ789def456GHI")
        assert entropy > 3.5


class TestLooksLikeSecret:
    """Tests for entropy-based secret detection."""

    def test_short_string_rejected(self):
        from addons.credential_guard import looks_like_secret

        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        assert not looks_like_secret("short", config)

    def test_low_diversity_rejected(self):
        from addons.credential_guard import looks_like_secret

        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # Long but repetitive
        assert not looks_like_secret("aaaaaaaaaaaaaaaaaaaaaaaaa", config)

    def test_high_entropy_accepted(self):
        from addons.credential_guard import looks_like_secret

        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # Random-looking API key
        assert looks_like_secret("sk-proj-abc123XYZ789def456GHI012jkl", config)


class TestHMACFingerprint:
    """Tests for HMAC fingerprinting."""

    def test_deterministic(self):
        from addons.credential_guard import hmac_fingerprint

        secret = b"test-secret"
        cred = "sk-abc123"

        fp1 = hmac_fingerprint(cred, secret)
        fp2 = hmac_fingerprint(cred, secret)
        assert fp1 == fp2

    def test_different_credentials_different_fingerprints(self):
        from addons.credential_guard import hmac_fingerprint

        secret = b"test-secret"
        fp1 = hmac_fingerprint("sk-abc123", secret)
        fp2 = hmac_fingerprint("sk-xyz789", secret)
        assert fp1 != fp2

    def test_different_secrets_different_fingerprints(self):
        from addons.credential_guard import hmac_fingerprint

        cred = "sk-abc123"
        fp1 = hmac_fingerprint(cred, b"secret1")
        fp2 = hmac_fingerprint(cred, b"secret2")
        assert fp1 != fp2

    def test_fingerprint_length(self):
        from addons.credential_guard import hmac_fingerprint

        fp = hmac_fingerprint("test", b"secret")
        assert len(fp) == 16  # First 16 chars of hex digest


class TestAnalyzeHeaders:
    """Tests for header analysis."""

    def test_detects_known_pattern_in_auth_header(self):
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"Authorization": "Bearer sk-proj-" + "a" * 80}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="standard"
        )

        assert len(detections) == 1
        assert detections[0]["rule_name"] == "openai"
        assert detections[0]["tier"] == 1
        assert detections[0]["confidence"] == "high"

    def test_detects_unknown_entropy_in_standard_mode(self):
        from addons.credential_guard import analyze_headers

        headers = {"X-Api-Key": "unknown-secret-abc123XYZ789def456GHI"}
        detections = analyze_headers(
            headers=headers,
            rules=[],
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["x-api-key"],
            detection_level="standard"
        )

        assert len(detections) == 1
        assert detections[0]["rule_name"] == "unknown_secret"
        assert detections[0]["tier"] == 2

    def test_skips_safe_headers(self):
        from addons.credential_guard import analyze_headers

        headers = {"X-Request-Id": "abc123XYZ789def456GHI012jkl345mno"}
        detections = analyze_headers(
            headers=headers,
            rules=[],
            safe_headers_config={"safe_patterns": ["x-request-id"]},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["x-request-id"],
            detection_level="paranoid"
        )

        assert len(detections) == 0


class TestDetermineDecision:
    """Tests for decision engine."""

    def test_allows_known_credential_to_correct_host(self):
        from addons.credential_guard import determine_decision, CredentialRule

        rules = [CredentialRule(name="test", patterns=[r"test-key"], allowed_hosts=["api.example.com"])]

        decision, context = determine_decision(
            credential="test-key",
            rule_name="test",
            host="api.example.com",
            path="/v1/api",
            rules=rules,
            policy={},
            hmac_secret=b"secret"
        )

        assert decision == "allow"

    def test_greylist_mismatch_for_wrong_host(self):
        from addons.credential_guard import determine_decision, CredentialRule

        rules = [CredentialRule(name="test", patterns=[r"test-key"], allowed_hosts=["api.example.com"])]

        decision, context = determine_decision(
            credential="test-key",
            rule_name="test",
            host="evil.com",
            path="/v1/api",
            rules=rules,
            policy={},
            hmac_secret=b"secret"
        )

        assert decision == "greylist_mismatch"
        assert "expected_hosts" in context

    def test_greylist_approval_for_unknown(self):
        from addons.credential_guard import determine_decision

        decision, context = determine_decision(
            credential="unknown-secret",
            rule_name="unknown_secret",
            host="api.example.com",
            path="/v1/api",
            rules=[],
            policy={},
            hmac_secret=b"secret"
        )

        assert decision == "greylist_approval"


class TestCheckPolicyApproval:
    """Tests for policy approval checking."""

    def test_approves_matching_policy(self):
        from addons.credential_guard import check_policy_approval, hmac_fingerprint

        secret = b"test-secret"
        credential = "my-api-key"
        fp = hmac_fingerprint(credential, secret)

        policy = {
            "approved": [
                {"token_hmac": fp, "hosts": ["api.example.com"], "paths": ["/**"]}
            ]
        }

        assert check_policy_approval(credential, "api.example.com", "/v1/test", policy, secret)

    def test_rejects_wrong_host(self):
        from addons.credential_guard import check_policy_approval, hmac_fingerprint

        secret = b"test-secret"
        credential = "my-api-key"
        fp = hmac_fingerprint(credential, secret)

        policy = {
            "approved": [
                {"token_hmac": fp, "hosts": ["api.example.com"], "paths": ["/**"]}
            ]
        }

        assert not check_policy_approval(credential, "evil.com", "/v1/test", policy, secret)

    def test_rejects_wrong_path(self):
        from addons.credential_guard import check_policy_approval, hmac_fingerprint

        secret = b"test-secret"
        credential = "my-api-key"
        fp = hmac_fingerprint(credential, secret)

        policy = {
            "approved": [
                {"token_hmac": fp, "hosts": ["api.example.com"], "paths": ["/v1/*"]}
            ]
        }

        assert not check_policy_approval(credential, "api.example.com", "/v2/test", policy, secret)


class TestResponseBuilders:
    """Tests for response building."""

    def test_mismatch_response_format(self):
        from addons.credential_guard import create_mismatch_response

        resp = create_mismatch_response(
            credential_type="openai",
            host="evil.com",
            expected_hosts=["api.openai.com"],
            fingerprint="hmac:abc123",
            path="/v1/chat",
        )

        assert resp.status_code == 428
        body = json.loads(resp.content)
        assert body["type"] == "destination_mismatch"
        assert body["credential_type"] == "openai"
        assert "api.openai.com" in body["expected_hosts"]

    def test_approval_response_format(self):
        from addons.credential_guard import create_approval_response

        resp = create_approval_response(
            credential_type="unknown_secret",
            host="api.example.com",
            fingerprint="hmac:abc123",
            path="/v1/api",
            reason="unknown_credential",
        )

        assert resp.status_code == 428
        body = json.loads(resp.content)
        assert body["type"] == "requires_approval"
        assert body["reason"] == "unknown_credential"


class TestCredentialGuardIntegration:
    """Integration tests using mitmproxy test fixtures."""

    def test_blocks_credential_to_wrong_host(self, credential_guard, make_flow):
        """Test that credentials to wrong host are blocked."""
        # Create flow with OpenAI key going to wrong host
        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        )

        credential_guard.request(flow)

        # Should be blocked
        assert flow.response is not None
        assert flow.response.status_code == 428
        assert flow.metadata.get("blocked_by") == "credential-guard"

    def test_allows_credential_to_correct_host(self, credential_guard, make_flow):
        """Test that credentials to correct host are allowed."""
        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        )

        credential_guard.request(flow)

        # Should not be blocked
        assert flow.response is None

    def test_allows_non_credential_requests(self, credential_guard, make_flow):
        """Test that requests without credentials pass through."""
        flow = make_flow(
            method="GET",
            url="https://example.com/api",
            headers={"Content-Type": "application/json"}
        )

        credential_guard.request(flow)

        assert flow.response is None

    def test_stats_increment_on_violation(self, credential_guard, make_flow):
        """Test that violation stats are tracked."""
        initial_count = credential_guard.violations_total

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        )
        credential_guard.request(flow)

        assert credential_guard.violations_total == initial_count + 1


class TestHomoglyphDetection:
    """Tests for homoglyph attack detection."""

    def test_detects_cyrillic_in_domain(self):
        from addons.credential_guard import detect_homoglyph_attack, HOMOGLYPH_ENABLED

        if not HOMOGLYPH_ENABLED:
            pytest.skip("confusable-homoglyphs not installed")

        # Cyrillic 'а' (U+0430) instead of Latin 'a'
        result = detect_homoglyph_attack("аpi.openai.com")
        assert result is not None
        assert result["dangerous"]

    def test_allows_normal_ascii_domain(self):
        from addons.credential_guard import detect_homoglyph_attack, HOMOGLYPH_ENABLED

        if not HOMOGLYPH_ENABLED:
            pytest.skip("confusable-homoglyphs not installed")

        result = detect_homoglyph_attack("api.openai.com")
        assert result is None


class TestBlockingMode:
    """Tests for blocking vs warn-only mode."""

    def test_warn_mode_logs_but_does_not_block(self, make_flow, policy_engine_initialized):
        """Test that warn mode (block=False) logs violation but doesn't block."""
        from addons.credential_guard import CredentialGuard, DEFAULT_RULES

        guard = CredentialGuard()
        guard.rules = list(DEFAULT_RULES)
        guard.hmac_secret = b"test-secret"
        guard.config = {}
        guard.safe_headers_config = {}

        # Mock _should_block to return False (warn-only mode)
        guard._should_block = lambda: False

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno"},
        )

        guard.request(flow)

        # Should NOT block (no response set)
        assert flow.response is None
        # But should still record the violation
        assert guard.violations_total == 1

    def test_blocking_mode_blocks(self, make_flow, policy_engine_initialized):
        """Test that blocking mode (block=True) actually blocks."""
        from addons.credential_guard import CredentialGuard, DEFAULT_RULES

        guard = CredentialGuard()
        guard.rules = list(DEFAULT_RULES)
        guard.hmac_secret = b"test-secret"
        guard.config = {}
        guard.safe_headers_config = {}

        # Mock _should_block to return True (blocking mode)
        guard._should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno"},
        )

        guard.request(flow)

        # Should block
        assert flow.response is not None
        assert flow.response.status_code == 428


class TestDetectionLevels:
    """Test material differences between paranoid, standard, and patterns-only modes."""

    def test_paranoid_catches_unknown_entropy_in_any_header(self):
        """Paranoid: Catches unknown high-entropy values in ANY non-safe header."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-Random-Header": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="paranoid"
        )

        # Paranoid mode should catch this (entropy heuristic on all headers)
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "unknown_secret"
        assert detections[0]["tier"] == 2

    def test_standard_ignores_unknown_entropy_in_nonsuspicious_header(self):
        """Standard: Does NOT catch unknown high-entropy in non-suspicious named headers."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-Random-Header": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="standard"
        )

        # Standard mode should NOT catch this (no suspicious name, no known pattern)
        assert len(detections) == 0

    def test_standard_catches_known_pattern_in_auth_header(self):
        """Standard: Catches known patterns in standard auth headers."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        # Key must be long enough to match the pattern (20+ chars after prefix)
        headers = {"Authorization": f"Bearer sk-proj-{'a' * 80}"}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="standard"
        )

        # Standard mode SHOULD catch this (known pattern in auth header)
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "openai"
        assert detections[0]["tier"] == 1

    def test_standard_ignores_pattern_in_non_auth_header(self):
        """Standard: Does NOT scan non-auth headers (only paranoid does)."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-Random-Header": "sk-proj-abc123xyz456def789ghijk"}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="standard"
        )

        # Standard mode only scans auth headers, not arbitrary headers
        assert len(detections) == 0

    def test_paranoid_catches_pattern_in_any_header(self):
        """Paranoid: Catches high-entropy in ANY header (not just auth)."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-Random-Header": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="paranoid"
        )

        # Paranoid catches entropy in any header
        assert len(detections) == 1
        assert detections[0]["rule_name"] == "unknown_secret"

    def test_patterns_only_ignores_unknown_entropy(self):
        """Patterns-only: Does NOT catch unknown high-entropy values."""
        from addons.credential_guard import analyze_headers, DEFAULT_RULES

        headers = {"X-Custom-Token": "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"}
        detections = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config={"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5},
            standard_auth_headers=["authorization"],
            detection_level="patterns-only"
        )

        # Patterns-only should NOT catch this (no entropy heuristics)
        assert len(detections) == 0


class TestSafeHeaders:
    """Test safe header detection."""

    def test_pattern_match(self):
        """Pattern-based header matches are detected."""
        from addons.credential_guard import is_safe_header

        config = {"safe_patterns": ["request-id", "trace", "correlation"]}
        assert is_safe_header("x-request-id", config) is True
        assert is_safe_header("x-correlation-id", config) is True
        assert is_safe_header("x-cloud-trace-context", config) is True
        assert is_safe_header("x-api-key", config) is False

    def test_case_insensitive(self):
        """Header matching is case-insensitive."""
        from addons.credential_guard import is_safe_header

        config = {"safe_patterns": ["request-id"]}
        assert is_safe_header("X-REQUEST-ID", config) is True
        assert is_safe_header("x-request-id", config) is True


class TestExtractToken:
    """Test token extraction from Authorization headers."""

    def test_bearer_scheme(self):
        """Extract token from 'Bearer <token>' format."""
        from addons.credential_guard import extract_bearer_token

        token = extract_bearer_token("Bearer sk-proj-abc123")
        assert token == "sk-proj-abc123"

    def test_no_scheme(self):
        """Token without scheme is returned as-is."""
        from addons.credential_guard import extract_bearer_token

        token = extract_bearer_token("sk-proj-abc123")
        assert token == "sk-proj-abc123"

    def test_empty_value(self):
        """Empty value returns empty string."""
        from addons.credential_guard import extract_bearer_token

        assert extract_bearer_token("") == ""


class TestHMACSecurityCritical:
    """Security-critical tests for HMAC fingerprinting."""

    def test_violation_log_never_contains_raw_credential(self, credential_guard, make_flow):
        """Ensure metadata never contains raw credentials."""
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
