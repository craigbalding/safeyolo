"""
Tests for credential_guard.py addon.

Tests credential detection, host authorization, and blocking behavior.

Structure:
- TestCredentialRule, TestHostMatching, TestPathMatching, TestShannonEntropy,
  TestLooksLikeSecret, TestHMACFingerprint, TestAnalyzeHeaders, TestSafeHeaders,
  TestExtractToken, TestDetectionLevels: These test detection/utils helpers, not
  credential_guard.py directly. They live here for historical reasons (moving
  them is out of scope).
- TestResponseBuilders: Tests create_mismatch_response and create_approval_response.
- TestResponseFromDecision: Tests response_from_decision() status mapping.
- TestEvaluateCredentialWithPDP: Tests the PDP evaluation function directly.
- TestMaybeReloadRules: Tests hot-reload and failure modes.
- TestRecordViolation: Tests stats counters.
- TestCredentialGuardRequest: Tests the request() method flow.
- TestCredentialGuardIntegration: Full integration tests with PDP.
- TestBlockingMode: Block vs warn mode.
- TestHMACSecurityCritical: Never leak raw credentials.
"""

import json
import logging
from unittest import mock

# =========================================================================
# Helper tests (detection/utils) -- kept as-is from prior file
# =========================================================================


class TestCredentialRule:
    """Tests for CredentialRule pattern matching."""

    def test_openai_key_pattern(self):
        """Test OpenAI API key pattern detection."""
        from credential_guard import CredentialRule

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
        from credential_guard import CredentialRule

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
    """Tests for host pattern matching (imported from utils)."""

    def test_exact_match(self):
        from safeyolo.core.utils import matches_host_pattern

        assert matches_host_pattern("api.openai.com", "api.openai.com")
        assert not matches_host_pattern("api.openai.com", "openai.com")

    def test_wildcard_match(self):
        from safeyolo.core.utils import matches_host_pattern

        assert matches_host_pattern("api.example.com", "*.example.com")
        assert matches_host_pattern("sub.api.example.com", "*.example.com")
        assert matches_host_pattern("example.com", "*.example.com")
        assert not matches_host_pattern("example.org", "*.example.com")

    def test_case_insensitive(self):
        from safeyolo.core.utils import matches_host_pattern

        assert matches_host_pattern("API.OpenAI.com", "api.openai.com")
        assert matches_host_pattern("api.openai.com", "API.OPENAI.COM")


class TestPathMatching:
    """Tests for path/resource pattern matching (imported from utils)."""

    def test_path_wildcard_suffix(self):
        from safeyolo.core.utils import matches_resource_pattern

        assert matches_resource_pattern("/v1/chat", "/v1/*")
        assert matches_resource_pattern("/v1/chat/completions", "/v1/*")
        assert not matches_resource_pattern("/v2/chat", "/v1/*")

    def test_path_double_wildcard(self):
        from safeyolo.core.utils import matches_resource_pattern

        assert matches_resource_pattern("/api/v1/anything", "/api/**")
        assert matches_resource_pattern("/api", "/api/**")
        assert not matches_resource_pattern("/other/path", "/api/**")

    def test_path_exact_match(self):
        from safeyolo.core.utils import matches_resource_pattern

        assert matches_resource_pattern("/v1/models", "/v1/models")
        assert not matches_resource_pattern("/v1/models/extra", "/v1/models")

    def test_path_full_wildcard(self):
        from safeyolo.core.utils import matches_resource_pattern

        assert matches_resource_pattern("/any/path", "/**")
        assert matches_resource_pattern("/", "/**")
        assert matches_resource_pattern("/any/path", "/*")

    def test_path_normalization(self):
        from safeyolo.core.utils import matches_resource_pattern

        # Double slash normalized
        assert matches_resource_pattern("//v1//models", "/v1/models")
        # Trailing slash normalized
        assert matches_resource_pattern("/v1/models/", "/v1/models")


class TestShannonEntropy:
    """Tests for entropy calculation (imported from utils)."""

    def test_empty_string(self):
        from safeyolo.core.utils import calculate_shannon_entropy

        assert calculate_shannon_entropy("") == 0.0

    def test_single_char(self):
        from safeyolo.core.utils import calculate_shannon_entropy

        assert calculate_shannon_entropy("a") == 0.0
        assert calculate_shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        from safeyolo.core.utils import calculate_shannon_entropy

        entropy = calculate_shannon_entropy("ab")
        assert abs(entropy - 1.0) < 0.01

    def test_high_entropy_string(self):
        from safeyolo.core.utils import calculate_shannon_entropy

        # Random-looking string should have high entropy
        entropy = calculate_shannon_entropy("sk-proj-abc123XYZ789def456GHI")
        assert entropy > 3.5


class TestLooksLikeSecret:
    """Tests for entropy-based secret detection (imported from utils)."""

    def test_short_string_rejected(self):
        from safeyolo.core.utils import looks_like_secret

        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        assert not looks_like_secret("short", config)

    def test_low_diversity_rejected(self):
        from safeyolo.core.utils import looks_like_secret

        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # Long but repetitive
        assert not looks_like_secret("aaaaaaaaaaaaaaaaaaaaaaaaa", config)

    def test_high_entropy_accepted(self):
        from safeyolo.core.utils import looks_like_secret

        config = {"min_length": 20, "min_charset_diversity": 0.5, "min_shannon_entropy": 3.5}
        # Random-looking API key
        assert looks_like_secret("sk-proj-abc123XYZ789def456GHI012jkl", config)


class TestHMACFingerprint:
    """Tests for HMAC fingerprinting (imported from utils)."""

    def test_deterministic(self):
        from safeyolo.core.utils import hmac_fingerprint

        secret = b"test-secret"
        cred = "sk-abc123"

        fp1 = hmac_fingerprint(cred, secret)
        fp2 = hmac_fingerprint(cred, secret)
        assert fp1 == fp2

    def test_different_credentials_different_fingerprints(self):
        from safeyolo.core.utils import hmac_fingerprint

        secret = b"test-secret"
        fp1 = hmac_fingerprint("sk-abc123", secret)
        fp2 = hmac_fingerprint("sk-xyz789", secret)
        assert fp1 != fp2

    def test_different_secrets_different_fingerprints(self):
        from safeyolo.core.utils import hmac_fingerprint

        cred = "sk-abc123"
        fp1 = hmac_fingerprint(cred, b"secret1")
        fp2 = hmac_fingerprint(cred, b"secret2")
        assert fp1 != fp2

    def test_fingerprint_length(self):
        from safeyolo.core.utils import hmac_fingerprint

        fp = hmac_fingerprint("test", b"secret")
        assert len(fp) == 16  # First 16 chars of hex digest


class TestAnalyzeHeaders:
    """Tests for header analysis."""

    def test_detects_known_pattern_in_auth_header(self):
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from credential_guard import analyze_headers

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
        from credential_guard import analyze_headers

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


class TestResponseBuilders:
    """Tests for response building."""

    def test_mismatch_response_format(self):
        from credential_guard import create_mismatch_response

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
        from credential_guard import create_approval_response

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


class TestDetectionLevels:
    """Test material differences between paranoid, standard, and patterns-only modes."""

    def test_paranoid_catches_unknown_entropy_in_any_header(self):
        """Paranoid: Catches unknown high-entropy values in ANY non-safe header."""
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from credential_guard import analyze_headers

        from safeyolo.detection import DEFAULT_RULES

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
        from safeyolo.detection import is_safe_header

        config = {"safe_patterns": ["request-id", "trace", "correlation"]}
        assert is_safe_header("x-request-id", config) is True
        assert is_safe_header("x-correlation-id", config) is True
        assert is_safe_header("x-cloud-trace-context", config) is True
        assert is_safe_header("x-api-key", config) is False

    def test_case_insensitive(self):
        """Header matching is case-insensitive."""
        from safeyolo.detection import is_safe_header

        config = {"safe_patterns": ["request-id"]}
        assert is_safe_header("X-REQUEST-ID", config) is True
        assert is_safe_header("x-request-id", config) is True


class TestExtractToken:
    """Test token extraction from Authorization headers."""

    def test_bearer_scheme(self):
        """Extract token from 'Bearer <token>' format."""
        from safeyolo.detection import extract_bearer_token

        token = extract_bearer_token("Bearer sk-proj-abc123")
        assert token == "sk-proj-abc123"

    def test_no_scheme(self):
        """Token without scheme is returned as-is."""
        from safeyolo.detection import extract_bearer_token

        token = extract_bearer_token("sk-proj-abc123")
        assert token == "sk-proj-abc123"

    def test_empty_value(self):
        """Empty value returns empty string."""
        from safeyolo.detection import extract_bearer_token

        assert extract_bearer_token("") == ""


# =========================================================================
# credential_guard.py-specific tests -- NEW
# =========================================================================


class TestEvaluateCredentialWithPDP:
    """Tests for evaluate_credential_with_pdp() function.

    Contract:
    - Calls get_policy_client() to get a client, then client.evaluate().
    - On RuntimeError from get_policy_client(), returns Effect.ERROR (fail-closed).
    - On any Exception from client.evaluate(), returns Effect.ERROR (fail-closed).
    - On success, returns (decision.effect, context_dict).
    - For DENY/REQUIRE_APPROVAL, context includes expected_hosts and suggested_url.
    - Credential type detected as "unknown" when detect_credential_type returns None.
    """

    def test_runtime_error_from_get_policy_client_returns_effect_error(self, make_flow):
        """B1: When PDP is not configured, fail closed with Effect.ERROR."""
        from credential_guard import evaluate_credential_with_pdp

        from pdp import Effect

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-test-abc"},
        )

        with mock.patch("credential_guard.get_policy_client", side_effect=RuntimeError("not configured")):
            effect, context = evaluate_credential_with_pdp(
                flow=flow,
                credential="sk-test-abc123def456ghi789",
                rule_name="openai",
                confidence="high",
                rules=[],
                hmac_secret=b"test-secret",
                principal_id="project:default",
            )

        assert effect == Effect.ERROR
        assert context["reason_codes"] == ["PDP_NOT_CONFIGURED"]
        assert "fail-closed" in context["reason"]
        assert context["fingerprint"].startswith("hmac:")

    def test_evaluate_exception_returns_effect_error(self, make_flow):
        """B1: When client.evaluate() throws, fail closed with Effect.ERROR."""
        from credential_guard import evaluate_credential_with_pdp

        from pdp import Effect

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-test-abc"},
        )

        mock_client = mock.MagicMock()
        mock_client.evaluate.side_effect = ConnectionError("PDP unreachable")

        with mock.patch("credential_guard.get_policy_client", return_value=mock_client):
            with mock.patch("credential_guard.build_http_event_from_flow", return_value=mock.MagicMock()):
                effect, context = evaluate_credential_with_pdp(
                    flow=flow,
                    credential="sk-test-abc123def456ghi789",
                    rule_name="openai",
                    confidence="high",
                    rules=[],
                    hmac_secret=b"test-secret",
                    principal_id="project:default",
                )

        assert effect == Effect.ERROR
        assert context["reason_codes"] == ["PDP_EVALUATION_FAILED"]
        assert "ConnectionError" in context["reason"]
        assert context["fingerprint"].startswith("hmac:")

    def test_allow_decision_returns_effect_allow(self, make_flow):
        """Normal flow: PDP says ALLOW, returns Effect.ALLOW with context."""
        from credential_guard import evaluate_credential_with_pdp

        from pdp import Effect

        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat",
            headers={"Authorization": "Bearer sk-test-abc"},
        )

        mock_decision = mock.MagicMock()
        mock_decision.effect = Effect.ALLOW
        mock_decision.reason_codes = ["ALLOWED"]
        mock_decision.reason = "Allowed by policy"

        mock_client = mock.MagicMock()
        mock_client.evaluate.return_value = mock_decision

        with mock.patch("credential_guard.get_policy_client", return_value=mock_client):
            with mock.patch("credential_guard.build_http_event_from_flow", return_value=mock.MagicMock()):
                effect, context = evaluate_credential_with_pdp(
                    flow=flow,
                    credential="sk-test-abc123def456ghi789",
                    rule_name="openai",
                    confidence="high",
                    rules=[],
                    hmac_secret=b"test-secret",
                    principal_id="project:default",
                )

        assert effect == Effect.ALLOW
        assert context["reason_codes"] == ["ALLOWED"]
        assert context["fingerprint"].startswith("hmac:")
        assert context["decision"] is mock_decision

    def test_deny_decision_populates_expected_hosts(self, make_flow):
        """DENY decisions include expected_hosts from matching rule."""
        from credential_guard import evaluate_credential_with_pdp

        from pdp import Effect
        from safeyolo.detection import CredentialRule

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-test-abc"},
        )

        mock_decision = mock.MagicMock()
        mock_decision.effect = Effect.DENY
        mock_decision.reason_codes = ["DESTINATION_MISMATCH"]
        mock_decision.reason = "Credential not allowed for this host"

        mock_client = mock.MagicMock()
        mock_client.evaluate.return_value = mock_decision

        rule = CredentialRule(
            name="openai",
            patterns=[r"sk-[a-zA-Z0-9]{20,}"],
            allowed_hosts=["api.openai.com"],
            suggested_url="https://api.openai.com/v1/chat",
        )

        with mock.patch("credential_guard.get_policy_client", return_value=mock_client):
            with mock.patch("credential_guard.build_http_event_from_flow", return_value=mock.MagicMock()):
                # detect_credential_type returns "openai" for this credential
                with mock.patch("credential_guard.detect_credential_type", return_value="openai"):
                    effect, context = evaluate_credential_with_pdp(
                        flow=flow,
                        credential="sk-test-abc123def456ghi789",
                        rule_name="openai",
                        confidence="high",
                        rules=[rule],
                        hmac_secret=b"test-secret",
                        principal_id="project:default",
                    )

        assert effect == Effect.DENY
        assert context["expected_hosts"] == ["api.openai.com"]
        assert context["suggested_url"] == "https://api.openai.com/v1/chat"

    def test_unknown_credential_type_defaults_to_unknown(self, make_flow):
        """When detect_credential_type returns None, type becomes 'unknown'."""
        from credential_guard import evaluate_credential_with_pdp

        from pdp import Effect

        flow = make_flow(
            method="POST",
            url="https://api.example.com/api",
            headers={"X-Api-Key": "some-secret"},
        )

        mock_decision = mock.MagicMock()
        mock_decision.effect = Effect.ALLOW
        mock_decision.reason_codes = ["ALLOWED"]
        mock_decision.reason = "Allowed"

        mock_client = mock.MagicMock()
        mock_client.evaluate.return_value = mock_decision

        with mock.patch("credential_guard.get_policy_client", return_value=mock_client):
            with mock.patch("credential_guard.detect_credential_type", return_value=None):
                with mock.patch("credential_guard.build_http_event_from_flow") as mock_build:
                    mock_build.return_value = mock.MagicMock()
                    evaluate_credential_with_pdp(
                        flow=flow,
                        credential="unknown-secret-value-here-long",
                        rule_name="unknown_secret",
                        confidence="low",
                        rules=[],
                        hmac_secret=b"test-secret",
                        principal_id="project:default",
                    )

                    # Verify the credential_type passed to build_http_event_from_flow was "unknown"
                    call_kwargs = mock_build.call_args[1]
                    assert call_kwargs["credential_type"] == "unknown"


class TestResponseFromDecision:
    """Tests for response_from_decision() function.

    Contract:
    - If decision has immediate_response, use its status_code and body_json.
    - If no immediate_response, fall back to status_map:
      DENY->403, REQUIRE_APPROVAL->428, BUDGET_EXCEEDED->429, ERROR->500.
    - Unknown effects fall back to 403.
    """

    def test_uses_immediate_response_when_present(self):
        """When PDP provides immediate_response, use it directly."""
        from credential_guard import response_from_decision

        ir = mock.MagicMock()
        ir.status_code = 428
        ir.body_json = {"error": "custom PDP response", "type": "test"}

        decision = mock.MagicMock()
        decision.immediate_response = ir

        resp = response_from_decision(decision)

        assert resp.status_code == 428
        body = json.loads(resp.content)
        assert body["error"] == "custom PDP response"
        assert body["type"] == "test"

    def test_fallback_deny_returns_403(self):
        """DENY without immediate_response returns 403."""
        from credential_guard import response_from_decision

        from pdp import Effect

        decision = mock.MagicMock()
        decision.immediate_response = None
        decision.effect = Effect.DENY
        decision.reason = "Destination mismatch"
        decision.reason_codes = ["DEST_MISMATCH"]

        resp = response_from_decision(decision)

        assert resp.status_code == 403
        body = json.loads(resp.content)
        assert body["error"] == "Deny"
        assert body["reason"] == "Destination mismatch"
        assert body["reason_codes"] == ["DEST_MISMATCH"]

    def test_fallback_require_approval_returns_428(self):
        """REQUIRE_APPROVAL without immediate_response returns 428."""
        from credential_guard import response_from_decision

        from pdp import Effect

        decision = mock.MagicMock()
        decision.immediate_response = None
        decision.effect = Effect.REQUIRE_APPROVAL
        decision.reason = "Needs approval"
        decision.reason_codes = ["REQUIRE_APPROVAL"]

        resp = response_from_decision(decision)

        assert resp.status_code == 428
        body = json.loads(resp.content)
        assert body["error"] == "Require Approval"

    def test_fallback_budget_exceeded_returns_429(self):
        """BUDGET_EXCEEDED without immediate_response returns 429."""
        from credential_guard import response_from_decision

        from pdp import Effect

        decision = mock.MagicMock()
        decision.immediate_response = None
        decision.effect = Effect.BUDGET_EXCEEDED
        decision.reason = "Rate limit"
        decision.reason_codes = ["BUDGET_EXCEEDED"]

        resp = response_from_decision(decision)

        assert resp.status_code == 429
        body = json.loads(resp.content)
        assert body["error"] == "Budget Exceeded"

    def test_fallback_error_returns_500(self):
        """ERROR without immediate_response returns 500."""
        from credential_guard import response_from_decision

        from pdp import Effect

        decision = mock.MagicMock()
        decision.immediate_response = None
        decision.effect = Effect.ERROR
        decision.reason = "PDP internal error"
        decision.reason_codes = ["PDP_ERROR"]

        resp = response_from_decision(decision)

        assert resp.status_code == 500
        body = json.loads(resp.content)
        assert body["error"] == "Error"

    def test_fallback_unknown_effect_returns_403(self):
        """Effect not in the status_map defaults to 403."""
        from credential_guard import response_from_decision

        from pdp import Effect

        # ALLOW is not in the fallback status_map (only DENY, REQUIRE_APPROVAL,
        # BUDGET_EXCEEDED, ERROR are mapped). This exercises the .get() default.
        decision = mock.MagicMock()
        decision.immediate_response = None
        decision.effect = Effect.ALLOW
        decision.reason = "Allowed but no immediate_response"
        decision.reason_codes = ["ALLOWED"]

        resp = response_from_decision(decision)

        assert resp.status_code == 403

    def test_response_has_blocked_by_header(self):
        """All responses include X-Blocked-By header."""
        from credential_guard import response_from_decision

        from pdp import Effect

        decision = mock.MagicMock()
        decision.immediate_response = None
        decision.effect = Effect.DENY
        decision.reason = "denied"
        decision.reason_codes = ["DENIED"]

        resp = response_from_decision(decision, addon_name="credential-guard")

        assert resp.headers.get("X-Blocked-By") == "credential-guard"


class TestMaybeReloadRules:
    """Tests for _maybe_reload_rules() method.

    Contract:
    - On policy hash change, reloads rules from PDP sensor_config.
    - On same hash, does nothing (no-op).
    - RuntimeError from get_policy_client() is swallowed (PDP not ready yet).
    - Other exceptions on first load (empty _last_policy_hash) log ERROR.
    - Other exceptions on subsequent reload log WARNING.
    """

    def _make_guard(self):
        from credential_guard import CredentialGuard
        guard = CredentialGuard()
        guard.hmac_secret = b"test-secret"
        guard.config = {}
        guard.safe_headers_config = {}
        return guard

    def test_reloads_on_hash_change(self):
        """Rules are reloaded when policy hash changes."""
        guard = self._make_guard()
        guard._last_policy_hash = "old-hash"

        mock_client = mock.MagicMock()
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "new-hash",
            "credential_rules": [
                {"name": "openai", "patterns": [r"sk-[a-zA-Z0-9]{20,}"], "allowed_hosts": ["api.openai.com"]},
            ],
            "addons": {},
        }

        with mock.patch("pdp.get_policy_client", return_value=mock_client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            guard._maybe_reload_rules()

        assert guard._last_policy_hash == "new-hash"
        assert len(guard.rules) == 1
        assert guard.rules[0].name == "openai"

    def test_noop_on_same_hash(self):
        """No reload when policy hash is unchanged."""
        guard = self._make_guard()
        guard._last_policy_hash = "same-hash"
        guard.rules = ["sentinel"]  # Should not be overwritten

        mock_client = mock.MagicMock()
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "same-hash",
        }

        with mock.patch("pdp.get_policy_client", return_value=mock_client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            guard._maybe_reload_rules()

        assert guard._last_policy_hash == "same-hash"
        assert guard.rules == ["sentinel"]

    def test_runtime_error_swallowed_silently(self):
        """RuntimeError from get_policy_client() is swallowed (PDP not ready)."""
        guard = self._make_guard()

        with mock.patch("pdp.is_policy_client_configured", return_value=False):
            # Should not raise
            guard._maybe_reload_rules()

        # No rules loaded, no hash change
        assert guard._last_policy_hash == ""
        assert guard.rules == []

    def test_first_load_failure_logs_error(self, caplog):
        """B2: First-load failure (empty hash) logs ERROR, not WARNING."""
        guard = self._make_guard()
        assert guard._last_policy_hash == ""

        mock_client = mock.MagicMock()
        mock_client.get_sensor_config.side_effect = ValueError("corrupted config")

        with mock.patch("pdp.get_policy_client", return_value=mock_client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            with caplog.at_level(logging.ERROR, logger="safeyolo.credential-guard"):
                guard._maybe_reload_rules()

        assert guard._last_policy_hash == ""
        assert any("First credential rule load failed" in r.message for r in caplog.records)
        assert any(r.levelno == logging.ERROR for r in caplog.records
                   if "First credential rule load failed" in r.message)

    def test_subsequent_reload_failure_logs_warning(self, caplog):
        """B2: Reload failure with existing rules logs WARNING, not ERROR."""
        guard = self._make_guard()
        guard._last_policy_hash = "existing-hash"

        mock_client = mock.MagicMock()
        mock_client.get_sensor_config.side_effect = ValueError("corrupted config")

        with mock.patch("pdp.get_policy_client", return_value=mock_client), \
             mock.patch("pdp.is_policy_client_configured", return_value=True):
            with caplog.at_level(logging.WARNING, logger="safeyolo.credential-guard"):
                guard._maybe_reload_rules()

        # Hash unchanged, previous rules preserved
        assert guard._last_policy_hash == "existing-hash"
        assert any("previous rules preserved" in r.message for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records
                   if "previous rules preserved" in r.message)


class TestRecordViolation:
    """Tests for _record_violation() stats tracking.

    Contract:
    - Increments violations_total by 1.
    - Increments violations_by_type[rule] by 1.
    - Multiple calls for same rule accumulate.
    - Different rules have separate counters.
    """

    def _make_guard(self):
        from credential_guard import CredentialGuard
        guard = CredentialGuard()
        return guard

    def test_increments_total_count(self):
        """Each violation increments total."""
        guard = self._make_guard()
        assert guard.violations_total == 0

        guard._record_violation("openai", "evil.com")

        assert guard.violations_total == 1

    def test_increments_by_type_count(self):
        """Each violation increments the type-specific counter."""
        guard = self._make_guard()
        assert guard.violations_by_type == {}

        guard._record_violation("openai", "evil.com")

        assert guard.violations_by_type == {"openai": 1}

    def test_accumulates_same_rule(self):
        """Multiple violations of same rule accumulate."""
        guard = self._make_guard()

        guard._record_violation("openai", "evil1.com")
        guard._record_violation("openai", "evil2.com")

        assert guard.violations_total == 2
        assert guard.violations_by_type == {"openai": 2}

    def test_separate_counters_per_rule(self):
        """Different rules have separate counters."""
        guard = self._make_guard()

        guard._record_violation("openai", "evil.com")
        guard._record_violation("github", "evil.com")
        guard._record_violation("openai", "bad.com")

        assert guard.violations_total == 3
        assert guard.violations_by_type == {"openai": 2, "github": 1}


class TestGetStats:
    """Tests for get_stats() method.

    Contract:
    - Returns dict with violations_total, violations_by_type, rules_count.
    """

    def test_stats_reflect_current_state(self):
        """get_stats() reflects current addon state."""
        from credential_guard import CredentialGuard

        guard = CredentialGuard()
        guard.violations_total = 5
        guard.violations_by_type = {"openai": 3, "github": 2}
        guard.rules = [mock.MagicMock(), mock.MagicMock()]

        stats = guard.get_stats()

        assert stats == {
            "violations_total": 5,
            "violations_by_type": {"openai": 3, "github": 2},
            "rules_count": 2,
        }

    def test_stats_default_values(self):
        """Fresh guard has zero stats."""
        from credential_guard import CredentialGuard

        guard = CredentialGuard()
        stats = guard.get_stats()

        assert stats == {
            "violations_total": 0,
            "violations_by_type": {},
            "rules_count": 0,
        }


class TestCredentialGuardRequest:
    """Tests for CredentialGuard.request() method.

    Contract:
    - Returns immediately if flow.response is already set.
    - Returns immediately if _is_enabled() returns False.
    - Calls _maybe_reload_rules() on every request.
    - When detections found and PDP says DENY in block mode:
      sets flow.response, sets flow.metadata["blocked_by"], records violation.
    - When detections found and PDP says DENY in warn mode:
      does NOT set flow.response, still records violation.
    - When PDP says ALLOW: no response set, no violation recorded.
    """

    def _make_guard(self):
        from credential_guard import CredentialGuard
        guard = CredentialGuard()
        guard.hmac_secret = b"test-secret"
        guard.config = {}
        guard.safe_headers_config = {}
        guard.rules = []
        return guard

    def test_early_exit_when_flow_has_response(self, make_flow):
        """If flow.response is already set, request() returns immediately."""
        from mitmproxy import http as mhttp

        guard = self._make_guard()

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-proj-" + "a" * 80},
        )
        # Simulate another addon already setting a response
        flow.response = mhttp.Response.make(403, b"already blocked")

        # Patch _maybe_reload_rules to verify it is NOT called
        with mock.patch.object(guard, "_maybe_reload_rules") as mock_reload:
            guard.request(flow)

        mock_reload.assert_not_called()
        assert flow.response.status_code == 403  # Original response preserved

    def test_returns_early_when_disabled(self, make_flow):
        """If _is_enabled returns False, request() skips processing."""
        guard = self._make_guard()

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-proj-" + "a" * 80},
        )

        with mock.patch.object(guard, "_is_enabled", return_value=False):
            with mock.patch.object(guard, "_maybe_reload_rules"):
                guard.request(flow)

        assert flow.response is None
        assert guard.violations_total == 0

    def test_no_detections_means_no_blocking(self, make_flow):
        """Requests without credentials pass through untouched."""
        guard = self._make_guard()

        flow = make_flow(
            method="GET",
            url="https://example.com/page",
            headers={"Accept": "text/html"},
        )

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[]):
                    guard.request(flow)

        assert flow.response is None
        assert guard.violations_total == 0

    def test_deny_in_block_mode_sets_response(self, make_flow):
        """DENY + block mode sets flow.response and metadata."""
        from pdp import Effect

        guard = self._make_guard()
        guard.should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-cred-value"},
        )

        detection = {
            "credential": "sk-cred-value-long-enough-for-test",
            "rule_name": "openai",
            "header_name": "authorization",
            "confidence": "high",
            "tier": 1,
        }

        mock_pdp_decision = mock.MagicMock()
        mock_pdp_decision.effect = Effect.DENY
        mock_pdp_decision.reason_codes = ["DESTINATION_MISMATCH"]
        mock_pdp_decision.reason = "Mismatch"
        mock_pdp_decision.immediate_response = None

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[detection]):
                    with mock.patch("credential_guard.evaluate_credential_with_pdp",
                                    return_value=(Effect.DENY, {
                                        "fingerprint": "hmac:abc123",
                                        "reason_codes": ["DESTINATION_MISMATCH"],
                                        "expected_hosts": ["api.openai.com"],
                                        "reason": "Mismatch",
                                    })):
                        guard.request(flow)

        assert flow.response is not None
        assert flow.metadata.get("blocked_by") == "credential-guard"
        assert flow.metadata.get("credential_fingerprint") == "hmac:abc123"
        assert guard.violations_total == 1
        assert guard.violations_by_type == {"openai": 1}

    def test_deny_in_warn_mode_does_not_set_response(self, make_flow):
        """DENY + warn mode records violation but does not block."""
        from pdp import Effect

        guard = self._make_guard()
        guard.should_block = lambda: False

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-cred-value"},
        )

        detection = {
            "credential": "sk-cred-value-long-enough-for-test",
            "rule_name": "openai",
            "header_name": "authorization",
            "confidence": "high",
            "tier": 1,
        }

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[detection]):
                    with mock.patch("credential_guard.evaluate_credential_with_pdp",
                                    return_value=(Effect.DENY, {
                                        "fingerprint": "hmac:abc123",
                                        "reason_codes": ["DESTINATION_MISMATCH"],
                                        "expected_hosts": ["api.openai.com"],
                                        "reason": "Mismatch",
                                    })):
                        guard.request(flow)

        assert flow.response is None
        assert guard.violations_total == 1

    def test_allow_does_not_block_or_record_violation(self, make_flow):
        """ALLOW from PDP means no blocking and no violation recorded."""
        from pdp import Effect

        guard = self._make_guard()
        guard.should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://api.openai.com/v1/chat",
            headers={"Authorization": "Bearer sk-cred-value"},
        )

        detection = {
            "credential": "sk-cred-value-long-enough-for-test",
            "rule_name": "openai",
            "header_name": "authorization",
            "confidence": "high",
            "tier": 1,
        }

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[detection]):
                    with mock.patch("credential_guard.evaluate_credential_with_pdp",
                                    return_value=(Effect.ALLOW, {
                                        "fingerprint": "hmac:abc123",
                                        "reason_codes": ["ALLOWED"],
                                        "reason": "Allowed by policy",
                                    })):
                        guard.request(flow)

        assert flow.response is None
        assert guard.violations_total == 0

    def test_error_effect_blocks_in_block_mode(self, make_flow):
        """Effect.ERROR from PDP evaluation triggers a block (fail-closed)."""
        from pdp import Effect

        guard = self._make_guard()
        guard.should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-cred-value"},
        )

        detection = {
            "credential": "sk-cred-value-long-enough-for-test",
            "rule_name": "openai",
            "header_name": "authorization",
            "confidence": "high",
            "tier": 1,
        }

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[detection]):
                    with mock.patch("credential_guard.evaluate_credential_with_pdp",
                                    return_value=(Effect.ERROR, {
                                        "fingerprint": "hmac:abc123",
                                        "reason_codes": ["PDP_NOT_CONFIGURED"],
                                        "reason": "Policy engine not configured",
                                    })):
                        guard.request(flow)

        assert flow.response is not None
        assert flow.metadata.get("blocked_by") == "credential-guard"
        assert guard.violations_total == 1

    def test_block_mode_uses_pdp_immediate_response_when_available(self, make_flow):
        """When PDP provides immediate_response, use it instead of legacy builders."""
        from pdp import Effect

        guard = self._make_guard()
        guard.should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-cred-value"},
        )

        detection = {
            "credential": "sk-cred-value-long-enough-for-test",
            "rule_name": "openai",
            "header_name": "authorization",
            "confidence": "high",
            "tier": 1,
        }

        mock_decision = mock.MagicMock()
        mock_decision.immediate_response = mock.MagicMock()
        mock_decision.immediate_response.status_code = 428
        mock_decision.immediate_response.body_json = {"error": "PDP says no", "type": "custom"}

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[detection]):
                    with mock.patch("credential_guard.evaluate_credential_with_pdp",
                                    return_value=(Effect.DENY, {
                                        "fingerprint": "hmac:abc123",
                                        "reason_codes": ["DESTINATION_MISMATCH"],
                                        "reason": "Mismatch",
                                        "decision": mock_decision,
                                    })):
                        guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        body = json.loads(flow.response.content)
        assert body["error"] == "PDP says no"

    def test_block_mode_deny_without_pdp_decision_uses_legacy_mismatch(self, make_flow):
        """DENY without PDP decision falls back to create_mismatch_response."""
        from pdp import Effect

        guard = self._make_guard()
        guard.should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/api",
            headers={"Authorization": "Bearer sk-cred-value"},
        )

        detection = {
            "credential": "sk-cred-value-long-enough-for-test",
            "rule_name": "openai",
            "header_name": "authorization",
            "confidence": "high",
            "tier": 1,
        }

        with mock.patch.object(guard, "_maybe_reload_rules"):
            with mock.patch.object(guard, "_is_enabled", return_value=True):
                with mock.patch("credential_guard.analyze_headers", return_value=[detection]):
                    with mock.patch("credential_guard.evaluate_credential_with_pdp",
                                    return_value=(Effect.DENY, {
                                        "fingerprint": "hmac:abc123",
                                        "reason_codes": ["DESTINATION_MISMATCH"],
                                        "expected_hosts": ["api.openai.com"],
                                        "suggested_url": "https://api.openai.com/v1/chat",
                                        "reason": "Mismatch",
                                        # No "decision" key => falls back to legacy
                                    })):
                        guard.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        body = json.loads(flow.response.content)
        assert body["type"] == "destination_mismatch"
        assert body["credential_type"] == "openai"


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


class TestBlockingMode:
    """Tests for blocking vs warn-only mode."""

    def test_warn_mode_logs_but_does_not_block(self, make_flow, policy_engine_initialized):
        """Test that warn mode (block=False) logs violation but doesn't block."""
        from credential_guard import CredentialGuard

        from safeyolo.detection import DEFAULT_RULES

        guard = CredentialGuard()
        guard.rules = list(DEFAULT_RULES)
        guard.hmac_secret = b"test-secret"
        guard.config = {}
        guard.safe_headers_config = {}

        # Mock should_block to return False (warn-only mode)
        guard.should_block = lambda: False

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
        from credential_guard import CredentialGuard

        from safeyolo.detection import DEFAULT_RULES

        guard = CredentialGuard()
        guard.rules = list(DEFAULT_RULES)
        guard.hmac_secret = b"test-secret"
        guard.config = {}
        guard.safe_headers_config = {}

        # Mock should_block to return True (blocking mode)
        guard.should_block = lambda: True

        flow = make_flow(
            method="POST",
            url="https://evil.com/steal",
            headers={"Authorization": "Bearer sk-proj-abc123xyz456def789ghijkghijklmno"},
        )

        guard.request(flow)

        # Should block
        assert flow.response is not None
        assert flow.response.status_code == 428


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


class TestIsEnabled:
    """Tests for _is_enabled() method.

    Contract:
    - Calls get_policy_client().is_addon_enabled() with addon name and context.
    - On RuntimeError (PDP not configured), defaults to True (enabled).
    """

    def test_returns_true_when_pdp_not_configured(self, make_flow):
        """When PDP is not configured, defaults to enabled."""
        from credential_guard import CredentialGuard

        guard = CredentialGuard()

        flow = make_flow(url="https://example.com/api")

        with mock.patch("credential_guard.get_policy_client", side_effect=RuntimeError("not configured")):
            result = guard._is_enabled(flow)

        assert result is True

    def test_returns_pdp_response_when_configured(self, make_flow):
        """Returns whatever PDP says when configured."""
        from credential_guard import CredentialGuard

        guard = CredentialGuard()

        flow = make_flow(url="https://example.com/api")

        mock_client = mock.MagicMock()
        mock_client.is_addon_enabled.return_value = False

        with mock.patch("credential_guard.get_policy_client", return_value=mock_client):
            result = guard._is_enabled(flow)

        assert result is False


class TestMismatchResponseContent:
    """Tests for create_mismatch_response detailed body content.

    Contract:
    - Status code is 428.
    - Body includes reflection, action, type, credential_type, destination, etc.
    - suggested_url only included when provided.
    """

    def test_mismatch_response_includes_reflection(self):
        """Reflection field helps agent self-correct."""
        from credential_guard import create_mismatch_response

        resp = create_mismatch_response(
            credential_type="openai",
            host="evil.com",
            expected_hosts=["api.openai.com"],
            fingerprint="hmac:abc123",
            path="/v1/chat",
        )

        body = json.loads(resp.content)
        assert body["action"] == "self_correct"
        assert "openai" in body["reflection"]
        assert "evil.com" in body["reflection"]
        assert "api.openai.com" in body["reflection"]

    def test_mismatch_response_includes_suggested_url_when_provided(self):
        """suggested_url appears in body when non-empty."""
        from credential_guard import create_mismatch_response

        resp = create_mismatch_response(
            credential_type="openai",
            host="evil.com",
            expected_hosts=["api.openai.com"],
            fingerprint="hmac:abc123",
            path="/v1/chat",
            suggested_url="https://api.openai.com/v1/chat",
        )

        body = json.loads(resp.content)
        assert body["suggested_url"] == "https://api.openai.com/v1/chat"

    def test_mismatch_response_omits_suggested_url_when_empty(self):
        """suggested_url is absent from body when empty string."""
        from credential_guard import create_mismatch_response

        resp = create_mismatch_response(
            credential_type="openai",
            host="evil.com",
            expected_hosts=["api.openai.com"],
            fingerprint="hmac:abc123",
            path="/v1/chat",
            suggested_url="",
        )

        body = json.loads(resp.content)
        assert "suggested_url" not in body


class TestApprovalResponseContent:
    """Tests for create_approval_response detailed body content.

    Contract:
    - Status code is 428.
    - Body includes reflection, action="wait_for_approval", type="requires_approval".
    """

    def test_approval_response_includes_reflection(self):
        """Approval response tells agent to wait."""
        from credential_guard import create_approval_response

        resp = create_approval_response(
            credential_type="unknown_secret",
            host="api.example.com",
            fingerprint="hmac:abc123",
            path="/v1/api",
            reason="unknown_credential",
        )

        body = json.loads(resp.content)
        assert body["action"] == "wait_for_approval"
        assert "approval" in body["reflection"].lower()
        assert body["destination"] == "api.example.com"
        assert body["credential_fingerprint"] == "hmac:abc123"


class TestEnvVarPaths:
    """Tests for SAFEYOLO_DATA_DIR env var support in credential_guard.configure().

    Contract:
    - HMAC secret path: SAFEYOLO_DATA_DIR/hmac_secret (falls back to /safeyolo/data/hmac_secret)
    - Only loaded once (when hmac_secret is empty bytes)
    """

    def test_hmac_path_uses_safeyolo_data_dir(self, monkeypatch):
        """When SAFEYOLO_DATA_DIR is set, HMAC secret is loaded from $SAFEYOLO_DATA_DIR/hmac_secret."""
        from pathlib import Path

        from credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        monkeypatch.setenv("SAFEYOLO_DATA_DIR", "/custom/data")
        captured_path = None

        def capture_load_hmac(path):
            nonlocal captured_path
            captured_path = path
            return b"test-secret"

        guard = CredentialGuard()
        with taddons.context(guard) as tctx, \
             mock.patch("credential_guard.load_hmac_secret", side_effect=capture_load_hmac):
            tctx.options.credguard_block = True

        assert captured_path == Path("/custom/data/hmac_secret")

    def test_hmac_path_falls_back_to_default(self, monkeypatch):
        """When SAFEYOLO_DATA_DIR is not set, HMAC secret is loaded from /safeyolo/data/hmac_secret."""
        from pathlib import Path

        from credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        monkeypatch.delenv("SAFEYOLO_DATA_DIR", raising=False)
        captured_path = None

        def capture_load_hmac(path):
            nonlocal captured_path
            captured_path = path
            return b"test-secret"

        guard = CredentialGuard()
        with taddons.context(guard) as tctx, \
             mock.patch("credential_guard.load_hmac_secret", side_effect=capture_load_hmac):
            tctx.options.credguard_block = True

        assert captured_path == Path("/safeyolo/data/hmac_secret")

    def test_hmac_loaded_only_once(self, monkeypatch):
        """When hmac_secret is already set, configure() does not reload it."""
        from credential_guard import CredentialGuard
        from mitmproxy.test import taddons

        monkeypatch.setenv("SAFEYOLO_DATA_DIR", "/custom/data")
        call_count = 0

        def counting_load_hmac(path):
            nonlocal call_count
            call_count += 1
            return b"test-secret"

        guard = CredentialGuard()
        with taddons.context(guard) as tctx, \
             mock.patch("credential_guard.load_hmac_secret", side_effect=counting_load_hmac):
            # First configure call loads the secret
            tctx.options.credguard_block = True
            assert call_count == 1
            # Second configure call should not reload
            tctx.options.credguard_scan_urls = True
            assert call_count == 1
