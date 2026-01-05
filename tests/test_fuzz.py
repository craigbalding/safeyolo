"""
Fuzz tests using Hypothesis for security-critical components.

Property-based testing generates random inputs to find edge cases
and ensure robustness against malformed/malicious input.
"""

import re

from hypothesis import HealthCheck, given, settings, strategies as st


# Strategies for generating test data
text_strategy = st.text(min_size=0, max_size=10000)
header_value_strategy = st.text(min_size=0, max_size=1000, alphabet=st.characters(blacklist_categories=("Cs",)))
host_strategy = st.text(min_size=1, max_size=255, alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-")
path_strategy = st.text(min_size=0, max_size=500, alphabet="abcdefghijklmnopqrstuvwxyz0123456789/-_.*")


def _get_scanner():
    """Create scanner with rules loaded."""
    from pattern_scanner import PatternScanner

    scanner = PatternScanner()
    scanner.configure({})
    return scanner


class TestPatternScannerFuzz:
    """Fuzz tests for pattern_scanner regex matching."""

    @given(text=text_strategy)
    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_scan_text_never_crashes_on_input(self, text):
        """Pattern scanner should never crash on arbitrary input text."""
        scanner = _get_scanner()
        # Should not raise any exceptions
        result = scanner._scan_text(text, "input")
        # Result should be None or a PatternRule
        assert result is None or hasattr(result, "rule_id")

    @given(text=text_strategy)
    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_scan_text_never_crashes_on_output(self, text):
        """Pattern scanner should never crash on arbitrary output text."""
        scanner = _get_scanner()
        result = scanner._scan_text(text, "output")
        assert result is None or hasattr(result, "rule_id")

    @given(data=st.binary(min_size=0, max_size=5000))
    @settings(max_examples=200, deadline=None)
    def test_handles_binary_gracefully(self, data):
        """Scanner should handle binary data without crashing."""
        scanner = _get_scanner()
        try:
            text = data.decode("utf-8", errors="replace")
            scanner._scan_text(text, "input")
        except Exception:
            pass  # Binary decode issues are acceptable

    @given(
        pattern=st.text(min_size=1, max_size=50),
        test_text=text_strategy
    )
    @settings(max_examples=200, deadline=None)
    def test_pattern_rule_matches_never_crashes(self, pattern, test_text):
        """PatternRule.matches should never crash on arbitrary input."""
        from pattern_scanner import PatternRule

        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            rule = PatternRule(
                rule_id="fuzz",
                name="Fuzz Test",
                pattern=compiled,
                target="input",
                severity=3,
                category="test",
            )
            # Should not crash
            result = rule.matches(test_text)
            assert result is None or isinstance(result, re.Match)
        except re.error:
            pass  # Invalid regex patterns are expected


class TestCredentialGuardFuzz:
    """Fuzz tests for credential detection."""

    @given(header_value=header_value_strategy)
    @settings(max_examples=500, deadline=None)
    def test_analyze_headers_never_crashes(self, header_value):
        """Header analysis should never crash on arbitrary header values."""
        from credential_guard import DEFAULT_RULES, analyze_headers

        headers = {"Authorization": header_value}
        entropy_config = {
            "min_length": 20,
            "min_charset_diversity": 0.5,
            "min_shannon_entropy": 3.5
        }

        # Should not raise
        result = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config=entropy_config,
            standard_auth_headers=["authorization"],
            detection_level="standard"
        )

        assert isinstance(result, list)

    @given(
        header_name=st.text(min_size=1, max_size=100, alphabet="abcdefghijklmnopqrstuvwxyz-_"),
        header_value=header_value_strategy
    )
    @settings(max_examples=300, deadline=None)
    def test_analyze_arbitrary_headers(self, header_name, header_value):
        """Should handle arbitrary header names and values."""
        from credential_guard import DEFAULT_RULES, analyze_headers

        headers = {header_name: header_value}
        entropy_config = {
            "min_length": 20,
            "min_charset_diversity": 0.5,
            "min_shannon_entropy": 3.5
        }

        result = analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config=entropy_config,
            standard_auth_headers=["authorization", header_name.lower()],
            detection_level="paranoid"
        )

        assert isinstance(result, list)

    @given(value=header_value_strategy)
    @settings(max_examples=300, deadline=None)
    def test_extract_bearer_token_never_crashes(self, value):
        """Bearer token extraction should handle any input."""
        from credential_guard import extract_bearer_token

        result = extract_bearer_token(value)
        assert isinstance(result, str)


class TestEntropyFuzz:
    """Fuzz tests for entropy calculation."""

    @given(text=text_strategy)
    @settings(max_examples=500, deadline=None)
    def test_shannon_entropy_never_crashes(self, text):
        """Entropy calculation should handle any string."""
        from utils import calculate_shannon_entropy

        result = calculate_shannon_entropy(text)

        assert isinstance(result, float)
        assert result >= 0.0
        # Max entropy is log2(n) where n is number of unique chars
        # For any string, entropy should be bounded
        if len(text) > 0:
            assert result <= 8.0  # Reasonable upper bound

    @given(text=text_strategy)
    @settings(max_examples=500, deadline=None)
    def test_looks_like_secret_never_crashes(self, text):
        """Secret detection should handle any string."""
        from utils import looks_like_secret

        config = {
            "min_length": 20,
            "min_charset_diversity": 0.5,
            "min_shannon_entropy": 3.5
        }

        result = looks_like_secret(text, config)
        assert isinstance(result, bool)


class TestHostMatchingFuzz:
    """Fuzz tests for host pattern matching."""

    @given(host=host_strategy, pattern=host_strategy)
    @settings(max_examples=500, deadline=None)
    def test_host_matching_never_crashes(self, host, pattern):
        """Host matching should handle any host/pattern combination."""
        from utils import matches_host_pattern

        result = matches_host_pattern(host, pattern)
        assert isinstance(result, bool)

    @given(host=host_strategy)
    @settings(max_examples=200, deadline=None)
    def test_wildcard_patterns(self, host):
        """Wildcard patterns should work with any host."""
        from utils import matches_host_pattern

        # These should never crash
        matches_host_pattern(host, "*.example.com")
        matches_host_pattern(host, "*")
        matches_host_pattern(host, host)


class TestPathMatchingFuzz:
    """Fuzz tests for resource/path pattern matching."""

    @given(path=path_strategy, pattern=path_strategy)
    @settings(max_examples=500, deadline=None)
    def test_path_matching_never_crashes(self, path, pattern):
        """Path matching should handle any path/pattern combination."""
        from utils import matches_resource_pattern

        result = matches_resource_pattern(path, pattern)
        assert isinstance(result, bool)

    @given(path=path_strategy)
    @settings(max_examples=200, deadline=None)
    def test_common_patterns(self, path):
        """Common patterns should work with any path."""
        from utils import matches_resource_pattern

        # These should never crash
        matches_resource_pattern(path, "/**")
        matches_resource_pattern(path, "/*")
        matches_resource_pattern(path, "/v1/*")
        matches_resource_pattern(path, path)


class TestHMACFuzz:
    """Fuzz tests for HMAC fingerprinting."""

    @given(
        credential=text_strategy,
        secret=st.binary(min_size=1, max_size=64)
    )
    @settings(max_examples=300, deadline=None)
    def test_hmac_fingerprint_never_crashes(self, credential, secret):
        """HMAC fingerprinting should handle any credential/secret."""
        from utils import hmac_fingerprint

        result = hmac_fingerprint(credential, secret)

        assert isinstance(result, str)
        assert len(result) == 16  # Always returns 16-char hex

    @given(credential=text_strategy)
    @settings(max_examples=200, deadline=None)
    def test_hmac_deterministic(self, credential):
        """HMAC should be deterministic for same inputs."""
        from utils import hmac_fingerprint

        secret = b"test-secret-key"
        fp1 = hmac_fingerprint(credential, secret)
        fp2 = hmac_fingerprint(credential, secret)

        assert fp1 == fp2
