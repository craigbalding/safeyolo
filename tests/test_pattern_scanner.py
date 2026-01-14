"""
Tests for pattern_scanner.py - user-configurable pattern scanning.

Pattern scanner is a framework for detecting arbitrary patterns in URLs,
headers, and bodies. It has NO built-in patterns by default - users configure
patterns via policy or enable builtin pattern sets.
"""

import re
from unittest.mock import patch

import pytest


class TestPatternRule:
    """Tests for PatternRule dataclass."""

    def test_matches_returns_match_object(self):
        """Test matches() returns Match object on match."""
        from detection.patterns import PatternRule

        rule = PatternRule(
            name="test-pattern",
            pattern=re.compile(r"PROJ-\d{5}"),
        )
        result = rule.matches("Found PROJ-12345 in text")

        assert result is not None
        assert result.group(0) == "PROJ-12345"

    def test_matches_returns_none_on_no_match(self):
        """Test matches() returns None when no match."""
        from detection.patterns import PatternRule

        rule = PatternRule(
            name="test-pattern",
            pattern=re.compile(r"PROJ-\d{5}"),
        )
        result = rule.matches("No project ID here")

        assert result is None

    def test_should_block_true_for_block_action(self):
        """Test should_block returns True when action is 'block'."""
        from detection.patterns import PatternRule

        rule = PatternRule(
            name="test",
            pattern=re.compile(r"test"),
            action="block",
        )
        assert rule.should_block is True

    def test_should_block_false_for_log_action(self):
        """Test should_block returns False when action is 'log'."""
        from detection.patterns import PatternRule

        rule = PatternRule(
            name="test",
            pattern=re.compile(r"test"),
            action="log",
        )
        assert rule.should_block is False

    def test_rule_id_generated_from_name(self):
        """Test rule_id is generated from name."""
        from detection.patterns import PatternRule

        rule = PatternRule(
            name="my-custom-rule",
            pattern=re.compile(r"test"),
        )
        assert rule.rule_id == "scan:my-custom-rule"

    def test_default_scope_is_body(self):
        """Test default scope is body only."""
        from detection.patterns import PatternRule

        rule = PatternRule(
            name="test",
            pattern=re.compile(r"test"),
        )
        assert rule.scope == {"body"}


class TestCompilePattern:
    """Tests for compile_pattern function."""

    def test_compiles_valid_pattern(self):
        """Test valid pattern compiles successfully."""
        from detection.patterns import compile_pattern

        result = compile_pattern(r"PROJ-\d{5}")

        assert result is not None
        assert result.search("PROJ-12345") is not None

    def test_returns_none_for_invalid_pattern(self):
        """Test invalid pattern returns None."""
        from detection.patterns import compile_pattern

        result = compile_pattern(r"[invalid")  # Unclosed bracket

        assert result is None

    def test_rejects_redos_pattern(self):
        """Test dangerous ReDoS patterns are rejected."""
        from detection.patterns import compile_pattern

        result = compile_pattern(r"(.+)+x")  # Nested quantifiers

        assert result is None

    def test_case_insensitive_flag(self):
        """Test case_sensitive=False makes pattern case insensitive."""
        from detection.patterns import compile_pattern

        result = compile_pattern(r"CONFIDENTIAL", case_sensitive=False)

        assert result is not None
        assert result.search("confidential") is not None
        assert result.search("CONFIDENTIAL") is not None


class TestScopeConfiguration:
    """Tests for scope parsing and configuration."""

    def test_parses_scope_list(self):
        """Test scope list is parsed correctly."""
        from detection.patterns import load_patterns_from_config

        config = [{
            "name": "test",
            "pattern": r"test",
            "scope": ["body", "url", "headers"],
        }]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body", "url", "headers"}

    def test_parses_single_scope_string(self):
        """Test single scope string is parsed correctly."""
        from detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "scope": "url"}]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"url"}

    def test_defaults_to_body_scope(self):
        """Test missing scope defaults to body."""
        from detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test"}]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body"}

    def test_ignores_invalid_scope(self):
        """Test invalid scope values are ignored."""
        from detection.patterns import load_patterns_from_config

        config = [{
            "name": "test",
            "pattern": r"test",
            "scope": ["body", "invalid", "url"],
        }]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body", "url"}

    def test_defaults_to_body_if_all_scopes_invalid(self):
        """Test defaults to body if all scope values are invalid."""
        from detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "scope": ["invalid"]}]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body"}


class TestLoadPatternsFromConfig:
    """Tests for load_patterns_from_config function."""

    def test_loads_valid_config(self):
        """Test valid config loads correctly."""
        from detection.patterns import load_patterns_from_config

        config = [{
            "name": "project-ids",
            "pattern": r"PROJ-\d{5}",
            "target": "request",
            "scope": ["body", "url"],
            "action": "block",
            "severity": "high",
            "message": "Project ID detected",
        }]
        rules = load_patterns_from_config(config)

        assert len(rules) == 1
        assert rules[0].name == "project-ids"
        assert rules[0].target == "request"
        assert rules[0].scope == {"body", "url"}
        assert rules[0].action == "block"
        assert rules[0].severity == "high"

    def test_skips_config_missing_name(self):
        """Test config without name is skipped."""
        from detection.patterns import load_patterns_from_config

        config = [{"pattern": r"test"}]
        rules = load_patterns_from_config(config)

        assert len(rules) == 0

    def test_skips_config_missing_pattern(self):
        """Test config without pattern is skipped."""
        from detection.patterns import load_patterns_from_config

        config = [{"name": "test"}]
        rules = load_patterns_from_config(config)

        assert len(rules) == 0

    def test_normalizes_input_target_to_request(self):
        """Test 'input' target is normalized to 'request'."""
        from detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "target": "input"}]
        rules = load_patterns_from_config(config)

        assert rules[0].target == "request"

    def test_normalizes_output_target_to_response(self):
        """Test 'output' target is normalized to 'response'."""
        from detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "target": "output"}]
        rules = load_patterns_from_config(config)

        assert rules[0].target == "response"


class TestBuiltinPatternSets:
    """Tests for builtin pattern sets."""

    def test_secrets_set_exists(self):
        """Test secrets builtin set exists and has patterns."""
        from detection.patterns import BUILTIN_PATTERN_SETS

        assert "secrets" in BUILTIN_PATTERN_SETS
        assert len(BUILTIN_PATTERN_SETS["secrets"]) > 0

    def test_pii_set_exists(self):
        """Test pii builtin set exists and has patterns."""
        from detection.patterns import BUILTIN_PATTERN_SETS

        assert "pii" in BUILTIN_PATTERN_SETS
        assert len(BUILTIN_PATTERN_SETS["pii"]) > 0

    def test_load_builtin_set_returns_patterns(self):
        """Test load_builtin_set returns pattern configs."""
        from detection.patterns import load_builtin_set

        patterns = load_builtin_set("secrets")

        assert len(patterns) > 0
        assert all("name" in p and "pattern" in p for p in patterns)

    def test_load_builtin_set_unknown_returns_empty(self):
        """Test load_builtin_set returns empty for unknown set."""
        from detection.patterns import load_builtin_set

        patterns = load_builtin_set("nonexistent")

        assert patterns == []

    def test_secrets_patterns_compile(self):
        """Test all secrets patterns compile successfully."""
        from detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])

        assert len(rules) == len(BUILTIN_PATTERN_SETS["secrets"])

    def test_secrets_patterns_detect_openai_key(self):
        """Test secrets patterns detect OpenAI API key."""
        from detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        test_key = "sk-abcdefghij1234567890abcdefghij1234567890abcdefgh"

        matched = None
        for rule in rules:
            if rule.matches(test_key):
                matched = rule
                break

        assert matched is not None
        assert "openai" in matched.name

    def test_secrets_patterns_detect_github_pat(self):
        """Test secrets patterns detect GitHub PAT."""
        from detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        test_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

        matched = None
        for rule in rules:
            if rule.matches(test_token):
                matched = rule
                break

        assert matched is not None
        assert "github" in matched.name


class TestPatternScanner:
    """Tests for PatternScanner addon."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        from pattern_scanner import PatternScanner

        return PatternScanner()

    def test_no_rules_by_default(self, scanner):
        """Test scanner starts with no rules."""
        assert scanner.rules == []

    def test_load_policy_config_loads_user_rules(self, scanner):
        """Test load_policy_config populates rules from user config."""
        config = {
            "scan_patterns": [
                {"name": "test", "pattern": r"TEST-\d+", "target": "both"}
            ]
        }
        scanner.load_policy_config(config)

        assert len(scanner.rules) == 1
        assert scanner.rules[0].name == "test"

    def test_load_policy_config_loads_builtin_sets(self, scanner):
        """Test load_policy_config loads builtin sets when enabled."""
        config = {
            "addons": {
                "pattern_scanner": {
                    "builtin_sets": ["secrets"]
                }
            }
        }
        scanner.load_policy_config(config)

        assert len(scanner.rules) > 0
        assert any("openai" in r.name for r in scanner.rules)

    def test_load_policy_config_combines_builtin_and_user(self, scanner):
        """Test load_policy_config combines builtin and user patterns."""
        config = {
            "addons": {
                "pattern_scanner": {
                    "builtin_sets": ["secrets"]
                }
            },
            "scan_patterns": [
                {"name": "custom", "pattern": r"CUSTOM-\d+", "target": "both"}
            ]
        }
        scanner.load_policy_config(config)

        # Should have both builtin and custom
        names = [r.name for r in scanner.rules]
        assert "custom" in names
        assert any("openai" in n for n in names)

    def test_request_skipped_when_no_rules(self, scanner, make_flow):
        """Test request processing skipped when no rules configured."""
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content="some content",
        )

        scanner.request(flow)

        assert flow.metadata.get("pattern_matched") is None

    def test_request_scans_url(self, scanner, make_flow):
        """Test request URL is scanned when scope includes url."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "project-id",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "scope": ["url"],
            }]
        })
        flow = make_flow(
            method="GET",
            url="https://api.example.com/projects/PROJ-12345/details",
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_request = False
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "project-id"
        assert flow.metadata.get("pattern_location") == "url"

    def test_request_scans_headers(self, scanner, make_flow):
        """Test request headers are scanned when scope includes headers."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "secret-header",
                "pattern": r"SECRET-\w+",
                "target": "request",
                "scope": ["headers"],
            }]
        })
        flow = make_flow(
            method="GET",
            url="https://api.example.com/data",
            headers={"X-Custom": "SECRET-abc123"},
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_request = False
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "secret-header"
        assert flow.metadata.get("pattern_location") == "header:X-Custom"

    def test_request_scans_body(self, scanner, make_flow):
        """Test request body is scanned when scope includes body."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "project-id",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "scope": ["body"],
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='{"project": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_request = False
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "project-id"
        assert flow.metadata.get("pattern_location") == "body"

    def test_request_respects_scope(self, scanner, make_flow):
        """Test request only scans locations in scope."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "url-only",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "scope": ["url"],  # Only URL, not body
            }]
        })
        # Pattern in body but scope is url-only
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='{"project": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_request = False
            scanner.request(flow)

        # Should NOT match because pattern is in body but scope is url
        assert flow.metadata.get("pattern_matched") is None

    def test_request_blocks_when_enabled(self, scanner, make_flow):
        """Test request is blocked when blocking enabled and rule matches."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "project-id",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "action": "block",
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='{"project": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_request = True
            scanner.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata.get("blocked_by") == "pattern-scanner"

    def test_response_scans_body(self, scanner, make_flow, make_response):
        """Test response body is scanned."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "customer-id",
                "pattern": r"CUST-\d{6}",
                "target": "response",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=200,
            content='{"customer": "CUST-123456"}',
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_response = False
            scanner.response(flow)

        assert flow.metadata.get("pattern_matched_response") == "customer-id"

    def test_response_blocks_when_enabled(self, scanner, make_flow, make_response):
        """Test response is blocked when blocking enabled and rule matches."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "customer-id",
                "pattern": r"CUST-\d{6}",
                "target": "response",
                "action": "block",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=200,
            content='{"customer": "CUST-123456"}',
        )

        with patch("pattern_scanner.ctx") as mock_ctx:
            mock_ctx.options.pattern_block_response = True
            scanner.response(flow)

        assert flow.response.status_code == 502
        assert flow.metadata.get("blocked_by") == "pattern-scanner"


class TestStats:
    """Tests for scanner statistics."""

    def test_stats_tracking(self):
        """Test that stats are tracked correctly."""
        from pattern_scanner import PatternScanner

        scanner = PatternScanner()
        scanner.load_policy_config({
            "scan_patterns": [
                {"name": "test", "pattern": r"MATCH", "target": "both"}
            ]
        })

        # Simulate scans
        scanner._scan_for_scope(scanner.rules, "body", "no match here", "request")
        scanner._scan_for_scope(scanner.rules, "body", "found MATCH here", "request")
        scanner._scan_for_scope(scanner.rules, "body", "another no match", "request")

        assert scanner.scans_total == 3
        assert scanner.matches_total == 1

    def test_get_stats_structure(self):
        """Test get_stats returns expected structure."""
        from pattern_scanner import PatternScanner

        scanner = PatternScanner()
        scanner.load_policy_config({
            "scan_patterns": [
                {"name": "test", "pattern": r"test", "target": "both"}
            ]
        })

        stats = scanner.get_stats()

        assert "rules_total" in stats
        assert "scans_total" in stats
        assert "matches_total" in stats
        assert "blocks_total" in stats
        assert stats["rules_total"] == 1
