"""
Tests for pattern_scanner.py - user-configurable pattern scanning.

Pattern scanner is a framework for detecting arbitrary patterns in URLs,
headers, and bodies. It has NO built-in patterns by default - users configure
patterns via policy or enable builtin pattern sets.
"""

import re
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode

from pdp.client import PolicyClient

pytestmark = pytest.mark.assurance_boundary


def _ctx(**options):
    """Concrete mitmproxy option state required by one test."""
    return SimpleNamespace(options=SimpleNamespace(**options))


def _websocket_flow(
    content: bytes,
    *,
    from_client: bool = True,
    opcode: Opcode = Opcode.TEXT,
):
    flow = tflow.twebsocketflow(messages=False)
    assert flow.websocket is not None
    flow.websocket.messages = [WebSocketMessage(opcode, from_client, content)]
    return flow


class TestPatternRule:
    """Tests for PatternRule dataclass."""

    def test_matches_returns_match_object(self):
        """Test matches() returns Match object on match."""
        from safeyolo.detection.patterns import PatternRule

        rule = PatternRule(
            name="test-pattern",
            pattern=re.compile(r"PROJ-\d{5}"),
        )
        result = rule.matches("Found PROJ-12345 in text")

        assert result is not None
        assert result.group(0) == "PROJ-12345"

    def test_matches_returns_none_on_no_match(self):
        """Test matches() returns None when no match."""
        from safeyolo.detection.patterns import PatternRule

        rule = PatternRule(
            name="test-pattern",
            pattern=re.compile(r"PROJ-\d{5}"),
        )
        result = rule.matches("No project ID here")

        assert result is None

    def test_should_block_true_for_block_action(self):
        """Test should_block returns True when action is 'block'."""
        from safeyolo.detection.patterns import PatternRule

        rule = PatternRule(
            name="test",
            pattern=re.compile(r"test"),
            action="block",
        )
        assert rule.should_block is True

    def test_should_block_false_for_log_action(self):
        """Test should_block returns False when action is 'log'."""
        from safeyolo.detection.patterns import PatternRule

        rule = PatternRule(
            name="test",
            pattern=re.compile(r"test"),
            action="log",
        )
        assert rule.should_block is False

    def test_rule_id_generated_from_name(self):
        """Test rule_id is generated from name."""
        from safeyolo.detection.patterns import PatternRule

        rule = PatternRule(
            name="my-custom-rule",
            pattern=re.compile(r"test"),
        )
        assert rule.rule_id == "scan:my-custom-rule"

    def test_default_scope_is_body(self):
        """Test default scope is body only."""
        from safeyolo.detection.patterns import PatternRule

        rule = PatternRule(
            name="test",
            pattern=re.compile(r"test"),
        )
        assert rule.scope == {"body"}


class TestCompilePattern:
    """Tests for compile_pattern function."""

    def test_compiles_valid_pattern(self):
        """Test valid pattern compiles successfully."""
        from safeyolo.detection.patterns import compile_pattern

        result = compile_pattern(r"PROJ-\d{5}")

        assert result is not None
        assert result.search("PROJ-12345") is not None

    def test_returns_none_for_invalid_pattern(self):
        """Test invalid pattern returns None."""
        from safeyolo.detection.patterns import compile_pattern

        result = compile_pattern(r"[invalid")  # Unclosed bracket

        assert result is None

    def test_rejects_redos_pattern(self):
        """Test dangerous ReDoS patterns are rejected."""
        from safeyolo.detection.patterns import compile_pattern

        result = compile_pattern(r"(.+)+x")  # Nested quantifiers

        assert result is None

    def test_case_insensitive_flag(self):
        """Test case_sensitive=False makes pattern case insensitive."""
        from safeyolo.detection.patterns import compile_pattern

        result = compile_pattern(r"CONFIDENTIAL", case_sensitive=False)

        assert result is not None
        assert result.search("confidential") is not None
        assert result.search("CONFIDENTIAL") is not None


class TestScopeConfiguration:
    """Tests for scope parsing and configuration."""

    def test_parses_scope_list(self):
        """Test scope list is parsed correctly."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{
            "name": "test",
            "pattern": r"test",
            "scope": ["body", "url", "headers"],
        }]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body", "url", "headers"}

    def test_parses_single_scope_string(self):
        """Test single scope string is parsed correctly."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "scope": "url"}]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"url"}

    def test_defaults_to_body_scope(self):
        """Test missing scope defaults to body."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test"}]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body"}

    def test_ignores_invalid_scope(self):
        """Test invalid scope values are ignored."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{
            "name": "test",
            "pattern": r"test",
            "scope": ["body", "invalid", "url"],
        }]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body", "url"}

    def test_defaults_to_body_if_all_scopes_invalid(self):
        """Test defaults to body if all scope values are invalid."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "scope": ["invalid"]}]
        rules = load_patterns_from_config(config)

        assert rules[0].scope == {"body"}


class TestLoadPatternsFromConfig:
    """Tests for load_patterns_from_config function."""

    def test_loads_valid_config(self):
        """Test valid config loads correctly."""
        from safeyolo.detection.patterns import load_patterns_from_config

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
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"pattern": r"test"}]
        rules = load_patterns_from_config(config)

        assert len(rules) == 0

    def test_skips_config_missing_pattern(self):
        """Test config without pattern is skipped."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"name": "test"}]
        rules = load_patterns_from_config(config)

        assert len(rules) == 0

    def test_normalizes_input_target_to_request(self):
        """Test 'input' target is normalized to 'request'."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "target": "input"}]
        rules = load_patterns_from_config(config)

        assert rules[0].target == "request"

    def test_normalizes_output_target_to_response(self):
        """Test 'output' target is normalized to 'response'."""
        from safeyolo.detection.patterns import load_patterns_from_config

        config = [{"name": "test", "pattern": r"test", "target": "output"}]
        rules = load_patterns_from_config(config)

        assert rules[0].target == "response"

    def test_empty_config_produces_zero_rules(self):
        """Test empty scan_patterns list produces zero rules."""
        from safeyolo.detection.patterns import load_patterns_from_config

        rules = load_patterns_from_config([])

        assert rules == []


class TestBuiltinPatternSets:
    """Tests for builtin pattern sets."""

    def test_secrets_set_exists(self):
        """Test secrets builtin set exists and has patterns."""
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS

        assert "secrets" in BUILTIN_PATTERN_SETS
        assert len(BUILTIN_PATTERN_SETS["secrets"]) > 0

    def test_pii_set_exists(self):
        """Test pii builtin set exists and has patterns."""
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS

        assert "pii" in BUILTIN_PATTERN_SETS
        assert len(BUILTIN_PATTERN_SETS["pii"]) > 0

    def test_load_builtin_set_returns_pattern_configs_with_required_fields(self):
        """Test load_builtin_set returns configs each having 'name' and 'pattern'."""
        from safeyolo.detection.patterns import load_builtin_set

        patterns = load_builtin_set("secrets")

        # The github family split (ghp_ / gho_ / ghu_ / ghs_ / ghr_ /
        # github_pat_) gives 6 github entries; the openai/anthropic/aws/
        # google/private-key/db-connection/generic-bearer-in-body entries
        # cover the rest. Assert nonzero and check field shape rather than
        # a magic number so future additions do not need edits here.
        assert len(patterns) > 0
        for p in patterns:
            assert "name" in p, f"Pattern missing 'name': {p}"
            assert "pattern" in p, f"Pattern missing 'pattern': {p}"

    def test_load_builtin_set_unknown_returns_empty(self):
        """Test load_builtin_set returns empty for unknown set."""
        from safeyolo.detection.patterns import load_builtin_set

        patterns = load_builtin_set("nonexistent")

        assert patterns == []

    def test_secrets_patterns_compile(self):
        """Test all secrets patterns compile successfully."""
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])

        assert len(rules) == len(BUILTIN_PATTERN_SETS["secrets"])

    def test_secrets_patterns_detect_openai_key(self):
        """Test secrets set detects an OpenAI API key by name."""
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        openai_rules = [r for r in rules if r.name == "openai-api-key"]
        assert len(openai_rules) == 1

        test_key = "sk-proj-abcdefghij1234567890abcdefghij1234567890"
        assert openai_rules[0].matches(test_key) is not None

    def test_secrets_patterns_label_generic_sk_key_as_ambiguous(self):
        """A generic sk- value must not be misattributed to OpenAI."""
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        ambiguous = [r for r in rules if r.name == "ambiguous-sk-api-key"]

        assert len(ambiguous) == 1
        assert ambiguous[0].matches("sk-deepseekCompatibleOpaqueValue123") is not None

    def test_secrets_patterns_detect_github_pat(self):
        """Test secrets set detects a GitHub PAT by name."""
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        github_rules = [r for r in rules if r.name == "github-pat"]
        assert len(github_rules) == 1

        test_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        assert github_rules[0].matches(test_token) is not None

    @pytest.mark.parametrize(
        "token",
        [
            "sk-ant-api03-" + "A_b" * 32,
            "sk-ant-admin01-" + "A_b" * 32,
            "sk-ant-oat01-" + "A_b" * 32,
            "sk-ant-ort01-" + "A_b" * 32,
            "sk-ant-sid01-" + "A_b" * 32,
            "sk-ant-ccsr-" + "eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "sk-ant-cc-" + "eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "sk-ant-si-" + "eyJhbGciOiJIUzI1NiJ9.payload.signature",
        ],
        ids=["api", "admin", "access", "refresh", "session", "sandbox", "cc", "ingress"],
    )
    def test_secrets_pattern_detects_anthropic_families(self, token):
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        anthropic_rule = next(rule for rule in rules if rule.name == "anthropic-api-key")

        assert anthropic_rule.matches(token) is not None

    def test_anthropic_pattern_requires_a_credential_body(self):
        from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS, load_patterns_from_config

        rules = load_patterns_from_config(BUILTIN_PATTERN_SETS["secrets"])
        anthropic_rule = next(rule for rule in rules if rule.name == "anthropic-api-key")

        assert anthropic_rule.matches("sk-ant-oat01-short") is None


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

    def test_load_registers_directional_websocket_overrides(self, scanner):
        """WebSocket block controls are independent boolean options."""
        registered = []

        class Loader:
            def add_option(self, **kwargs):
                registered.append(kwargs)

        scanner.load(Loader())

        options = {entry["name"]: entry for entry in registered}
        assert options["pattern_block_websocket_request"]["default"] is False
        assert options["pattern_block_websocket_response"]["default"] is False

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
        """Test load_policy_config loads builtin sets and includes openai rule."""
        config = {
            "addons": {
                "pattern_scanner": {
                    "builtin_sets": ["secrets"]
                }
            }
        }
        scanner.load_policy_config(config)

        rule_names = [r.name for r in scanner.rules]
        # Check membership rather than a magic count -- adding new
        # families (like the github split) does not need edits here.
        assert len(scanner.rules) > 0
        assert "openai-api-key" in rule_names

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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "project-id"
        assert flow.metadata.get("pattern_location") == "body"

    def test_builtin_secrets_scan_refresh_token_in_json_body(self, scanner, make_flow):
        """Refresh tokens travel in OAuth JSON bodies and must hit the DLP net."""
        scanner.load_policy_config({
            "addons": {"pattern_scanner": {"builtin_sets": ["secrets"]}}
        })
        token = "sk-ant-ort01-" + "A_b" * 32
        flow = make_flow(
            method="POST",
            url="https://console.anthropic.com/v1/oauth/token",
            content=f'{{"refresh_token": "{token}"}}',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "anthropic-api-key"
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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=True)):
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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=False)):
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

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=True)):
            scanner.response(flow)

        assert flow.response.status_code == 502
        assert flow.metadata.get("blocked_by") == "pattern-scanner"


class TestResponseHeaderScanningWithEmptyBody:
    """Tests that response() scans headers even when the body is empty.

    This pins the fix: previously response() returned early when the body
    was empty, skipping header scanning entirely.
    """

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_response_header_matched_when_body_is_empty(self, scanner, make_flow, make_response):
        """A response with no body but a matching header must still be detected."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "leaked-token",
                "pattern": r"SECRET-\w{10}",
                "target": "response",
                "scope": ["headers"],
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=204,
            content=b"",
            headers={"X-Debug": "SECRET-abcdefghij"},
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=False)):
            scanner.response(flow)

        assert flow.metadata.get("pattern_matched_response") == "leaked-token"
        assert flow.metadata.get("pattern_location_response") == "header:X-Debug"

    def test_response_header_blocked_when_body_is_empty(self, scanner, make_flow, make_response):
        """A response with empty body and matching header is blocked when blocking is on."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "leaked-token",
                "pattern": r"SECRET-\w{10}",
                "target": "response",
                "scope": ["headers"],
                "action": "block",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=204,
            content=b"",
            headers={"X-Debug": "SECRET-abcdefghij"},
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=True)):
            scanner.response(flow)

        assert flow.response.status_code == 502
        assert flow.metadata.get("blocked_by") == "pattern-scanner"


class TestDirectionFiltering:
    """Tests that direction (target) filtering is enforced."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_request_only_rule_does_not_match_response(self, scanner, make_flow, make_response):
        """A rule with target=request must not trigger on a response."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "request-only",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=200,
            content='{"id": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=False)):
            scanner.response(flow)

        assert flow.metadata.get("pattern_matched_response") is None

    def test_response_only_rule_does_not_match_request(self, scanner, make_flow):
        """A rule with target=response must not trigger on a request."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "response-only",
                "pattern": r"PROJ-\d{5}",
                "target": "response",
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='{"id": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") is None

    def test_both_target_matches_request(self, scanner, make_flow):
        """A rule with target=both must match on a request."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "both-dir",
                "pattern": r"PROJ-\d{5}",
                "target": "both",
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='{"id": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "both-dir"

    def test_both_target_matches_response(self, scanner, make_flow, make_response):
        """A rule with target=both must match on a response."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "both-dir",
                "pattern": r"PROJ-\d{5}",
                "target": "both",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=200,
            content='{"id": "PROJ-12345"}',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=False)):
            scanner.response(flow)

        assert flow.metadata.get("pattern_matched_response") == "both-dir"


class TestBlockResponseContent:
    """Tests that block responses include the correct body fields."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_request_block_response_body_contains_rule_and_location(self, scanner, make_flow):
        """Blocked request response body includes error, rule, location, and message."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "proj-id",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "action": "block",
                "message": "Project ID leak",
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='PROJ-12345',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=True)):
            scanner.request(flow)

        import json
        body = json.loads(flow.response.get_text())
        assert body["error"] == "Request blocked by pattern policy"
        assert body["rule"] == "proj-id"
        assert body["location"] == "body"
        assert body["message"] == "Project ID leak"

    def test_response_block_response_body_contains_rule_and_location(self, scanner, make_flow, make_response):
        """Blocked response body includes error, rule, location, and message."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "cust-id",
                "pattern": r"CUST-\d{6}",
                "target": "response",
                "action": "block",
                "message": "Customer ID in response",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=200,
            content='CUST-123456',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=True)):
            scanner.response(flow)

        import json
        body = json.loads(flow.response.get_text())
        assert body["error"] == "Response blocked by pattern policy"
        assert body["rule"] == "cust-id"
        assert body["location"] == "body"
        assert body["message"] == "Customer ID in response"


class TestLogOnlyPath:
    """Tests that log-only rules do not block traffic."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_log_action_request_sets_metadata_but_does_not_block(self, scanner, make_flow):
        """A rule with action=log matches but does not produce a block response."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "audit-only",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "action": "log",
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='PROJ-12345',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=True)):
            scanner.request(flow)

        # Metadata is set (match happened)
        assert flow.metadata.get("pattern_matched") == "audit-only"
        # But no block response
        assert flow.metadata.get("blocked_by") is None
        assert flow.response is None

    def test_log_action_response_sets_metadata_but_does_not_block(self, scanner, make_flow, make_response):
        """A response rule with action=log matches but does not block."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "audit-resp",
                "pattern": r"CUST-\d{6}",
                "target": "response",
                "action": "log",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = make_response(
            status_code=200,
            content='CUST-123456',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=True)):
            scanner.response(flow)

        assert flow.metadata.get("pattern_matched_response") == "audit-resp"
        # The original 200 response is preserved, not replaced with a block
        assert flow.response.status_code == 200


class TestBlockRequiresBothRuleActionAndOption:
    """Tests that blocking requires BOTH rule.action=='block' AND the option enabled."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_block_action_with_option_disabled_does_not_block(self, scanner, make_flow):
        """A block-action rule with pattern_block_request=False must not block."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "block-rule",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "action": "block",
            }]
        })
        flow = make_flow(
            method="POST",
            url="https://api.example.com/data",
            content='PROJ-12345',
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "block-rule"
        assert flow.response is None
        assert flow.metadata.get("blocked_by") is None


class TestMaybeReloadPatterns:
    """Tests for _maybe_reload_patterns contract."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_reloads_when_policy_hash_changes(self, scanner):
        """When policy hash changes, rules are reloaded from config."""
        mock_client = create_autospec(PolicyClient, instance=True, spec_set=True)
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "hash-v2",
            "scan_patterns": [
                {"name": "new-rule", "pattern": r"NEW-\d+", "target": "both"}
            ],
        }

        scanner._last_policy_hash = "hash-v1"
        assert scanner.rules == []

        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client), \
             patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
            scanner._maybe_reload_patterns()

        assert len(scanner.rules) == 1
        assert scanner.rules[0].name == "new-rule"
        assert scanner._last_policy_hash == "hash-v2"

    def test_skips_reload_when_policy_hash_unchanged(self, scanner):
        """When policy hash is the same, rules are not reloaded."""
        scanner.load_policy_config({
            "scan_patterns": [
                {"name": "existing", "pattern": r"OLD-\d+", "target": "both"}
            ]
        })
        scanner._last_policy_hash = "same-hash"

        mock_client = create_autospec(PolicyClient, instance=True, spec_set=True)
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "same-hash",
            "scan_patterns": [
                {"name": "different", "pattern": r"DIFF-\d+", "target": "both"}
            ],
        }

        with patch("pdp.get_policy_client", autospec=True, return_value=mock_client), \
             patch("pdp.is_policy_client_configured", autospec=True, return_value=True):
            scanner._maybe_reload_patterns()

        # Rules should not have changed
        assert len(scanner.rules) == 1
        assert scanner.rules[0].name == "existing"

    def test_runtime_error_silently_caught(self, scanner):
        """PolicyClient not configured is silently caught."""
        scanner.load_policy_config({
            "scan_patterns": [
                {"name": "kept", "pattern": r"KEEP-\d+", "target": "both"}
            ]
        })

        with patch("pdp.is_policy_client_configured", autospec=True, return_value=False):
            scanner._maybe_reload_patterns()

        # Rules unchanged, no exception raised
        assert len(scanner.rules) == 1
        assert scanner.rules[0].name == "kept"


class TestRequestWithNoBody:
    """Tests that request scanning works when the body is empty."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_request_with_no_body_still_scans_url(self, scanner, make_flow):
        """A GET request with no body still scans the URL."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "url-leak",
                "pattern": r"PROJ-\d{5}",
                "target": "request",
                "scope": ["url"],
            }]
        })
        flow = make_flow(
            method="GET",
            url="https://api.example.com/PROJ-12345",
            content=b"",
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "url-leak"
        assert flow.metadata.get("pattern_location") == "url"

    def test_request_with_no_body_still_scans_headers(self, scanner, make_flow):
        """A GET request with no body still scans headers."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "header-leak",
                "pattern": r"SECRET-\w{8}",
                "target": "request",
                "scope": ["headers"],
            }]
        })
        flow = make_flow(
            method="GET",
            url="https://api.example.com/data",
            content=b"",
            headers={"X-Token": "SECRET-abcdefgh"},
        )

        with patch("pattern_scanner.ctx", _ctx(pattern_block_request=False)):
            scanner.request(flow)

        assert flow.metadata.get("pattern_matched") == "header-leak"
        assert flow.metadata.get("pattern_location") == "header:X-Token"


class TestResponseSkippedWhenNone:
    """Test that response() handles missing flow.response gracefully."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    def test_response_with_no_flow_response_is_noop(self, scanner, make_flow):
        """response() returns silently when flow.response is None."""
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "test",
                "pattern": r"MATCH",
                "target": "response",
            }]
        })
        flow = make_flow(url="https://api.example.com/data")
        flow.response = None

        with patch("pattern_scanner.ctx", _ctx(pattern_block_response=False)):
            scanner.response(flow)

        assert flow.metadata.get("pattern_matched_response") is None


class TestWebSocketMessageScanning:
    """Tests for message-level WebSocket pattern inspection."""

    @pytest.fixture
    def scanner(self):
        from pattern_scanner import PatternScanner
        return PatternScanner()

    @staticmethod
    def load_rule(scanner, *, target="both", action="block", pattern=r"PROJ-\d{5}"):
        scanner.load_policy_config({
            "scan_patterns": [{
                "name": "project-id",
                "pattern": pattern,
                "target": target,
                "scope": ["body"],
                "action": action,
            }]
        })

    @pytest.mark.parametrize(
        ("from_client", "target", "expected_direction"),
        [
            (True, "request", "request"),
            (False, "response", "response"),
        ],
    )
    def test_block_rule_drops_message_in_each_supported_direction(
        self,
        scanner,
        from_client,
        target,
        expected_direction,
        caplog,
    ):
        self.load_rule(scanner, target=target)
        inspected_payload = b"PROJ-12345"
        flow = _websocket_flow(inspected_payload, from_client=from_client)
        original_response = flow.response

        with patch(
            "pattern_scanner.ctx",
            _ctx(pattern_block_request=True, pattern_block_response=True),
        ), patch.object(
            scanner,
            "log_decision",
            autospec=True,
        ) as log_decision, caplog.at_level("WARNING"):
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is True
        assert flow.metadata["websocket_pattern_direction"] == expected_direction
        assert flow.metadata["websocket_pattern_matched"] == "project-id"
        # Message blocking must not replace the successful HTTP upgrade.
        assert flow.response is original_response
        assert inspected_payload.decode() not in caplog.text
        assert inspected_payload.decode() not in repr(log_decision.call_args)

    @pytest.mark.parametrize(
        ("from_client", "target"),
        [
            (True, "response"),
            (False, "request"),
        ],
    )
    def test_direction_mismatch_does_not_drop_message(
        self,
        scanner,
        from_client,
        target,
    ):
        self.load_rule(scanner, target=target)
        flow = _websocket_flow(b"PROJ-12345", from_client=from_client)

        with patch(
            "pattern_scanner.ctx",
            _ctx(pattern_block_request=True, pattern_block_response=True),
        ):
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is False
        assert "websocket_pattern_matched" not in flow.metadata

    @pytest.mark.parametrize("opcode", [Opcode.TEXT, Opcode.BINARY])
    def test_complete_text_and_binary_messages_use_body_rules(
        self,
        scanner,
        opcode,
    ):
        self.load_rule(scanner, target="request", pattern=r"PROJ-12345")
        # Mitmproxy calls this hook with one complete message after it joins
        # fragmented frames. The scanner therefore sees the joined content.
        flow = _websocket_flow(b"PROJ-" + b"12345", opcode=opcode)

        with patch(
            "pattern_scanner.ctx",
            _ctx(pattern_block_request=True, pattern_block_response=True),
        ):
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is True
        assert flow.metadata["websocket_pattern_message_type"] == opcode.name.lower()

    @pytest.mark.parametrize(
        ("action", "block_enabled"),
        [
            ("log", True),
            ("block", False),
        ],
    )
    def test_non_blocking_modes_record_without_dropping(
        self,
        scanner,
        action,
        block_enabled,
    ):
        self.load_rule(scanner, target="request", action=action)
        flow = _websocket_flow(b"PROJ-12345")

        with patch(
            "pattern_scanner.ctx",
            _ctx(
                pattern_block_request=block_enabled,
                pattern_block_response=True,
            ),
        ), patch.object(scanner, "log_decision", autospec=True) as log_decision:
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is False
        assert flow.metadata["websocket_pattern_matched"] == "project-id"
        log_decision.assert_called_once()
        assert log_decision.call_args.args[1].value == "log"

    @pytest.mark.parametrize(
        (
            "from_client",
            "http_option",
            "http_enabled",
            "websocket_option",
            "websocket_enabled",
            "expected_dropped",
        ),
        [
            # Explicit false keeps WebSocket messages in warn-only mode.
            (True, "pattern_block_request", True, "pattern_block_websocket_request", False, False),
            # Explicit true can block WebSocket traffic while HTTP remains warn-only.
            (False, "pattern_block_response", False, "pattern_block_websocket_response", True, True),
        ],
    )
    def test_directional_websocket_override_is_independent_of_http_mode(
        self,
        scanner,
        from_client,
        http_option,
        http_enabled,
        websocket_option,
        websocket_enabled,
        expected_dropped,
    ):
        self.load_rule(scanner, target="both")
        flow = _websocket_flow(b"PROJ-12345", from_client=from_client)
        options = {
            "pattern_block_request": False,
            "pattern_block_response": False,
            "pattern_block_websocket_request": False,
            "pattern_block_websocket_response": False,
        }
        options[http_option] = http_enabled
        options[websocket_option] = websocket_enabled

        with patch("pattern_scanner.ctx", _ctx(**options)):
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is expected_dropped

    def test_inspection_error_drops_without_logging_message_content(
        self,
        scanner,
        caplog,
    ):
        secret = "payload-must-not-appear"
        self.load_rule(scanner, target="request", pattern=r"payload")
        flow = _websocket_flow(secret.encode())

        with patch.object(
            scanner,
            "_scan_for_scope",
            autospec=True,
            side_effect=RuntimeError(secret),
        ), patch.object(
            scanner,
            "log_decision",
            autospec=True,
        ) as log_decision, caplog.at_level("ERROR"):
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is True
        assert secret not in caplog.text
        assert secret not in repr(log_decision.call_args)
        assert log_decision.call_args.kwargs["error_type"] == "RuntimeError"

    def test_invalid_text_message_fails_closed(self, scanner):
        self.load_rule(scanner, target="request", pattern=r"MATCH")
        flow = _websocket_flow(b"\xffMATCH", opcode=Opcode.TEXT)

        with patch.object(scanner, "log_decision", autospec=True) as log_decision:
            scanner.websocket_message(flow)

        assert flow.websocket is not None
        assert flow.websocket.messages[-1].dropped is True
        assert log_decision.call_args.kwargs["error_type"] == "UnicodeDecodeError"


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

    def test_get_stats_returns_exact_values(self):
        """Test get_stats returns exact expected values after known operations."""
        from pattern_scanner import PatternScanner

        scanner = PatternScanner()
        scanner.load_policy_config({
            "scan_patterns": [
                {"name": "rule-a", "pattern": r"AAA", "target": "both"},
                {"name": "rule-b", "pattern": r"BBB", "target": "both"},
            ]
        })

        # Perform known operations
        scanner._scan_for_scope(scanner.rules, "body", "contains AAA", "request")
        scanner._scan_for_scope(scanner.rules, "body", "no match", "request")

        stats = scanner.get_stats()

        assert stats == {
            "rules_total": 2,
            "scans_total": 2,
            "matches_total": 1,
            "blocks_total": 0,
        }
