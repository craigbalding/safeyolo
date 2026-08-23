"""Tests for test_context addon — context header enforcement for target hosts."""

import json
from unittest.mock import MagicMock, patch

# =============================================================================
# Unit tests for helper functions
# =============================================================================


class TestParseContextHeader:
    """Tests for _parse_context_header()."""

    def test_valid_full_header(self):
        from test_context import _parse_context_header

        result = _parse_context_header("run=sec1;agent=idor;test=IDOR-003")
        assert result == {"run": "sec1", "agent": "idor", "test": "IDOR-003"}

    def test_valid_minimal_header(self):
        from test_context import _parse_context_header

        result = _parse_context_header("run=sec1;agent=idor")
        assert result == {"run": "sec1", "agent": "idor"}

    def test_valid_with_phase(self):
        from test_context import _parse_context_header

        result = _parse_context_header("run=sec1;agent=xss;test=xss-reflected-1;phase=test")
        assert result == {"run": "sec1", "agent": "xss", "test": "xss-reflected-1", "phase": "test"}

    def test_missing_required_run(self):
        from test_context import _parse_context_header

        result = _parse_context_header("agent=idor;test=IDOR-003")
        assert result is None

    def test_missing_required_agent(self):
        from test_context import _parse_context_header

        result = _parse_context_header("run=sec1;test=IDOR-003")
        assert result is None

    def test_empty_string(self):
        from test_context import _parse_context_header

        assert _parse_context_header("") is None

    def test_whitespace_only(self):
        from test_context import _parse_context_header

        assert _parse_context_header("   ") is None

    def test_no_equals_sign(self):
        from test_context import _parse_context_header

        assert _parse_context_header("run-sec1;agent-idor") is None

    def test_empty_value(self):
        from test_context import _parse_context_header

        assert _parse_context_header("run=;agent=idor") is None

    def test_empty_key(self):
        from test_context import _parse_context_header

        assert _parse_context_header("=sec1;agent=idor") is None

    def test_tolerates_whitespace_around_parts(self):
        from test_context import _parse_context_header

        result = _parse_context_header(" run=sec1 ; agent=idor ; test=IDOR-003 ")
        assert result == {"run": "sec1", "agent": "idor", "test": "IDOR-003"}


class TestCaptureBody:
    """Tests for _capture_body()."""

    def test_empty_body(self):
        from test_context import _capture_body

        assert _capture_body(b"") == ""

    def test_small_body_returned_fully(self):
        from test_context import _capture_body

        body = b'{"status": "ok"}'
        assert _capture_body(body) == '{"status": "ok"}'

    def test_body_under_limit(self):
        from test_context import _capture_body

        body = b"x" * 4096
        result = _capture_body(body, max_head=4096)
        assert result == "x" * 4096
        assert "truncated" not in result

    def test_body_over_limit_includes_truncation_marker(self):
        from test_context import _capture_body

        body = b"x" * 8192
        result = _capture_body(body, max_head=4096)
        assert "truncated" in result
        assert "8192 bytes total" in result

    def test_body_over_limit_includes_tail(self):
        from test_context import _capture_body

        lines = [f"line-{i}" for i in range(100)]
        body = "\n".join(lines).encode()
        result = _capture_body(body, max_head=100, tail_lines=3)
        assert "truncated" in result
        assert "line-99" in result
        assert "line-98" in result
        assert "line-97" in result

    def test_handles_binary_content(self):
        from test_context import _capture_body

        body = b"\xff\xfe\x00\x01" * 2000
        result = _capture_body(body, max_head=100)
        # Should not raise, uses errors="replace"
        assert isinstance(result, str)


# =============================================================================
# Addon integration tests
# =============================================================================


def _make_mock_flow(
    method="GET",
    host="target.example.com",
    path="/v1/feeds",
    headers=None,
    content=b"",
):
    """Create a mock flow for test_context tests."""
    flow = MagicMock()
    flow.request.method = method
    flow.request.host = host
    flow.request.path = path
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.url = f"https://{host}{path}"
    flow.request.content = content
    flow.request.headers = {}
    if headers:
        flow.request.headers.update(headers)
    flow.request.query = None
    flow.client_conn.peername = ("192.168.1.1", 12345)
    flow.metadata = {}
    flow.response = None
    return flow


def _make_addon_with_targets(targets=None, block=True):
    """Create a TestContext addon with target hosts pre-configured."""
    from test_context import TestContext

    addon = TestContext()
    addon._target_hosts = targets if targets is not None else ["target.example.com"]
    # Prevent config reload from overwriting our test config
    addon._last_policy_hash = "test-hash"

    return addon


class TestTestContextAddon:
    """Integration tests for TestContext addon."""

    def test_addon_name(self):
        from test_context import TestContext
        addon = TestContext()
        assert addon.name == "test-context"

    def test_initial_stats(self):
        from test_context import TestContext
        addon = TestContext()
        stats = addon.get_stats()
        assert stats["checks_total"] == 0
        assert stats["allowed_total"] == 0
        assert stats["blocked_total"] == 0
        assert stats["target_hosts"] == 0

    def test_non_target_host_passes_through(self):
        """Requests without context to non-target hosts pass without checks."""
        addon = _make_addon_with_targets(["target.example.com"])
        flow = _make_mock_flow(host="api.openai.com", path="/v1/chat")

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.checks == 0

    def test_non_target_valid_header_opts_into_provenance(self):
        addon = _make_addon_with_targets(["target.example.com"])
        flow = _make_mock_flow(
            host="ordinary.example.com",
            headers={
                "X-Test-Context": (
                    "run=acceptance;agent=codey;role=auditor;test=CTX-001;"
                    "intent=verify;expect=recorded"
                )
            },
        )
        flow.metadata["agent"] = "codey"

        with (
            patch.object(addon, "_maybe_reload_config"),
            patch("test_context.write_event"),
        ):
            addon.request(flow)

        assert flow.response is None
        assert "X-Test-Context" not in flow.request.headers
        assert flow.metadata["ccapt_context"]["test"] == "CTX-001"
        assert flow.metadata["test_id"] == "CTX-001"
        assert flow.metadata["test_agent_match"] is True
        assert addon.stats.checks == 1
        assert addon.stats.allowed == 1

    def test_non_target_malformed_header_warns_strips_and_passes(self):
        addon = _make_addon_with_targets(["target.example.com"])
        flow = _make_mock_flow(
            host="ordinary.example.com",
            headers={"X-Test-Context": "not-valid"},
        )

        with (
            patch.object(addon, "_maybe_reload_config"),
            patch("test_context.write_event"),
        ):
            addon.request(flow)

        assert flow.response is None
        assert "X-Test-Context" not in flow.request.headers
        assert "ccapt_context" not in flow.metadata
        assert addon.stats.checks == 1
        assert addon.stats.warned == 1

    def test_target_host_missing_header_blocks_428(self):
        """Requests to target hosts without context header get 428."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        body = json.loads(flow.response.content)
        assert body["type"] == "missing_context"
        assert body["destination"] == "target.example.com"
        assert body["header"] == "X-Test-Context"
        assert "format" in body
        assert "example" in body
        assert flow.metadata.get("blocked_by") == "test-context"
        assert addon.stats.blocked == 1

    def test_target_host_malformed_header_blocks_428(self):
        """Malformed context header triggers 428."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": "garbage-no-equals"})

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        assert addon.stats.blocked == 1

    def test_target_host_incomplete_header_blocks_428(self):
        """Header missing required keys triggers 428."""
        addon = _make_addon_with_targets()
        # Missing 'agent' key
        flow = _make_mock_flow(headers={"X-Test-Context": "run=sec1;test=IDOR-003"})

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428

    def test_target_host_valid_header_allows(self):
        """Valid context header lets request through."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor;test=IDOR-003"}
        )

        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow)

        assert flow.response is None
        assert flow.metadata["ccapt_context"] == {
            "run": "sec1",
            "agent": "idor",
            "test": "IDOR-003",
        }
        assert addon.stats.allowed == 1
        assert addon.stats.blocked == 0

    def test_context_header_stripped_before_upstream(self):
        """X-Test-Context header is removed from request before it hits the wire."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor;test=IDOR-003"}
        )

        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow)

        assert "X-Test-Context" not in flow.request.headers
        # Context still preserved in metadata for response logging
        assert flow.metadata["ccapt_context"]["run"] == "sec1"

    def test_canonical_context_is_promoted_without_overwriting_trusted_agent(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={
                "X-Test-Context": (
                    "run=sec1;agent=declared;role=guest;suite=payments;"
                    "subject=CTRL-1;step=4;test=FLOW-05;intent=forge;expect=blocked;"
                    "extra=retained"
                )
            }
        )
        flow.metadata["agent"] = "trusted"

        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event") as mock_write:
            addon.request(flow)

        assert flow.metadata["agent"] == "trusted"
        assert flow.metadata["test_run"] == "sec1"
        assert flow.metadata["test_agent"] == "declared"
        assert flow.metadata["test_role"] == "guest"
        assert flow.metadata["test_suite"] == "payments"
        assert flow.metadata["test_subject"] == "CTRL-1"
        assert flow.metadata["test_step"] == "4"
        assert flow.metadata["test_id"] == "FLOW-05"
        assert flow.metadata["test_intent"] == "forge"
        assert flow.metadata["test_expect"] == "blocked"
        assert flow.metadata["test_agent_match"] is False
        assert "extra" not in flow.metadata
        assert flow.metadata["ccapt_context"]["extra"] == "retained"
        details = mock_write.call_args.kwargs["details"]
        assert details["trusted_agent"] == "trusted"
        assert details["test_agent_match"] is False

    def test_matching_agent_is_explicit_and_absent_trusted_agent_is_unknown(self):
        addon = _make_addon_with_targets()
        matching = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=cody"}
        )
        matching.metadata["agent"] = "cody"
        unattributed = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=cody"}
        )

        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(matching)
            addon.request(unattributed)

        assert matching.metadata["test_agent_match"] is True
        assert "test_agent_match" not in unattributed.metadata

    def test_warn_mode_does_not_block(self):
        """In warn mode, missing header logs but doesn't block."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        # should_block returns False in warn mode
        with patch("safeyolo.core.base.get_option_safe", side_effect=lambda name, default=True: name != "test_context_block"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1
        assert addon.stats.blocked == 0

    def test_no_target_hosts_without_header_passes_without_checks(self):
        """With no target hosts, unannotated requests pass through."""
        addon = _make_addon_with_targets(targets=[])
        flow = _make_mock_flow()

        with patch.object(addon, "_maybe_reload_config"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.checks == 0

    def test_no_target_hosts_valid_header_opts_into_provenance(self):
        addon = _make_addon_with_targets(targets=[])
        flow = _make_mock_flow(
            host="ordinary.example.com",
            headers={
                "X-Test-Context": "run=acceptance;agent=codey;test=CTX-001"
            },
        )
        flow.metadata["agent"] = "codey"

        with (
            patch.object(addon, "_maybe_reload_config"),
            patch("test_context.write_event"),
        ):
            addon.request(flow)

        assert flow.response is None
        assert "X-Test-Context" not in flow.request.headers
        assert flow.metadata["ccapt_context"]["test"] == "CTX-001"
        assert addon.stats.allowed == 1

    def test_already_blocked_flow_skipped(self):
        """Flow already blocked by another addon is skipped."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        flow.response = MagicMock()  # Already has a response

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.checks == 0

    def test_wildcard_target_host_matching(self):
        """Wildcard patterns in target_hosts work."""
        addon = _make_addon_with_targets(["*.example.com"])
        flow = _make_mock_flow(host="target.example.com")

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        # Should be treated as target host (blocked for missing header)
        assert flow.response is not None
        assert flow.response.status_code == 428

    def test_response_logging_with_context(self):
        """Response phase logs when context was set in request phase.

        Also asserts the event carries `agent=` — /explain's strict
        agent-scope filter (issue #213) drops events without agent
        attribution, and the response-side event previously omitted it,
        silently hiding it from correlated lookups.
        """
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor;test=IDOR-003"}
        )
        flow.metadata["agent"] = "resolved-agent"

        # Simulate request phase
        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow)

        # Simulate response
        flow.response = MagicMock()
        flow.response.status_code = 200
        flow.response.content = b'{"data": "test"}'

        with patch("test_context.write_event") as mock_write:
            addon.response(flow)

        mock_write.assert_called_once()
        call_kwargs = mock_write.call_args
        details = call_kwargs[1]["details"]
        assert details["phase"] == "response"
        assert details["status_code"] == 200
        assert details["context"]["run"] == "sec1"
        # Agent attribution must be threaded through so /explain finds it.
        assert call_kwargs[1]["agent"] == "resolved-agent"

    def test_response_skipped_without_context(self):
        """Response phase is a no-op if request didn't set context."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        flow.response = MagicMock()
        flow.response.status_code = 200
        flow.response.content = b"ok"

        with patch("test_context.write_event") as mock_write:
            addon.response(flow)

        mock_write.assert_not_called()

    def test_request_event_logged_with_context(self):
        """Request phase logs structured event with context fields."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            method="POST",
            path="/v1/entries/42",
            headers={"X-Test-Context": "run=sec1;agent=idor;test=IDOR-003"},
            content=b'{"title": "test"}',
        )

        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event") as mock_write:
            addon.request(flow)

        mock_write.assert_called_once()
        args, kwargs = mock_write.call_args
        assert args[0] == "security.test_context"
        details = kwargs["details"]
        assert details["phase"] == "request"
        assert details["method"] == "POST"
        assert kwargs["host"] == "target.example.com"
        assert details["path"] == "/v1/entries/42"
        assert details["context"]["agent"] == "idor"

    def test_config_reload_updates_target_hosts(self):
        """Config reload from PDP updates target hosts list."""
        from test_context import TestContext

        addon = TestContext()
        assert addon._target_hosts == []

        mock_client = MagicMock()
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "new-hash",
            "addons": {
                "test_context": {
                    "target_hosts": ["target1.example.com", "target2.example.com"],
                },
            },
        }

        with patch("pdp.get_policy_client", return_value=mock_client), \
             patch("pdp.is_policy_client_configured", return_value=True):
            addon._maybe_reload_config()

        assert addon._target_hosts == ["target1.example.com", "target2.example.com"]
        assert addon._last_policy_hash == "new-hash"

    def test_config_reload_skips_if_hash_unchanged(self):
        """Config reload skips if policy hash hasn't changed."""
        addon = _make_addon_with_targets(["original.example.com"])
        addon._last_policy_hash = "same-hash"

        mock_client = MagicMock()
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "same-hash",
            "addons": {
                "test_context": {
                    "target_hosts": ["changed.example.com"],
                },
            },
        }

        with patch("pdp.get_policy_client", return_value=mock_client), \
             patch("pdp.is_policy_client_configured", return_value=True):
            addon._maybe_reload_config()

        # Should still have original targets
        assert addon._target_hosts == ["original.example.com"]

    def test_get_stats_reflects_state(self):
        """get_stats returns current addon state."""
        addon = _make_addon_with_targets(["a.com", "b.com"])
        addon.stats.checks = 10
        addon.stats.allowed = 7
        addon.stats.blocked = 2
        addon.stats.warned = 1

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            stats = addon.get_stats()

        assert stats["target_hosts"] == 2
        assert stats["checks_total"] == 10
        assert stats["allowed_total"] == 7
        assert stats["blocked_total"] == 2
        assert stats["warned_total"] == 1

    def test_multiple_target_hosts(self):
        """Addon checks against all configured target hosts."""
        addon = _make_addon_with_targets([
            "target.example.com",
            "other-target.example.com",
        ])

        flow1 = _make_mock_flow(host="other-target.example.com")
        flow2 = _make_mock_flow(host="not-a-target.example.com")

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow1)
            addon.request(flow2)

        # flow1 is a target host -> blocked (missing header)
        assert flow1.response is not None
        assert flow1.response.status_code == 428
        # flow2 is not a target host -> passes through
        assert flow2.response is None

    def test_response_duration_calculated(self):
        """Response event includes duration_ms from request timing."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor"}
        )

        # Request phase sets timing
        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"), \
             patch("test_context.time") as mock_time:
            mock_time.time.return_value = 1000.0
            addon.request(flow)

        flow.response = MagicMock()
        flow.response.status_code = 200
        flow.response.content = b"ok"

        with patch("test_context.write_event") as mock_write, \
             patch("test_context.time") as mock_time:
            mock_time.time.return_value = 1000.250  # 250ms later
            addon.response(flow)

        call_kwargs = mock_write.call_args[1]
        assert call_kwargs["details"]["duration_ms"] == 250


# =============================================================================
# Additional parser tests — safety, boundaries, edge cases
# =============================================================================


class TestParseContextHeaderEdgeCases:
    """Edge-case tests for _parse_context_header()."""

    def test_unsafe_chars_in_key_rejected(self):
        """Keys containing chars outside [a-zA-Z0-9_\\-.:] are rejected."""
        from test_context import _parse_context_header

        assert _parse_context_header("ru<n>=sec1;agent=idor") is None
        assert _parse_context_header("run name=sec1;agent=idor") is None
        assert _parse_context_header("ru{n}=sec1;agent=idor") is None

    def test_unsafe_chars_in_value_rejected(self):
        """Values containing chars outside [a-zA-Z0-9_\\-.:] are rejected."""
        from test_context import _parse_context_header

        assert _parse_context_header("run=sec 1;agent=idor") is None
        assert _parse_context_header("run=sec1;agent=id<or>") is None
        assert _parse_context_header("run=sec1;agent=id\tor") is None

    def test_duplicate_keys_rejected(self):
        """Duplicate provenance keys are ambiguous and rejected."""
        from test_context import _parse_context_header

        assert _parse_context_header("run=first;agent=idor;run=second") is None

    def test_max_pairs_boundary_accepted(self):
        """Exactly _MAX_CONTEXT_PAIRS pairs are accepted."""
        from test_context import _MAX_CONTEXT_PAIRS, _parse_context_header

        # Build exactly 20 pairs: run, agent, plus 18 extras
        pairs = ["run=sec1", "agent=idor"]
        for i in range(_MAX_CONTEXT_PAIRS - 2):
            pairs.append(f"k{i}=v{i}")
        header = ";".join(pairs)
        result = _parse_context_header(header)
        assert result is not None
        assert len(result) == _MAX_CONTEXT_PAIRS

    def test_pairs_beyond_max_are_rejected(self):
        """Over-limit provenance is rejected instead of silently truncated."""
        from test_context import _MAX_CONTEXT_PAIRS, _parse_context_header

        pairs = ["run=sec1", "agent=idor"]
        for i in range(_MAX_CONTEXT_PAIRS - 2):
            pairs.append(f"k{i}=v{i}")
        # A 21st pair makes the complete provenance value invalid.
        pairs.append("extra=dropped")
        header = ";".join(pairs)
        assert _parse_context_header(header) is None

    def test_trailing_semicolons_tolerated(self):
        """Trailing semicolons produce empty parts that are skipped."""
        from test_context import _parse_context_header

        result = _parse_context_header("run=sec1;agent=idor;;")
        assert result == {"run": "sec1", "agent": "idor"}

    def test_leading_semicolons_tolerated(self):
        """Leading semicolons produce empty parts that are skipped."""
        from test_context import _parse_context_header

        result = _parse_context_header(";;run=sec1;agent=idor")
        assert result == {"run": "sec1", "agent": "idor"}


# =============================================================================
# Additional capture_body tests
# =============================================================================


class TestCaptureBodyEdgeCases:
    """Edge-case tests for _capture_body()."""

    def test_one_byte_over_limit_triggers_truncation(self):
        """A body of max_head+1 bytes includes the truncation marker."""
        from test_context import _capture_body

        body = b"A" * 4097
        result = _capture_body(body, max_head=4096)
        assert "truncated" in result
        assert "4097 bytes total" in result
        # Head portion is exactly 4096 chars of 'A'
        assert result.startswith("A" * 4096)


# =============================================================================
# Additional addon integration tests — block body, counters, config errors
# =============================================================================


class TestTestContextBlockBody:
    """Tests for the structure of block response bodies."""

    def test_malformed_header_body_has_type_field(self):
        """Block body for malformed header includes type=malformed_context."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": "not;valid;pairs"})

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "malformed_context"

    def test_missing_header_body_has_type_field(self):
        """Block body for missing header includes type=missing_context."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "missing_context"

    def test_block_body_includes_reflection_and_action(self):
        """Block body contains both 'reflection' and 'action' fields."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert "reflection" in body
        assert "action" in body
        assert body["action"] == "add_header"
        assert "X-Test-Context" in body["reflection"]


class TestTestContextCounters:
    """Tests that stats counters are incremented at the right points."""

    def test_checks_counter_incremented_on_target_host(self):
        """stats.checks increments for every request to a target host."""
        addon = _make_addon_with_targets()

        # Missing header -> blocked, but checks still counts
        flow1 = _make_mock_flow()
        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow1)
        assert addon.stats.checks == 1

        # Valid header -> allowed, checks still counts
        flow2 = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor"}
        )
        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow2)
        assert addon.stats.checks == 2

    def test_checks_counter_not_incremented_for_non_target(self):
        """stats.checks does NOT increment for non-target hosts."""
        addon = _make_addon_with_targets(["target.example.com"])
        flow = _make_mock_flow(host="other.example.com")

        with patch("safeyolo.core.base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.checks == 0


class TestTestContextConfigReload:
    """Tests for _maybe_reload_config error handling."""

    def test_config_reload_runtime_error_silently_passes(self):
        """RuntimeError from get_policy_client is silently swallowed."""
        from test_context import TestContext

        addon = TestContext()
        addon._target_hosts = ["original.example.com"]

        with patch("pdp.is_policy_client_configured", return_value=False):
            addon._maybe_reload_config()

        # Target hosts unchanged
        assert addon._target_hosts == ["original.example.com"]

    def test_config_reload_other_exception_logs_warning(self):
        """Non-RuntimeError exceptions log a warning and don't crash."""
        from test_context import TestContext

        addon = TestContext()
        addon._target_hosts = ["original.example.com"]

        mock_client = MagicMock()
        mock_client.get_sensor_config.side_effect = ConnectionError("timeout")
        with patch("pdp.get_policy_client", return_value=mock_client), \
             patch("pdp.is_policy_client_configured", return_value=True), \
             patch("test_context.log") as mock_log:
            addon._maybe_reload_config()

        # Target hosts unchanged
        assert addon._target_hosts == ["original.example.com"]
        # Warning was logged
        mock_log.warning.assert_called_once()
        warning_msg = mock_log.warning.call_args[0][0]
        assert "ConnectionError" in warning_msg


class TestTestContextWarnMode:
    """Tests for warn mode behaviour with various header states."""

    def test_warn_mode_with_malformed_header(self):
        """Malformed header in warn mode logs warning, does not block."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": "garbage-no-equals"})

        with patch("safeyolo.core.base.get_option_safe", side_effect=lambda name, default=True: name != "test_context_block"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1
        assert addon.stats.blocked == 0


# =============================================================================
# Declared-context (mobile / header-less traffic) tests
# =============================================================================


def _mock_discovery(agent="pickup"):
    """Resolve a fixed agent via the addon registry, deterministically.

    Patches ``ctx.master`` with a registry that returns a mock service-discovery
    so ``_trusted_agent`` resolves through it regardless of any leftover taddons
    master left behind by another test (the module singleton is not consulted
    when a master is present).
    """
    sd = MagicMock()
    sd.get_client_for_ip.return_value = agent
    master = MagicMock()
    master.addons.get.return_value = sd
    return patch("mitmproxy.ctx.master", master, create=True)


class TestDeclarationStore:
    """Unit tests for the (source_id, trusted_agent)-bound declaration store."""

    def test_set_get_round_trip_and_defensive_copy(self):
        addon = _make_addon_with_targets()
        original = {"run": "r1", "agent": "pickup", "test": "T-1"}
        granted = addon.set_declaration("src-1", "pickup", original, 120)
        assert granted == 120

        rec = addon.get_declaration("src-1", "pickup")
        assert rec is not None
        context, expires_in = rec
        assert context == {"run": "r1", "agent": "pickup", "test": "T-1"}
        assert 1 <= expires_in <= 120

        # Mutating inputs/outputs must not affect stored state.
        original["run"] = "mutated"
        context["agent"] = "mutated"
        again, _ = addon.get_declaration("src-1", "pickup")
        assert again["run"] == "r1"
        assert again["agent"] == "pickup"

    def test_omitted_ttl_receives_max(self):
        addon = _make_addon_with_targets()
        granted = addon.set_declaration("src", "pickup", {"run": "r", "agent": "pickup"}, None)
        assert granted == 900  # default option ceiling

    def test_requested_ttl_bounded_to_max(self):
        addon = _make_addon_with_targets()
        assert addon.set_declaration("s", "pickup", {"run": "r", "agent": "pickup"}, 60) == 60
        assert addon.set_declaration("s", "pickup", {"run": "r", "agent": "pickup"}, 99999) == 900

    def test_invalid_ttl_raises(self):
        addon = _make_addon_with_targets()
        ctx = {"run": "r", "agent": "pickup"}
        for bad in (0, -5, True, False, "120", 12.5):
            try:
                addon.set_declaration("s", "pickup", ctx, bad)
            except ValueError:
                continue
            raise AssertionError(f"expected ValueError for ttl={bad!r}")

    def test_unusable_identity_raises(self):
        addon = _make_addon_with_targets()
        ctx = {"run": "r", "agent": "pickup"}
        for src, agent in [("unknown", "pickup"), ("", "pickup"), ("s", "unknown"), ("s", "default"), ("s", "")]:
            try:
                addon.set_declaration(src, agent, ctx, 60)
            except ValueError:
                continue
            raise AssertionError(f"expected ValueError for ({src!r},{agent!r})")

    def test_expiry_uses_monotonic(self):
        addon = _make_addon_with_targets()
        with patch("test_context.time.monotonic", return_value=1000.0):
            addon.set_declaration("s", "pickup", {"run": "r", "agent": "pickup"}, 60)
        # Before expiry
        with patch("test_context.time.monotonic", return_value=1059.0):
            assert addon.get_declaration("s", "pickup") is not None
        # At/after expiry -> None and removed
        with patch("test_context.time.monotonic", return_value=1060.0):
            assert addon.get_declaration("s", "pickup") is None
        assert "s" not in addon._declarations

    def test_agent_mismatch_returns_none_and_evicts(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("s", "pickup", {"run": "r", "agent": "pickup"}, 60)
        assert addon.get_declaration("s", "other") is None
        # Stale binding is dropped immediately (slot-reuse guard).
        assert "s" not in addon._declarations

    def test_two_sources_isolated(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("a", "agentA", {"run": "ra", "agent": "agentA"}, 60)
        addon.set_declaration("b", "agentB", {"run": "rb", "agent": "agentB"}, 60)
        assert addon.get_declaration("a", "agentA")[0]["run"] == "ra"
        assert addon.get_declaration("b", "agentB")[0]["run"] == "rb"
        assert addon.get_declaration("a", "agentB") is None

    def test_clear_returns_existence(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("s", "pickup", {"run": "r", "agent": "pickup"}, 60)
        assert addon.clear_declaration("s") is True
        assert addon.clear_declaration("s") is False

    def test_active_count_evicts_expired(self):
        addon = _make_addon_with_targets()
        with patch("test_context.time.monotonic", return_value=100.0):
            addon.set_declaration("live", "pickup", {"run": "r", "agent": "pickup"}, 60)
            addon.set_declaration("dead", "pickup", {"run": "r", "agent": "pickup"}, 10)
        with patch("test_context.time.monotonic", return_value=140.0):
            assert addon._declared_active_count() == 1
        assert "dead" not in addon._declarations


class TestDeclaredConfig:
    """Effective feature/TTL configuration resolution."""

    def test_inject_enabled_from_config(self):
        addon = _make_addon_with_targets()
        with patch("safeyolo.core.config_cache.addon_section", return_value={"inject_declared": True}):
            assert addon._inject_declared_enabled() is True

    def test_inject_invalid_config_falls_back_to_option(self):
        addon = _make_addon_with_targets()
        with patch("safeyolo.core.config_cache.addon_section", return_value={"inject_declared": "yes"}), \
             patch("test_context.get_option_safe", return_value=False):
            assert addon._inject_declared_enabled() is False

    def test_inject_default_option_false(self):
        addon = _make_addon_with_targets()
        with patch("safeyolo.core.config_cache.addon_section", return_value={}):
            # Option unavailable -> default False
            assert addon._inject_declared_enabled() is False

    def test_ttl_max_from_config(self):
        addon = _make_addon_with_targets()
        with patch("safeyolo.core.config_cache.addon_section", return_value={"declared_ttl_max": 300}):
            assert addon._declared_ttl_max() == 300

    def test_ttl_max_invalid_config_falls_back(self):
        addon = _make_addon_with_targets()
        for bad in ({"declared_ttl_max": 0}, {"declared_ttl_max": -1}, {"declared_ttl_max": True}, {"declared_ttl_max": "60"}):
            with patch("safeyolo.core.config_cache.addon_section", return_value=bad), \
                 patch("test_context.get_option_safe", return_value=900):
                assert addon._declared_ttl_max() == 900


class TestDeclaredInjection:
    """Request-path behavior for declared-context injection on target hosts."""

    def _run(self, addon, flow, *, enabled=True, block=True):
        side = (lambda name, default=True: name != "test_context_block") if not block else None
        basepatch = (
            patch("safeyolo.core.base.get_option_safe", side_effect=side)
            if side else patch("safeyolo.core.base.get_option_safe", return_value=True)
        )
        with _mock_discovery("pickup"), \
             patch.object(addon, "_inject_declared_enabled", return_value=enabled), \
             patch("test_context.write_event"), \
             basepatch:
            addon.request(flow)

    def test_missing_header_valid_declaration_injects(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "pickup", {"run": "r1", "agent": "pickup", "test": "T"}, 120)
        flow = _make_mock_flow()  # no header
        self._run(addon, flow)

        assert flow.response is None
        assert flow.metadata["ccapt_context"] == {"run": "r1", "agent": "pickup", "test": "T"}
        assert flow.metadata["test_context_source"] == "declared"
        assert flow.metadata["agent"] == "pickup"
        assert addon.stats.allowed == 1
        assert addon._declared_injections_total == 1

    def test_empty_header_strips_and_injects(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "pickup", {"run": "r1", "agent": "pickup"}, 120)
        flow = _make_mock_flow(headers={"X-Test-Context": ""})
        self._run(addon, flow)

        assert "X-Test-Context" not in flow.request.headers
        assert flow.metadata["test_context_source"] == "declared"

    def test_missing_header_no_declaration_blocks(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        self._run(addon, flow)
        assert flow.response.status_code == 428
        assert addon._declared_injections_total == 0

    def test_missing_header_expired_declaration_blocks(self):
        addon = _make_addon_with_targets()
        with patch("test_context.time.monotonic", return_value=1000.0):
            addon.set_declaration("192.168.1.1", "pickup", {"run": "r", "agent": "pickup"}, 30)
        flow = _make_mock_flow()
        with patch("test_context.time.monotonic", return_value=2000.0):
            self._run(addon, flow)
        assert flow.response.status_code == 428

    def test_missing_header_agent_mismatch_blocks(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "someone-else", {"run": "r", "agent": "x"}, 120)
        flow = _make_mock_flow()
        self._run(addon, flow)  # discovery resolves "pickup" != stored "someone-else"
        assert flow.response.status_code == 428

    def test_valid_header_ignores_declaration(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "pickup", {"run": "declared", "agent": "pickup"}, 120)
        flow = _make_mock_flow(headers={"X-Test-Context": "run=hdr;agent=pickup"})
        self._run(addon, flow)
        assert flow.metadata["ccapt_context"] == {"run": "hdr", "agent": "pickup"}
        assert flow.metadata["test_context_source"] == "header"
        assert addon._declared_injections_total == 0

    def test_malformed_header_never_rescued_block_mode(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "pickup", {"run": "r", "agent": "pickup"}, 120)
        flow = _make_mock_flow(headers={"X-Test-Context": "garbage-no-equals"})
        self._run(addon, flow)
        assert flow.response.status_code == 428
        assert "X-Test-Context" not in flow.request.headers  # leak fix
        assert "ccapt_context" not in flow.metadata

    def test_malformed_header_warn_mode_strips_and_forwards(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": "garbage-no-equals"})
        self._run(addon, flow, block=False)
        assert flow.response is None
        assert "X-Test-Context" not in flow.request.headers  # warn-mode leak fix
        assert addon.stats.warned == 1

    def test_feature_disabled_ignores_declaration(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "pickup", {"run": "r", "agent": "pickup"}, 120)
        flow = _make_mock_flow()
        self._run(addon, flow, enabled=False)
        assert flow.response.status_code == 428

    def test_non_target_no_header_passthrough_no_lookup(self):
        addon = _make_addon_with_targets(["target.example.com"])
        addon.set_declaration("192.168.1.1", "pickup", {"run": "r", "agent": "pickup"}, 120)
        flow = _make_mock_flow(host="ordinary.example.com")
        # Injection must not be consulted for a non-target host.
        with patch.object(addon, "_trusted_agent", side_effect=AssertionError("must not resolve")), \
             patch.object(addon, "_inject_declared_enabled", return_value=True):
            addon.request(flow)
        assert flow.response is None
        assert "ccapt_context" not in flow.metadata


class TestProvenanceAuditContract:
    """test_context_source must appear in BOTH request and response events."""

    def _set_response(self, flow):
        flow.response = MagicMock()
        flow.response.status_code = 200
        flow.response.content = b'{"ok": true}'
        return flow

    def test_header_source_in_request_and_response_events(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": "run=sec1;agent=idor"})
        with patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event") as we:
            addon.request(flow)          # flow.response is None here
            self._set_response(flow)     # backend responded
            addon.response(flow)
        sources = [c.kwargs["details"].get("test_context_source") for c in we.call_args_list]
        phases = [c.kwargs["details"].get("phase") for c in we.call_args_list]
        assert phases == ["request", "response"]
        assert sources == ["header", "header"]

    def test_declared_source_in_request_and_response_events(self):
        addon = _make_addon_with_targets()
        addon.set_declaration("192.168.1.1", "pickup", {"run": "r", "agent": "pickup"}, 120)
        flow = _make_mock_flow()
        with _mock_discovery("pickup"), \
             patch.object(addon, "_inject_declared_enabled", return_value=True), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event") as we:
            addon.request(flow)          # flow.response is None here
            self._set_response(flow)     # backend responded
            addon.response(flow)
        sources = [c.kwargs["details"].get("test_context_source") for c in we.call_args_list]
        phases = [c.kwargs["details"].get("phase") for c in we.call_args_list]
        assert phases == ["request", "response"]
        assert sources == ["declared", "declared"]


class TestTrustedAgentResolution:
    """Direct tests for _trusted_agent() — the injection identity guard."""

    def test_missing_discovery_returns_none(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        # No running master and no singleton -> unresolved (deterministic).
        with patch("mitmproxy.ctx.master", None, create=True), \
             patch("service_discovery.get_service_discovery", return_value=None):
            assert addon._trusted_agent(flow) is None

    def test_unknown_and_default_rejected(self):
        addon = _make_addon_with_targets()
        for name in ("unknown", "default", ""):
            flow = _make_mock_flow()
            with _mock_discovery(name):
                assert addon._trusted_agent(flow) is None

    def test_matching_prestamped_metadata_accepted(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        flow.metadata["agent"] = "pickup"
        with _mock_discovery("pickup"):
            assert addon._trusted_agent(flow) == "pickup"
        assert flow.metadata["agent"] == "pickup"

    def test_absent_metadata_gets_populated(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()  # no agent stamped
        with _mock_discovery("pickup"):
            assert addon._trusted_agent(flow) == "pickup"
        assert flow.metadata["agent"] == "pickup"

    def test_conflicting_prestamped_metadata_fails_no_overwrite(self):
        """Security-relevant: a pre-stamped agent that conflicts with the
        resolved trusted agent must fail rather than be silently overwritten."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        flow.metadata["agent"] = "attacker"
        with _mock_discovery("pickup"):
            assert addon._trusted_agent(flow) is None
        # Must NOT overwrite the conflicting stamp.
        assert flow.metadata["agent"] == "attacker"


class TestEmptyHeaderNoDeclaration:
    """Explicit-empty header without a declaration: strip + ordinary policy."""

    def test_empty_header_block_mode_strips_and_428(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": ""})
        with _mock_discovery("pickup"), \
             patch.object(addon, "_inject_declared_enabled", return_value=True), \
             patch("safeyolo.core.base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow)
        assert flow.response.status_code == 428
        assert "X-Test-Context" not in flow.request.headers
        assert "ccapt_context" not in flow.metadata

    def test_empty_header_warn_mode_strips_and_forwards(self):
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(headers={"X-Test-Context": ""})
        with _mock_discovery("pickup"), \
             patch.object(addon, "_inject_declared_enabled", return_value=True), \
             patch("safeyolo.core.base.get_option_safe", side_effect=lambda name, default=True: name != "test_context_block"), \
             patch("test_context.write_event"):
            addon.request(flow)
        assert flow.response is None
        assert "X-Test-Context" not in flow.request.headers
        assert addon.stats.warned == 1


class TestDeclarationReplacementRace:
    """v4 called out the replace-vs-expiry race explicitly; pin it."""

    def test_replacement_not_evicted_by_stale_expiry(self):
        addon = _make_addon_with_targets()
        # Original short-lived declaration.
        with patch("test_context.time.monotonic", return_value=1000.0):
            addon.set_declaration("s", "pickup", {"run": "old", "agent": "pickup"}, 10)  # exp 1010
        # Replaced with a fresh, longer one before the original would expire.
        with patch("test_context.time.monotonic", return_value=1005.0):
            addon.set_declaration("s", "pickup", {"run": "new", "agent": "pickup"}, 100)  # exp 1105
        # A read past the ORIGINAL expiry must see the fresh record, not evict it.
        with patch("test_context.time.monotonic", return_value=1050.0):
            rec = addon.get_declaration("s", "pickup")
        assert rec is not None
        assert rec[0]["run"] == "new"
        assert "s" in addon._declarations


class TestConfigFallbackHonorsOption:
    """When the addon config key is absent, the mitmproxy option is honored."""

    def test_option_enables_injection_when_config_key_absent(self):
        addon = _make_addon_with_targets()
        with patch("safeyolo.core.config_cache.addon_section", return_value={}), \
             patch("test_context.get_option_safe", return_value=True):
            assert addon._inject_declared_enabled() is True

    def test_non_default_option_ttl_honored_when_config_key_absent(self):
        addon = _make_addon_with_targets()
        with patch("safeyolo.core.config_cache.addon_section", return_value={}), \
             patch("test_context.get_option_safe", return_value=300):
            assert addon._declared_ttl_max() == 300
        # And that ceiling is actually applied to an over-max request.
        with patch("safeyolo.core.config_cache.addon_section", return_value={}), \
             patch("test_context.get_option_safe", return_value=300):
            assert addon.set_declaration("s", "pickup", {"run": "r", "agent": "pickup"}, 9999) == 300

# The registry-vs-singleton resolution mechanics now live in the inherited
# SecurityAddon._resolve_service_discovery() and are covered by tests/test_base.py
# (registry-first, master-authoritative, singleton-only-without-a-master). The
# _trusted_agent tests above only supply a controlled registry via _mock_discovery.
