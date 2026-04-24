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
        """Requests to non-target hosts should pass without checks."""
        addon = _make_addon_with_targets(["target.example.com"])
        flow = _make_mock_flow(host="api.openai.com", path="/v1/chat")

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.checks == 0

    def test_target_host_missing_header_blocks_428(self):
        """Requests to target hosts without context header get 428."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        with patch("base.get_option_safe", return_value=True):
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

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428
        assert addon.stats.blocked == 1

    def test_target_host_incomplete_header_blocks_428(self):
        """Header missing required keys triggers 428."""
        addon = _make_addon_with_targets()
        # Missing 'agent' key
        flow = _make_mock_flow(headers={"X-Test-Context": "run=sec1;test=IDOR-003"})

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 428

    def test_target_host_valid_header_allows(self):
        """Valid context header lets request through."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor;test=IDOR-003"}
        )

        with patch("base.get_option_safe", return_value=True), \
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

        with patch("base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow)

        assert "X-Test-Context" not in flow.request.headers
        # Context still preserved in metadata for response logging
        assert flow.metadata["ccapt_context"]["run"] == "sec1"

    def test_warn_mode_does_not_block(self):
        """In warn mode, missing header logs but doesn't block."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        # should_block returns False in warn mode
        with patch("base.get_option_safe", side_effect=lambda name, default=True: name != "test_context_block"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1
        assert addon.stats.blocked == 0

    def test_no_target_hosts_passes_everything(self):
        """With no target hosts configured, all requests pass through."""
        addon = _make_addon_with_targets(targets=[])
        flow = _make_mock_flow()

        with patch.object(addon, "_maybe_reload_config"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.checks == 0

    def test_already_blocked_flow_skipped(self):
        """Flow already blocked by another addon is skipped."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()
        flow.response = MagicMock()  # Already has a response

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        assert addon.stats.checks == 0

    def test_wildcard_target_host_matching(self):
        """Wildcard patterns in target_hosts work."""
        addon = _make_addon_with_targets(["*.example.com"])
        flow = _make_mock_flow(host="target.example.com")

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        # Should be treated as target host (blocked for missing header)
        assert flow.response is not None
        assert flow.response.status_code == 428

    def test_response_logging_with_context(self):
        """Response phase logs when context was set in request phase."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor;test=IDOR-003"}
        )

        # Simulate request phase
        with patch("base.get_option_safe", return_value=True), \
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

        with patch("base.get_option_safe", return_value=True), \
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

        with patch("base.get_option_safe", return_value=True):
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

        with patch("base.get_option_safe", return_value=True):
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
        with patch("base.get_option_safe", return_value=True), \
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

    def test_duplicate_keys_last_wins(self):
        """When a key appears twice, the last value wins."""
        from test_context import _parse_context_header

        result = _parse_context_header("run=first;agent=idor;run=second")
        assert result is not None
        assert result["run"] == "second"

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

    def test_pairs_beyond_max_are_silently_dropped(self):
        """Pairs beyond _MAX_CONTEXT_PAIRS are ignored; result uses first 20."""
        from test_context import _MAX_CONTEXT_PAIRS, _parse_context_header

        pairs = ["run=sec1", "agent=idor"]
        for i in range(_MAX_CONTEXT_PAIRS - 2):
            pairs.append(f"k{i}=v{i}")
        # 21st pair should be dropped
        pairs.append("extra=dropped")
        header = ";".join(pairs)
        result = _parse_context_header(header)
        assert result is not None
        assert "extra" not in result
        assert len(result) == _MAX_CONTEXT_PAIRS

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

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "malformed_context"

    def test_missing_header_body_has_type_field(self):
        """Block body for missing header includes type=missing_context."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        with patch("base.get_option_safe", return_value=True):
            addon.request(flow)

        body = json.loads(flow.response.content)
        assert body["type"] == "missing_context"

    def test_block_body_includes_reflection_and_action(self):
        """Block body contains both 'reflection' and 'action' fields."""
        addon = _make_addon_with_targets()
        flow = _make_mock_flow()

        with patch("base.get_option_safe", return_value=True):
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
        with patch("base.get_option_safe", return_value=True):
            addon.request(flow1)
        assert addon.stats.checks == 1

        # Valid header -> allowed, checks still counts
        flow2 = _make_mock_flow(
            headers={"X-Test-Context": "run=sec1;agent=idor"}
        )
        with patch("base.get_option_safe", return_value=True), \
             patch("test_context.write_event"):
            addon.request(flow2)
        assert addon.stats.checks == 2

    def test_checks_counter_not_incremented_for_non_target(self):
        """stats.checks does NOT increment for non-target hosts."""
        addon = _make_addon_with_targets(["target.example.com"])
        flow = _make_mock_flow(host="other.example.com")

        with patch("base.get_option_safe", return_value=True):
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

        with patch("base.get_option_safe", side_effect=lambda name, default=True: name != "test_context_block"):
            addon.request(flow)

        assert flow.response is None
        assert addon.stats.warned == 1
        assert addon.stats.blocked == 0
