"""Tests for request_logger — structured traffic.* logging and quiet hosts.

Organised by contract area:
- _should_quiet matcher
- Request event shape (including host/addon invariants)
- Response event shape
- Paired-flow invariants (catches host divergence bugs)
- URL edge cases (userinfo, port, missing response)
- Hot reload (PDP sensor config refresh)
- PDP config parsing (malformed input fail-closed)
- Counter semantics
"""

import json
import time
from pathlib import Path
from unittest import mock
from unittest.mock import Mock, patch

import pytest

import safeyolo.core.utils as utils  # imported for AUDIT_LOG_PATH patching

# =========================================================================
# Helpers
# =========================================================================


def _make_flow(url="https://api.example.com/v1/data", *,
               method="GET", content=b"", metadata=None,
               status=200, response_content=b"",
               peername=("192.168.1.1", 12345)):
    """Build a mock flow with the fields request_logger touches."""
    flow = Mock()
    flow.metadata = dict(metadata or {})
    flow.request.pretty_url = url
    flow.request.method = method
    flow.request.content = content
    flow.client_conn.peername = peername
    if status is None:
        flow.response = None
    else:
        flow.response.status_code = status
        flow.response.content = response_content
    return flow


@pytest.fixture
def logger_with_log(tmp_path):
    """Yield (RequestLogger, log_path) with AUDIT_LOG_PATH patched to tmp."""
    from request_logger import RequestLogger
    log_path = tmp_path / "test.jsonl"
    with patch.object(utils, "AUDIT_LOG_PATH", log_path):
        yield RequestLogger(), log_path


def _read_events(log_path: Path) -> list[dict]:
    """Read all JSONL entries from a log file.

    `write_event` is now async (background writer thread). Drain the
    queue before reading so assertions see events the addon actually
    enqueued, not races with the writer thread.
    """
    from safeyolo.core.audit_writer import get_writer
    assert get_writer().wait_for_drain(timeout_s=3.0), "audit writer failed to drain"
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line]


# =========================================================================
# _should_quiet matcher
# =========================================================================


class TestShouldQuiet:
    def test_exact_host_match(self):
        from request_logger import RequestLogger
        addon = RequestLogger()
        addon._quiet_hosts = {"statsig.anthropic.com"}

        assert addon._should_quiet("statsig.anthropic.com", "/v1/rgstr") is True
        assert addon._should_quiet("api.example.com", "/data") is False

    def test_wildcard_host_pattern(self):
        from request_logger import RequestLogger
        addon = RequestLogger()
        addon._quiet_host_patterns = ["*.telemetry.com"]

        assert addon._should_quiet("app.telemetry.com", "/") is True
        assert addon._should_quiet("api.telemetry.com", "/") is True
        assert addon._should_quiet("telemetry.com.evil.com", "/") is False

    def test_host_path_pattern(self):
        from request_logger import RequestLogger
        addon = RequestLogger()
        addon._quiet_paths = {"api.example.com": ["/health", "/metrics/*"]}

        assert addon._should_quiet("api.example.com", "/health") is True
        assert addon._should_quiet("api.example.com", "/metrics/cpu") is True
        assert addon._should_quiet("api.example.com", "/v1/data") is False

    def test_case_insensitive_host(self):
        from request_logger import RequestLogger
        addon = RequestLogger()
        addon._quiet_hosts = {"example.com"}

        assert addon._should_quiet("EXAMPLE.COM", "/") is True
        assert addon._should_quiet("Example.Com", "/") is True


# =========================================================================
# Request event shape
# =========================================================================


class TestRequestEventShape:
    def test_full_request_event_shape(self, logger_with_log):
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://api.example.com/v1/data",
            method="GET",
            content=b"hello",
            metadata={"request_id": "req-abc", "agent": "boris"},
        )

        addon.request(flow)

        events = _read_events(log_path)
        assert len(events) == 1
        ev = events[0]
        assert ev["event"] == "traffic.request"
        assert ev["kind"] == "traffic"
        assert ev["severity"] == "low"
        assert ev["summary"] == "GET api.example.com/v1/data"
        assert ev["host"] == "api.example.com"
        assert ev["request_id"] == "req-abc"
        assert ev["agent"] == "boris"
        assert ev["addon"] == "request-logger"
        assert ev["details"] == {
            "method": "GET",
            "path": "/v1/data",
            "size": 5,
            "client": "192.168.1.1",
        }

    def test_request_without_client_conn_peername(self, logger_with_log):
        addon, log_path = logger_with_log
        flow = _make_flow(peername=None)

        addon.request(flow)

        events = _read_events(log_path)
        assert events[0]["details"]["client"] is None

    def test_request_event_carries_addon_field(self, logger_with_log):
        """Every traffic.* event must include addon=request-logger so operators
        can filter the audit log by emitting addon."""
        addon, log_path = logger_with_log
        addon.request(_make_flow(metadata={"request_id": "req-1"}))

        assert _read_events(log_path)[0]["addon"] == "request-logger"


# =========================================================================
# Response event shape
# =========================================================================


class TestResponseEventShape:
    def test_full_response_event_shape(self, logger_with_log):
        addon, log_path = logger_with_log
        start = time.time() - 0.05  # ~50ms ago
        flow = _make_flow(
            url="https://api.example.com/v1/data",
            metadata={"request_id": "req-xyz", "start_time": start},
            status=200,
            response_content=b"x" * 100,
        )

        addon.response(flow)

        events = _read_events(log_path)
        assert len(events) == 1
        ev = events[0]
        assert ev["event"] == "traffic.response"
        assert ev["kind"] == "traffic"
        assert ev["severity"] == "low"
        assert ev["host"] == "api.example.com"
        assert ev["summary"].startswith("200 api.example.com/v1/data")
        assert ev["request_id"] == "req-xyz"
        assert ev["addon"] == "request-logger"
        assert ev["details"]["status"] == 200
        assert ev["details"]["path"] == "/v1/data"
        assert ev["details"]["size"] == 100
        assert isinstance(ev["details"]["ms"], float)
        assert ev["details"]["ms"] >= 0.0

    def test_block_response_is_high_severity_with_suffix(self, logger_with_log):
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://evil.com/steal",
            metadata={
                "request_id": "req-blk",
                "blocked_by": "credential-guard",
                "credential_fingerprint": "hmac:abc123",
                "start_time": time.time(),
            },
            status=428,
        )

        addon.response(flow)

        ev = _read_events(log_path)[0]
        assert ev["severity"] == "high"
        assert ev["summary"].endswith("[blocked by credential-guard]")
        assert ev["details"]["blocked_by"] == "credential-guard"
        assert ev["details"]["credential_fingerprint"] == "hmac:abc123"
        assert addon.blocks_total == 1

    def test_duration_ms_computed_from_start_time(self, logger_with_log):
        """With a fixed start_time, duration_ms is computed from wall clock."""
        addon, log_path = logger_with_log
        # Use a patched time to make this deterministic
        with mock.patch("request_logger.time.time", return_value=1000.075):
            flow = _make_flow(metadata={"start_time": 1000.0})
            addon.response(flow)

        ev = _read_events(log_path)[0]
        assert ev["details"]["ms"] == 75.0


# =========================================================================
# Paired-flow invariants — catches B1 (host vs netloc divergence)
# =========================================================================


class TestPairedFlowInvariants:
    def test_request_and_response_use_same_host(self, logger_with_log):
        """For the same flow, the request and response events MUST agree on host."""
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://api.example.com:8443/v1/data",
            metadata={"request_id": "req-p1", "start_time": time.time()},
        )

        addon.request(flow)
        addon.response(flow)

        events = _read_events(log_path)
        assert len(events) == 2
        assert events[0]["host"] == events[1]["host"] == "api.example.com"

    def test_request_id_matches_across_pair(self, logger_with_log):
        addon, log_path = logger_with_log
        flow = _make_flow(metadata={"request_id": "req-pair-xyz", "start_time": time.time()})

        addon.request(flow)
        addon.response(flow)

        events = _read_events(log_path)
        assert events[0]["request_id"] == events[1]["request_id"] == "req-pair-xyz"

    def test_userinfo_does_not_leak_to_host_field(self, logger_with_log):
        """urlparse.hostname strips userinfo; parsed.netloc would leak it.
        This test pins the B1 fix."""
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://user:secret@api.example.com/path",
            metadata={"request_id": "req-leak", "start_time": time.time()},
        )

        addon.request(flow)
        addon.response(flow)

        for ev in _read_events(log_path):
            assert "user" not in ev["host"]
            assert "secret" not in ev["host"]
            assert ev["host"] == "api.example.com"

    def test_non_default_port_does_not_appear_in_host_field(self, logger_with_log):
        """The `host` field must be the bare hostname, not host:port."""
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://api.example.com:8443/v1/x",
            metadata={"request_id": "req-port", "start_time": time.time()},
        )

        addon.request(flow)
        addon.response(flow)

        for ev in _read_events(log_path):
            assert ev["host"] == "api.example.com"


# =========================================================================
# Missing-response edge case (B3)
# =========================================================================


class TestMissingResponse:
    def test_none_response_emits_ops_response_missing(self, logger_with_log):
        """When flow.response is None, emit ops.response_missing, not a fake traffic.response."""
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://api.example.com/v1/data",
            metadata={"request_id": "req-noresp", "start_time": time.time()},
            status=None,
        )

        addon.response(flow)

        events = _read_events(log_path)
        assert len(events) == 1
        assert events[0]["event"] == "ops.response_missing"
        assert events[0]["kind"] == "ops"
        assert events[0]["host"] == "api.example.com"
        assert events[0]["addon"] == "request-logger"
        assert events[0]["request_id"] == "req-noresp"

    def test_none_response_does_not_increment_response_counter(self, logger_with_log):
        addon, log_path = logger_with_log
        flow = _make_flow(status=None, metadata={"request_id": "x"})
        addon.response(flow)

        assert addon.responses_total == 0
        assert addon.blocks_total == 0


# =========================================================================
# Quiet hosts
# =========================================================================


class TestQuietHosts:
    def test_quieted_request_writes_no_event(self, logger_with_log):
        addon, log_path = logger_with_log
        addon._quiet_hosts = {"telemetry.example.com"}
        flow = _make_flow(
            url="https://telemetry.example.com/v1/track",
            method="POST",
            metadata={"request_id": "req-q"},
        )

        addon.request(flow)

        assert _read_events(log_path) == []
        assert addon.requests_quieted == 1
        assert flow.metadata["quieted"] is True

    def test_quieted_response_skipped(self, logger_with_log):
        addon, log_path = logger_with_log
        flow = _make_flow(metadata={"quieted": True})

        addon.response(flow)

        assert _read_events(log_path) == []

    def test_block_overrides_quiet(self, logger_with_log):
        """Security override: blocked responses are logged even on quieted hosts."""
        addon, log_path = logger_with_log
        flow = _make_flow(
            url="https://telemetry.example.com/v1/track",
            metadata={
                "quieted": True,
                "blocked_by": "network-guard",
                "start_time": time.time(),
            },
            status=403,
        )

        addon.response(flow)

        events = _read_events(log_path)
        assert len(events) == 1
        assert events[0]["details"]["blocked_by"] == "network-guard"
        assert addon.blocks_total == 1


# =========================================================================
# Hot reload (B4)
# =========================================================================


class TestHotReload:
    def test_runtime_error_on_unconfigured_client_is_silent(self, logger_with_log):
        """Startup path: PolicyClient not yet configured; request still logs normally."""
        addon, log_path = logger_with_log
        with mock.patch("request_logger.get_policy_client", side_effect=RuntimeError("not ready")):
            addon.request(_make_flow(metadata={"request_id": "req-s"}))

        # Request event was still written (swallowed error didn't prevent the log)
        events = _read_events(log_path)
        assert len(events) == 1
        assert events[0]["event"] == "traffic.request"

    def test_reload_exception_emits_ops_config_error(self, logger_with_log):
        """Non-RuntimeError reload failure surfaces as an ops.config_error audit event."""
        addon, log_path = logger_with_log

        # Simulate the client raising a non-RuntimeError
        mock_client = Mock()
        mock_client.get_sensor_config.side_effect = KeyError("missing key")
        with mock.patch("request_logger.get_policy_client", return_value=mock_client):
            addon.request(_make_flow(metadata={"request_id": "req-err"}))

        events = _read_events(log_path)
        event_types = [e["event"] for e in events]
        assert "ops.config_error" in event_types
        err_event = next(e for e in events if e["event"] == "ops.config_error")
        assert err_event["addon"] == "request-logger"
        assert err_event["details"]["error_type"] == "KeyError"

    def test_reload_exception_preserves_last_known_quiet_hosts(self, logger_with_log):
        addon, log_path = logger_with_log
        addon._quiet_hosts = {"quiet.example.com"}

        mock_client = Mock()
        mock_client.get_sensor_config.side_effect = RuntimeError  # caught branch 1
        with mock.patch("request_logger.get_policy_client", return_value=mock_client):
            # A request to quiet.example.com should still be quieted
            flow = _make_flow(url="https://quiet.example.com/x")
            addon.request(flow)

        assert flow.metadata["quieted"] is True

    def test_unchanged_policy_hash_does_not_reload(self, logger_with_log):
        addon, log_path = logger_with_log
        addon._last_policy_hash = "h1"
        addon._quiet_hosts = {"pinned.example.com"}

        mock_client = Mock()
        mock_client.get_sensor_config.return_value = {"policy_hash": "h1"}
        with mock.patch("request_logger.get_policy_client", return_value=mock_client):
            addon.request(_make_flow(metadata={"request_id": "req-u"}))

        # _quiet_hosts is unchanged because the hash matched
        assert addon._quiet_hosts == {"pinned.example.com"}

    def test_changed_policy_hash_triggers_reload(self, logger_with_log):
        addon, log_path = logger_with_log
        addon._last_policy_hash = "old"

        mock_client = Mock()
        mock_client.get_sensor_config.return_value = {
            "policy_hash": "new",
            "addons": {
                "request_logger": {
                    "quiet_hosts": {"hosts": ["telemetry.example.com"]}
                }
            },
        }
        with mock.patch("request_logger.get_policy_client", return_value=mock_client):
            addon.request(_make_flow(metadata={"request_id": "req-r"}))

        assert addon._quiet_hosts == {"telemetry.example.com"}
        assert addon._last_policy_hash == "new"


# =========================================================================
# PDP config parsing — fail-closed on malformed input (B5, B6)
# =========================================================================


class TestLoadQuietHostsFromPdp:
    def _call(self, config):
        from request_logger import RequestLogger
        addon = RequestLogger()
        addon._load_quiet_hosts_from_pdp(config)
        return addon

    def test_hosts_wildcard_and_exact_split(self):
        addon = self._call({
            "addons": {"request_logger": {"quiet_hosts": {
                "hosts": ["*.telemetry.com", "stats.example.com"]
            }}}
        })
        assert addon._quiet_hosts == {"stats.example.com"}
        assert addon._quiet_host_patterns == ["*.telemetry.com"]

    def test_paths_host_keys_lowercased(self):
        addon = self._call({
            "addons": {"request_logger": {"quiet_hosts": {
                "paths": {"API.EXAMPLE.COM": ["/health"]}
            }}}
        })
        assert "api.example.com" in addon._quiet_paths
        assert addon._quiet_paths["api.example.com"] == ["/health"]

    def test_missing_addons_key_is_noop(self):
        addon = self._call({})
        assert addon._quiet_hosts == set()
        assert addon._quiet_host_patterns == []
        assert addon._quiet_paths == {}

    def test_missing_quiet_hosts_key_is_noop(self):
        addon = self._call({"addons": {"request_logger": {}}})
        assert addon._quiet_hosts == set()

    def test_malformed_hosts_non_list_raises(self):
        """A YAML typo like `hosts: "foo.com"` must not silently become single-char rules."""
        with pytest.raises(ValueError, match="quiet_hosts.hosts must be a list"):
            self._call({
                "addons": {"request_logger": {"quiet_hosts": {"hosts": "foo.com"}}}
            })

    def test_malformed_paths_value_non_list_raises(self):
        with pytest.raises(ValueError, match=r"quiet_hosts\.paths\['api\.example\.com'\]"):
            self._call({
                "addons": {"request_logger": {"quiet_hosts": {
                    "paths": {"api.example.com": "/health"}
                }}}
            })

    def test_malformed_paths_dict_raises(self):
        with pytest.raises(ValueError, match="quiet_hosts.paths must be a dict"):
            self._call({
                "addons": {"request_logger": {"quiet_hosts": {"paths": ["bad"]}}}
            })

    def test_paths_list_is_copied_not_referenced(self):
        """Mutating the sensor config after load must not affect our state."""
        source_list = ["/health"]
        config = {
            "addons": {"request_logger": {"quiet_hosts": {
                "paths": {"api.example.com": source_list}
            }}}
        }
        addon = self._call(config)
        source_list.append("/other")

        assert addon._quiet_paths["api.example.com"] == ["/health"]


# =========================================================================
# Counter semantics
# =========================================================================


class TestCounters:
    def test_requests_total_includes_quieted(self, logger_with_log):
        """Documented: requests_total counts EVERY incoming request, quieted or not."""
        addon, log_path = logger_with_log
        addon._quiet_hosts = {"quiet.example.com"}

        addon.request(_make_flow(url="https://noisy.example.com/a"))
        addon.request(_make_flow(url="https://quiet.example.com/b"))
        addon.request(_make_flow(url="https://noisy.example.com/c"))

        stats = addon.get_stats()
        assert stats["requests_total"] == 3
        assert stats["requests_quieted"] == 1

    def test_block_increments_blocks_not_responses(self, logger_with_log):
        addon, log_path = logger_with_log
        addon.response(_make_flow(
            metadata={"blocked_by": "x", "start_time": time.time()},
            status=403,
        ))
        addon.response(_make_flow(
            metadata={"start_time": time.time()},
            status=200,
        ))

        stats = addon.get_stats()
        assert stats["blocks_total"] == 1
        assert stats["responses_total"] == 1

    def test_stats_returns_fresh_snapshot(self, logger_with_log):
        addon, _ = logger_with_log
        s1 = addon.get_stats()
        addon.requests_total = 5
        s2 = addon.get_stats()

        assert s1["requests_total"] == 0
        assert s2["requests_total"] == 5


# =========================================================================
# Addon identity
# =========================================================================


class TestAddonIdentity:
    def test_addon_name_is_request_logger(self):
        from request_logger import RequestLogger
        assert RequestLogger().name == "request-logger"
