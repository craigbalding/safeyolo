"""
Tests for request_logger.py - Request/response JSONL logging.

Tests logging functionality and quiet hosts configuration.
Note: Quiet hosts config now loaded from PDP, not file-based QuietHostsConfig.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import utils  # Import to patch AUDIT_LOG_PATH


class TestRequestLoggerShouldQuiet:
    """Tests for _should_quiet internal method."""

    def test_matches_exact_host(self):
        """Test exact host matching."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        addon._quiet_hosts = {"statsig.anthropic.com", "telemetry.example.com"}

        assert addon._should_quiet("statsig.anthropic.com", "/v1/rgstr") is True
        assert addon._should_quiet("telemetry.example.com", "/metrics") is True
        assert addon._should_quiet("api.example.com", "/data") is False

    def test_matches_wildcard_patterns(self):
        """Test wildcard host pattern matching."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        addon._quiet_host_patterns = ["*.telemetry.com", "stats.*"]

        assert addon._should_quiet("app.telemetry.com", "/") is True
        assert addon._should_quiet("api.telemetry.com", "/") is True
        assert addon._should_quiet("stats.example.com", "/") is True
        assert addon._should_quiet("api.example.com", "/") is False

    def test_matches_path_patterns(self):
        """Test host:path pattern matching."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        addon._quiet_paths = {
            "api.example.com": ["/health", "/metrics/*"]
        }

        assert addon._should_quiet("api.example.com", "/health") is True
        assert addon._should_quiet("api.example.com", "/metrics/foo") is True
        assert addon._should_quiet("api.example.com", "/v1/data") is False

    def test_case_insensitive_matching(self):
        """Test host matching is case insensitive."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        addon._quiet_hosts = {"example.com"}

        assert addon._should_quiet("example.com", "/") is True
        assert addon._should_quiet("EXAMPLE.COM", "/") is True
        assert addon._should_quiet("Example.Com", "/") is True


class TestRequestLogger:
    """Tests for RequestLogger addon."""

    def test_addon_name(self):
        """Test addon has correct name."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        assert addon.name == "request-logger"

    def test_initial_stats_zero(self):
        """Test stats start at zero."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        assert addon.requests_total == 0
        assert addon.requests_quieted == 0
        assert addon.responses_total == 0
        assert addon.blocks_total == 0


class TestRequestLoggerLogging:
    """Tests for logging functionality."""

    def test_logs_request_to_file(self):
        """Test request is logged to JSONL file."""
        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            with patch.object(utils, "AUDIT_LOG_PATH", log_path):
                addon = RequestLogger()

                flow = Mock()
                flow.metadata = {"request_id": "test-123"}
                flow.request.pretty_url = "https://api.example.com/v1/data"
                flow.request.method = "GET"
                flow.request.content = b"test body"
                flow.client_conn.peername = ("192.168.1.1", 12345)

                addon.request(flow)

            # Read log file
            assert log_path.exists()
            with open(log_path) as f:
                entry = json.loads(f.readline())

            assert entry["event"] == "traffic.request"
            assert entry["request_id"] == "test-123"
            assert entry["host"] == "api.example.com"
            assert entry["details"]["method"] == "GET"
            assert entry["details"]["path"] == "/v1/data"
            assert addon.requests_total == 1

    def test_logs_response_to_file(self):
        """Test response is logged to JSONL file."""
        import time

        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            with patch.object(utils, "AUDIT_LOG_PATH", log_path):
                addon = RequestLogger()

                flow = Mock()
                flow.metadata = {"request_id": "test-456", "start_time": time.time()}
                flow.request.pretty_url = "https://api.example.com/v1/data"
                flow.response.status_code = 200
                flow.response.content = b"response body"

                addon.response(flow)

            assert log_path.exists()
            with open(log_path) as f:
                entry = json.loads(f.readline())

            assert entry["event"] == "traffic.response"
            assert entry["request_id"] == "test-456"
            assert entry["details"]["status"] == 200
            assert "ms" in entry["details"]
            assert addon.responses_total == 1

    def test_logs_block_with_details(self):
        """Test blocked requests include block details."""
        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            with patch.object(utils, "AUDIT_LOG_PATH", log_path):
                addon = RequestLogger()

                flow = Mock()
                flow.metadata = {
                    "request_id": "test-789",
                    "blocked_by": "credential-guard",
                    "credential_fingerprint": "hmac:abc123",
                }
                flow.request.pretty_url = "https://evil.com/steal"
                flow.response.status_code = 428
                flow.response.content = b""

                addon.response(flow)

            with open(log_path) as f:
                entry = json.loads(f.readline())

            assert entry["details"]["blocked_by"] == "credential-guard"
            assert entry["details"]["credential_fingerprint"] == "hmac:abc123"
            assert addon.blocks_total == 1


class TestRequestLoggerQuiet:
    """Tests for quiet hosts functionality."""

    def test_quiets_matching_hosts(self):
        """Test matching hosts are not logged."""
        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            with patch.object(utils, "AUDIT_LOG_PATH", log_path):
                addon = RequestLogger()
                # Directly set quiet hosts (normally loaded from PDP)
                addon._quiet_hosts = {"telemetry.example.com"}

                flow = Mock()
                flow.metadata = {}
                flow.request.pretty_url = "https://telemetry.example.com/v1/track"
                flow.request.method = "POST"
                flow.request.content = b""
                flow.client_conn.peername = ("127.0.0.1", 12345)

                addon.request(flow)

            # Should NOT write to log
            assert not log_path.exists() or log_path.stat().st_size == 0
            assert addon.requests_quieted == 1
            assert flow.metadata.get("quieted") is True

    def test_skips_quieted_response_logging(self):
        """Test quieted requests don't log responses."""
        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            with patch.object(utils, "AUDIT_LOG_PATH", log_path):
                addon = RequestLogger()

                flow = Mock()
                flow.metadata = {"quieted": True}
                flow.request.pretty_url = "https://telemetry.example.com/v1/track"
                flow.response.status_code = 200
                flow.response.content = b""

                addon.response(flow)

            # Should NOT write to log
            assert not log_path.exists() or log_path.stat().st_size == 0

    def test_logs_blocks_even_when_quieted(self):
        """Test blocked requests are logged even if host is quieted."""
        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            with patch.object(utils, "AUDIT_LOG_PATH", log_path):
                addon = RequestLogger()

                flow = Mock()
                flow.metadata = {
                    "quieted": True,
                    "blocked_by": "network-guard"
                }
                flow.request.pretty_url = "https://telemetry.example.com/v1/track"
                flow.response.status_code = 403
                flow.response.content = b""

                addon.response(flow)

            # SHOULD write to log because it was blocked
            assert log_path.exists()
            with open(log_path) as f:
                entry = json.loads(f.readline())
            assert entry["details"]["blocked_by"] == "network-guard"
            assert addon.blocks_total == 1


class TestRequestLoggerStats:
    """Tests for stats tracking."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns proper structure."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        addon.requests_total = 100
        addon.requests_quieted = 10
        addon.responses_total = 85
        addon.blocks_total = 5

        stats = addon.get_stats()

        assert stats["requests_total"] == 100
        assert stats["requests_quieted"] == 10
        assert stats["responses_total"] == 85
        assert stats["blocks_total"] == 5
