"""
Tests for request_logger.py - Request/response JSONL logging.

Tests logging functionality and quiet hosts configuration.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock


class TestQuietHostsConfig:
    """Tests for QuietHostsConfig class."""

    def test_loads_empty_config(self):
        """Test loading empty config file."""
        from request_logger import QuietHostsConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "quiet_hosts.yaml"
            config_path.write_text("hosts: []\npaths: {}")

            config = QuietHostsConfig(config_path)
            result = config.load()

            assert result is True

    def test_loads_hosts_list(self):
        """Test loading hosts list from config."""
        from request_logger import QuietHostsConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "quiet_hosts.yaml"
            config_path.write_text("""
hosts:
  - statsig.anthropic.com
  - telemetry.example.com
""")

            config = QuietHostsConfig(config_path)
            config.load()

            assert config.should_quiet("statsig.anthropic.com", "/v1/rgstr") is True
            assert config.should_quiet("telemetry.example.com", "/metrics") is True
            assert config.should_quiet("api.example.com", "/data") is False

    def test_loads_wildcard_patterns(self):
        """Test loading wildcard host patterns."""
        from request_logger import QuietHostsConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "quiet_hosts.yaml"
            config_path.write_text("""
hosts:
  - "*.telemetry.com"
  - "stats.*"
""")

            config = QuietHostsConfig(config_path)
            config.load()

            assert config.should_quiet("app.telemetry.com", "/") is True
            assert config.should_quiet("api.telemetry.com", "/") is True
            assert config.should_quiet("stats.example.com", "/") is True
            assert config.should_quiet("api.example.com", "/") is False

    def test_loads_path_patterns(self):
        """Test loading host:path patterns."""
        from request_logger import QuietHostsConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "quiet_hosts.yaml"
            config_path.write_text("""
hosts: []
paths:
  api.example.com:
    - /health
    - /metrics/*
""")

            config = QuietHostsConfig(config_path)
            config.load()

            assert config.should_quiet("api.example.com", "/health") is True
            assert config.should_quiet("api.example.com", "/metrics/foo") is True
            assert config.should_quiet("api.example.com", "/v1/data") is False

    def test_handles_missing_file(self):
        """Test handling of missing config file."""
        from request_logger import QuietHostsConfig

        config = QuietHostsConfig(Path("/nonexistent/path.yaml"))
        result = config.load()

        assert result is False

    def test_handles_invalid_yaml(self):
        """Test handling of invalid YAML."""
        from request_logger import QuietHostsConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "quiet_hosts.yaml"
            config_path.write_text("not: valid: yaml: {{{")

            config = QuietHostsConfig(config_path)
            result = config.load()

            assert result is False

    def test_case_insensitive_matching(self):
        """Test host matching is case insensitive."""
        from request_logger import QuietHostsConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "quiet_hosts.yaml"
            config_path.write_text("hosts:\n  - Example.Com")

            config = QuietHostsConfig(config_path)
            config.load()

            assert config.should_quiet("example.com", "/") is True
            assert config.should_quiet("EXAMPLE.COM", "/") is True
            assert config.should_quiet("Example.Com", "/") is True


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

            addon = RequestLogger()
            addon.log_path = log_path

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
            assert entry["method"] == "GET"
            assert entry["host"] == "api.example.com"
            assert entry["path"] == "/v1/data"
            assert addon.requests_total == 1

    def test_logs_response_to_file(self):
        """Test response is logged to JSONL file."""
        import time

        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            addon = RequestLogger()
            addon.log_path = log_path

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
            assert entry["status"] == 200
            assert "ms" in entry
            assert addon.responses_total == 1

    def test_logs_block_with_details(self):
        """Test blocked requests include block details."""
        from request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"

            addon = RequestLogger()
            addon.log_path = log_path

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

            assert entry["blocked_by"] == "credential-guard"
            assert entry["credential_fingerprint"] == "hmac:abc123"
            assert addon.blocks_total == 1


class TestRequestLoggerQuiet:
    """Tests for quiet hosts functionality."""

    def test_quiets_matching_hosts(self):
        """Test matching hosts are not logged."""
        from request_logger import QuietHostsConfig, RequestLogger

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.jsonl"
            config_path = Path(tmpdir) / "quiet.yaml"
            config_path.write_text("hosts:\n  - telemetry.example.com")

            addon = RequestLogger()
            addon.log_path = log_path
            addon.quiet_hosts = QuietHostsConfig(config_path)
            addon.quiet_hosts.load()

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

            addon = RequestLogger()
            addon.log_path = log_path

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

            addon = RequestLogger()
            addon.log_path = log_path

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
            assert entry["blocked_by"] == "network-guard"
            assert addon.blocks_total == 1


class TestRequestLoggerStats:
    """Tests for stats tracking."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns proper structure."""
        from request_logger import RequestLogger

        addon = RequestLogger()
        addon.log_path = Path("/app/logs/test.jsonl")
        addon.requests_total = 100
        addon.requests_quieted = 10
        addon.responses_total = 85
        addon.blocks_total = 5

        stats = addon.get_stats()

        assert stats["requests_total"] == 100
        assert stats["requests_quieted"] == 10
        assert stats["responses_total"] == 85
        assert stats["blocks_total"] == 5
        assert stats["log_path"] == "/app/logs/test.jsonl"
