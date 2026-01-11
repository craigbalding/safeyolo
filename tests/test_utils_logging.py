"""
Tests for the utils.py logging functions.

Tests write_event(), write_audit_event(), and taxonomy validation.
"""

import json
from unittest.mock import patch

import pytest


class TestWriteEvent:
    """Tests for write_event function."""

    @pytest.fixture
    def temp_log(self, tmp_path):
        """Create a temporary log file path."""
        log_path = tmp_path / "test.jsonl"
        with patch("utils.AUDIT_LOG_PATH", log_path):
            yield log_path

    def test_writes_valid_json(self, temp_log):
        """write_event outputs valid JSONL."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("traffic.request", host="example.com", method="GET")

        lines = temp_log.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "traffic.request"
        assert entry["host"] == "example.com"
        assert entry["method"] == "GET"

    def test_includes_timestamp(self, temp_log):
        """Event includes ISO timestamp."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("traffic.response", status=200)

        entry = json.loads(temp_log.read_text().strip())
        assert "ts" in entry
        # ISO format check
        assert "T" in entry["ts"]
        assert entry["ts"].endswith("+00:00") or entry["ts"].endswith("Z")

    def test_traffic_prefix_valid(self, temp_log, caplog):
        """traffic.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("traffic.request")
            write_event("traffic.response")

        assert "doesn't match taxonomy" not in caplog.text

    def test_security_prefix_valid(self, temp_log, caplog):
        """security.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("security.credential", decision="block")
            write_event("security.injection", decision="warn")
            write_event("security.yara", decision="allow")
            write_event("security.pattern", decision="redact")
            write_event("security.ratelimit", decision="block")
            write_event("security.circuit", circuit_event="open")

        assert "doesn't match taxonomy" not in caplog.text

    def test_ops_prefix_valid(self, temp_log, caplog):
        """ops.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("ops.startup", addon="test")
            write_event("ops.config_reload", config="test.yaml")
            write_event("ops.config_error", error="parse failed")

        assert "doesn't match taxonomy" not in caplog.text

    def test_admin_prefix_valid(self, temp_log, caplog):
        """admin.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("admin.approve", token="abc123")
            write_event("admin.deny", token="def456")
            write_event("admin.mode_change", new_mode="block")
            write_event("admin.auth_failure", path="/api/admin")

        assert "doesn't match taxonomy" not in caplog.text

    def test_invalid_prefix_warns(self, temp_log, caplog):
        """Invalid event prefix logs a warning but still writes."""
        import logging

        from utils import write_event

        caplog.set_level(logging.WARNING)

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("invalid_event", data="test")

        assert "doesn't match taxonomy" in caplog.text
        # But event is still written
        entry = json.loads(temp_log.read_text().strip())
        assert entry["event"] == "invalid_event"

    def test_preserves_all_kwargs(self, temp_log):
        """All kwargs are included in the log entry."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event(
                "security.credential",
                request_id="req-abc123",
                addon="credential-guard",
                decision="block",
                rule="openai",
                host="api.openai.com",
                path="/v1/chat",
                reason="destination_mismatch",
                credential_fingerprint="sha256:abc...",
            )

        entry = json.loads(temp_log.read_text().strip())
        assert entry["request_id"] == "req-abc123"
        assert entry["addon"] == "credential-guard"
        assert entry["decision"] == "block"
        assert entry["rule"] == "openai"
        assert entry["host"] == "api.openai.com"
        assert entry["path"] == "/v1/chat"
        assert entry["reason"] == "destination_mismatch"
        assert entry["credential_fingerprint"] == "sha256:abc..."

    def test_multiple_events_append(self, temp_log):
        """Multiple events are appended, not overwritten."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("traffic.request", seq=1)
            write_event("security.credential", seq=2)
            write_event("traffic.response", seq=3)

        lines = temp_log.read_text().strip().split("\n")
        assert len(lines) == 3
        entries = [json.loads(line) for line in lines]
        assert entries[0]["seq"] == 1
        assert entries[1]["seq"] == 2
        assert entries[2]["seq"] == 3

    def test_creates_parent_directory(self, tmp_path):
        """Creates parent directory if it doesn't exist."""
        from utils import write_event

        nested_path = tmp_path / "deep" / "nested" / "log.jsonl"
        assert not nested_path.parent.exists()

        with patch("utils.AUDIT_LOG_PATH", nested_path):
            write_event("traffic.request")

        assert nested_path.exists()


class TestWriteAuditEvent:
    """Tests for write_audit_event (legacy/compatibility) function."""

    @pytest.fixture
    def temp_log(self, tmp_path):
        """Create a temporary log file path."""
        log_path = tmp_path / "audit.jsonl"
        with patch("utils.AUDIT_LOG_PATH", log_path):
            yield log_path

    def test_auto_prefixes_ops(self, temp_log):
        """Events without prefix get ops. prefix."""
        from utils import write_audit_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_audit_event("config_reload", addon="test")

        entry = json.loads(temp_log.read_text().strip())
        assert entry["event"] == "ops.config_reload"

    def test_preserves_existing_prefix(self, temp_log):
        """Events with valid prefix are not double-prefixed."""
        from utils import write_audit_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_audit_event("admin.approve", token="xyz")

        entry = json.loads(temp_log.read_text().strip())
        assert entry["event"] == "admin.approve"  # Not ops.admin.approve

    def test_includes_all_fields(self, temp_log):
        """All kwargs are passed through."""
        from utils import write_audit_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_audit_event("startup", addon="test-addon", version="1.0")

        entry = json.loads(temp_log.read_text().strip())
        assert entry["addon"] == "test-addon"
        assert entry["version"] == "1.0"


class TestValidEventPrefixes:
    """Tests for VALID_EVENT_PREFIXES constant."""

    def test_contains_traffic(self):
        """traffic. prefix is valid."""
        from utils import VALID_EVENT_PREFIXES
        assert "traffic." in VALID_EVENT_PREFIXES

    def test_contains_security(self):
        """security. prefix is valid."""
        from utils import VALID_EVENT_PREFIXES
        assert "security." in VALID_EVENT_PREFIXES

    def test_contains_ops(self):
        """ops. prefix is valid."""
        from utils import VALID_EVENT_PREFIXES
        assert "ops." in VALID_EVENT_PREFIXES

    def test_contains_admin(self):
        """admin. prefix is valid."""
        from utils import VALID_EVENT_PREFIXES
        assert "admin." in VALID_EVENT_PREFIXES

    def test_is_tuple(self):
        """VALID_EVENT_PREFIXES is a tuple (immutable)."""
        from utils import VALID_EVENT_PREFIXES
        assert isinstance(VALID_EVENT_PREFIXES, tuple)


class TestMakeBlockResponse:
    """Tests for make_block_response utility."""

    def test_creates_response(self):
        """Creates valid mitmproxy Response."""
        from utils import make_block_response

        resp = make_block_response(403, {"error": "blocked"}, "test-addon")

        assert resp.status_code == 403
        assert resp.headers["Content-Type"] == "application/json"
        assert resp.headers["X-Blocked-By"] == "test-addon"

    def test_json_body(self):
        """Body is JSON-encoded."""
        from utils import make_block_response

        resp = make_block_response(429, {"error": "rate limited", "wait_ms": 1000}, "rate-limiter")

        body = json.loads(resp.content)
        assert body["error"] == "rate limited"
        assert body["wait_ms"] == 1000

    def test_custom_headers(self):
        """Extra headers are included."""
        from utils import make_block_response

        resp = make_block_response(
            503,
            {"error": "circuit open"},
            "circuit-breaker",
            extra_headers={"Retry-After": "30"},
        )

        assert resp.headers["Retry-After"] == "30"
        assert resp.headers["X-Blocked-By"] == "circuit-breaker"

    def test_various_status_codes(self):
        """Works with different status codes."""
        from utils import make_block_response

        for status in [400, 403, 429, 500, 502, 503]:
            resp = make_block_response(status, {"error": "test"}, "test")
            assert resp.status_code == status


class TestConfigureFileLogging:
    """Tests for configure_file_logging function."""

    def test_creates_log_directory(self, tmp_path):
        """Creates log directory if it doesn't exist."""
        import logging

        from utils import configure_file_logging

        log_path = tmp_path / "logs" / "mitmproxy.log"
        assert not log_path.parent.exists()

        with patch("utils.MITMPROXY_LOG_PATH", log_path):
            # Clear any existing handlers first
            logger = logging.getLogger("safeyolo")
            logger.handlers = []
            configure_file_logging()

        assert log_path.parent.exists()

    def test_adds_rotating_file_handler(self, tmp_path):
        """Adds RotatingFileHandler to safeyolo logger."""
        import logging
        from logging.handlers import RotatingFileHandler

        from utils import configure_file_logging

        log_path = tmp_path / "mitmproxy.log"

        with patch("utils.MITMPROXY_LOG_PATH", log_path):
            logger = logging.getLogger("safeyolo")
            logger.handlers = []
            configure_file_logging()

        handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
        assert len(handlers) == 1

    def test_idempotent(self, tmp_path):
        """Calling twice doesn't add duplicate handlers."""
        import logging
        from logging.handlers import RotatingFileHandler

        from utils import configure_file_logging

        log_path = tmp_path / "mitmproxy.log"

        with patch("utils.MITMPROXY_LOG_PATH", log_path):
            logger = logging.getLogger("safeyolo")
            logger.handlers = []
            configure_file_logging()
            configure_file_logging()  # Second call

        handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
        assert len(handlers) == 1

    def test_raises_on_permission_error(self, tmp_path):
        """Raises RuntimeError if can't create log directory."""
        from utils import configure_file_logging

        # Path that can't be created (root-level)
        log_path = tmp_path / "nonexistent" / "mitmproxy.log"

        with patch("utils.MITMPROXY_LOG_PATH", log_path):
            with patch("pathlib.Path.mkdir", side_effect=PermissionError("denied")):
                import logging
                logger = logging.getLogger("safeyolo")
                logger.handlers = []

                with pytest.raises(RuntimeError, match="FATAL.*cannot run without logging"):
                    configure_file_logging()


class TestFileLoggingAddon:
    """Tests for FileLoggingAddon mitmproxy addon."""

    def test_running_calls_configure(self, tmp_path):
        """running() hook calls configure_file_logging."""
        from utils import FileLoggingAddon

        addon = FileLoggingAddon()

        with patch("utils.configure_file_logging") as mock_configure:
            addon.running()

        mock_configure.assert_called_once()

    def test_addon_can_be_instantiated(self):
        """FileLoggingAddon can be instantiated without errors."""
        from utils import FileLoggingAddon

        addon = FileLoggingAddon()
        assert addon is not None
