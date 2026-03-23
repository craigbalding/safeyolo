"""
Tests for the utils.py logging functions.

Tests write_event() with the new structured audit event signature.
"""

import json
from unittest.mock import patch

import pytest

from audit_schema import Decision, EventKind, Severity


class TestWriteEvent:
    """Tests for write_event function."""

    @pytest.fixture
    def temp_log(self, tmp_path):
        """Create a temporary log file path."""
        log_path = tmp_path / "test.jsonl"
        with patch("utils.AUDIT_LOG_PATH", log_path):
            yield log_path

    def test_writes_valid_json(self, temp_log):
        """write_event outputs valid JSONL with audit envelope."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event(
                "traffic.request",
                kind=EventKind.TRAFFIC,
                severity=Severity.LOW,
                summary="GET example.com/",
                host="example.com",
            )

        lines = temp_log.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "traffic.request"
        assert entry["kind"] == "traffic"
        assert entry["severity"] == "low"
        assert entry["host"] == "example.com"
        assert entry["schema_version"] == 1

    def test_includes_timestamp(self, temp_log):
        """Event includes ISO timestamp."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event(
                "traffic.response",
                kind=EventKind.TRAFFIC,
                severity=Severity.LOW,
                summary="200 OK",
            )

        entry = json.loads(temp_log.read_text().strip())
        assert "ts" in entry
        assert "T" in entry["ts"]

    def test_traffic_prefix_valid(self, temp_log, caplog):
        """traffic.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("traffic.request", kind=EventKind.TRAFFIC, severity=Severity.LOW, summary="test")
            write_event("traffic.response", kind=EventKind.TRAFFIC, severity=Severity.LOW, summary="test")

        assert "doesn't match taxonomy" not in caplog.text

    def test_security_prefix_valid(self, temp_log, caplog):
        """security.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("security.credential_guard", kind=EventKind.SECURITY, severity=Severity.HIGH, summary="test", decision=Decision.DENY)
            write_event("security.network_guard", kind=EventKind.SECURITY, severity=Severity.HIGH, summary="test", decision=Decision.DENY)
            write_event("security.pattern_scanner", kind=EventKind.SECURITY, severity=Severity.MEDIUM, summary="test", decision=Decision.LOG)

        assert "doesn't match taxonomy" not in caplog.text

    def test_ops_prefix_valid(self, temp_log, caplog):
        """ops.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("ops.startup", kind=EventKind.OPS, severity=Severity.LOW, summary="started", addon="test")
            write_event("ops.config_reload", kind=EventKind.OPS, severity=Severity.MEDIUM, summary="reloaded")

        assert "doesn't match taxonomy" not in caplog.text

    def test_admin_prefix_valid(self, temp_log, caplog):
        """admin.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("admin.approval_added", kind=EventKind.ADMIN, severity=Severity.MEDIUM, summary="approved")
            write_event("admin.denial", kind=EventKind.ADMIN, severity=Severity.MEDIUM, summary="denied")
            write_event("admin.mode_change", kind=EventKind.ADMIN, severity=Severity.MEDIUM, summary="changed")

        assert "doesn't match taxonomy" not in caplog.text

    def test_agent_prefix_valid(self, temp_log, caplog):
        """agent.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("agent.added", kind=EventKind.AGENT, severity=Severity.LOW, summary="added", agent="myproject")
            write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary="started", agent="myproject")

        assert "doesn't match taxonomy" not in caplog.text

    def test_gateway_prefix_valid(self, temp_log, caplog):
        """gateway.* events are valid taxonomy."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("gateway.allow", kind=EventKind.GATEWAY, severity=Severity.LOW, summary="injected", decision=Decision.ALLOW)
            write_event("gateway.deny", kind=EventKind.GATEWAY, severity=Severity.HIGH, summary="denied", decision=Decision.DENY)

        assert "doesn't match taxonomy" not in caplog.text

    def test_invalid_prefix_warns(self, temp_log, caplog):
        """Invalid event prefix logs a warning but still writes."""
        import logging

        from utils import write_event

        caplog.set_level(logging.WARNING)

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("invalid_event", kind=EventKind.OPS, severity=Severity.LOW, summary="test")

        assert "doesn't match taxonomy" in caplog.text
        # But event is still written
        entry = json.loads(temp_log.read_text().strip())
        assert entry["event"] == "invalid_event"

    def test_details_in_output(self, temp_log):
        """Details dict is included in the log entry."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event(
                "security.credential_guard",
                kind=EventKind.SECURITY,
                severity=Severity.CRITICAL,
                summary="Credential blocked",
                decision=Decision.DENY,
                request_id="req-abc123",
                addon="credential-guard",
                host="api.openai.com",
                details={
                    "rule": "openai",
                    "fingerprint": "hmac:abc123",
                    "reason": "destination_mismatch",
                },
            )

        entry = json.loads(temp_log.read_text().strip())
        assert entry["request_id"] == "req-abc123"
        assert entry["addon"] == "credential-guard"
        assert entry["decision"] == "deny"
        assert entry["host"] == "api.openai.com"
        assert entry["details"]["rule"] == "openai"
        assert entry["details"]["fingerprint"] == "hmac:abc123"

    def test_multiple_events_append(self, temp_log):
        """Multiple events are appended, not overwritten."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event("traffic.request", kind=EventKind.TRAFFIC, severity=Severity.LOW, summary="1")
            write_event("security.credential_guard", kind=EventKind.SECURITY, severity=Severity.HIGH, summary="2")
            write_event("traffic.response", kind=EventKind.TRAFFIC, severity=Severity.LOW, summary="3")

        lines = temp_log.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_creates_parent_directory(self, tmp_path):
        """Creates parent directory if it doesn't exist."""
        from utils import write_event

        nested_path = tmp_path / "deep" / "nested" / "log.jsonl"
        assert not nested_path.parent.exists()

        with patch("utils.AUDIT_LOG_PATH", nested_path):
            write_event("traffic.request", kind=EventKind.TRAFFIC, severity=Severity.LOW, summary="test")

        assert nested_path.exists()

    def test_none_fields_excluded(self, temp_log):
        """None fields are excluded from output."""
        from utils import write_event

        with patch("utils.AUDIT_LOG_PATH", temp_log):
            write_event(
                "ops.startup",
                kind=EventKind.OPS,
                severity=Severity.LOW,
                summary="started",
                addon="memory-monitor",
            )

        entry = json.loads(temp_log.read_text().strip())
        assert "request_id" not in entry
        assert "agent" not in entry
        assert "decision" not in entry
        assert "host" not in entry
        assert "approval" not in entry


class TestValidEventPrefixes:
    """Tests for VALID_EVENT_PREFIXES constant."""

    def test_contains_traffic(self):
        from utils import VALID_EVENT_PREFIXES
        assert "traffic." in VALID_EVENT_PREFIXES

    def test_contains_security(self):
        from utils import VALID_EVENT_PREFIXES
        assert "security." in VALID_EVENT_PREFIXES

    def test_contains_ops(self):
        from utils import VALID_EVENT_PREFIXES
        assert "ops." in VALID_EVENT_PREFIXES

    def test_contains_admin(self):
        from utils import VALID_EVENT_PREFIXES
        assert "admin." in VALID_EVENT_PREFIXES

    def test_contains_agent(self):
        from utils import VALID_EVENT_PREFIXES
        assert "agent." in VALID_EVENT_PREFIXES

    def test_contains_gateway(self):
        """gateway. prefix replaces broker."""
        from utils import VALID_EVENT_PREFIXES
        assert "gateway." in VALID_EVENT_PREFIXES
        assert "broker." not in VALID_EVENT_PREFIXES

    def test_is_tuple(self):
        from utils import VALID_EVENT_PREFIXES
        assert isinstance(VALID_EVENT_PREFIXES, tuple)


class TestMakeBlockResponse:
    """Tests for make_block_response utility."""

    def test_creates_response(self):
        from utils import make_block_response

        resp = make_block_response(403, {"error": "blocked"}, "test-addon")

        assert resp.status_code == 403
        assert resp.headers["Content-Type"] == "application/json"
        assert resp.headers["X-Blocked-By"] == "test-addon"

    def test_json_body(self):
        from utils import make_block_response

        resp = make_block_response(429, {"error": "rate limited", "wait_ms": 1000}, "rate-limiter")

        body = json.loads(resp.content)
        assert body["error"] == "rate limited"
        assert body["wait_ms"] == 1000

    def test_custom_headers(self):
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
        from utils import make_block_response

        for status in [400, 403, 429, 500, 502, 503]:
            resp = make_block_response(status, {"error": "test"}, "test")
            assert resp.status_code == status


class TestConfigureFileLogging:
    """Tests for configure_file_logging function."""

    def test_creates_log_directory(self, tmp_path):
        import logging

        from utils import configure_file_logging

        log_path = tmp_path / "logs" / "mitmproxy.log"
        assert not log_path.parent.exists()

        with patch("utils.MITMPROXY_LOG_PATH", log_path):
            logger = logging.getLogger("safeyolo")
            logger.handlers = []
            configure_file_logging()

        assert log_path.parent.exists()

    def test_adds_rotating_file_handler(self, tmp_path):
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
        import logging
        from logging.handlers import RotatingFileHandler

        from utils import configure_file_logging

        log_path = tmp_path / "mitmproxy.log"

        with patch("utils.MITMPROXY_LOG_PATH", log_path):
            logger = logging.getLogger("safeyolo")
            logger.handlers = []
            configure_file_logging()
            configure_file_logging()

        handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
        assert len(handlers) == 1

    def test_raises_on_permission_error(self, tmp_path):
        from utils import configure_file_logging

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
        from utils import FileLoggingAddon

        addon = FileLoggingAddon()

        with patch("utils.configure_file_logging") as mock_configure:
            addon.running()

        mock_configure.assert_called_once()

    def test_addon_can_be_instantiated(self):
        from utils import FileLoggingAddon

        addon = FileLoggingAddon()
        assert addon is not None
