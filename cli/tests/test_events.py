"""Tests for CLI event logging."""

import json

from safeyolo.events import EventKind, Severity, write_event


class TestWriteEvent:
    """Tests for CLI write_event function."""

    def test_writes_valid_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary="Agent started", agent="myproject")

        log_path = tmp_path / "safeyolo.jsonl"
        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "agent.started"
        assert entry["agent"] == "myproject"
        assert entry["summary"] == "Agent started"
        assert entry["kind"] == "agent"
        assert entry["schema_version"] == 1
        assert "ts" in entry

    def test_appends_multiple_events(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary="Started", agent="a")
        write_event("agent.stopped", kind=EventKind.AGENT, severity=Severity.LOW, summary="Stopped", agent="a", details={"exit_code": 0})

        log_path = tmp_path / "safeyolo.jsonl"
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["event"] == "agent.started"
        assert json.loads(lines[1])["event"] == "agent.stopped"
        assert json.loads(lines[1])["details"]["exit_code"] == 0

    def test_creates_logs_dir(self, tmp_path, monkeypatch):
        logs_dir = tmp_path / "nested" / "logs"
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs_dir))
        write_event("agent.added", kind=EventKind.AGENT, severity=Severity.LOW, summary="Added", agent="test", details={"template": "claude-code"})

        assert (logs_dir / "safeyolo.jsonl").exists()

    def test_includes_all_fields(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event(
            "agent.config_changed",
            kind=EventKind.AGENT,
            severity=Severity.LOW,
            summary="Config changed",
            agent="boris",
            details={"changes": ["mounts", "ports"]},
        )

        entry = json.loads((tmp_path / "safeyolo.jsonl").read_text().strip())
        assert entry["agent"] == "boris"
        assert entry["details"]["changes"] == ["mounts", "ports"]

    def test_survives_write_failure(self, tmp_path, monkeypatch, capsys):
        """write_event prints to stderr on failure, doesn't raise."""
        log_file = tmp_path / "safeyolo.jsonl"
        log_file.touch(mode=0o000)
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary="Started", agent="test")
        captured = capsys.readouterr()
        assert "Event log write failed" in captured.err

    def test_write_event_validation_failure_writes_fallback(self, tmp_path, monkeypatch):
        """When AuditEvent validation fails, a fallback dict is written instead of nothing.

        The fallback must still contain ts, event, kind, severity, summary so
        the operator can diagnose the issue from the log.
        """
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        # kind/event mismatch triggers AuditEvent validation error
        # "traffic.foo" does not match kind=AGENT
        write_event(
            "traffic.mismatch",
            kind=EventKind.AGENT,
            severity=Severity.LOW,
            summary="This will fail validation",
        )
        log_path = tmp_path / "safeyolo.jsonl"
        entry = json.loads(log_path.read_text().strip())
        # Fallback entry has the basic spine fields
        assert entry["event"] == "traffic.mismatch"
        assert entry["kind"] == "agent"
        assert entry["severity"] == "low"
        assert entry["summary"] == "This will fail validation"
        assert "ts" in entry
        # Should NOT have schema_version (that's only on valid AuditEvent)
        assert "schema_version" not in entry

    def test_write_event_creates_parent_directory(self, tmp_path, monkeypatch):
        """write_event creates the logs parent directory if it does not exist."""
        logs_dir = tmp_path / "deep" / "nested" / "logs"
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs_dir))
        write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary="Started", agent="test")
        assert (logs_dir / "safeyolo.jsonl").exists()
        entry = json.loads((logs_dir / "safeyolo.jsonl").read_text().strip())
        assert entry["event"] == "agent.started"
