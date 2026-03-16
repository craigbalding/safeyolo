"""Tests for CLI event logging."""

import json

from safeyolo.events import write_event


class TestWriteEvent:
    """Tests for CLI write_event function."""

    def test_writes_valid_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event("agent.started", agent="myproject")

        log_path = tmp_path / "safeyolo.jsonl"
        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "agent.started"
        assert entry["agent"] == "myproject"
        assert "ts" in entry

    def test_appends_multiple_events(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event("agent.started", agent="a")
        write_event("agent.stopped", agent="a", exit_code=0)

        log_path = tmp_path / "safeyolo.jsonl"
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["event"] == "agent.started"
        assert json.loads(lines[1])["event"] == "agent.stopped"
        assert json.loads(lines[1])["exit_code"] == 0

    def test_creates_logs_dir(self, tmp_path, monkeypatch):
        logs_dir = tmp_path / "nested" / "logs"
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs_dir))
        write_event("agent.added", agent="test", template="claude-code")

        assert (logs_dir / "safeyolo.jsonl").exists()

    def test_includes_all_fields(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        write_event(
            "agent.config_changed",
            agent="boris",
            changes=["mounts", "ports"],
        )

        entry = json.loads((tmp_path / "safeyolo.jsonl").read_text().strip())
        assert entry["agent"] == "boris"
        assert entry["changes"] == ["mounts", "ports"]

    def test_survives_write_failure(self, tmp_path, monkeypatch, capsys):
        """write_event prints to stderr on failure, doesn't raise."""
        # Point to a dir that exists but make the file unwritable
        log_file = tmp_path / "safeyolo.jsonl"
        log_file.touch(mode=0o000)
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path))
        # Should not raise
        write_event("agent.started", agent="test")
        captured = capsys.readouterr()
        assert "Event log write failed" in captured.err
