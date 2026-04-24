"""Tests for addons/audit_writer.py — background JSONL appender."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

# addons/ is loaded by mitmproxy as a sys.path entry, so we replicate that
# for tests — same convention as existing addon tests.
_ADDONS_DIR = Path(__file__).resolve().parent.parent / "addons"
sys.path.insert(0, str(_ADDONS_DIR))

from safeyolo.core.audit_writer import _AuditWriter  # noqa: E402


@pytest.fixture
def tmp_log(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


def _make_writer(log_path: Path, max_queue: int = 100) -> _AuditWriter:
    return _AuditWriter(
        path_provider=lambda: log_path,
        rotate=lambda: None,  # no rotation in unit tests
        max_queue=max_queue,
        flush_timeout_s=2.0,
    )


def _read_entries(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line]


def _wait_for_entries(log_path: Path, expected: int, timeout_s: float = 2.0) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        entries = _read_entries(log_path)
        if len(entries) >= expected:
            return entries
        time.sleep(0.02)
    raise AssertionError(
        f"timed out waiting for {expected} entries in {log_path}; got {_read_entries(log_path)!r}"
    )


class TestHappyPath:
    def test_single_event_written(self, tmp_log):
        writer = _make_writer(tmp_log)
        writer.put_event({"event": "test.one", "n": 1})
        entries = _wait_for_entries(tmp_log, 1)
        assert entries == [{"event": "test.one", "n": 1}]

    def test_many_events_preserved_in_order(self, tmp_log):
        writer = _make_writer(tmp_log)
        for i in range(50):
            writer.put_event({"event": "test.order", "n": i})
        entries = _wait_for_entries(tmp_log, 50)
        # Single producer -> monotonic order is the contract.
        assert [e["n"] for e in entries] == list(range(50))


class TestBatching:
    def test_enqueued_bursts_drain_in_one_flush(self, tmp_log):
        """`_run` drains the queue nonblocking after the first get, so
        a burst of N produced back-to-back coalesces into a single
        `write()` syscall. Not something to assert via count-syscalls,
        but we can at least confirm the writer copes with larger bursts
        than the OS pipe buffer."""
        writer = _make_writer(tmp_log, max_queue=500)
        for i in range(500):
            writer.put_event({"event": "burst", "n": i})
        entries = _wait_for_entries(tmp_log, 500, timeout_s=5.0)
        assert len(entries) == 500


class TestOverflow:
    def test_full_queue_drops_and_counts(self, tmp_log, capsys):
        # Tiny queue + no writer progress = forced overflow.
        writer = _make_writer(tmp_log, max_queue=2)
        # Block the writer thread by using a rotate callback that sleeps
        # so the queue fills before we start draining.
        start_gate = [True]

        def slow_rotate():
            while start_gate[0]:
                time.sleep(0.01)

        writer._rotate = slow_rotate  # noqa: SLF001 — deliberate test hook
        for i in range(10):
            writer.put_event({"event": "overflow", "n": i})
        # At least some must have been dropped — the queue cap is 2.
        assert writer.dropped_count >= 1
        err = capsys.readouterr().err
        assert "audit writer queue full" in err
        # Unblock so shutdown doesn't hang.
        start_gate[0] = False


class TestFlushFailure:
    def test_flush_error_falls_back_to_stderr(self, tmp_log, capsys):
        bad_path = tmp_log.parent / "nonexistent" / "deep" / "audit.jsonl"
        writer = _AuditWriter(
            path_provider=lambda: bad_path,
            # Force a write error by short-circuiting `_flush` in the
            # `try` block via a raising rotate hook. `_flush`'s stderr
            # fallback then echoes the batch.
            rotate=lambda: (_ for _ in ()).throw(RuntimeError("synthetic")),
            max_queue=10,
            flush_timeout_s=2.0,
        )
        writer.put_event({"event": "failure", "n": 1})
        # Give the writer thread a moment to hit the error branch.
        time.sleep(0.3)
        err = capsys.readouterr().err
        assert "audit writer flush failed" in err
        assert "synthetic" in err
        # The event itself is echoed as a last-ditch record.
        assert "\"event\": \"failure\"" in err


class TestShutdown:
    def test_shutdown_drains_pending(self, tmp_path):
        log_path = tmp_path / "shutdown.jsonl"
        writer = _make_writer(log_path, max_queue=100)
        for i in range(20):
            writer.put_event({"event": "shutdown", "n": i})
        writer._shutdown()  # noqa: SLF001 — explicit drain in test
        entries = _read_entries(log_path)
        assert len(entries) == 20

    def test_lazy_start_no_thread_until_first_put(self, tmp_log):
        writer = _make_writer(tmp_log)
        assert writer._thread is None  # noqa: SLF001
        assert not writer._started  # noqa: SLF001
        writer.put_event({"event": "start"})
        assert writer._started  # noqa: SLF001
        assert writer._thread is not None  # noqa: SLF001
