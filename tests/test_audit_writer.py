"""Tests for addons/audit_writer.py — background JSONL appender."""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

# addons/ is loaded by mitmproxy as a sys.path entry, so we replicate that
# for tests — same convention as existing addon tests.
_ADDONS_DIR = Path(__file__).resolve().parent.parent / "addons"
sys.path.insert(0, str(_ADDONS_DIR))

from safeyolo.core.audit_writer import AuditAppendError, _AuditWriter  # noqa: E402


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


class TestConfirmedAppend:
    def test_receipt_waits_for_append_and_ordinary_event_stays_async(self, tmp_log):
        entered = threading.Event()
        release = threading.Event()

        def slow_rotate():
            entered.set()
            assert release.wait(timeout=2)

        writer = _AuditWriter(lambda: tmp_log, slow_rotate, max_queue=10)
        writer.put_event({"event": "ordinary"})
        assert entered.wait(timeout=2)
        with ThreadPoolExecutor(max_workers=1) as pool:
            receipt = pool.submit(writer.put_event_confirmed, {"event": "approval"})
            assert not receipt.done()
            assert _read_entries(tmp_log) == []
            release.set()
            receipt.result(timeout=2)
        assert writer.wait_for_drain(timeout_s=2)
        assert _read_entries(tmp_log) == [{"event": "ordinary"}, {"event": "approval"}]

    def test_failed_destination_rejects_receipt_and_same_writer_recovers(self, tmp_log, tmp_path):
        blocked_parent = tmp_path / "not-a-directory"
        blocked_parent.write_text("occupied")
        destination = [blocked_parent / "audit.jsonl"]
        writer = _AuditWriter(lambda: destination[0], lambda: None, max_queue=10)
        with pytest.raises(AuditAppendError, match="append failed"):
            writer.put_event_confirmed({"event": "lost"})
        assert not tmp_log.exists()
        destination[0] = tmp_log
        writer.put_event_confirmed({"event": "restored"})
        assert _read_entries(tmp_log) == [{"event": "restored"}]

    def test_queue_full_and_stopped_reject_confirmed_events(self, tmp_log, monkeypatch):
        writer = _make_writer(tmp_log)
        original_put = writer._queue.put_nowait  # noqa: SLF001 — forced queue failure

        def full(_item):
            raise queue.Full()

        monkeypatch.setattr(writer._queue, "put_nowait", full)  # noqa: SLF001
        with pytest.raises(AuditAppendError, match="queue full"):
            writer.put_event_confirmed({"event": "unaccepted"})
        assert writer.pending_count() == 0
        monkeypatch.setattr(writer._queue, "put_nowait", original_put)  # noqa: SLF001
        writer.put_event_confirmed({"event": "accepted"})
        writer._shutdown()  # noqa: SLF001 — test post-shutdown rejection
        with pytest.raises(AuditAppendError, match="stopped"):
            writer.put_event_confirmed({"event": "too-late"})
        assert _read_entries(tmp_log) == [{"event": "accepted"}]

    def test_bounded_wait_never_claims_unconfirmed_append(self, tmp_log):
        entered = threading.Event()
        release = threading.Event()

        def slow_rotate():
            entered.set()
            assert release.wait(timeout=2)

        writer = _AuditWriter(lambda: tmp_log, slow_rotate, max_queue=10)
        try:
            with pytest.raises(AuditAppendError, match="timed out"):
                writer.put_event_confirmed({"event": "slow"}, timeout_s=0.05)
            assert entered.is_set() and not tmp_log.exists()
        finally:
            release.set()
        assert writer.wait_for_drain(timeout_s=2)

    def test_full_shutdown_queue_rejects_discarded_receipt(self, tmp_log):
        entered = threading.Event()
        release = threading.Event()

        def slow_rotate():
            entered.set()
            assert release.wait(timeout=2)

        writer = _AuditWriter(lambda: tmp_log, slow_rotate, max_queue=1, flush_timeout_s=0.05)
        writer.put_event({"event": "active"})
        assert entered.wait(timeout=2)
        with ThreadPoolExecutor(max_workers=1) as pool:
            receipt = pool.submit(writer.put_event_confirmed, {"event": "discarded"}, timeout_s=1)
            deadline = time.monotonic() + 2
            while writer.pending_count() < 2:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            writer._shutdown()  # noqa: SLF001 — force full-queue shutdown branch
            with pytest.raises(AuditAppendError, match="append failed"):
                receipt.result(timeout=2)
        release.set()
        assert writer.wait_for_drain(timeout_s=2)
        assert _read_entries(tmp_log) == [{"event": "active"}]


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


class TestInflightSynchronization:
    """Issue #213 second-pass review: `pending_count` and `wait_for_drain`
    must account for events the writer has dequeued but not yet flushed,
    not just events still in the queue. A `queue.empty()` heuristic misses
    the mid-flush window and lets `/explain` return a false empty.
    """

    def test_pending_count_covers_mid_flush(self, tmp_log, monkeypatch):
        """While the writer thread is stalled inside `_flush`, pending_count
        must still reflect the batch — the queue is empty but the events
        aren't persisted yet.
        """
        import threading

        writer = _make_writer(tmp_log, max_queue=10)

        # Gate the flush so we can observe the mid-flush state deterministically.
        enter_flush = threading.Event()
        release_flush = threading.Event()
        original_flush = writer._flush  # noqa: SLF001

        def slow_flush(batch):
            if batch:
                enter_flush.set()
                release_flush.wait(timeout=2.0)
            original_flush(batch)

        monkeypatch.setattr(writer, "_flush", slow_flush)

        writer.put_event({"event": "in_flight"})
        assert enter_flush.wait(timeout=2.0), "writer never entered flush"

        # Queue is empty (item was dequeued), but the flush hasn't finished.
        assert writer._queue.empty()  # noqa: SLF001
        # Old heuristic would have said "drained". The new counter reflects
        # what actually happened: the event is not yet on disk.
        assert writer.pending_count() == 1, (
            "pending_count regressed to a queue.empty() heuristic — a "
            "mid-flush event was reported as drained"
        )

        release_flush.set()
        assert writer.wait_for_drain(timeout_s=2.0)
        assert writer.pending_count() == 0
        assert _read_entries(tmp_log) == [{"event": "in_flight"}]

    def test_wait_for_drain_waits_for_flush_to_complete(self, tmp_log, monkeypatch):
        """wait_for_drain must not return True while a batch is mid-flush,
        even if the queue is empty. This is the direct regression against
        the false-empty `/explain` behaviour issue #213 flagged.
        """
        import threading

        writer = _make_writer(tmp_log, max_queue=10)
        enter_flush = threading.Event()
        release_flush = threading.Event()
        original_flush = writer._flush  # noqa: SLF001

        def slow_flush(batch):
            if batch:
                enter_flush.set()
                release_flush.wait(timeout=2.0)
            original_flush(batch)

        monkeypatch.setattr(writer, "_flush", slow_flush)

        writer.put_event({"event": "must_wait"})
        assert enter_flush.wait(timeout=2.0)

        # Short drain call while the flush is blocked — must time out, NOT
        # return True.
        assert writer.wait_for_drain(timeout_s=0.1) is False

        release_flush.set()
        assert writer.wait_for_drain(timeout_s=2.0)

    def test_full_queue_releases_inflight(self, tmp_path, monkeypatch):
        """When the queue is full and `put_event` drops the entry, the
        in-flight counter must not leak — otherwise every dropped event
        would permanently inflate pending_count.
        """
        writer = _make_writer(tmp_path / "full.jsonl", max_queue=1)

        # Stop the writer thread from consuming so `put_event` will see
        # the queue as full on the second call.
        import queue as _q
        original_put = writer._queue.put_nowait
        raise_full = {"n": 0}

        def maybe_full(item):
            raise_full["n"] += 1
            if raise_full["n"] > 1:
                raise _q.Full()
            return original_put(item)

        monkeypatch.setattr(writer._queue, "put_nowait", maybe_full)

        writer.put_event({"event": "first"})
        assert writer.pending_count() >= 0  # may have been flushed already

        # This one is dropped by the full queue.
        writer.put_event({"event": "dropped"})
        assert writer.dropped_count == 1

        # Give the first event time to flush, then assert no leak.
        assert writer.wait_for_drain(timeout_s=2.0)
        assert writer.pending_count() == 0, (
            "dropped event leaked an in-flight reservation"
        )
