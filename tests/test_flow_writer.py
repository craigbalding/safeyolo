"""Tests for addons/flow_writer.py — async wrapper around FlowStore."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

_ADDONS_DIR = Path(__file__).resolve().parent.parent / "addons"
sys.path.insert(0, str(_ADDONS_DIR))

from flow_writer import _FlowWriter  # noqa: E402


def _make_store() -> MagicMock:
    """Stub FlowStore with a record_flow that succeeds by default."""
    store = MagicMock()
    store.record_flow.return_value = 1
    return store


def _wait_for_records(store: MagicMock, expected: int, timeout_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if store.record_flow.call_count >= expected:
            return
        time.sleep(0.02)
    raise AssertionError(
        f"timed out: expected {expected} record_flow calls, got {store.record_flow.call_count}"
    )


class TestPutRecord:
    def test_single_record_forwarded_to_store(self):
        store = _make_store()
        writer = _FlowWriter(store=store, max_queue=10)
        writer.put_record({"request_id": "r1"})
        _wait_for_records(store, 1)
        store.record_flow.assert_called_once_with({"request_id": "r1"})

    def test_many_records_preserved_in_order(self):
        store = _make_store()
        writer = _FlowWriter(store=store, max_queue=100)
        for i in range(30):
            writer.put_record({"request_id": f"r{i}"})
        _wait_for_records(store, 30)
        # Single producer -> monotonic order is the contract (same as
        # audit_writer's ordering guarantee).
        passed = [c.args[0]["request_id"] for c in store.record_flow.call_args_list]
        assert passed == [f"r{i}" for i in range(30)]

    def test_lazy_thread_start_until_first_put(self):
        store = _make_store()
        writer = _FlowWriter(store=store, max_queue=10)
        assert writer._thread is None
        assert not writer._started
        writer.put_record({"request_id": "r"})
        assert writer._started
        assert writer._thread is not None


class TestQueueFullDropping:
    def test_overflow_drops_and_counts(self, capsys):
        store = _make_store()
        # Block the writer on store.record_flow so the queue can fill.
        release = threading.Event()
        store.record_flow.side_effect = lambda r: release.wait(timeout=5)
        writer = _FlowWriter(store=store, max_queue=2)

        for i in range(10):
            writer.put_record({"request_id": f"r{i}"})

        assert writer.dropped_queue_full >= 1
        err = capsys.readouterr().err
        assert "flow writer queue full" in err
        # Unblock writer so shutdown doesn't hang.
        release.set()


class TestWriteErrors:
    def test_error_in_record_flow_drops_and_increments(self, caplog):
        store = _make_store()
        store.record_flow.side_effect = RuntimeError("disk full")
        writer = _FlowWriter(store=store, max_queue=10)

        writer.put_record({"request_id": "r1"})
        # Wait for the writer to process + log.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and writer.dropped_on_error == 0:
            time.sleep(0.01)

        assert writer.dropped_on_error == 1
        assert "flow writer failed to record" in caplog.text

    def test_subsequent_records_still_processed_after_error(self):
        """One broken record shouldn't wedge the writer thread."""
        store = _make_store()
        calls = {"n": 0}

        def sometimes_fail(record):
            calls["n"] += 1
            if record["request_id"] == "bad":
                raise ValueError("nope")

        store.record_flow.side_effect = sometimes_fail
        writer = _FlowWriter(store=store, max_queue=10)

        writer.put_record({"request_id": "r1"})
        writer.put_record({"request_id": "bad"})
        writer.put_record({"request_id": "r2"})

        # 3 attempts total, one recorded as an on-error drop.
        _wait_for_records(store, 3)
        assert writer.dropped_on_error == 1


class TestWaitForDrain:
    def test_returns_true_when_queue_empty(self):
        store = _make_store()
        writer = _FlowWriter(store=store, max_queue=10)
        writer.put_record({"request_id": "r"})
        assert writer.wait_for_drain(timeout_s=2.0) is True
        store.record_flow.assert_called_once()

    def test_returns_false_when_blocked(self):
        store = _make_store()
        store.record_flow.side_effect = lambda r: time.sleep(5)
        writer = _FlowWriter(store=store, max_queue=10)
        writer.put_record({"request_id": "r"})
        # Give the writer thread a beat to pick the item up.
        time.sleep(0.05)
        # Queue is empty (writer took the item) but record is still in
        # flight — drain returns True in that case because our helper
        # checks the queue, not the writer task. Push another record
        # so the queue stays non-empty.
        writer.put_record({"request_id": "r2"})
        assert writer.wait_for_drain(timeout_s=0.3) is False


class TestShutdown:
    def test_shutdown_drains_pending(self):
        store = _make_store()
        writer = _FlowWriter(store=store, max_queue=100)
        for i in range(20):
            writer.put_record({"request_id": f"r{i}"})
        writer._shutdown()  # noqa: SLF001
        assert store.record_flow.call_count == 20


class TestInstallHelpers:
    def test_install_sets_module_singleton(self):
        import flow_writer as fw
        store = _make_store()
        writer = fw.install(store)
        assert fw.get_writer() is writer
        assert writer._store is store

    def test_put_record_without_install_warns_and_drops(self, caplog):
        import flow_writer as fw
        # Reset module singleton so we can hit the uninstalled path.
        fw._writer = None
        fw.put_record({"request_id": "r"})
        assert "called before install" in caplog.text
