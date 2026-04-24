"""Async wrapper around FlowStore.record_flow.

`flow_recorder.response` used to call `FlowStore.record_flow(record)`
directly inside the mitmproxy `response` hook. Each call is expensive:
gzip-compressing request and response bodies, extracting previews,
building an FTS index, and doing a SQLite INSERT — all on the hook
thread. Same pattern we fixed for the audit log in #202.

This module moves that work to a dedicated background thread behind a
bounded queue. Producers (the `response`/`error` hooks) call
`put_record(record)` — one `queue.put_nowait` — and return. The writer
thread drains the queue, calls `store.record_flow(record)`, and
handles rotation / retries itself.

Failure modes match the audit writer's:

1. Queue is full (producer outpaces writer — big body compressions
   queued behind a slow disk): `put_record` drops the record, bumps
   a counter, and emits a one-line warning to stderr.
2. Writer's `record_flow` raises: the error is logged at WARNING; the
   record is dropped from the queue. We do *not* echo the record to
   stderr (they can contain request/response bodies — potentially
   large, potentially sensitive). The counter is available via
   `dropped_on_error` for the addon's stats.
3. Process exits: `atexit` hook enqueues a shutdown sentinel and
   waits up to 5 s for the writer to drain before closing the
   FlowStore. Remaining records at that point are lost.

The existing FlowStore uses `sqlite3.connect(..., check_same_thread=False)`
plus an internal `threading.Lock`, so off-thread `record_flow` calls
are already safe — no SQLite layer changes needed.
"""
from __future__ import annotations

import atexit
import logging
import os
import queue
import sys
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid circular-ish import at module load
    from flow_store import FlowStore


log = logging.getLogger("safeyolo.flow-writer")


class _FlowWriter:
    """Single background thread draining flow records into a FlowStore."""

    _SHUTDOWN = object()

    def __init__(
        self,
        store: FlowStore,
        max_queue: int,
        flush_timeout_s: float = 5.0,
    ) -> None:
        self._store = store
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._flush_timeout_s = flush_timeout_s
        self._thread: threading.Thread | None = None
        self._started = False
        self._start_lock = threading.Lock()
        self._dropped_queue_full = 0
        self._dropped_on_error = 0
        self._stats_lock = threading.Lock()

    # ---- producer side (called from mitmproxy hooks) ----------------------
    def put_record(self, record: dict) -> None:
        """Non-blocking enqueue. Drops + warns if the queue is full."""
        self._ensure_started()
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._stats_lock:
                self._dropped_queue_full += 1
                total = self._dropped_queue_full
            # One-liner to stderr; body content stays out of the log.
            print(
                f"[safeyolo] flow writer queue full (maxsize={self._queue.maxsize}); "
                f"dropped record (total_dropped={total})",
                file=sys.stderr,
                flush=True,
            )

    @property
    def dropped_queue_full(self) -> int:
        with self._stats_lock:
            return self._dropped_queue_full

    @property
    def dropped_on_error(self) -> int:
        with self._stats_lock:
            return self._dropped_on_error

    def _ensure_started(self) -> None:
        if self._started:
            return
        with self._start_lock:
            if self._started:
                return
            self._thread = threading.Thread(
                target=self._run,
                name="safeyolo.flow-writer",
                daemon=True,
            )
            self._thread.start()
            atexit.register(self._shutdown)
            self._started = True

    # ---- consumer side (runs on the background thread) -------------------
    def _run(self) -> None:
        while True:
            # Block on the first item.
            item = self._queue.get()
            if item is self._SHUTDOWN:
                return
            self._write_one(item)
            # Drain any other queued records without blocking. Keeps
            # throughput high under bursts — each iteration hits
            # `record_flow` only once per record.
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is self._SHUTDOWN:
                    return
                self._write_one(item)

    def _write_one(self, record: dict) -> None:
        try:
            self._store.record_flow(record)
        except Exception as exc:  # noqa: BLE001 — record is dropped, counter bumped
            with self._stats_lock:
                self._dropped_on_error += 1
            log.warning(
                "flow writer failed to record: %s: %s",
                type(exc).__name__,
                exc,
            )

    def wait_for_drain(self, timeout_s: float = 2.0) -> bool:
        """Block until the queue is empty. Returns False on timeout.

        Test helper. Production doesn't call this — enqueue is
        fire-and-forget, and shutdown flushes via `atexit`.
        """
        import time
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._queue.empty():
                time.sleep(0.02)
                if self._queue.empty():
                    return True
            time.sleep(0.01)
        return False

    def _shutdown(self) -> None:
        if not self._started or self._thread is None:
            return
        try:
            self._queue.put(self._SHUTDOWN, timeout=self._flush_timeout_s)
        except queue.Full:
            # Writer is wedged or queue is overflowing — best we can do is
            # note the lost records. Skipping stderr echo (bodies, size).
            return
        self._thread.join(timeout=self._flush_timeout_s)


# Module-level singleton — constructed by `flow_recorder.running()` once
# the FlowStore is initialised.
_writer: _FlowWriter | None = None
_writer_lock = threading.Lock()


def _default_queue_max() -> int:
    try:
        return int(os.environ.get("SAFEYOLO_FLOW_QUEUE_MAX", "500"))
    except ValueError:
        return 500


def install(store: FlowStore) -> _FlowWriter:
    """Wire up the module-level writer around an initialised FlowStore.

    Called from `FlowRecorder.running()` after `store.init_db()`.
    Returns the writer so the caller can surface stats via its own
    `get_stats()` accessor.
    """
    global _writer
    with _writer_lock:
        _writer = _FlowWriter(store=store, max_queue=_default_queue_max())
    return _writer


def put_record(record: dict) -> None:
    """Enqueue a flow record for background write.

    If `install` hasn't been called yet (shouldn't happen in the normal
    addon load order — `running` wires the writer before `response`
    can fire), logs a warning and drops the record.
    """
    if _writer is None:
        log.warning("flow_writer.put_record called before install(); dropped")
        return
    _writer.put_record(record)


def get_writer() -> _FlowWriter | None:
    """Return the installed writer (may be None during startup/tests)."""
    return _writer


# Pure infrastructure — not a mitmproxy addon. Empty addons list makes
# intent explicit for anyone tempted to wire it up with `-s`.
addons: list = []
