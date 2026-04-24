"""Async audit event writer — drains a queue into the JSONL audit log.

Each `write_event()` call in `utils.py` used to do three blocking things
inside a mitmproxy hook: build the entry, open the log file, append.
File I/O on every request/response hook is the classic hot-path
regression. This module moves the file write off the hook thread
onto a single dedicated background thread. Callers enqueue with
`put_event()` (one `queue.put_nowait` call, non-blocking), the writer
thread batches whatever is currently queued into a single `write()`
syscall, and rotation still runs — just on the writer, not the caller.

Why a thread and not asyncio: mitmproxy addon hooks are synchronous
(`def request(self, flow)` etc.). Calling into an `asyncio.Queue`
from a sync hook requires `run_coroutine_threadsafe` + a reference
to the event loop, which we'd have to acquire carefully. A stdlib
`queue.Queue` plus a thread is equivalent throughput here and
simpler.

Failure modes, in order of how they surface:

1. Queue is full (producer outpacing writer): `put_event` drops the
   entry, bumps a counter, and emits a one-line warning to stderr.
2. Writer's file append fails: the batch is echoed to stderr as a
   last-ditch record so audit events are never silently lost.
3. Process exits: `atexit` hook enqueues a shutdown sentinel and
   waits up to 5 s for the writer to drain. If the queue was large
   enough that 5 s is insufficient, the remaining entries are
   unavoidably dropped — tune SAFEYOLO_AUDIT_QUEUE_MAX down if this
   matters in your deployment.
"""
from __future__ import annotations

import atexit
import json
import os
import queue
import sys
import threading
from collections.abc import Callable
from pathlib import Path


class _AuditWriter:
    """Single-threaded JSONL appender behind a bounded queue."""

    _SHUTDOWN = object()

    def __init__(
        self,
        path_provider: Callable[[], Path],
        rotate: Callable[[], None],
        max_queue: int,
        flush_timeout_s: float = 5.0,
    ) -> None:
        # Path is resolved on each flush so tests that monkey-patch
        # `utils.AUDIT_LOG_PATH` at setUp see the new target. Production
        # passes a constant lambda; same code path, zero overhead.
        self._path_provider = path_provider
        self._rotate = rotate
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._flush_timeout_s = flush_timeout_s
        self._thread: threading.Thread | None = None
        self._started = False
        self._start_lock = threading.Lock()
        self._dropped = 0
        self._dropped_lock = threading.Lock()

    # ---- producer side (called from addon hooks) --------------------------
    def put_event(self, entry: dict) -> None:
        """Non-blocking enqueue. Drops + warns if the queue is full."""
        self._ensure_started()
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            with self._dropped_lock:
                self._dropped += 1
                total = self._dropped
            # One-liner to stderr; keeps debugging trivially grep-able.
            print(
                f"[safeyolo] audit writer queue full (maxsize={self._queue.maxsize}); "
                f"dropped event (total_dropped={total})",
                file=sys.stderr,
                flush=True,
            )

    @property
    def dropped_count(self) -> int:
        with self._dropped_lock:
            return self._dropped

    def wait_for_drain(self, timeout_s: float = 2.0) -> bool:
        """Block until the queue is empty. Returns False on timeout.

        Test helper only. Production doesn't need this — enqueue is
        fire-and-forget, and shutdown flushes via atexit. Tests that
        assert on log-file contents after a `write_event` call it to
        avoid racing the writer thread.
        """
        import time
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._queue.empty():
                # Empty queue + no one in _flush = fully drained.
                # We can't observe "in _flush" directly, so sleep one
                # writer-loop tick to cover the tail.
                time.sleep(0.02)
                if self._queue.empty():
                    return True
            time.sleep(0.01)
        return False

    def _ensure_started(self) -> None:
        # Deferred start so import time stays cheap and tests can
        # instantiate _AuditWriter without a background thread firing.
        if self._started:
            return
        with self._start_lock:
            if self._started:
                return
            self._thread = threading.Thread(
                target=self._run,
                name="safeyolo.audit-writer",
                daemon=True,
            )
            self._thread.start()
            atexit.register(self._shutdown)
            self._started = True

    # ---- consumer side (runs on the background thread) -------------------
    def _run(self) -> None:
        """Drain + flush loop. Exits when the shutdown sentinel arrives."""
        batch: list[dict] = []
        while True:
            # Block for the first item; drain everything else nonblocking.
            first = self._queue.get()
            if first is self._SHUTDOWN:
                return
            batch.append(first)
            self._drain_pending(batch)
            if batch and batch[-1] is self._SHUTDOWN:
                batch.pop()
                self._flush(batch)
                return
            self._flush(batch)
            batch.clear()

    def _drain_pending(self, batch: list[dict]) -> None:
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                return

    def _flush(self, batch: list[dict]) -> None:
        if not batch:
            return
        try:
            path = self._path_provider()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate()
            lines = "".join(json.dumps(entry) + "\n" for entry in batch)
            with open(path, "a") as f:
                f.write(lines)
        except Exception as exc:  # noqa: BLE001 — stderr fallback is the point
            print(
                f"[safeyolo] audit writer flush failed "
                f"({len(batch)} entries): {type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            for entry in batch:
                print(f"[safeyolo] Event: {json.dumps(entry)}", file=sys.stderr, flush=True)

    def _shutdown(self) -> None:
        if not self._started or self._thread is None:
            return
        try:
            self._queue.put(self._SHUTDOWN, timeout=self._flush_timeout_s)
        except queue.Full:
            # Writer is wedged or the queue is overflowing — last-ditch
            # dump of whatever is visible so nothing is silently dropped.
            remaining: list[dict] = []
            try:
                while True:
                    remaining.append(self._queue.get_nowait())
            except queue.Empty:
                pass
            for entry in remaining:
                print(f"[safeyolo] Event (shutdown): {json.dumps(entry)}", file=sys.stderr, flush=True)
            return
        self._thread.join(timeout=self._flush_timeout_s)


# Module-level singleton. Construction is cheap — the thread starts on
# the first enqueued event, not on import.
def _default_queue_max() -> int:
    try:
        return int(os.environ.get("SAFEYOLO_AUDIT_QUEUE_MAX", "10000"))
    except ValueError:
        return 10000


_writer: _AuditWriter | None = None
_writer_lock = threading.Lock()


def get_writer() -> _AuditWriter:
    """Return the module-level writer, constructing it on first use.

    Lazy construction lets callers mutate `AUDIT_LOG_PATH` (e.g. tests
    setting SAFEYOLO_LOG_PATH before the first `write_event`) without
    the writer having baked in a path at import time.
    """
    global _writer
    if _writer is not None:
        return _writer
    with _writer_lock:
        if _writer is not None:
            return _writer
        # Local import — `utils` imports `audit_writer`, so the reverse
        # must be deferred to avoid a circular import at module load.
        import safeyolo.core.utils as utils
        _writer = _AuditWriter(
            # Read attribute live on every flush so tests that
            # `monkeypatch.setattr("utils.AUDIT_LOG_PATH", tmp_path)`
            # see the new target without rebuilding the singleton.
            path_provider=lambda: utils.AUDIT_LOG_PATH,
            rotate=utils._rotate_jsonl_if_needed,
            max_queue=_default_queue_max(),
        )
        return _writer


def put_event(entry: dict) -> None:
    """Enqueue an already-built audit entry for background write."""
    get_writer().put_event(entry)


# No mitmproxy addon here — this module is pure infrastructure, loaded
# by `utils.write_event`. Declaring an empty addons list makes the
# intent explicit for anyone tempted to wire it up with `-s`.
addons: list = []
