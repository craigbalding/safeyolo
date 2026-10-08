"""Async audit event writer — drains a queue into the JSONL audit log.

Each ordinary `write_event()` call in `utils.py` used to do three blocking things
inside a mitmproxy hook: build the entry, open the log file, append.
File I/O on every request/response hook is the classic hot-path
regression. This module moves the file write off the hook thread
onto a single dedicated background thread. Callers enqueue with
`put_event()` (one `queue.put_nowait` call, non-blocking), the writer
thread batches whatever is currently queued into a single `write()`
syscall, and rotation still runs — just on the writer, not the caller.
Approval requests that promise operator review use `put_event_confirmed()`:
the caller waits for that batch's append and close before claiming success.

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


class AuditAppendError(RuntimeError):
    """An approval event was not confirmed in the operator audit file."""


class _ConfirmedEvent:
    def __init__(self, entry: dict) -> None:
        self.entry = entry
        self.done = threading.Event()
        self.error: Exception | None = None


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
        self._stopped = False
        self._start_lock = threading.Lock()
        self._dropped = 0
        self._dropped_lock = threading.Lock()
        # In-flight accounting for `wait_for_drain` / `pending_count`. Covers
        # both queued-but-not-yet-dequeued events AND events the writer thread
        # has already dequeued but not yet flushed to disk. Incremented on
        # successful enqueue, decremented after `_flush` returns (in a
        # finally block so failed flushes still drop the count — the events
        # were echoed to stderr, they aren't waiting to be persisted).
        # `/explain` freshness (issue #213) relies on this to avoid the race
        # where queue.empty() reads as drained while a batch is mid-flush.
        self._inflight = 0
        self._inflight_cv = threading.Condition()

    # ---- producer side (called from addon hooks) --------------------------
    def put_event(self, entry: dict) -> None:
        """Non-blocking enqueue. Drops + warns if the queue is full."""
        self._enqueue(entry, confirmed=False)

    def put_event_confirmed(self, entry: dict, *, timeout_s: float | None = None) -> None:
        """Return only after append/close, not merely after queue admission.

        This does not fsync the file or promise survival of a process or host
        crash. A timeout fails closed even if the writer later appends the row.
        """
        item = _ConfirmedEvent(entry)
        self._enqueue(item, confirmed=True)
        if not item.done.wait(self._flush_timeout_s if timeout_s is None else timeout_s):
            raise AuditAppendError("audit append acknowledgement timed out")
        if item.error is not None:
            raise AuditAppendError("audit append failed") from item.error

    def _enqueue(self, item: dict | _ConfirmedEvent, *, confirmed: bool) -> None:
        self._ensure_started()
        # Reserve the in-flight slot BEFORE the put so a reader that
        # observes queue.empty() cannot conclude "drained" while we're
        # still in the middle of enqueuing.
        with self._start_lock:
            if self._stopped:
                reason = "stopped"
            else:
                with self._inflight_cv:
                    self._inflight += 1
                try:
                    self._queue.put_nowait(item)
                    return
                except queue.Full:
                    with self._inflight_cv:
                        self._inflight -= 1
                        self._inflight_cv.notify_all()
                    reason = f"queue full (maxsize={self._queue.maxsize})"
        with self._dropped_lock:
            self._dropped += 1
            total = self._dropped
        print(
            f"[safeyolo] audit writer {reason}; dropped event (total_dropped={total})",
            file=sys.stderr,
            flush=True,
        )
        if confirmed:
            raise AuditAppendError(f"audit writer {reason}")

    @property
    def dropped_count(self) -> int:
        with self._dropped_lock:
            return self._dropped

    def wait_for_drain(self, timeout_s: float = 2.0) -> bool:
        """Block until every enqueued event has been flushed. Returns False
        on timeout.

        Uses the in-flight counter (incremented on `put_event`, decremented
        after `_flush` returns) rather than `queue.empty()`, so a batch
        currently being flushed still counts as pending. Fixes the race
        where a reader saw an empty queue between the writer dequeuing a
        batch and finishing the file write — the reason `/explain` used to
        return a false empty (issue #213 second-pass review).
        """
        import time
        deadline = time.monotonic() + timeout_s
        with self._inflight_cv:
            while self._inflight > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                # Condition.wait releases the lock while blocked; the writer
                # thread will notify_all after the flush finishes.
                self._inflight_cv.wait(timeout=remaining)
            return True

    def pending_count(self) -> int:
        """Events queued OR mid-flush that haven't hit disk yet.

        Union of "in the queue" and "the writer dequeued them but hasn't
        finished writing". Callers use this to decide whether an empty
        `/explain` scan is genuinely empty or just early (issue #213).
        """
        with self._inflight_cv:
            return self._inflight

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
        batch: list[dict | _ConfirmedEvent] = []
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

    def _drain_pending(self, batch: list[dict | _ConfirmedEvent]) -> None:
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                return

    def _flush(self, batch: list[dict | _ConfirmedEvent]) -> None:
        if not batch:
            return
        error: Exception | None = None
        entries = [item.entry if isinstance(item, _ConfirmedEvent) else item for item in batch]
        try:
            path = self._path_provider()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate()
            lines = "".join(json.dumps(entry) + "\n" for entry in entries)
            with open(path, "a") as f:
                f.write(lines)
        except Exception as exc:  # noqa: BLE001 — stderr fallback is the point
            error = exc
            print(
                f"[safeyolo] audit writer flush failed "
                f"({len(batch)} entries): {type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            for entry in entries:
                print(f"[safeyolo] Event: {json.dumps(entry)}", file=sys.stderr, flush=True)
        finally:
            for item in batch:
                if isinstance(item, _ConfirmedEvent):
                    item.error = error
                    item.done.set()
            # Release the in-flight reservations these events held. Runs on
            # both success and stderr-fallback paths so `wait_for_drain`
            # doesn't wedge on a persistent flush failure — the events are
            # no longer waiting to be persisted regardless.
            with self._inflight_cv:
                self._inflight -= len(batch)
                self._inflight_cv.notify_all()

    def _shutdown(self) -> None:
        with self._start_lock:
            if not self._started or self._thread is None or self._stopped:
                return
            self._stopped = True
        try:
            self._queue.put(self._SHUTDOWN, timeout=self._flush_timeout_s)
        except queue.Full:
            # Writer is wedged or the queue is overflowing — last-ditch
            # dump of whatever is visible so nothing is silently dropped.
            remaining: list[dict | _ConfirmedEvent] = []
            try:
                while True:
                    remaining.append(self._queue.get_nowait())
            except queue.Empty:
                pass
            for item in remaining:
                entry = item.entry if isinstance(item, _ConfirmedEvent) else item
                print(f"[safeyolo] Event (shutdown): {json.dumps(entry)}", file=sys.stderr, flush=True)
                if isinstance(item, _ConfirmedEvent):
                    item.error = AuditAppendError("audit writer stopped before append")
                    item.done.set()
            with self._inflight_cv:
                self._inflight -= len(remaining)
                self._inflight_cv.notify_all()
            self._queue.put_nowait(self._SHUTDOWN)
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


def put_event_confirmed(entry: dict) -> None:
    """Wait for the canonical audit append before claiming approval submission."""
    get_writer().put_event_confirmed(entry)


# No mitmproxy addon here — this module is pure infrastructure, loaded
# by `utils.write_event`. Declaring an empty addons list makes the
# intent explicit for anyone tempted to wire it up with `-s`.
addons: list = []
