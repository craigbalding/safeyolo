"""Optional phase-level timing for `safeyolo agent run`.

Enabled by setting `SAFEYOLO_TIMING=1` in the host environment. On
exit, the CLI prints a breakdown of how long each phase took. When the
env var is unset, every call here is effectively free (two attribute
reads and an append).

Why this exists: real CLI-to-agent-prompt time has contributions from
Python startup, network setup, helper spawn, VZ restore, guest-side
per-run, and the agent's own init. Without per-phase numbers, every
optimization discussion is a guess. With them, we can target the
actually-expensive phase.

The companion timestamps on the Swift helper's `[vm state]` lines
(VMRunner prints epoch timestamps when VZ state transitions) and on
the guest-init phase markers (echoed to /dev/console with timestamps)
give the complete picture. Host and guest clocks may disagree on
restore because the guest clock was frozen during the save/restore
round-trip; compare deltas, not absolutes, across that boundary.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

_ENABLED = os.environ.get("SAFEYOLO_TIMING") == "1"

# Recorded at import time — captures how long Python startup and
# safeyolo module imports took once we reach any other point.
_MODULE_LOAD_AT = time.monotonic()


@dataclass
class Phase:
    name: str
    started_at: float
    ended_at: Optional[float] = None

    @property
    def duration(self) -> Optional[float]:
        if self.ended_at is None:
            return None
        return self.ended_at - self.started_at


@dataclass
class Recorder:
    phases: list[Phase] = field(default_factory=list)
    _active: Optional[Phase] = None

    def enter(self, name: str) -> None:
        """Start a phase. If another phase is active it is closed off
        (phases don't nest — adjacent boundaries are what matter here)."""
        if not _ENABLED:
            return
        now = time.monotonic()
        if self._active is not None:
            self._active.ended_at = now
        p = Phase(name=name, started_at=now)
        self.phases.append(p)
        self._active = p

    def mark(self, name: str) -> None:
        """Close the current phase at 'now' and record a zero-length
        boundary marker. Useful for single-instant events."""
        if not _ENABLED:
            return
        now = time.monotonic()
        if self._active is not None:
            self._active.ended_at = now
        self.phases.append(Phase(name=name, started_at=now, ended_at=now))
        self._active = None

    def finish(self) -> None:
        if not _ENABLED:
            return
        now = time.monotonic()
        if self._active is not None:
            self._active.ended_at = now
        self._active = None

    def emit(self) -> None:
        if not _ENABLED:
            return
        self.finish()
        # Also include the pre-entry time: how long from Python import
        # of this module to the first phase (usually "cli entry"). That
        # captures the slow-start cost we can't otherwise see.
        startup_cost = (
            self.phases[0].started_at - _MODULE_LOAD_AT
            if self.phases
            else 0.0
        )
        # Writing to stderr so it doesn't corrupt any stdout consumer
        # (though `safeyolo agent run` isn't really pipeable anyway).
        sys.stderr.write("\n=== TIMING ===\n")
        if startup_cost > 0.001:
            sys.stderr.write(
                f"  (module import → first phase): {startup_cost*1000:8.1f} ms\n"
            )
        for p in self.phases:
            dur = p.duration or 0.0
            sys.stderr.write(f"  {p.name:40s} {dur*1000:8.1f} ms\n")
        total = sum((p.duration or 0.0) for p in self.phases)
        sys.stderr.write(f"  {'TOTAL':40s} {total*1000:8.1f} ms\n")
        sys.stderr.write("==============\n")


_CURRENT: Optional[Recorder] = None


def recorder() -> Recorder:
    """Return the process-wide recorder, creating it on first access."""
    global _CURRENT
    if _CURRENT is None:
        _CURRENT = Recorder()
    return _CURRENT


def enter(name: str) -> None:
    """Start a named phase. Closes whatever phase was previously active."""
    recorder().enter(name)


def mark(name: str) -> None:
    """Record an instantaneous boundary marker."""
    recorder().mark(name)


def emit() -> None:
    """Print the timing summary to stderr (if SAFEYOLO_TIMING=1)."""
    recorder().emit()
