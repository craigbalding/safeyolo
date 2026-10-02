"""Exercise the installed P4 guest handoff around the admitted-work marker."""

from __future__ import annotations

import json
import sys

import pytest

from tests.blackbox import installed_lifecycle as pilot


def test_held_guest_keeps_preamble_and_observation(monkeypatch):
    observation = {
        "phase": "drain",
        "agent": "bbtest",
        "forwarder": {"pid": 42},
        "result": {"http": "completed", "connect_closed": True},
    }
    script = (
        "print('shell preamble'); "
        "print('P4_READY=drain', flush=True); "
        f"print('P4_OBSERVATION=' + {json.dumps(json.dumps(observation))}, flush=True)"
    )
    monkeypatch.setattr(pilot, "guest_command", lambda *_args: [sys.executable, "-u", "-c", script])

    process, first = pilot.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)
    assert pilot.finish_guest(process, first, "drain", "bbtest") == observation["result"]


def test_held_guest_reports_exit_before_ready(monkeypatch):
    monkeypatch.setattr(
        pilot,
        "guest_command",
        lambda *_args: [sys.executable, "-u", "-c", "print('shell preamble', flush=True); raise SystemExit(4)"],
    )

    with pytest.raises(AssertionError, match="exited before its admitted-work boundary"):
        pilot.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)
