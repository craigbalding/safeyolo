"""Reached source audit exceptions and circuit effects, using owned in-memory state.

The actual write_event envelope runs; only its queue submission is replaced with
a finite recorder that either returns normally or raises RuntimeError. No file,
socket, operational settings, credential, or HTTP transport is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from safeyolo.mitm_addons import circuit_breaker

HOST = "owned.invalid"
NOW = 1000.0


def run():
    logging.disable(logging.CRITICAL)
    rows = []
    settings = {
        "failure_threshold": 2,
        "success_threshold": 2,
        "timeout_seconds": 60,
        "half_open_max_requests": 3,
        "use_exponential_backoff": False,
    }
    states = {
        "open": {"state": "closed", "failure_count": 1, "failure_streak": 0},
        "reopen": {"state": "half_open", "failure_count": 2, "failure_streak": 1},
        "close": {
            "state": "half_open",
            "failure_count": 3,
            "success_count": 1,
            "failure_streak": 1,
        },
        "half_request": {"state": "open", "failure_count": 5, "opened_at": 0},
        "half_stats": {"state": "open", "failure_count": 5, "opened_at": 0},
    }
    for operation, initial in states.items():
        for fail in (False, True):
            cb = circuit_breaker.CircuitBreaker()
            for key, value in settings.items():
                setattr(cb, key, value)
            cb._state.set(HOST, dict(initial))
            if operation == "half_stats":
                cb._state.set("later.invalid", dict(initial))
            initial_states = {domain: dict(cb._state.get(domain)) for domain in cb._state.all_domains()}
            attempts, submitted = [], []

            def put_event(event, *, attempts=attempts, fail=fail, submitted=submitted):
                recorded = {key: value for key, value in event.items() if key != "ts"}
                attempts.append(recorded)
                if fail:
                    raise RuntimeError("synthetic audit submission failure")
                submitted.append(recorded)

            error = None
            flow = SimpleNamespace(metadata={"request_id": "req-circuit-owned", "agent": "alice"})
            with (
                patch.object(circuit_breaker.time, "time", return_value=NOW),
                patch("safeyolo.core.audit_writer.put_event", side_effect=put_event),
            ):
                try:
                    if operation in {"open", "reopen"}:
                        cb.record_failure(HOST, "HTTP 503", flow=flow)
                    elif operation == "close":
                        cb.record_success(HOST, flow=flow)
                    elif operation == "half_request":
                        cb.should_allow_request(HOST)
                    else:
                        cb.get_stats()
                except RuntimeError as exception:
                    error = type(exception).__name__
            rows.append(
                {
                    "name": operation + ("_error" if fail else "_success"),
                    "operation": operation,
                    "submission_error": fail,
                    "initial_states": initial_states,
                    "exception": error,
                    "attempts": attempts,
                    "submitted": submitted,
                    "states": {domain: cb._state.get(domain) for domain in cb._state.all_domains()},
                    "counters": {
                        "checks": cb.checks_total,
                        "opens": cb.opens_total,
                        "half_opens": cb.half_opens_total,
                        "recoveries": cb.recoveries_total,
                    },
                }
            )
    root = Path(__file__).resolve().parents[2]
    paths = [
        "cli/src/safeyolo/mitm_addons/circuit_breaker.py",
        "cli/src/safeyolo/core/utils.py",
        "cli/src/safeyolo/core/audit_schema.py",
    ]
    return {
        "now": NOW,
        "settings": settings,
        "rows": rows,
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in paths},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = run()
    if args.check:
        assert result == json.loads(args.check.read_text()), "Source circuit audit ordering changed"
        print("10 actual source circuit audit ordering rows match")
    else:
        print(json.dumps(result, indent=2))
