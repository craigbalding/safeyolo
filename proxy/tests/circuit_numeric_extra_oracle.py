"""Exact division and source-successful nonfinite circuit state/persistence witnesses."""
import copy
import json
import math
import pathlib
import struct
import sys
import tempfile
from unittest.mock import patch

from safeyolo.mitm_addons.circuit_breaker import CircuitBreaker, InMemoryCircuitState


def ratios(rows):
    output = []
    for row in rows:
        try:
            bits = struct.pack(">d", int(row["a"]) / int(row["b"])).hex()
            error = None
        except (OverflowError, ZeroDivisionError) as exc:
            bits = None
            error = type(exc).__name__
        output.append({"a": row["a"], "b": row["b"], "bits": bits, "error": error})
    return output


def nonfinite():
    cb = CircuitBreaker()
    cb._state._states = {"api": {
        "state": "half_open", "failure_count": math.nan,
        "failure_streak": math.nan, "success_count": math.inf,
    }}
    events = []
    cb._log_circuit_event = lambda name, domain, flow=None, **details: events.append((name, details))
    with (
        patch("safeyolo.mitm_addons.circuit_breaker.time.time", return_value=100.0),
        patch("safeyolo.mitm_addons.circuit_breaker.random.uniform", return_value=0.0),
        tempfile.TemporaryDirectory() as directory,
    ):
        result = cb.record_failure("api")
        output = {
            "failure_nan": math.isnan(result.failure_count),
            "streak_nan": math.isnan(result.failure_streak),
            "state": result.state.value,
            "opens": cb.opens_total,
            "reopen_event_nan": events[0][0] == "reopen" and math.isnan(events[0][1]["streak"]),
        }
        cb._state._states["infinite"] = {"failure_count": math.inf}
        cb._state._state_file = pathlib.Path(directory) / "state.json"
        cb._state._save_state()
        text = cb._state._state_file.read_text()
        output["saved_json_has_nan"] = "NaN" in text
        output["saved_json_has_infinity"] = "Infinity" in text
        with patch.object(InMemoryCircuitState, "_start_snapshots"):
            restored = InMemoryCircuitState(cb._state._state_file)
        output["reload_preserves_nan"] = math.isnan(restored.get("api")["failure_count"])
        output["reload_preserves_infinity"] = restored.get("infinite")["failure_count"] == math.inf
        # get_stats observes all domains before its caller serializes the result.
        cb._state._states = {
            "nan": {"state": "closed", "failure_count": math.nan},
            "later": {"state": "open", "opened_at": 0},
        }
        stats = copy.deepcopy(cb.get_stats())
        output["stats_visits_later_domain"] = stats["domains"]["later"]["state"] == "half_open"
        output["stats_json_has_nan"] = "NaN" in json.dumps(stats)
    return output


if __name__ == "__main__":
    json.dump({"ratios": ratios(json.load(sys.stdin)), "nonfinite": nonfinite()}, sys.stdout)
