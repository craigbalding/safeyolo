"""Synthetic numeric operations against the shipped circuit addon; no listener or worker."""
import copy
import dataclasses
import json
import struct
import sys
from unittest.mock import patch

from safeyolo.mitm_addons.circuit_breaker import CircuitBreaker


def encode(value):
    if type(value) is int:
        return {"integer": str(value)}
    if type(value) is float:
        return {"float_bits": struct.pack(">d", value).hex()}
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    return value


def status(value):
    value = dataclasses.asdict(value)
    value["state"] = value["state"].value
    return value


def run(cases):
    output = []
    for case in cases:
        cb = CircuitBreaker()
        cb.is_enabled = lambda: True
        operations = []
        for index, op in enumerate(case["operations"]):
            now = float(op.get("now", 100))
            events = []
            samples = op.get("random", [0.5])
            draws = [0]

            def unit(samples=samples, draws=draws):
                value = samples[draws[0] % len(samples)]
                draws[0] += 1
                return value

            def uniform(a, b, unit=unit):
                return a + (b - a) * unit()

            cb._log_circuit_event = lambda name, domain, flow=None, events=events, **details: events.append(
                {"event": name, "domain": domain, "details": details or None}
            )
            with (
                patch("safeyolo.mitm_addons.circuit_breaker.time.time", return_value=now),
                patch("safeyolo.mitm_addons.circuit_breaker.random.uniform", side_effect=uniform),
            ):
                error = None
                value = None
                try:
                    kind = op["op"]
                    if kind == "config":
                        section = json.loads(op["json"]) if "json" in op else op["value"]
                        config = {"policy_hash": str(index + 1), "addons": {"circuit_breaker": section}}
                        with patch("safeyolo.core.config_cache.get_or_raise", return_value=config):
                            cb._maybe_reload_config()
                        value = True
                    elif kind == "restore":
                        cb._state._states = copy.deepcopy(op["value"]["states"])
                        cb._reconcile_stale_circuits()
                    elif kind == "timeout":
                        value = cb._calculate_timeout(json.loads(op["streak_json"]) if "streak_json" in op else op["streak"])
                    elif kind == "status":
                        value = status(cb.get_status("api"))
                    elif kind == "failure":
                        value = status(cb.record_failure("api"))
                    elif kind == "success":
                        value = status(cb.record_success("api"))
                    elif kind == "force":
                        cb.force_open("api")
                    elif kind == "admit":
                        allowed, current = cb.should_allow_request("api")
                        value = [allowed, status(current)]
                    elif kind == "stats":
                        value = cb.get_stats()
                    else:
                        raise AssertionError(kind)
                except (TypeError, ValueError, OverflowError, ZeroDivisionError) as exc:
                    error = type(exc).__name__
                operations.append({
                    "value": encode(value), "error": error, "events": encode(events),
                    "snapshot": encode({"states": copy.deepcopy(cb._state._states), "saved_at": now}),
                    "state_order": list(cb._state._states), "draws": draws[0],
                })
        output.append({"name": case["name"], "operations": operations})
    return output


if __name__ == "__main__":
    json.dump(run(json.load(sys.stdin)), sys.stdout, allow_nan=False)
