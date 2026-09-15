"""Actual LocalPolicyClient + CircuitBreaker settings application, no egress.

--write freezes the adjacent fixture; --check reruns the actual source methods.
Only clock/jitter, watcher scheduling, audit delivery and cache selection are
controlled. Settings inputs are ordinary synthetic policy documents.
"""

import argparse
import datetime
import json
import logging
import os
import socket
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.mitm_addons.circuit_breaker import CircuitBreaker
from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module

HERE = Path(__file__).resolve().parent
FIELDS = [
    "failure_threshold", "success_threshold", "timeout_seconds", "half_open_max_requests",
    "use_exponential_backoff", "max_timeout_seconds", "backoff_multiplier", "jitter_factor",
    "streak_decay_seconds",
]


def describe(value):
    if isinstance(value, (datetime.date, datetime.time)):
        return {"temporal": str(value)}
    if isinstance(value, dict):
        return {"mapping": [{"key": describe(key), "value": describe(item)} for key, item in value.items()]}
    if isinstance(value, list):
        return [describe(item) for item in value]
    return value


def policy(values, **extra):
    return {"format": "json", "source": json.dumps({"addons": {"circuit_breaker": values}}), **extra}


def specimens():
    yield "initial_omitted_empty", [
        {"raw": {"addons": {"circuit_breaker": {"failure_threshold": 99}}}},
        {"format": "json", "source": None},
        {"format": "json", "source": "{}"},
        policy({}),
    ]
    yield "ordered_values_nested_ignored_retention", [
        policy({"failure_threshold": 7, "use_exponential_backoff": False, "timeout_seconds": 11,
                "excluded_domains": ["custom.invalid"], "settings": {"failure_threshold": 99}}),
        policy({"settings": {"failure_threshold": 31}, "excluded_domains": []}),
        {"format": "json", "source": "{}"},
    ]
    yield "same_hash_skips_changed_and_malformed_payload", [
        {"raw": {"policy_hash": "same", "addons": {"circuit_breaker": {"failure_threshold": 7}}}},
        {"raw": {"policy_hash": "same", "addons": {"circuit_breaker": {"failure_threshold": 99}}}},
        {"raw": {"policy_hash": "same", "addons": False}},
    ]
    yield "partial_failure_retry_and_commit", [
        {"raw": {"policy_hash": "good", "addons": {"circuit_breaker": {"failure_threshold": 2}}}},
        {"raw": {"policy_hash": "next", "addons": {"circuit_breaker": {
            "failure_threshold": 9, "success_threshold": 8, "timeout_seconds": 7,
            "half_open_max_requests": 6, "use_exponential_backoff": [], "max_timeout_seconds": 5,
            "backoff_multiplier": 4, "jitter_factor": 3, "streak_decay_seconds": 2,
            "excluded_domains": ["first.invalid", [], "never.invalid"]}}}},
        {"raw": {"policy_hash": "next", "addons": {"circuit_breaker": {
            "failure_threshold": 10, "excluded_domains": ["second.invalid", {}]}}}},
        {"raw": {"policy_hash": "next", "addons": {"circuit_breaker": {"excluded_domains": ["last.invalid"]}}}},
    ]
    yield "nonnumeric_values_load_then_consumption_fails", [
        policy({"failure_threshold": "bad", "success_threshold": None, "timeout_seconds": [],
                "half_open_max_requests": {}, "use_exponential_backoff": True,
                "max_timeout_seconds": False, "backoff_multiplier": 2, "jitter_factor": "bad",
                "streak_decay_seconds": -1}, operation="failure"),
    ]
    for name, scalar, field, operation in [
        ("date_threshold", "2001-02-03", "failure_threshold", "failure"),
        ("datetime_timeout", "2001-02-03T04:05:06Z", "timeout_seconds", "timeout0"),
        ("datetime_timeout_consumed", "2001-02-03T04:05:06Z", "timeout_seconds", "timeout1"),
        ("temporal_backoff_truth", "2001-02-03", "use_exponential_backoff", "timeout1"),
    ]:
        yield name, [{"format": "yaml", "source": f"addons: {{circuit_breaker: {{{field}: {scalar}, jitter_factor: 0}}}}\n", "operation": operation}]
    yield "time_timeout", [{"format": "toml", "source": "[addons.circuit_breaker]\ntimeout_seconds=04:05:06.123456789\n", "operation": "timeout0"}]
    yield "authored_lookalike_is_ordinary_object", [
        policy({"failure_threshold": {"yaml_date": "2001-02-03"}, "timeout_seconds": "2001-02-03"}, operation="failure")
    ]
    yield "temporal_descendants_and_keys_retained", [
        {"format": "yaml", "source": "addons:\n  circuit_breaker:\n    failure_threshold: {2001-02-03: [2001-02-04], '2001-02-03': 'ordinary'}\n", "operation": "failure"}
    ]
    yield "string_exclusions_iterate_codepoints", [policy({"excluded_domains": "aé🙂a"})]
    yield "mapping_exclusions_consume_keys_only", [policy({"excluded_domains": {"map.invalid": [[], {}], "other.invalid": None}})]
    yield "list_hashable_scalars_and_temporal_then_unhashable", [
        {"format": "yaml", "source": "addons:\n  circuit_breaker:\n    failure_threshold: 17\n    excluded_domains: [2001-02-03, '2001-02-03', null, false, true, 1, 1.5, 'prefix.invalid', {nested: 2001-02-04}, 'never.invalid']\n"}
    ]
    yield "temporal_mapping_key_is_not_string", [
        {"format": "yaml", "source": "addons:\n  circuit_breaker:\n    excluded_domains:\n      2001-02-03: ignored\n      '2001-02-03': [[], {}]\n      2001-02-04: ignored\n"}
    ]
    yield "temporal_exclusion_scalar_is_not_iterable", [
        {"format": "yaml", "source": "addons: {circuit_breaker: {failure_threshold: 19, excluded_domains: 2001-02-03}}\n"}
    ]
    yield "false_exclusions_skip_noniterable_consumption", [policy({"excluded_domains": value, "use_exponential_backoff": value}) for value in [None, False, 0, -0.0, "", [], {}]]
    yield "true_noniterable_exclusions_fail_after_fields", [policy({"failure_threshold": index, "excluded_domains": value}) for index, value in enumerate([True, 1, -2, 1.5], 31)]
    yield "backoff_truth_follows_container_not_entries", [policy({"use_exponential_backoff": value, "jitter_factor": 0}, operation="timeout1") for value in ["false", [False], {"unused": None}, 0.0]]
    yield "raw_structural_checks_are_separate", [
        {"raw": {"policy_hash": "bad", "addons": False}, "structural_gap": True},
        {"raw": {"policy_hash": "bad", "addons": {"circuit_breaker": None}}, "structural_gap": True},
    ]


def run():
    logging.disable(logging.CRITICAL)
    rows = []
    attempts = []

    def no_network(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("circuit config oracle has no network workload")

    with tempfile.TemporaryDirectory(prefix="circuit-config-") as temp, ExitStack() as stack:
        root = Path(temp)
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temp, "SAFEYOLO_LOG_PATH": str(root / "audit")}))
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.budget_tracker.time.time", return_value=100.0))
        stack.enter_context(patch("safeyolo.mitm_addons.circuit_breaker.time.time", return_value=100.0))
        stack.enter_context(patch("safeyolo.mitm_addons.circuit_breaker.random.uniform", return_value=0.0))
        for module in (loader_module, engine_module):
            stack.enter_context(patch.object(module, "write_event"))
        stack.enter_context(patch("safeyolo.mitm_addons.circuit_breaker.write_event"))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=no_network))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=no_network))
        for name, steps in specimens():
            cb = CircuitBreaker()
            results = []
            for index, step in enumerate(steps):
                client = None
                if "raw" in step:
                    sensor = step["raw"]
                else:
                    path = root / f"policy.{step['format']}"
                    if step["source"] is not None:
                        path.write_text(step["source"])
                    client = LocalPolicyClient(PolicyClientConfig(baseline_path=path if step["source"] is not None else None))
                    assert step["source"] is None or client._pdp._engine.get_baseline() is not None
                    sensor = client.get_sensor_config()
                previous = cb._last_policy_hash
                error = None
                try:
                    with patch("safeyolo.core.config_cache.get_or_raise", return_value=sensor):
                        cb._maybe_reload_config()
                except (TypeError, AttributeError) as failure:
                    error = type(failure).__name__
                finally:
                    if client is not None:
                        client.shutdown()
                operation = None
                if "operation" in step:
                    try:
                        if step["operation"] == "failure":
                            cb.record_failure("owned.invalid")
                            value = None
                        else:
                            value = cb._calculate_timeout(int(step["operation"][-1]))
                        operation = {"value": describe(value), "error": None}
                    except TypeError as failure:
                        operation = {"value": None, "error": type(failure).__name__}
                stats_json_error = None
                try:
                    with patch.object(cb, "is_enabled", return_value=True):
                        json.dumps(cb.get_stats())
                except TypeError as failure:
                    stats_json_error = type(failure).__name__
                settings = {field: describe(getattr(cb, field)) for field in FIELDS}
                settings["use_exponential_backoff"] = bool(cb.use_exponential_backoff)
                results.append({
                    "index": index, "input": step, "error": error,
                    "changed": cb._last_policy_hash != previous,
                    "last_hash": cb._last_policy_hash, "settings": settings,
                    "excluded_strings": sorted(value for value in cb._excluded_domains if isinstance(value, str)),
                    "operation": operation, "stats_json_error": stats_json_error,
                })
            rows.append({"case": name, "steps": results})
    assert not attempts
    return {"rows": rows, "network_attempts": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = run()
    fixture = HERE / "circuit_config_source.json"
    if args.write:
        fixture.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    if args.check:
        assert json.loads(fixture.read_text()) == result
    print(json.dumps({"traces": len(result["rows"]), "steps": sum(len(row["steps"]) for row in result["rows"]), "network_attempts": result["network_attempts"]}))
