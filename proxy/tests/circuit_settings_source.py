"""Finite actual LocalPolicyClient circuit projection, no network or secrets.

Use --write to regenerate the adjacent golden or --check to compare it. The
source loader, canonical model, task loader, hash and single budget tracker are
real. Only watcher scheduling, budget clock and audit delivery are controlled.
"""

import argparse
import copy
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
from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module

HERE = Path(__file__).resolve().parent


def describe(value):
    if isinstance(value, (datetime.date, datetime.time)):
        return {"temporal": str(value)}
    if isinstance(value, dict):
        return {"mapping": [{"key": describe(key), "value": describe(item)} for key, item in value.items()]}
    if isinstance(value, list):
        return [describe(item) for item in value]
    return value


def specimens():
    return [
        ("unconfigured", "json", None),
        ("configured_empty", "json", "{}"),
        ("explicit_empty_addon", "toml", "[addons.circuit_breaker]\n"),
        ("nested_settings_only", "toml", "[addons.circuit_breaker.settings]\nfailure_threshold=31\n"),
        ("top_level_threshold", "toml", "[addons.circuit_breaker]\nfailure_threshold=7\n"),
        (
            "top_level_wins_and_disabled_is_retained",
            "toml",
            "[addons.circuit_breaker]\nenabled=false\nfailure_threshold=7\n[addons.circuit_breaker.settings]\nfailure_threshold=31\n",
        ),
        (
            "unvalidated_direct_values",
            "json",
            json.dumps(
                {
                    "addons": {
                        "circuit_breaker": {
                            "failure_threshold": "not-numeric",
                            "success_threshold": None,
                            "timeout_seconds": [],
                            "half_open_max_requests": {},
                            "max_timeout_seconds": True,
                            "use_exponential_backoff": False,
                            "backoff_multiplier": 9007199254740993,
                            "jitter_factor": 1.5,
                            "streak_decay_seconds": -2,
                        }
                    }
                }
            ),
        ),
        (
            "unrelated_addon_timestamp",
            "yaml",
            "addons:\n  circuit_breaker: {failure_threshold: 7}\n  unused: {settings: {observed: 2001-02-03}}\n",
        ),
        ("consumed_date", "yaml", "addons: {circuit_breaker: {failure_threshold: 2001-02-03}}\n"),
        ("consumed_datetime", "yaml", "addons: {circuit_breaker: {timeout_seconds: 2001-02-03T04:05:06Z}}\n"),
        ("consumed_time", "toml", "[addons.circuit_breaker]\ntimeout_seconds=04:05:06.123456789\n"),
        (
            "temporal_excluded_list",
            "yaml",
            "addons: {circuit_breaker: {excluded_domains: [2001-02-03, '2001-02-03', {nested: 2001-02-04}]}}\n",
        ),
        (
            "temporal_excluded_mapping_key",
            "yaml",
            "addons:\n  circuit_breaker:\n    excluded_domains:\n      2001-02-03: true\n      '2001-02-03': false\n",
        ),
        (
            "authored_lookalikes",
            "yaml",
            "addons: {circuit_breaker: {failure_threshold: '2001-02-03', timeout_seconds: {yaml_date: '2001-02-03'}}}\n",
        ),
    ]


def run():
    logging.disable(logging.CRITICAL)
    rows = []
    attempts = []

    def no_network(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("circuit projection oracle has no network workload")

    with tempfile.TemporaryDirectory(prefix="circuit-settings-") as temp, ExitStack() as stack:
        root = Path(temp)
        stack.enter_context(
            patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temp, "SAFEYOLO_LOG_PATH": str(root / "audit")})
        )
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.budget_tracker.time.time", return_value=1000.0))
        for module in (loader_module, engine_module):
            stack.enter_context(patch.object(module, "write_event"))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=no_network))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=no_network))

        def observe(client, name, source, format):
            engine = client._pdp._engine
            tracker = engine._budget_tracker
            before = copy.deepcopy(tracker._budgets), engine._evaluations, client._pdp.policy_hash
            sensor = client.get_sensor_config()
            again = client.get_sensor_config()
            assert sensor == again
            assert before == (tracker._budgets, engine._evaluations, client._pdp.policy_hash)
            addon = sensor["addons"].get("circuit_breaker")
            try:
                json.dumps(sensor)
                json_ok = True
            except TypeError:
                # Deliberate serializer boundary, not a loader/client failure.
                json_ok = False
            row = {
                "case": name,
                "format": format,
                "source": source,
                "hash": sensor["policy_hash"],
                "values": describe(addon),
                "http_sensor_json_ok": json_ok,
                "read_preserves_evaluations_budgets_hash": True,
                "evaluations": engine._evaluations,
                "tracked_keys": len(tracker._budgets),
            }
            rows.append(row)
            return row

        for name, format, source in specimens():
            directory = root / name
            directory.mkdir()
            path = directory / ("policy." + format)
            if source is not None:
                path.write_text(source)
            client = LocalPolicyClient(PolicyClientConfig(baseline_path=path if source is not None else None))
            try:
                assert source is None or client._pdp._engine.get_baseline() is not None
                observe(client, name, source, format)
            finally:
                client.shutdown()

        budget_source = '[{"action":"network:request","resource":"fixture.invalid/*","effect":"budget","budget":1}]'
        source = '{"permissions":' + budget_source + ',"addons":{"circuit_breaker":{"failure_threshold":7}}}'
        path = root / "policy.json"
        path.write_text(source)
        client = LocalPolicyClient(PolicyClientConfig(baseline_path=path))
        try:
            engine = client._pdp._engine
            assert engine.evaluate_request("fixture.invalid").effect == "allow"
            base = observe(client, "charged_baseline", source, "json")
            assert base["evaluations"] == base["tracked_keys"] == 1
            task_source = '{"addons":{"circuit_breaker":{"failure_threshold":99}}}'
            task_path = root / "task.json"
            task_path.write_text(task_source)
            assert engine.load_task_policy(task_path)
            task = observe(client, "task_changes_hash_not_baseline_addon", source, "json")
            task["task_source"] = task_source
            assert task["values"] == base["values"] and task["hash"] != base["hash"]
            engine.clear_task_policy()
            reloaded = source.replace('"failure_threshold":7', '"failure_threshold":"later-error"')
            path.write_text(reloaded)
            assert engine._loader.reload()
            good = observe(client, "valid_reload_retains_budget_and_raw_value", reloaded, "json")
            path.write_text('{"permissions":false}')
            assert not engine._loader.reload()
            bad = observe(client, "invalid_reload_retains_last_projection", reloaded, "json")
            assert good["hash"] == bad["hash"] and good["values"] == bad["values"]
        finally:
            client.shutdown()
    assert attempts == []
    return {
        "rows": rows,
        "network_attempts": 0,
        "source_scope": "actual LocalPolicyClient/PolicyLoader/PDPCore; no circuit adapter or numeric operation",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = run()
    path = HERE / "circuit_settings_source.json"
    if args.write:
        path.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
    if args.check:
        assert result == json.loads(path.read_text())
    print(
        json.dumps({"rows": len(result["rows"]), "network_attempts": result["network_attempts"], "checked": args.check})
    )
