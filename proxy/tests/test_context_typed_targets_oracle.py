"""Loaded-policy target hooks: isolated files, no network, credentials or providers."""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]

from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

from pdp.client import LocalPolicyClient, PolicyClientConfig  # noqa: E402
from safeyolo.core import config_cache  # noqa: E402
from safeyolo.mitm_addons import test_context as module  # noqa: E402
from safeyolo.policy import engine as engine_module  # noqa: E402
from safeyolo.policy import loader as loader_module  # noqa: E402


def request(host="target.invalid", header=None, **fields):
    return {"host": host, "header": header, "prior": False, **fields}


def cases():
    def yaml(target):
        return "addons:\n  test_context:\n    target_hosts: " + target + "\n"

    entries = [
        ("root-date", "2030-01-02"),
        ("root-datetime", "2030-01-02T03:04:05Z"),
        ("quoted-root-date", '"2030-01-02"'),
        ("list-match-before-date", '["target.invalid", 2030-01-02]'),
        ("list-date-before-match", '[2030-01-02, "target.invalid"]'),
        ("list-quoted-date", '["2030-01-02", "target.invalid"]'),
        ("map-temporal-values-ignored", '{"target.invalid": 2030-01-02, "later.invalid": 2030-01-02T03:04:05Z}'),
        ("map-match-before-date", '{"target.invalid": false, 2030-01-02: ignored}'),
        ("map-date-before-match", '{2030-01-02: ignored, "target.invalid": false}'),
        ("map-quoted-before-typed-key", '{"2030-01-02": false, 2030-01-02: ignored}'),
        ("map-typed-before-quoted-key", '{2030-01-02: ignored, "2030-01-02": false}'),
        ("map-datetime-key", '{2030-01-02T03:04:05Z: ignored, "target.invalid": true}'),
    ]
    rows = [
        {
            "case": name,
            "format": "yaml",
            "source": yaml(target),
            "steps": [
                request(prior=True, header="run=r;agent=a"),
                request(),
                request("other.invalid", header="run=r;agent=a"),
                request("2030-01-02"),
                request("2"),
            ],
        }
        for name, target in entries
    ]
    rows.extend(
        [
            {
                "case": "toml-root-datetime",
                "format": "toml",
                "source": "[addons.test_context]\ntarget_hosts=2030-01-02T03:04:05Z\n",
                "steps": [request(), request()],
            },
            {
                "case": "toml-list-date",
                "format": "toml",
                "source": '[addons.test_context]\ntarget_hosts=["target.invalid", 2030-01-02]\n',
                "steps": [request(), request("other.invalid")],
            },
            {
                "case": "alias-merge-order",
                "format": "yaml",
                "source": "addons:\n  test_context:\n    ignored: &targets {target.invalid: true, 2030-01-02: ignored}\n    target_hosts:\n      <<: *targets\n      target.invalid: false\n",
                "steps": [request(), request("other.invalid")],
            },
            {
                "case": "temporal-alias-value",
                "format": "yaml",
                "source": "addons:\n  test_context:\n    ignored: &date 2030-01-02\n    target_hosts: [target.invalid, *date]\n",
                "steps": [request(), request("other.invalid")],
            },
            {
                "case": "unrelated-temporal-fields",
                "format": "yaml",
                "source": "addons:\n  test_context:\n    target_hosts: [target.invalid]\n    ignored: {2030-01-02: [2030-01-02T03:04:05Z]}\n  another:\n    settings: {created: 2030-01-02}\n",
                "steps": [request(), request("other.invalid")],
            },
            {
                "case": "nested-target-ignored",
                "format": "yaml",
                "source": "addons:\n  test_context:\n    settings: {target_hosts: 2030-01-02}\n",
                "steps": [request()],
            },
            {
                "case": "task-addon-ignored",
                "format": "yaml",
                "source": yaml("[target.invalid]"),
                "task": '{"addons":{"test_context":{"target_hosts":true}}}',
                "steps": [request(), request("other.invalid")],
            },
            {
                "case": "reload-and-unavailable",
                "format": "yaml",
                "source": yaml("2030-01-02"),
                "steps": [
                    request(),
                    request(),
                    request(source=yaml("[target.invalid]")),
                    request(source=yaml("{target.invalid: 2030-01-02}")),
                    request(source="addons: {test_context: {}}", prior=True),
                    request(available=False),
                    request(),
                ],
            },
        ]
    )
    rows.append(
        {
            "case": "authored-date-shaped-object",
            "format": "json",
            "source": '{"addons":{"test_context":{"target_hosts":{"yaml_date":"2030-01-02"}}}}',
            "steps": [request("yaml_date"), request()],
        }
    )
    for name, key in (("integer-key", "7"), ("boolean-key", "true"), ("null-key", "null")):
        rows.append(
            {
                "case": name,
                "native_gap": "nonstring YAML mapping keys are not admitted by the existing frontend",
                "format": "yaml",
                "source": yaml("{target.invalid: false, " + key + ": ignored}"),
                "steps": [request(), request("other.invalid")],
            }
        )
    return rows


def observe_row(row, root):
    path = root / (row["case"] + "." + row["format"])
    path.write_text(row["source"])
    client = LocalPolicyClient(PolicyClientConfig(baseline_path=path))
    try:
        engine = client._pdp._engine
        assert engine._loader.reload(), "source must successfully load the tested document"
        if row.get("task"):
            task = root / "task.json"
            task.write_text(row["task"])
            assert engine.load_task_policy(task)
        owner = module.TestContext()
        owner.should_block = lambda: True
        owner.log_decision = lambda *args, **kwargs: None
        available = True

        def sensor():
            if not available:
                raise RuntimeError("isolated unavailable provider")
            return client.get_sensor_config()

        observations = []
        with (
            patch.object(config_cache, "get_or_raise", sensor),
            patch.object(config_cache._cache, "get", lambda: sensor() if available else {}),
            patch.object(module, "get_option_safe", lambda name, default: default),
            patch.object(module, "write_event"),
            patch.object(module.time, "monotonic", lambda: 0.0),
        ):
            for step in row["steps"]:
                if "source" in step:
                    path.write_text(step["source"])
                    assert engine._loader.reload(), "source reload must succeed"
                available = step.get("available", True)
                before = engine._evaluations, client._pdp.policy_hash, len(engine._budget_tracker._budgets)
                flow = tflow.tflow()
                flow.request.host = step["host"]
                flow.request.headers = http.Headers([])
                if step["header"] is not None:
                    flow.request.headers[module.TEST_CONTEXT_HEADER] = step["header"]
                flow.response = http.Response.make(200, b"") if step["prior"] else None
                result = {"error": None, "stats_error": None, "stats": None}
                try:
                    owner.request(flow)
                except (TypeError, AttributeError) as exc:
                    result["error"] = type(exc).__name__
                result.update(
                    status=flow.response.status_code if flow.response else 0,
                    header_retained=module.TEST_CONTEXT_HEADER in flow.request.headers,
                    hash=owner._last_policy_hash,
                )
                try:
                    result["stats"] = owner.get_stats()
                except TypeError as exc:
                    result["stats_error"] = type(exc).__name__
                result["counts"] = {
                    "checks": owner.stats.checks,
                    "allowed": owner.stats.allowed,
                    "blocked": owner.stats.blocked,
                    "warned": owner.stats.warned,
                }
                assert before == (engine._evaluations, client._pdp.policy_hash, len(engine._budget_tracker._budgets))
                observations.append(result)
        return {**row, "observations": observations}
    finally:
        client.shutdown()


def observe(rows):
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="tc-typed-targets-") as directory, ExitStack() as stack:
        root = Path(directory)
        stack.enter_context(
            patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory, "SAFEYOLO_LOG_PATH": str(root / "audit")})
        )
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        for target in (loader_module, engine_module):
            stack.enter_context(patch.object(target, "write_event"))
        for name in ("getaddrinfo", "create_connection"):
            stack.enter_context(patch.object(socket, name, side_effect=AssertionError("no source network workload")))
        output = [observe_row(row, root) for row in rows]
    return {"rows": output, "trace_count": len(output), "operation_count": sum(len(row["steps"]) for row in output)}


if __name__ == "__main__":
    print(json.dumps(observe(cases() if "--generate" in sys.argv else json.load(sys.stdin)), indent=2))
