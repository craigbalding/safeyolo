"""Actual local policy/declaration settings, with no external providers or tokens."""

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

from pdp.client import LocalPolicyClient, PolicyClientConfig  # noqa: E402
from safeyolo.core import config_cache  # noqa: E402
from safeyolo.mitm_addons import test_context as module  # noqa: E402
from safeyolo.policy import engine as engine_module  # noqa: E402
from safeyolo.policy import loader as loader_module  # noqa: E402


def cases():
    return [
        {"case": "unconfigured", "source": None, "format": "json"},
        {"case": "omitted", "source": "{}", "format": "json"},
        {
            "case": "direct",
            "source": '{"addons":{"test_context":{"declared_ttl_max":23,"inject_declared":false}}}',
            "format": "json",
        },
        {
            "case": "disabled-still-declarable",
            "source": '{"addons":{"test_context":{"enabled":false,"declared_ttl_max":23,"inject_declared":true}}}',
            "format": "json",
        },
        {
            "case": "nested-ignored",
            "source": '{"addons":{"test_context":{"settings":{"declared_ttl_max":23,"inject_declared":false}}}}',
            "format": "json",
        },
        {
            "case": "huge-integer",
            "source": '{"addons":{"test_context":{"declared_ttl_max":' + str(10**400) + "}}}",
            "format": "json",
        },
        {
            "case": "typed-yaml-fields",
            "source": "addons:\n  test_context:\n    declared_ttl_max: 2030-01-02\n    inject_declared: 2030-01-02T03:04:05Z\n",
            "format": "yaml",
        },
        {
            "case": "quoted-yaml-fields",
            "source": 'addons:\n  test_context:\n    declared_ttl_max: "2030-01-02"\n    inject_declared: "2030-01-02T03:04:05Z"\n',
            "format": "yaml",
        },
        {
            "case": "typed-toml-fields",
            "source": "[addons.test_context]\ndeclared_ttl_max=2030-01-02\ninject_declared=2030-01-02T03:04:05Z\n",
            "format": "toml",
        },
        {
            "case": "unrelated-temporals",
            "source": "addons:\n  test_context:\n    declared_ttl_max: 23\n    inject_declared: false\n    target_hosts: [2030-01-02]\n    unrelated: {2030-01-02: ignored}\n  another:\n    settings: {created: 2030-01-02}\n",
            "format": "yaml",
        },
        {
            "case": "nested-temporal-key-ignored",
            "source": "addons:\n  test_context:\n    unrelated: {2030-01-02: 999}\n    declared_ttl_max: 23\n    inject_declared: false\n",
            "format": "yaml",
        },
        {
            "case": "false-and-float-fallback",
            "source": '{"addons":{"test_context":{"declared_ttl_max":1.0,"inject_declared":"false"}}}',
            "format": "json",
        },
        {
            "case": "task-addon-ignored",
            "source": '{"addons":{"test_context":{"declared_ttl_max":23,"inject_declared":false}}}',
            "format": "json",
            "task": '{"addons":{"test_context":{"declared_ttl_max":99,"inject_declared":true}}}',
        },
    ]


def observe(rows):
    output = []
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="tc-settings-") as directory, ExitStack() as stack:
        root = Path(directory)
        stack.enter_context(
            patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory, "SAFEYOLO_LOG_PATH": str(root / "audit")})
        )
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        for target in (loader_module, engine_module):
            stack.enter_context(patch.object(target, "write_event"))
        for name in ("getaddrinfo", "create_connection"):
            stack.enter_context(patch.object(socket, name, side_effect=AssertionError("no source network workload")))
        for row in rows:
            path = root / (row["case"] + "." + row["format"])
            if row["source"] is not None:
                path.write_text(row["source"])
            client = LocalPolicyClient(PolicyClientConfig(baseline_path=path if row["source"] is not None else None))
            try:
                engine = client._pdp._engine
                # A failed initial source load can install an empty fallback
                # baseline. Verify the actual loader result, not mere presence.
                assert row["source"] is None or engine._loader.reload()
                if row.get("task"):
                    task = root / "task.json"
                    task.write_text(row["task"])
                    assert engine.load_task_policy(task)
                before = engine._evaluations, client._pdp.policy_hash, len(engine._budget_tracker._budgets)
                owner = module.TestContext()
                owner._target_hosts = ["held.invalid"]
                owner._last_policy_hash = "held"
                with (
                    patch.object(config_cache._cache, "get", client.get_sensor_config),
                    patch.object(
                        module,
                        "get_option_safe",
                        lambda name, default: {
                            "test_context_inject_declared": True,
                            "test_context_declared_ttl": 11,
                        }.get(name, default),
                    ),
                ):
                    settings = {"ttl": owner._declared_ttl_max(), "inject": owner._inject_declared_enabled()}
                assert before == (engine._evaluations, client._pdp.policy_hash, len(engine._budget_tracker._budgets))
                assert owner._target_hosts == ["held.invalid"] and owner._last_policy_hash == "held"
                try:
                    json.dumps(client.get_sensor_config())
                    json_ok = True
                except TypeError:
                    json_ok = False
                output.append({**row, "settings": settings, "sensor_json_ok": json_ok})
            finally:
                client.shutdown()
    return {"rows": output, "case_count": len(output)}


if __name__ == "__main__":
    print(json.dumps(observe(cases() if "--generate" in sys.argv else json.load(sys.stdin)), indent=2))
