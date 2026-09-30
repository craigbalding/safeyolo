"""Selected real policy-loader publication and canonical audit contracts.

The loader is constructed without paths or a watcher. Each case uses owned
files, real parsing/compilation/validation and the real audit serializer. Only
the final audit submission and registered callbacks inject explicit failures.
This is component evidence; no proxy, policy watcher or production startup runs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import logging
import os
import socket
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
SOURCE_PATHS = [
    "cli/src/safeyolo/policy/loader.py",
    "cli/src/safeyolo/policy/compiler.py",
    "cli/src/safeyolo/policy/models.py",
    "cli/src/safeyolo/policy/toml_roundtrip.py",
    "cli/src/safeyolo/policy/toml_normalize.py",
    "cli/src/safeyolo/core/identifiers.py",
    "cli/src/safeyolo/core/utils.py",
    "cli/src/safeyolo/core/audit_schema.py",
    "cli/src/safeyolo/core/audit_writer.py",
]


def iam(description):
    return {
        "metadata": {"description": description},
        "permissions": [
            {"action": "network:request", "resource": "owned.invalid/*", "effect": "allow"},
            {
                "action": "network:request",
                "resource": "conditioned.invalid/*",
                "effect": "deny",
                "condition": {"port": 443},
            },
        ],
    }


def cases():
    success = {"path": "policy.yaml", "document": iam("candidate")}
    malformed = {"path": "policy.yaml", "text": "[invalid"}
    compile_error = {"path": "policy.yaml", "document": {"hosts": {"owned.invalid": "invalid"}}}
    validation_error = {"path": "policy.yaml", "document": {"permissions": [{"action": "network:request"}]}}
    return [
        {"name": "iam_success", "file": success},
        {
            "name": "host_centric_count_excludes_pre_simple",
            "file": {
                "path": "policy.yaml",
                "document": {
                    "metadata": {"description": "host candidate"},
                    "hosts": {
                        "allow.invalid": {"egress": "allow"},
                        "deny.invalid": {"egress": "deny"},
                        "budget.invalid": {"rate_limit": 3},
                    },
                },
            },
        },
        {"name": "empty_yaml_is_empty_policy", "file": {"path": "policy.yaml", "text": ""}},
        {"name": "null_yaml_is_empty_policy", "file": {"path": "policy.yaml", "text": "null\n"}},
        {"name": "empty_toml_is_empty_policy", "file": {"path": "policy.toml", "text": ""}},
        {"name": "null_json_fixed_error", "file": {"path": "policy.json", "text": "null"}},
        {"name": "missing_file_fixed_error", "file": {"path": "policy.yaml", "missing": True}},
        {"name": "invalid_yaml_fixed_error", "file": malformed},
        {"name": "invalid_json_fixed_error", "file": {"path": "policy.json", "text": "{"}},
        {"name": "compile_error_retains_prior", "file": compile_error},
        {"name": "validation_error_retains_prior", "file": validation_error},
        {"name": "success_submission_failure_publishes", "file": success, "audit_failures": ["ops.policy_reload"]},
        {
            "name": "fixed_error_submission_failure_escapes",
            "file": {"path": "policy.yaml", "missing": True},
            "audit_failures": ["ops.policy_error"],
        },
        {
            "name": "compile_error_submission_failure_escapes",
            "file": compile_error,
            "audit_failures": ["ops.policy_error"],
        },
        {
            "name": "success_and_error_submission_failures_escape",
            "file": success,
            "audit_failures": ["ops.policy_reload", "ops.policy_error"],
        },
        {"name": "callback_failure_does_not_stop_later_callback", "file": success, "callbacks": ["raise", "ok"]},
        {
            "name": "reload_failed_baseline_still_loads_task",
            "entrypoint": "reload",
            "file": malformed,
            "task_file": {"path": "task.json", "document": {"metadata": {"task_id": "owned-task"}, "permissions": []}},
        },
        {
            "name": "reload_task_failure_keeps_published_baseline",
            "entrypoint": "reload",
            "file": success,
            "task_file": {"path": "task.json", "document": validation_error["document"]},
        },
    ]


def sets_view(index):
    # Set iteration is not a source ordering contract. Dict insertion order is.
    return [
        {"action": action, "effect": effect, "resources": sorted(resources)}
        for (action, effect), resources in index.items()
    ]


def state(loader):
    def policy(value):
        return value.model_dump(mode="json") if value is not None else None

    return {
        "baseline": policy(loader._baseline),
        "task": policy(loader._task_policy),
        "baseline_simple": sets_view(loader._baseline_simple),
        "baseline_exact": [
            {"action": action, "resource": resource, "permissions": [p.model_dump(mode="json") for p in permissions]}
            for (action, resource), permissions in loader._baseline_exact.items()
        ],
        "baseline_patterns": [p.model_dump(mode="json") for p in loader._baseline_patterns],
        "pre_extracted_simple": sets_view(loader._pre_extracted_simple)
        if hasattr(loader, "_pre_extracted_simple")
        else None,
        "baseline_mtime": loader._last_baseline_mtime,
        "task_mtime": loader._last_task_mtime,
    }


def write_file(directory, recipe):
    path = directory / recipe["path"]
    if not recipe.get("missing"):
        # JSON is a YAML subset; TOML controls use explicit text.
        text = recipe["text"] if "text" in recipe else json.dumps(recipe["document"])
        path.write_text(text, encoding="utf-8")
        os.utime(path, (1234, 1234))
    return path


def observe(spec, directory, modules):
    directory.mkdir()
    loader = modules.loader.PolicyLoader()
    loader.set_baseline(modules.loader.UnifiedPolicy.model_validate(iam("prior")))
    loader._baseline_path = write_file(directory, spec["file"])
    if "task_file" in spec:
        loader.set_task_policy(modules.loader.UnifiedPolicy.model_validate({"metadata": {"task_id": "prior-task"}}))
        loader._task_policy_path = write_file(directory, spec["task_file"])
    before = state(loader)
    timeline, attempts = [], []
    real_load = loader._load_file
    real_compile = modules.loader.compile_policy
    real_validate = modules.loader.UnifiedPolicy.model_validate
    real_index = modules.loader._build_permission_index

    def load_file(path):
        assert path.is_relative_to(directory), "policy reads must use owned files"
        timeline.append({"phase": "load_file_enter", "path": path.name})
        result = real_load(path)
        timeline.append({"phase": "load_file_return", "path": path.name, "value": copy.deepcopy(result)})
        return result

    def compile_policy(raw):
        timeline.append({"phase": "compile_enter"})
        try:
            result = real_compile(raw)
        except Exception as error:
            # Observation boundary: preserve the actual exception for the loader.
            timeline.append({"phase": "compile_raise", "class": type(error).__name__, "message": str(error)})
            raise
        timeline.append({"phase": "compile_return", "permissions_count": len(result["permissions"])})
        return result

    def validate(raw, *args, **kwargs):
        timeline.append({"phase": "validate_enter", "baseline_description": loader._baseline.metadata.description})
        try:
            result = real_validate(raw, *args, **kwargs)
        except Exception as error:
            timeline.append({"phase": "validate_raise", "class": type(error).__name__, "message": str(error)})
            raise
        timeline.append({"phase": "validate_return", "permissions_count": len(result.permissions)})
        return result

    def index(permissions):
        timeline.append({"phase": "index_enter", "baseline_description": loader._baseline.metadata.description})
        return real_index(permissions)

    def submit(entry):
        event = copy.deepcopy(entry)
        event["ts"] = "<canonical timestamp>"
        failed = event["event"] in spec.get("audit_failures", [])
        attempts.append({"event": event, "accepted": not failed, "state_at_submit": state(loader)})
        timeline.append({"phase": "audit", "attempt": len(attempts) - 1, "accepted": not failed})
        if failed:
            raise RuntimeError("owned " + event["event"] + " submission failure")

    def callback(position, outcome):
        timeline.append({"phase": "callback", "position": position, "outcome": outcome, "state": state(loader)})
        if outcome == "raise":
            raise RuntimeError("owned reload callback failure")

    for position, outcome in enumerate(spec.get("callbacks", ["ok"])):
        loader.add_reload_callback(lambda position=position, outcome=outcome: callback(position, outcome))

    result, escaped = None, None
    with (
        patch.object(loader, "_load_file", side_effect=load_file),
        patch.object(modules.loader, "compile_policy", side_effect=compile_policy),
        patch.object(modules.loader.UnifiedPolicy, "model_validate", side_effect=validate),
        patch.object(modules.loader, "_build_permission_index", side_effect=index),
        patch.object(modules.audit_writer, "put_event", side_effect=submit),
    ):
        try:
            result = loader.reload() if spec.get("entrypoint") == "reload" else loader._load_baseline()
        except Exception as error:
            # The result records escaped source errors; assertions below require
            # exactly the selected RuntimeError controls, not arbitrary success.
            escaped = {"class": type(error).__name__, "message": str(error)}
    row = {
        "input": spec,
        "before": before,
        "return": result,
        "escaped": escaped,
        "timeline": timeline,
        "attempts": attempts,
        "after": state(loader),
    }
    return json.loads(json.dumps(row).replace(str(directory), "<owned>"))


def check_contract(rows):
    named = {row["input"]["name"]: row for row in rows}
    for row in rows:
        for attempt in row["attempts"]:
            event = attempt["event"]
            assert event["kind"] == "ops" and event["addon"] == "policy-loader"
            assert not {"agent", "request_id", "host", "decision", "approval"}.intersection(event)
            assert "attribution" not in event["details"]
            assert event["severity"] == ("medium" if event["event"] == "ops.policy_reload" else "high")
        if row["escaped"]:
            assert row["input"]["audit_failures"][-1] == "ops.policy_error"
            assert row["escaped"]["class"] == "RuntimeError" and row["return"] is None
    assert named["iam_success"]["attempts"][0]["event"]["details"]["permissions_count"] == 2
    host = named["host_centric_count_excludes_pre_simple"]
    assert host["return"] is True and len(host["after"]["baseline"]["permissions"]) == 1
    assert host["attempts"][0]["event"]["details"]["permissions_count"] == 1
    assert sum(len(item["resources"]) for item in host["after"]["pre_extracted_simple"]) == 2
    assert next(p["permissions_count"] for p in host["timeline"] if p["phase"] == "compile_return") == 3
    for name in ("empty_yaml_is_empty_policy", "null_yaml_is_empty_policy", "empty_toml_is_empty_policy"):
        row = named[name]
        assert row["return"] is True and row["attempts"][0]["event"]["details"]["permissions_count"] == 0
    for name in (
        "null_json_fixed_error",
        "missing_file_fixed_error",
        "invalid_yaml_fixed_error",
        "invalid_json_fixed_error",
    ):
        row = named[name]
        assert row["return"] is False and row["before"] == row["after"]
        assert row["attempts"][0]["event"]["details"] == {
            "policy_type": "baseline",
            "error": "File not found or invalid",
        }
    for name in ("compile_error_retains_prior", "validation_error_retains_prior"):
        row = named[name]
        assert row["return"] is False and row["before"] == row["after"]
        assert row["attempts"][0]["event"]["event"] == "ops.policy_error"
        assert not any(p["phase"] == "callback" for p in row["timeline"])
    for name in ("fixed_error_submission_failure_escapes", "compile_error_submission_failure_escapes"):
        row = named[name]
        assert row["escaped"]["class"] == "RuntimeError" and row["before"] == row["after"]
    for name in ("success_submission_failure_publishes", "success_and_error_submission_failures_escape"):
        row = named[name]
        assert row["after"]["baseline"]["metadata"]["description"] == "candidate"
        assert [a["event"]["event"] for a in row["attempts"]] == ["ops.policy_reload", "ops.policy_error"]
        assert all(a["state_at_submit"] == row["after"] for a in row["attempts"])
        assert not any(phase["phase"] == "callback" for phase in row["timeline"])
    assert named["success_submission_failure_publishes"]["return"] is False
    row = named["callback_failure_does_not_stop_later_callback"]
    assert row["return"] is True and len(row["attempts"]) == 1
    assert [p["outcome"] for p in row["timeline"] if p["phase"] == "callback"] == ["raise", "ok"]
    assert [p["phase"] for p in row["timeline"]][-3:] == ["audit", "callback", "callback"]
    row = named["reload_failed_baseline_still_loads_task"]
    assert row["return"] is False and row["after"]["task"]["metadata"]["task_id"] == "owned-task"
    assert [a["event"]["details"]["policy_type"] for a in row["attempts"]] == ["baseline", "task"]
    row = named["reload_task_failure_keeps_published_baseline"]
    assert row["return"] is False and row["after"]["task"] == row["before"]["task"]
    assert row["after"]["baseline"]["metadata"]["description"] == "candidate" and len(row["attempts"]) == 1


def no_network(*_args, **_kwargs):
    raise AssertionError("this oracle has no network operations")


def run():
    sys.path.insert(0, str(ROOT / "cli/src"))
    sys.path.insert(0, str(ROOT))
    with tempfile.TemporaryDirectory(prefix="owned-policy-reload-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        stack.enter_context(
            patch.dict(
                os.environ,
                {"SAFEYOLO_DATA_DIR": str(directory), "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl")},
            )
        )
        stack.enter_context(patch.object(socket, "create_connection", side_effect=no_network))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=no_network))
        previous_logging = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        stack.callback(logging.disable, previous_logging)
        from safeyolo.core import audit_writer
        from safeyolo.policy import loader

        modules = SimpleNamespace(loader=loader, audit_writer=audit_writer)
        rows = [observe(spec, directory / str(i), modules) for i, spec in enumerate(cases())]
        check_contract(rows)
        assert not (directory / "unused-audit.jsonl").exists()
        result = {
            "rows": rows,
            "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS},
        }
    assert not directory.exists()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = args.output or Path(__file__).with_suffix(".json")
    rendered = json.dumps(run(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        assert output.read_text(encoding="utf-8") == rendered, "source fixture drift"
    else:
        output.write_text(rendered, encoding="utf-8")
    print("policy reload: 18 selected source workflows passed")


if __name__ == "__main__":
    main()
