"""Finite foreground executions of the actual PolicyLoader watcher closure.

Thread.start captures the source target instead of starting a thread. A finite
stop/wait object applies owned file mutations before each iteration and records
the source's two-second wait without sleeping. Parsing, loads, metadata reads
and audit serialization remain real; declared stat/submission faults are local.
"""

from __future__ import annotations

import argparse
import copy
import errno
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
    "cli/src/safeyolo/policy/list_loader.py",
    "cli/src/safeyolo/policy/compiler.py",
    "cli/src/safeyolo/policy/models.py",
    "cli/src/safeyolo/core/utils.py",
    "cli/src/safeyolo/core/audit_schema.py",
]
SECOND = 1_000_000_000


def policy(description):
    return {"metadata": {"description": description}, "permissions": []}


def document(value, seconds):
    return {"document": value, "mtime_ns": seconds * SECOND}


def cases():
    epoch = 1_700_000_000
    baseline = "policy.yaml"
    return [
        {
            "name": "baseline_strict_float_mtime_and_invalid_retry",
            "initial_files": {baseline: document(policy("initial"), epoch)},
            "iterations": [
                {"name": "equal", "write": {baseline: document(policy("equal"), epoch)}},
                {"name": "older", "write": {baseline: document(policy("older"), epoch - 1)}},
                {"name": "deleted", "remove": [baseline]},
                {"name": "restored_equal", "write": {baseline: document(policy("restored"), epoch)}},
                {
                    "name": "one_ns_same_float",
                    "write": {baseline: {"document": policy("one ns"), "mtime_ns": epoch * SECOND + 1}},
                },
                {"name": "newer_valid", "write": {baseline: document(policy("newer"), epoch + 2)}},
                {"name": "newer_invalid", "write": {baseline: {"text": "[invalid", "mtime_ns": (epoch + 4) * SECOND}}},
                {"name": "unchanged_invalid_retries"},
                {"name": "repair_same_candidate_mtime", "write": {baseline: document(policy("repaired"), epoch + 4)}},
            ],
        },
        {
            "name": "addon_lifecycle_retains_absent_watermark",
            "initial_files": {baseline: document(policy("initial"), 100)},
            "iterations": [
                {"name": "appears", "write": {"addons.yaml": document({"required": ["network-guard"]}, 50)}},
                {"name": "changes", "write": {"addons.yaml": document({"required": ["circuit-breaker"]}, 70)}},
                {"name": "deleted", "remove": ["addons.yaml"]},
                {
                    "name": "baseline_load_while_addon_absent",
                    "write": {baseline: document(policy("without addon"), 200)},
                },
                {
                    "name": "reappears_older_than_stale_mark",
                    "write": {"addons.yaml": document({"required": ["request-logger"]}, 60)},
                },
                {"name": "reappears_newer", "write": {"addons.yaml": document({"required": ["test-context"]}, 80)}},
            ],
        },
        {
            "name": "raw_lists_all_strings_use_one_maximum",
            "initial_files": {
                baseline: document(
                    {
                        "hosts": {"$used": {"egress": "allow"}},
                        "lists": {
                            "used": "used.txt",
                            "unused": "unused.txt",
                            "missing": "missing.txt",
                            "not_string": 7,
                        },
                    },
                    10,
                ),
                "used.txt": {"text": "initial.invalid\n", "mtime_ns": 100 * SECOND},
                "unused.txt": {"text": "unreferenced.invalid\n", "mtime_ns": 500 * SECOND},
            },
            "iterations": [
                {
                    "name": "used_changes_below_unrelated_max",
                    "write": {"used.txt": {"text": "changed.invalid\n", "mtime_ns": 400 * SECOND}},
                },
                {
                    "name": "missing_unreferenced_appears_above_max",
                    "write": {"missing.txt": {"text": "not-used.invalid\n", "mtime_ns": 600 * SECOND}},
                },
                {"name": "maximum_list_deleted", "remove": ["missing.txt"]},
                {
                    "name": "used_exceeds_old_max",
                    "write": {"used.txt": {"text": "newest.invalid\n", "mtime_ns": 700 * SECOND}},
                },
                {
                    "name": "unreferenced_list_triggers",
                    "write": {"unused.txt": {"text": "still-unused.invalid\n", "mtime_ns": 800 * SECOND}},
                },
                {"name": "used_list_deleted_without_new_max", "remove": ["used.txt"]},
            ],
        },
        {
            "name": "addon_only_list_is_not_watched",
            "initial_files": {
                baseline: document({"hosts": {"$addon": {"egress": "allow"}}}, 100),
                "addons.yaml": document({"lists": {"addon": "addon.txt"}}, 50),
                "addon.txt": {"text": "initial.invalid\n", "mtime_ns": 100 * SECOND},
            },
            "iterations": [
                {
                    "name": "list_only_change",
                    "write": {"addon.txt": {"text": "changed.invalid\n", "mtime_ns": 200 * SECOND}},
                },
                {
                    "name": "addon_timestamp_triggers_expansion",
                    "write": {"addons.yaml": document({"lists": {"addon": "addon.txt"}}, 60)},
                },
            ],
        },
        {
            "name": "later_check_failure_prevents_earlier_trigger",
            "initial_files": {baseline: document(policy("initial"), 100), "addons.yaml": document({}, 50)},
            "iterations": [
                {
                    "name": "baseline_newer_then_addon_stat_denied",
                    "write": {baseline: document(policy("candidate"), 200)},
                    "stat_error": {"path": "addons.yaml", "errno": "EACCES"},
                },
                {"name": "same_baseline_retries_after_stat_recovers"},
            ],
        },
        {
            "name": "success_audit_failure_publishes_watermarks",
            "initial_files": {baseline: document(policy("initial"), 100)},
            "iterations": [
                {
                    "name": "newer_success_submit_fails",
                    "write": {baseline: document(policy("published"), 200)},
                    "audit_failures": ["ops.policy_reload"],
                },
                {"name": "unchanged_published_candidate_does_not_retry"},
            ],
        },
        {
            "name": "baseline_is_its_own_addon_sibling",
            "baseline_path": "addons.yaml",
            "initial_files": {"addons.yaml": document(policy("initial"), 100)},
            "iterations": [
                {"name": "equal", "write": {"addons.yaml": document(policy("equal"), 100)}},
                {"name": "newer", "write": {"addons.yaml": document(policy("newer"), 101)}},
            ],
        },
        {
            "name": "raw_list_scan_errors_prevent_reload",
            "initial_files": {baseline: document(policy("initial"), 100)},
            "iterations": [
                {"name": "truthy_nonmapping", "write": {baseline: document([42], 200)}},
                {
                    "name": "nul_list_path",
                    "write": {baseline: document({"lists": {"bad": "bad\0path"}, "permissions": []}, 300)},
                },
                {"name": "repair", "write": {baseline: document(policy("repaired"), 400)}},
            ],
        },
        {
            "name": "post_validation_stat_failure_partially_publishes",
            "initial_files": {baseline: document(policy("initial"), 100)},
            "iterations": [
                {
                    "name": "new_model_then_stat_failure",
                    "write": {
                        baseline: document(
                            {
                                "metadata": {"description": "partially published"},
                                "permissions": [
                                    {"action": "network:request", "resource": "owned.invalid/*", "effect": "allow"}
                                ],
                            },
                            200,
                        )
                    },
                    "stat_error": {"path": baseline, "errno": "EACCES", "after_validate": True},
                },
                {"name": "same_candidate_retries"},
            ],
        },
    ]


def snapshot(loader):
    return {
        "watermarks": {
            "baseline": loader._last_baseline_mtime,
            "addons": loader._last_addons_mtime,
            "lists": loader._last_lists_mtime,
        },
        "policy": {
            "description": loader.baseline.metadata.description,
            "required": list(loader.baseline.required),
            "permissions_count": len(loader.baseline.permissions),
            "simple": [
                {"action": action, "effect": effect, "resources": sorted(resources)}
                for (action, effect), resources in loader._baseline_simple.items()
            ],
        },
    }


def mutate(directory, recipe):
    for path in recipe.get("remove", []):
        (directory / path).unlink()
    for path, value in recipe.get("write", {}).items():
        target = directory / path
        text = value["text"] if "text" in value else json.dumps(value["document"])
        target.write_text(text, encoding="utf-8")
        os.utime(target, ns=(value["mtime_ns"], value["mtime_ns"]))


def observe(spec, directory, modules):
    directory.mkdir()
    mutate(directory, {"write": spec["initial_files"]})
    loader = modules.loader.PolicyLoader()
    loader._baseline_path = directory / spec.get("baseline_path", "policy.yaml")
    current = {"name": "initial", "timeline": [], "events": [], "loads": [], "callbacks": 0, "warnings": []}
    watching = False
    validated = False
    selected = {}
    iterations = []
    real_stat = Path.stat
    real_load = loader._load_baseline
    real_max = loader._lists_max_mtime
    real_file = loader._load_file
    real_validate = modules.loader.UnifiedPolicy.model_validate

    def stat(path, *args, **kwargs):
        observed = watching and path.is_relative_to(directory)
        if observed:
            fault = selected.get("stat_error")
            if fault and path == directory / fault["path"] and (not fault.get("after_validate") or validated):
                number = getattr(errno, fault["errno"])
                error = OSError(number, os.strerror(number), str(path))
                current["timeline"].append(
                    {
                        "phase": "stat_raise",
                        "path": str(path.relative_to(directory)),
                        "class": type(error).__name__,
                        "errno": number,
                    }
                )
                raise error
        try:
            result = real_stat(path, *args, **kwargs)
        except (OSError, ValueError) as error:
            if observed:
                current["timeline"].append(
                    {
                        "phase": "stat_raise",
                        "path": str(path.relative_to(directory)),
                        "class": type(error).__name__,
                        "errno": getattr(error, "errno", None),
                    }
                )
            raise
        if observed:
            current["timeline"].append(
                {
                    "phase": "stat",
                    "path": str(path.relative_to(directory)),
                    "mtime": result.st_mtime,
                    "mtime_ns": result.st_mtime_ns,
                }
            )
        return result

    def load_file(path):
        assert path.is_relative_to(directory), "source loader must read owned paths"
        current["timeline"].append({"phase": "load_file", "path": str(path.relative_to(directory))})
        return real_file(path)

    def validate(raw, *args, **kwargs):
        nonlocal validated
        result = real_validate(raw, *args, **kwargs)
        validated = True
        current["timeline"].append({"phase": "model_validated", "permissions_count": len(result.permissions)})
        return result

    def lists_max():
        current["timeline"].append({"phase": "list_max_enter"})
        result = real_max()
        current["timeline"].append({"phase": "list_max_return", "mtime": result})
        return result

    def load_baseline():
        current["timeline"].append({"phase": "baseline_load_enter"})
        result = real_load()
        current["loads"].append(result)
        current["timeline"].append({"phase": "baseline_load_return", "result": result})
        return result

    def submit(entry):
        event = copy.deepcopy(entry)
        event["ts"] = "<canonical timestamp>"
        failed = event["event"] in selected.get("audit_failures", [])
        current["events"].append({"event": event, "accepted": not failed, "state_at_submit": snapshot(loader)})
        current["timeline"].append({"phase": "audit", "event": event["event"], "accepted": not failed})
        if failed:
            raise RuntimeError("owned policy watcher submission failure")

    def callback():
        current["callbacks"] += 1
        current["timeline"].append({"phase": "callback"})

    class Warnings(logging.Handler):
        def emit(self, record):
            current["warnings"].append({"level": record.levelname, "message": record.getMessage()})

    class FiniteStop:
        cursor = 0

        def is_set(self):
            nonlocal current, selected, watching, validated
            if self.cursor == len(spec["iterations"]):
                return True
            assert not watching
            selected = spec["iterations"][self.cursor]
            validated = False
            mutate(directory, selected)
            current = {
                "name": selected["name"],
                "timeline": [],
                "events": [],
                "loads": [],
                "callbacks": 0,
                "warnings": [],
            }
            watching = True
            return False

        def wait(self, *, timeout):
            nonlocal watching
            assert watching and timeout == 2.0
            watching = False
            current["wait_seconds"] = timeout
            current["after"] = snapshot(loader)
            iterations.append(current)
            self.cursor += 1
            return False

    captures = []

    class CapturedThread:
        def __init__(self, *, target, daemon, name):
            self.target = target
            self.daemon = daemon
            self.name = name
            self.started = False
            captures.append(self)

        def start(self):
            self.started = True

    loader.add_reload_callback(callback)
    logger = modules.loader.log
    with ExitStack() as stack:
        stack.enter_context(patch.object(Path, "stat", new=stat))
        stack.enter_context(patch.object(loader, "_load_file", side_effect=load_file))
        stack.enter_context(patch.object(loader, "_lists_max_mtime", side_effect=lists_max))
        stack.enter_context(patch.object(loader, "_load_baseline", side_effect=load_baseline))
        stack.enter_context(patch.object(modules.loader.UnifiedPolicy, "model_validate", side_effect=validate))
        stack.enter_context(patch.object(modules.audit_writer, "put_event", side_effect=submit))
        stack.enter_context(patch.object(logger, "handlers", [Warnings()]))
        stack.enter_context(patch.object(logger, "propagate", False))
        stack.enter_context(patch.object(logger, "level", logging.WARNING))
        assert loader._load_baseline() is True
        initial = {**current, "after": snapshot(loader)}
        loader._watcher_stop = FiniteStop()
        with patch.object(modules.loader.threading, "Thread", CapturedThread):
            loader.start_watcher()
            loader.start_watcher()
        assert len(captures) == 1 and captures[0].started and captures[0].daemon
        assert captures[0].name == "policy-watcher" and loader._task_policy_path is None
        captures[0].target()
        assert loader._watcher_stop.cursor == len(spec["iterations"])
    return {
        "input": spec,
        "initial": initial,
        "iterations": iterations,
        "thread": {"name": captures[0].name, "daemon": captures[0].daemon, "actual_thread_started": False},
    }


def check_contract(rows):
    by_name = {row["input"]["name"]: row for row in rows}
    baseline = by_name["baseline_strict_float_mtime_and_invalid_retry"]["iterations"]
    assert [item["loads"] for item in baseline] == [[], [], [], [], [], [True], [False], [False], [True]]
    assert baseline[4]["after"]["policy"]["description"] == "initial"
    first = next(item for item in baseline[4]["timeline"] if item["phase"] == "stat")
    assert first["mtime_ns"] == 1_700_000_000 * SECOND + 1 and first["mtime"] == 1_700_000_000.0
    assert baseline[6]["after"] == baseline[5]["after"] == baseline[7]["after"]
    addon = by_name["addon_lifecycle_retains_absent_watermark"]["iterations"]
    assert [item["loads"] for item in addon] == [[True], [True], [], [True], [], [True]]
    assert [item["after"]["watermarks"]["addons"] for item in addon] == [50.0, 70.0, 70.0, 70.0, 70.0, 80.0]
    assert addon[3]["after"]["policy"]["required"] == addon[4]["after"]["policy"]["required"] == []
    lists = by_name["raw_lists_all_strings_use_one_maximum"]
    assert lists["initial"]["after"]["watermarks"]["lists"] == 500.0
    assert [item["loads"] for item in lists["iterations"]] == [[], [True], [], [True], [True], []]
    assert [item["after"]["watermarks"]["lists"] for item in lists["iterations"]] == [
        500.0,
        600.0,
        600.0,
        700.0,
        800.0,
        800.0,
    ]
    assert lists["iterations"][0]["after"]["policy"]["simple"][0]["resources"] == ["initial.invalid/*"]
    assert lists["iterations"][1]["after"]["policy"]["simple"][0]["resources"] == ["changed.invalid/*"]
    ignored = by_name["addon_only_list_is_not_watched"]["iterations"]
    assert [item["loads"] for item in ignored] == [[], [True]]
    assert all(item["after"]["watermarks"]["lists"] == 0 for item in ignored)
    denied = by_name["later_check_failure_prevents_earlier_trigger"]
    assert denied["iterations"][0]["loads"] == [] and denied["iterations"][0]["events"] == []
    assert denied["iterations"][0]["after"] == denied["initial"]["after"]
    assert not any(item["phase"] == "list_max_enter" for item in denied["iterations"][0]["timeline"])
    assert denied["iterations"][0]["warnings"][0]["message"].startswith("Policy watcher error: PermissionError:")
    assert denied["iterations"][1]["loads"] == [True]
    audit = by_name["success_audit_failure_publishes_watermarks"]["iterations"]
    assert audit[0]["loads"] == [False] and audit[0]["callbacks"] == 0
    assert [item["event"]["event"] for item in audit[0]["events"]] == ["ops.policy_reload", "ops.policy_error"]
    assert [item["accepted"] for item in audit[0]["events"]] == [False, True]
    assert (
        audit[0]["after"]["watermarks"]["baseline"] == 200.0
        and audit[0]["after"]["policy"]["description"] == "published"
    )
    assert audit[1]["loads"] == [] and audit[1]["events"] == [] and audit[1]["after"] == audit[0]["after"]
    same = by_name["baseline_is_its_own_addon_sibling"]
    assert same["initial"]["after"]["watermarks"] == {"baseline": 100.0, "addons": 100.0, "lists": 0.0}
    assert [item["loads"] for item in same["iterations"]] == [[], [True]]
    assert same["iterations"][1]["after"]["watermarks"] == {"baseline": 101.0, "addons": 101.0, "lists": 0.0}
    raw = by_name["raw_list_scan_errors_prevent_reload"]
    for item, error_class in zip(raw["iterations"][:2], ["AttributeError", "ValueError"]):
        assert item["loads"] == [] and item["events"] == [] and item["after"] == raw["initial"]["after"]
        assert item["warnings"][0]["message"].startswith("Policy watcher error: " + error_class + ":")
    assert raw["iterations"][2]["loads"] == [True]
    partial = by_name["post_validation_stat_failure_partially_publishes"]["iterations"]
    assert partial[0]["loads"] == [False] and partial[0]["callbacks"] == 0
    assert partial[0]["after"]["watermarks"] == {"baseline": 100.0, "addons": 0, "lists": 0.0}
    assert partial[0]["after"]["policy"]["description"] == "partially published"
    assert partial[0]["after"]["policy"]["permissions_count"] == 1 and partial[0]["after"]["policy"]["simple"] == []
    assert partial[0]["events"][0]["event"]["event"] == "ops.policy_error"
    assert partial[1]["loads"] == [True] and partial[1]["after"]["policy"]["simple"][0]["resources"] == [
        "owned.invalid/*"
    ]
    assert sum(len(row["iterations"]) for row in rows) == 34
    assert all(item["wait_seconds"] == 2.0 for row in rows for item in row["iterations"])


def no_network(*_args, **_kwargs):
    raise AssertionError("this source oracle has no network operations")


def run():
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="owned-policy-watch-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        stack.enter_context(
            patch.dict(
                os.environ,
                {"SAFEYOLO_DATA_DIR": str(directory), "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl")},
            )
        )
        stack.enter_context(patch.object(socket, "create_connection", side_effect=no_network))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=no_network))
        from safeyolo.core import audit_writer
        from safeyolo.policy import loader

        modules = SimpleNamespace(loader=loader, audit_writer=audit_writer)
        rows = [observe(spec, directory / str(index), modules) for index, spec in enumerate(cases())]
        check_contract(rows)
        assert not (directory / "unused-audit.jsonl").exists()
        result = {
            "rows": rows,
            "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS},
        }
        result = json.loads(json.dumps(result).replace(str(directory), "<owned>"))
    assert not directory.exists()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = args.output or Path(__file__).with_suffix(".json")
    rendered = json.dumps(run(), indent=2) + "\n"
    if args.check:
        assert path.read_text(encoding="utf-8") == rendered, "source fixture drift"
    else:
        path.write_text(rendered, encoding="utf-8")
    print("PASS: 9 actual watcher closures, 34 foreground iterations, no background thread")


if __name__ == "__main__":
    main()
