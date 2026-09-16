"""Actual baseline expiry persistence on owned files and a finite watcher.

Only the expiry clock, final audit submission, selected move/directory-fsync
faults, and watcher Thread/stop-wait scheduling are supplied. Parsing,
normalization, pruning, round-trip saving, compilation and validation are real.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import errno
import hashlib
import json
import logging
import os
import socket
import stat
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
NOW = "2026-01-02T00:00:00+00:00"
SECOND = 1_000_000_000
SOURCE_PATHS = [
    "cli/src/safeyolo/policy/loader.py",
    "cli/src/safeyolo/policy/toml_roundtrip.py",
    "cli/src/safeyolo/policy/toml_normalize.py",
    "cli/src/safeyolo/policy/compiler.py",
    "cli/src/safeyolo/policy/models.py",
    "cli/src/safeyolo/core/utils.py",
    "cli/src/safeyolo/core/audit_schema.py",
]
SIMPLE = """# Keep the operator's leading comment.
description = "expiry fixture"

[hosts]
"expired.invalid" = { egress = "deny", expires = 2026-01-02T00:00:00Z } # remove this line
"permanent.invalid" = { egress = "allow" } # retain this comment
"""


def cases():
    mixed = """# Keep this heading.
description = "mixed expiry"
[hosts]
"past.invalid" = { egress = "deny", expires = 2026-01-01T00:00:00Z }
"equal.invalid" = { egress = "deny", expires = "2026-01-02T00:00:00+00:00" }
"naive.invalid" = { egress = "deny", expires = 2026-01-01T00:00:00 }
"future.invalid" = { egress = "allow", expires = 2027-01-01T00:00:00Z } # retain future
"invalid.invalid" = { egress = "deny", expires = "next tuesday" }
"integer.invalid" = { egress = "deny", expires = 42 }
"date.invalid" = { egress = "deny", expires = 2020-01-01 }
"permanent.invalid" = { egress = "allow" }
"""
    document = {
        "hosts": {
            "expired.invalid": {"egress": "deny", "expires": "2026-01-02T00:00:00+00:00"},
            "permanent.invalid": {"egress": "allow"},
        }
    }
    return [
        {"name": "mixed_toml_expiry_and_comments", "text": mixed, "steps": [{"operation": "load"}]},
        {
            "name": "no_expired_entry_no_write",
            "text": mixed.replace("2026-01-01", "2027-01-01").replace("2026-01-02", "2027-01-02"),
            "steps": [{"operation": "load"}, {"operation": "load"}],
        },
        {
            "name": "prune_precedes_compile_rejection",
            "text": 'description="accepted"\n[hosts]\n"accepted.invalid"={egress="allow"}\n',
            "steps": [
                {"operation": "load"},
                {
                    "operation": "load",
                    "write": "budget = 10\n" + SIMPLE + '"invalid-rate.invalid" = { rate = 0 }\n',
                    "mtime_ns": 2000 * SECOND,
                },
            ],
        },
        {
            "name": "yaml_prunes_without_disk_write",
            "filename": "policy.yaml",
            "text": json.dumps(document),
            "steps": [{"operation": "load"}],
        },
        {
            "name": "json_prunes_without_disk_write",
            "filename": "policy.json",
            "text": json.dumps(document),
            "steps": [{"operation": "load"}],
        },
        {
            "name": "top_level_only_agent_host_retained",
            "text": SIMPLE
            + """
[agents.alice.hosts]
"agent-expired.invalid" = { egress = "allow", expires = 2020-01-01T00:00:00Z, rate = 3 } # agent survives
""",
            "steps": [{"operation": "load"}],
        },
        {"name": "configured_symlink_is_replaced", "text": SIMPLE, "symlink": True, "steps": [{"operation": "load"}]},
        {
            "name": "move_error_keeps_disk_and_accepts_pruned_memory",
            "text": SIMPLE,
            "steps": [{"operation": "load", "fault": "move"}, {"operation": "load"}],
        },
        {
            "name": "directory_fsync_error_after_visible_replacement",
            "text": SIMPLE,
            "steps": [{"operation": "load", "fault": "directory_fsync"}, {"operation": "load"}],
        },
        {
            "name": "watcher_time_alone_does_not_prune",
            "text": SIMPLE,
            "steps": [
                {"operation": "load", "now": "2026-01-01T00:00:00+00:00"},
                {"operation": "watch"},
                {"operation": "watch", "touch_ns": 2000 * SECOND},
                {"operation": "watch"},
            ],
        },
    ]


def observe(spec, directory, modules):
    directory.mkdir()
    path = directory / spec.get("filename", "policy.toml")
    target = directory / "target.toml" if spec.get("symlink") else path
    target.write_text(spec["text"], encoding="utf-8")
    target.chmod(0o640)
    os.utime(target, ns=(1000 * SECOND, 1000 * SECOND))
    if spec.get("symlink"):
        path.symlink_to(target.name)
    loader = modules.loader.PolicyLoader()
    loader._baseline_path = path
    current = {}
    selected = {}
    saved_times = {}
    save_index = 0
    original_datetime = datetime.datetime
    real_load = loader._load_baseline
    real_save = modules.roundtrip.save_roundtrip
    real_move = modules.roundtrip.shutil.move
    real_fsync = modules.roundtrip.os.fsync
    real_compile = modules.loader.compile_policy
    real_validate = modules.loader.UnifiedPolicy.model_validate

    def time_value(value):
        return saved_times.get(value, value)

    def disk(file):
        metadata = file.stat()
        return {
            "text": file.read_text(encoding="utf-8"),
            "mode": oct(stat.S_IMODE(metadata.st_mode)),
            "mtime_ns": time_value(metadata.st_mtime_ns),
            "is_symlink": file.is_symlink(),
        }

    def policy():
        return {
            "description": loader.baseline.metadata.description,
            "permissions": [item.model_dump(mode="json", exclude_none=True) for item in loader.baseline.permissions],
            "simple": [
                {"action": action, "effect": effect, "resources": sorted(resources)}
                for (action, effect), resources in loader._baseline_simple.items()
            ],
            "watermarks": {
                "baseline": time_value(loader._last_baseline_mtime),
                "addons": loader._last_addons_mtime,
                "lists": loader._last_lists_mtime,
            },
        }

    class ClockMeta(type):
        def __instancecheck__(cls, instance):
            return isinstance(instance, original_datetime)

    class Clock(original_datetime, metaclass=ClockMeta):
        @classmethod
        def now(cls, tz=None):
            value = original_datetime.fromisoformat(selected.get("now", NOW))
            current["timeline"].append({"phase": "expiry_clock", "now": value.isoformat()})
            return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)

    def submit(entry):
        event = copy.deepcopy(entry)
        event["ts"] = "<canonical timestamp>"
        current["events"].append({"event": event, "policy": policy(), "disk": disk(path)})
        current["timeline"].append({"phase": "audit", "event": event["event"]})

    def save(file, doc):
        nonlocal save_index
        assert file == path
        before = file.stat().st_ino
        current["timeline"].append({"phase": "save_enter"})
        try:
            real_save(file, doc)
        except OSError as error:
            current["timeline"].append(
                {"phase": "save_error", "class": type(error).__name__, "committed": getattr(error, "committed", None)}
            )
            raise
        else:
            current["timeline"].append({"phase": "save_return"})
        finally:
            metadata = file.stat()
            if metadata.st_ino != before:
                save_index += 1
                label = f"<save {save_index} mtime>"
                saved_times[metadata.st_mtime_ns] = label
                saved_times[metadata.st_mtime] = label

    def move(source, destination, *args, **kwargs):
        assert Path(source).parent == directory and Path(destination) == path
        current["timeline"].append({"phase": "move", "injected_error": selected.get("fault") == "move"})
        if selected.get("fault") == "move":
            raise OSError(errno.EIO, "owned move failure")
        return real_move(source, destination, *args, **kwargs)

    def fsync(fd):
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        failed = is_directory and selected.get("fault") == "directory_fsync"
        current["timeline"].append({"phase": "fsync", "directory": is_directory, "injected_error": failed})
        if failed:
            raise OSError(errno.EIO, "owned directory fsync failure")
        return real_fsync(fd)

    def compile_policy(raw):
        current["timeline"].append(
            {
                "phase": "compile",
                "hosts": list(raw.get("hosts", {})),
                "agent_hosts": {agent: list(value.get("hosts", {})) for agent, value in raw.get("agents", {}).items()},
            }
        )
        return real_compile(raw)

    def validate(raw, *args, **kwargs):
        current["timeline"].append({"phase": "validate"})
        return real_validate(raw, *args, **kwargs)

    def load():
        current["timeline"].append({"phase": "load_enter"})
        result = real_load()
        current["loads"].append(result)
        current["timeline"].append({"phase": "load_return", "result": result})
        return result

    def callback():
        current["callbacks"] += 1
        current["timeline"].append({"phase": "callback"})

    class Warnings(logging.Handler):
        def emit(self, record):
            current["warnings"].append({"level": record.levelname, "message": record.getMessage()})

    def begin(recipe):
        nonlocal current, selected
        selected = recipe
        if "write" in recipe:
            path.write_text(recipe["write"], encoding="utf-8")
            os.utime(path, ns=(recipe["mtime_ns"], recipe["mtime_ns"]))
        if "touch_ns" in recipe:
            os.utime(path, ns=(recipe["touch_ns"], recipe["touch_ns"]))
        current = {
            "operation": recipe["operation"],
            "before_disk": disk(path),
            "timeline": [],
            "events": [],
            "loads": [],
            "callbacks": 0,
            "warnings": [],
        }
        return path.stat().st_ino

    def finish(before_inode):
        current["after_disk"] = disk(path)
        current["inode_replaced"] = path.stat().st_ino != before_inode
        current["policy"] = policy()
        current["remaining_files"] = sorted(file.name for file in directory.iterdir())
        if spec.get("symlink"):
            current["target_disk"] = disk(target)
        steps.append(current)

    captures = []

    class CapturedThread:
        def __init__(self, *, target, daemon, name):
            assert daemon and name == "policy-watcher"
            self.target = target
            captures.append(self)

        def start(self):
            pass  # Explicit foreground target execution below; no thread starts.

    watcher_recipes = [item for item in spec["steps"] if item["operation"] == "watch"]

    class FiniteStop:
        cursor = 0
        before_inode = None

        def is_set(self):
            if self.cursor == len(watcher_recipes):
                return True
            self.before_inode = begin(watcher_recipes[self.cursor])
            return False

        def wait(self, *, timeout):
            assert timeout == 2.0
            current["wait_seconds"] = timeout
            finish(self.before_inode)
            self.cursor += 1
            return False

    steps = []
    loader.add_reload_callback(callback)
    with ExitStack() as stack:
        stack.enter_context(patch.object(datetime, "datetime", Clock))
        stack.enter_context(patch.object(modules.audit_writer, "put_event", side_effect=submit))
        stack.enter_context(patch.object(modules.roundtrip, "save_roundtrip", side_effect=save))
        stack.enter_context(patch.object(modules.roundtrip.shutil, "move", side_effect=move))
        stack.enter_context(patch.object(modules.roundtrip.os, "fsync", side_effect=fsync))
        stack.enter_context(patch.object(modules.loader, "compile_policy", side_effect=compile_policy))
        stack.enter_context(patch.object(modules.loader.UnifiedPolicy, "model_validate", side_effect=validate))
        stack.enter_context(patch.object(loader, "_load_baseline", side_effect=load))
        for logger in (modules.loader.log, modules.roundtrip.log):
            stack.enter_context(patch.object(logger, "handlers", [Warnings()]))
            stack.enter_context(patch.object(logger, "propagate", False))
            stack.enter_context(patch.object(logger, "level", logging.WARNING))
        for recipe in spec["steps"]:
            if recipe["operation"] == "watch":
                break
            before = begin(recipe)
            loader._load_baseline()
            finish(before)
        if watcher_recipes:
            loader._watcher_stop = FiniteStop()
            with patch.object(modules.loader.threading, "Thread", CapturedThread):
                loader.start_watcher()
            assert len(captures) == 1
            captures[0].target()
            assert loader._watcher_stop.cursor == len(watcher_recipes)
        assert loader._task_policy_path is None
    return {
        "input": {"filename": "policy.toml", "mode": "0o640", "mtime_ns": 1000 * SECOND, "now": NOW, **spec},
        "steps": steps,
        "actual_thread_started": False,
    }


def check_contract(rows):
    found = {row["input"]["name"]: row["steps"] for row in rows}
    mixed = found["mixed_toml_expiry_and_comments"][0]
    assert mixed["loads"] == [True] and mixed["inode_replaced"]
    assert mixed["before_disk"]["mode"] == "0o640" and mixed["after_disk"]["mode"] == "0o600"
    for name in ("past.invalid", "equal.invalid", "naive.invalid"):
        assert name not in mixed["after_disk"]["text"]
    for name in ("future.invalid", "invalid.invalid", "integer.invalid", "date.invalid", "permanent.invalid"):
        assert name in mixed["after_disk"]["text"]
    assert "# Keep this heading." in mixed["after_disk"]["text"] and "# retain future" in mixed["after_disk"]["text"]
    assert len(mixed["warnings"]) == 3
    for step in found["no_expired_entry_no_write"]:
        assert step["loads"] == [True] and step["before_disk"] == step["after_disk"] and not step["inode_replaced"]
        assert not any(item["phase"] == "save_enter" for item in step["timeline"])
    rejected = found["prune_precedes_compile_rejection"]
    assert rejected[1]["loads"] == [False] and rejected[1]["policy"] == rejected[0]["policy"]
    assert rejected[1]["inode_replaced"] and "expired.invalid" not in rejected[1]["after_disk"]["text"]
    assert rejected[1]["events"][0]["event"]["event"] == "ops.policy_error"
    assert rejected[1]["callbacks"] == 0
    for name in ("yaml_prunes_without_disk_write", "json_prunes_without_disk_write"):
        step = found[name][0]
        assert step["loads"] == [True] and step["before_disk"] == step["after_disk"] and not step["inode_replaced"]
        assert all("expired.invalid/*" not in group["resources"] for group in step["policy"]["simple"])
    agent = found["top_level_only_agent_host_retained"][0]
    assert agent["loads"] == [True] and '"expired.invalid"' not in agent["after_disk"]["text"]
    assert "agent-expired.invalid" in agent["after_disk"]["text"]
    assert any(
        item["condition"].get("agent") == "alice" and item["resource"] == "agent-expired.invalid/*"
        for item in agent["policy"]["permissions"]
    )
    link = found["configured_symlink_is_replaced"][0]
    assert link["loads"] == [True] and link["before_disk"]["is_symlink"] and not link["after_disk"]["is_symlink"]
    assert link["target_disk"]["text"] == SIMPLE and link["target_disk"]["mode"] == "0o640"
    move = found["move_error_keeps_disk_and_accepts_pruned_memory"]
    assert (
        move[0]["loads"] == [True] and move[0]["before_disk"] == move[0]["after_disk"] and not move[0]["inode_replaced"]
    )
    assert move[0]["remaining_files"] == ["policy.toml"] and len(move[0]["warnings"]) == 1
    assert move[0]["policy"]["simple"] == move[1]["policy"]["simple"] and move[1]["inode_replaced"]
    committed = found["directory_fsync_error_after_visible_replacement"]
    assert committed[0]["loads"] == [True] and committed[0]["inode_replaced"] and len(committed[0]["warnings"]) == 1
    assert any(
        item["phase"] == "save_error" and item["class"] == "PolicySaveError" and item["committed"]
        for item in committed[0]["timeline"]
    )
    assert committed[1]["before_disk"] == committed[1]["after_disk"] and not committed[1]["inode_replaced"]
    watcher = found["watcher_time_alone_does_not_prune"]
    assert [step["loads"] for step in watcher] == [[True], [], [True], []]
    assert watcher[0]["after_disk"] == watcher[1]["after_disk"] and not watcher[1]["events"]
    assert watcher[2]["inode_replaced"] and watcher[2]["after_disk"] == watcher[3]["after_disk"]
    assert watcher[2]["policy"]["watermarks"]["baseline"] == watcher[2]["after_disk"]["mtime_ns"]
    for row in rows:
        for step in row["steps"]:
            assert step["remaining_files"] == (
                ["policy.toml", "target.toml"] if row["input"].get("symlink") else [row["input"]["filename"]]
            )
            if step["loads"] == [True]:
                assert step["callbacks"] == 1 and [item["event"]["event"] for item in step["events"]] == [
                    "ops.policy_reload"
                ]
            phases = [item["phase"] for item in step["timeline"]]
            if "save_enter" in phases:
                assert phases.index("save_enter") < phases.index("compile") < phases.index("audit")
    assert len(rows) == 10 and sum(len(row["steps"]) for row in rows) == 17


def no_network(*_args, **_kwargs):
    raise AssertionError("expiry source oracle has no network operations")


def run():
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="owned-policy-expiry-") as temporary, ExitStack() as stack:
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
        from safeyolo.policy import loader, toml_roundtrip

        modules = SimpleNamespace(loader=loader, audit_writer=audit_writer, roundtrip=toml_roundtrip)
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
    print("PASS: 10 expiry workflows, 17 load/watch steps; real owned-file round-trip writes")


if __name__ == "__main__":
    main()
