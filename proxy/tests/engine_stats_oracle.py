# ruff: noqa: E402 -- Establish the isolated source import root first.
"""Focused source evaluation/statistics transitions with all network denied."""

import hashlib
import json
import logging
import os
import platform
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / "cli/src")]
from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module


def permission(action, resource, effect="allow", **fields):
    return {"action": action, "resource": resource, "effect": effect, **fields}


BASELINE = {
    "required": ["network_guard", "pattern_scanner", "fixture_control", "pattern_scanner"],
    "permissions": [
        permission("network:request", "allow.invalid/*"),
        permission("network:request", "deny.invalid/*", "deny"),
        permission("network:request", "prompt.invalid/*", "prompt"),
        permission("network:request", "limited.invalid/*", "budget", budget=1),
        permission("credential:use", "allow.invalid/*"),
        permission("credential:use", "deny.invalid/*", "deny"),
        permission("credential:use", "limited.invalid/*", "budget", budget=1),
        permission("gateway:risky_route", "*", condition={"service": "allowed"}),
        permission("gateway:risky_route", "*", "deny", condition={"service": "denied"}),
        permission("gateway:risky_route", "*", "budget", budget=1, condition={"service": "budgeted"}),
        permission("gateway:request", "fixture:/allowed"),
        permission("gateway:request", "fixture:/budget", "budget", budget=1),
    ],
}
RELOAD = {
    "hosts": {"simple.invalid": {"egress": "allow"}, "*.invalid": {"egress": "deny"}},
    "required": ["pattern_scanner", "fixture_control"],
}
TASK = {
    "permissions": [permission("network:request", "task.invalid/*"), permission("network:request", "other.invalid/*")]
}
OPERATIONS = [
    {"kind": "read"},
    *(
        {"kind": "network", "host": host}
        for host in ["allow.invalid", "deny.invalid", "prompt.invalid", "absent.invalid"]
    ),
    {"kind": "network", "host": "limited.invalid", "port": 0},
    {"kind": "network", "host": "limited.invalid", "consume": False},
    *({"kind": "network", "host": "limited.invalid"} for _ in range(3)),
    {"kind": "network", "host": "limited.invalid", "method": "CONNECT"},
    *(
        {"kind": "credential", "host": host}
        for host in [
            "allow.invalid",
            "deny.invalid",
            "absent.invalid",
            "limited.invalid",
            "limited.invalid",
            "limited.invalid",
        ]
    ),
    *({"kind": "risk", "service": service} for service in ["allowed", "denied", "absent", "budgeted"]),
    *({"kind": "gateway", "path": path} for path in ["/allowed", "/budget", "/absent"]),
    {"kind": "network", "host": "limited.invalid", "clock_error": True},
    {"kind": "credential", "host": "limited.invalid", "clock_error": True},
    {"kind": "read"},
    {"kind": "reload", "document": RELOAD},
    {"kind": "reload", "invalid": True},
    {"kind": "task", "document": TASK},
    {"kind": "task", "invalid": True},
    {"kind": "network", "host": "task.invalid"},
    {"kind": "task", "document": {}},
    {"kind": "clear_task"},
    {"kind": "read"},
]


ATTEMPTS = []


def reject_network(*_args, **_kwargs):
    ATTEMPTS.append(True)
    raise AssertionError("source stats oracle attempted network or credential issuance")


def main():
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="engine-stats-") as directory, ExitStack() as stack:
        root = Path(directory)
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory}))
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.budget_tracker.time.time", return_value=1000.0))
        stack.enter_context(patch("safeyolo.policy.compiler.mint_gateway_token", side_effect=reject_network))
        for target in ["socket.getaddrinfo", "socket.create_connection", "asyncio.open_connection"]:
            stack.enter_context(patch(target, side_effect=reject_network))
        for module in [loader_module, engine_module]:
            stack.enter_context(patch.object(module, "write_event"))
        unconfigured = engine_module.PolicyEngine().get_stats()
        baseline = root / "baseline.json"
        task = root / "task.json"
        baseline.write_text(json.dumps(BASELINE))
        engine = engine_module.PolicyEngine(Path(str(root) + "/./baseline.json"))

        def snapshot():
            value = engine.get_stats()
            for field in ["baseline_path", "task_policy_path"]:
                if value[field] is not None:
                    value[field] = value[field].replace(str(root), "$ROOT", 1)
            return value

        initial = snapshot()
        rows = []
        for operation in OPERATIONS:
            before = snapshot()
            kind = operation["kind"]
            try:
                with ExitStack() as clock:
                    if operation.get("clock_error"):
                        clock.enter_context(
                            patch(
                                "safeyolo.policy.budget_tracker.time.time",
                                side_effect=RuntimeError("synthetic clock failure"),
                            )
                        )
                    if kind == "network":
                        value = engine.evaluate_request(
                            operation["host"],
                            port=operation.get("port"),
                            method=operation.get("method", "GET"),
                            consume_budget=operation.get("consume", True),
                        ).effect
                    elif kind == "credential":
                        value = engine.evaluate_credential("fixture", operation["host"]).effect
                    elif kind == "risk":
                        value = engine.evaluate_risky_route(
                            operation["service"], "alice", "account", [], [], False
                        ).effect
                    elif kind == "gateway":
                        value = engine.evaluate_gateway_request(
                            "fixture", "reader", "alice", "GET", operation["path"]
                        ).effect
                    elif kind in ["reload", "task"]:
                        path = baseline if kind == "reload" else task
                        path.write_text("{" if operation.get("invalid") else json.dumps(operation["document"]))
                        value = (
                            engine._loader.reload()
                            if kind == "reload"
                            else engine.load_task_policy(Path(str(root) + "/./task.json"))
                        )
                    elif kind == "clear_task":
                        engine.clear_task_policy()
                        value = None
                    else:
                        engine.get_stats()
                        engine.get_budget_stats()
                        value = None
                    outcome = {"value": value}
            except Exception as error:
                outcome = {"error": type(error).__name__}
            after = snapshot()
            rows.append(
                {
                    "operation": operation,
                    "outcome": outcome,
                    "after": after,
                    "count_delta": after["evaluations"] - before["evaluations"],
                }
            )
        paths = ["", ".", "./", "./a//b/./../c/", "//a///b//", "///a//b", "a/../b", "a\\b", "é/份额", "/", "//", "///"]
        assert not ATTEMPTS, "source stats oracle attempted network or credential issuance"
        result = {
            "source_commit": "838319a1a6a97a5317350e678fda6abc5a44fed1",
            "python": platform.python_version(),
            "source_hashes": {
                name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                for name in [
                    "cli/src/safeyolo/policy/engine.py",
                    "cli/src/safeyolo/policy/loader.py",
                    "cli/src/safeyolo/policy/budget_tracker.py",
                ]
            },
            "baseline": BASELINE,
            "initial": initial,
            "unconfigured": unconfigured,
            "rows": rows,
            "path_rows": [{"raw": path, "display": str(Path(path))} for path in paths],
            "external_network_attempts": 0,
            "issued_credentials": 0,
        }
        if "--emit" in sys.argv:
            print(json.dumps(result))
        else:
            Path(__file__).with_name("engine_stats_source.json").write_text(json.dumps(result, indent=2) + "\n")
            print(
                json.dumps(
                    {
                        "operations": len(rows),
                        "path_rows": len(paths),
                        "final_evaluations": rows[-1]["after"]["evaluations"],
                    }
                )
            )


if __name__ == "__main__":
    main()
