"""Finite, isolated observations of the shipped TestContext configuration hooks."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]

from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

from safeyolo.core import config_cache  # noqa: E402
from safeyolo.mitm_addons import test_context as module  # noqa: E402


def sensor(targets, policy_hash="a", **fields):
    return {"policy_hash": policy_hash, "addons": {"test_context": {"target_hosts": targets, **fields}}}


def configure(value):
    return {"action": "configure", "sensor": value}


def request(host="target.invalid", header=None, prior=False):
    return {"action": "request", "host": host, "header": header, "prior": prior}


def cases():
    rows = []
    targets = [
        (
            "list-wildcards",
            ["*.target.invalid", "literal*"],
            ["target.invalid", "DEEP.TARGET.INVALID", "evil-target.invalid", "literal*", "literalx"],
        ),
        ("string-characters", "aé", ["a", "A", "é", "aé", "target.invalid"]),
        ("string-domain-is-characters", "target.invalid", ["target.invalid", "t", "."]),
        (
            "mapping-keys-only",
            {"*.target.invalid": None, "other.invalid": [False]},
            ["target.invalid", "OTHER.INVALID", "else.invalid"],
        ),
        (
            "list-lazy-error",
            ["target.invalid", False, "later.invalid"],
            ["target.invalid", "other.invalid", "later.invalid"],
        ),
        ("list-leading-error", [False, "target.invalid"], ["target.invalid"]),
        ("list-nested-error", [[], "target.invalid"], ["target.invalid"]),
        ("list-object-error", [{"target.invalid": True}], ["target.invalid"]),
        ("empty-list", [], ["target.invalid"]),
        ("empty-string", "", ["target.invalid"]),
        ("empty-map", {}, ["target.invalid"]),
        ("null", None, ["target.invalid"]),
        ("false", False, ["target.invalid"]),
        ("zero", 0, ["target.invalid"]),
        ("true", True, ["target.invalid"]),
        ("integer", 7, ["target.invalid"]),
        ("float", 1.5, ["target.invalid"]),
    ]
    for label, value, hosts in targets:
        rows.append(
            {
                "case": label,
                "steps": [configure(sensor(value)), {"action": "stats"}] + [request(host) for host in hosts],
            }
        )
    rows += [
        {
            "case": "initial-empty-hash-skips",
            "steps": [
                configure(sensor(["target.invalid"], "")),
                request(),
                configure(sensor(["target.invalid"])),
                request(),
            ],
        },
        {
            "case": "unchanged-skips-new-targets",
            "steps": [
                configure(sensor(["target.invalid"])),
                configure(sensor(None)),
                request(),
                configure(sensor({}, "b")),
                request(),
            ],
        },
        {
            "case": "omitted-target-clears",
            "steps": [
                configure(sensor(["target.invalid"])),
                configure({"policy_hash": "b", "addons": {"test_context": {}}}),
                request(),
            ],
        },
        {"case": "unavailable-retains", "steps": [configure(sensor(["target.invalid"])), configure(None), request()]},
        {
            "case": "nested-not-flattened",
            "steps": [
                configure(
                    {"policy_hash": "a", "addons": {"test_context": {"settings": {"target_hosts": ["target.invalid"]}}}}
                ),
                request(),
            ],
        },
        {
            "case": "assignment-before-log-error",
            "steps": [
                configure(sensor(["target.invalid"])),
                configure(sensor(1, "b")),
                configure(sensor(["target.invalid"], "b")),
                request(),
                {"action": "stats"},
                configure(sensor(["target.invalid"], "c")),
                request(),
            ],
        },
        {
            "case": "request-error-before-header-removal",
            "steps": [
                configure(sensor([None])),
                request(header="run=r;agent=a"),
                request(header=""),
                request(header="broken"),
                request(header="run=r;agent=a", prior=True),
            ],
        },
        {
            "case": "declared-options-without-target-refresh",
            "steps": [
                configure(sensor(["target.invalid"], "a", declared_ttl_max=10)),
                {"action": "declare", "sensor": sensor([], "b", declared_ttl_max=2, inject_declared=True)},
                {"action": "stats"},
                request(),
                {"action": "configure", "sensor": sensor([], "b", declared_ttl_max=2, inject_declared=True)},
                request(),
            ],
        },
    ]
    rows.append(
        {
            "case": "stats-error-before-declaration-expiry-cleanup",
            "steps": [
                configure(sensor(["target.invalid"], declared_ttl_max=2)),
                {"action": "declare", "sensor": sensor(["target.invalid"], declared_ttl_max=2)},
                configure(sensor(None, "b")),
                {"action": "stats", "now": 3},
                configure(sensor([], "c")),
                {"action": "stats", "now": 3},
            ],
        }
    )
    return rows


def observe_trace(row):
    owner = module.TestContext()
    current = None
    now = 0.0
    observations = []
    owner.log_decision = lambda *args, **kwargs: None
    owner.should_block = lambda: True

    def get_config():
        if current is None:
            raise RuntimeError("isolated cache unavailable")
        return current

    with (
        patch.object(config_cache, "get_or_raise", get_config),
        patch.object(config_cache._cache, "get", lambda: current or {}),
        patch.object(module, "get_option_safe", lambda name, default: default),
        patch.object(module, "write_event", lambda *args, **kwargs: None),
        patch.object(module.time, "monotonic", lambda: now),
    ):
        for step in row["steps"]:
            action = step["action"]
            now = step.get("now", 0.0)
            result = {"action": action, "error": None}
            if action in ("configure", "declare"):
                current = step["sensor"]
            try:
                if action == "configure":
                    owner._maybe_reload_config()
                elif action == "declare":
                    result["ttl"] = owner.set_declaration("owned-source", "alice", {"run": "r", "agent": "a"}, None)
                elif action == "stats":
                    result["stats"] = owner.get_stats()
                elif action == "request":
                    flow = tflow.tflow()
                    flow.request.host = step["host"]
                    flow.request.headers = http.Headers([])
                    if step["header"] is not None:
                        flow.request.headers[module.TEST_CONTEXT_HEADER] = step["header"]
                    flow.response = http.Response.make(200, b"") if step["prior"] else None
                    try:
                        owner.request(flow)
                    finally:
                        result["status"] = flow.response.status_code if flow.response else 0
                        result["header_retained"] = module.TEST_CONTEXT_HEADER in flow.request.headers
                else:
                    raise AssertionError("unknown fixture operation")
            except (AttributeError, TypeError) as exc:
                result["error"] = type(exc).__name__
            result["declaration_records"] = len(owner._declarations)
            result["targets"] = owner._target_hosts
            result["hash"] = owner._last_policy_hash
            result["counts"] = {
                "checks": owner.stats.checks,
                "allowed": owner.stats.allowed,
                "blocked": owner.stats.blocked,
                "warned": owner.stats.warned,
            }
            observations.append(result)
    return {"case": row["case"], "steps": row["steps"], "observations": observations}


def observe(rows):
    results = [observe_trace(row) for row in rows]
    return {"rows": results, "trace_count": len(results), "operation_count": sum(len(row["steps"]) for row in results)}


if __name__ == "__main__":
    rows = cases() if "--generate" in sys.argv else json.load(sys.stdin)
    print(json.dumps(observe(rows), ensure_ascii=False, indent=2))
