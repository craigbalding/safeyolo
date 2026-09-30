"""Finite actual-source inner declaration handler/clock observations, no I/O."""

from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]

from mitmproxy.test import tflow  # noqa: E402

from safeyolo.core import config_cache, utils  # noqa: E402
from safeyolo.mitm_addons import agent_api as api_module  # noqa: E402
from safeyolo.mitm_addons import test_context as tc_module  # noqa: E402


def action(body=None, method="POST", now="0", limit=900):
    return {"method": method, "body": body, "now": now, "limit": limit}


def cases():
    valid = '"context":"run=R;agent=claimed"'
    rows = []
    for label, body in [
        ("missing-body", None),
        ("null-body", "null"),
        ("array-body", "[]"),
        ("missing-context", "{}"),
        ("typed-context-before-ttl", '{"context":NaN,"ttl":NaN}'),
        ("parse-context-before-ttl", '{"context":"broken","ttl":NaN}'),
        ("null-ttl", "{" + valid + ',"ttl":null}'),
        ("boolean-ttl", "{" + valid + ',"ttl":true}'),
        ("zero-ttl", "{" + valid + ',"ttl":0}'),
        ("negative-ttl", "{" + valid + ',"ttl":-1}'),
        ("float-ttl", "{" + valid + ',"ttl":1.0}'),
        ("exponent-ttl", "{" + valid + ',"ttl":1e0}'),
        ("nan-ttl", "{" + valid + ',"ttl":NaN}'),
        ("infinity-ttl", "{" + valid + ',"ttl":Infinity}'),
        ("string-ttl", "{" + valid + ',"ttl":"1"}'),
        ("unused-nonfinite", "{" + valid + ',"unused":{"a":NaN,"b":[Infinity,-Infinity]}}'),
        ("unused-deep", "{" + valid + ',"unused":' + "[" * 128 + "NaN" + "]" * 128 + "}"),
        ("huge-request-capped", "{" + valid + ',"ttl":' + str(10**400) + "}"),
    ]:
        rows.append({"case": label, "actions": [action(body), action(method="GET")]})
    maximum = ((1 << 53) - 1) << 971
    half_step = 1 << 970
    for label, limit, now in [
        ("integer-conversion-overflow", 10**400, "0"),
        ("maximum-integer-float", maximum, "0"),
        ("rounding-below-overflow", maximum + half_step - 1, "0"),
        ("rounding-at-overflow", maximum + half_step, "0"),
        ("finite-addition-infinity", maximum, "1e308"),
        ("nan-clock", 2, "nan"),
        ("positive-infinite-clock", 2, "inf"),
        ("negative-infinite-clock", 2, "-inf"),
    ]:
        rows.append(
            {
                "case": label,
                "actions": [
                    action("{" + valid + "}", limit=limit, now=now),
                    action(method="GET"),
                    {"method": "stats", "now": "0", "limit": limit},
                ],
            }
        )
    rows += [
        {
            "case": "huge-limit-small-request",
            "actions": [action("{" + valid + ',"ttl":1}', limit=10**400), action(method="GET")],
        },
        {
            "case": "remaining-float-subtraction-overflow",
            "actions": [
                action("{" + valid + "}", now=str(sys.float_info.max), limit=1),
                action(method="GET", now=str(-sys.float_info.max)),
            ],
        },
        {"case": "nan-remaining-then-delete", "actions": [action(method="GET", now="nan"), action(method="DELETE")]},
        {"case": "get-ignores-body", "actions": [action('{"context":NaN,"ttl":Infinity}', method="GET")]},
    ]
    return rows


def observe_trace(row):
    owner = tc_module.TestContext()
    api = api_module.AgentAPI()
    now = 0.0
    limit = 900
    current = {}
    output = []
    result = {}

    def respond(_flow, status, body):
        result.update(status=status, body=body)

    def event(name, **kwargs):
        result["audit"] = {
            "event": name,
            "source_id": "owned-source",
            "trusted_agent": "alice",
            "details": kwargs["details"],
        }

    def sensor():
        return {"addons": {"test_context": {"declared_ttl_max": limit}}}

    with (
        patch.object(tc_module.time, "monotonic", lambda: now),
        patch.object(config_cache._cache, "get", sensor),
        patch.object(tc_module, "get_option_safe", lambda name, default: default),
        patch.object(api_module, "write_event", event),
        patch.object(utils, "get_client_ip", lambda flow: "owned-source"),
    ):
        owner.set_declaration("owned-source", "alice", {"run": "prior", "agent": "alice"}, 7)
        api._respond = respond
        api._resolve_agent_id = lambda flow: "alice"
        api._find_addon = lambda name: owner
        api._read_json_body = lambda flow: current
        for spec in row["actions"]:
            now = float(spec["now"])
            limit = spec["limit"]
            current = json.loads(spec["body"]) if spec.get("body") is not None else None
            result = {"error": None, "audit": None}
            try:
                if spec["method"] == "stats":
                    result["stats"] = owner.get_stats()
                else:
                    flow = tflow.tflow()
                    flow.request.method = spec["method"]
                    api._handle_test_context_current(flow)
            except (ValueError, OverflowError) as exc:
                result["error"] = type(exc).__name__
            record = owner._declarations.get("owned-source")
            result["record"] = (
                None
                if record is None
                else {"agent": record[0], "context": record[1], "expiry_bits": struct.pack(">d", record[2]).hex()}
            )
            output.append(result)
    return {"case": row["case"], "actions": row["actions"], "observations": output}


def observe(rows):
    rows = [observe_trace(row) for row in rows]
    return {"rows": rows, "trace_count": len(rows), "operation_count": sum(len(row["actions"]) for row in rows)}


if __name__ == "__main__":
    rows = cases() if "--generate" in sys.argv else json.load(sys.stdin)
    print(json.dumps(observe(rows), ensure_ascii=False, indent=2))
