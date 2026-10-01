"""Finite actual TraceStore and AgentAPI trace source oracle.

Uses owned memory/flows, explicit clocks and a temporary synthetic agent token.
Store quirks remain unchanged. No sockets, doctor probes or operational state.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import secrets
import socket
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
A, B, C, D = ["req-" + char * 32 for char in "abcd"]
CLOCK = {"now": 0.0}
ENV = {
    "SAFEYOLO_TRACE_TTL_S": "300",
    "SAFEYOLO_TRACE_GLOBAL_MAX": "1000",
    "SAFEYOLO_TRACE_PER_AGENT_MAX": "200",
    "SAFEYOLO_TRACE_STEPS_MAX": "128",
    "SAFEYOLO_TRACE_DETAILS_MAX_BYTES": "4096",
}


def clock():
    return CLOCK["now"]


def append(rid=A, agent="alice", now=1.0, **step):
    return {
        "op": "append",
        "rid": rid,
        "agent": agent,
        "now": now,
        "step": {"addon": "network-guard", "hook": "request", "state": "evaluated", **step},
    }


def get(rid=A, agent="alice", now=2.0):
    return {"op": "get", "rid": rid, "agent": agent, "now": now}


def api(path=None, **values):
    return {"op": "api", "now": 2.0, "path": path or f"/trace?request_id={A}", **values}


def case(name, *steps, **settings):
    return {"name": name, "settings": settings, "steps": list(steps)}


def record(*, flag=True, rid=A, **values):
    return {
        "op": "record",
        "now": 1.0,
        "trace": flag,
        "rid": rid,
        "agent": "alice",
        "step": {"addon": "network-guard", "hook": "request", "state": "evaluated"},
        **values,
    }


def cases():
    return [
        case(
            "defaults_order_and_fields",
            append(
                outcome="allowed",
                duration_us=17,
                details={"count": 2},
                connection_id="owned-connection",
                method="GET",
                host="owned.invalid",
                port=80,
            ),
            append(now=1.5, addon="test-context", hook="response", state="bypassed", reason="prior_response"),
            get(),
            get(),
        ),
        case(
            "owner_latch_none_fill_and_empty_nonfill",
            append(agent=None),
            get(agent=None),
            get(),
            append(agent="alice", now=2.0),
            append(agent="bob", now=2.5),
            get(now=3.0),
            get(agent="bob", now=3.0),
            get(agent="", now=3.0),
            get(C, now=3.0),
            append(B, agent="", now=3.0),
            append(B, agent="alice", now=3.5),
            get(B, now=4.0),
        ),
        case(
            "late_owner_fill_omits_cap_until_next_record",
            append(A, None),
            append(B, None, now=2.0),
            append(A, now=3.0),
            append(B, now=4.0),
            get(A, now=4.0),
            get(B, now=4.0),
            append(C, now=5.0),
            get(A, now=5.0),
            get(B, now=5.0),
            get(C, now=5.0),
            per_agent_max=1,
        ),
        case(
            "global_lru_append_but_not_get",
            append(A),
            append(B, now=2.0),
            get(A, now=2.5),
            append(C, now=3.0),
            get(A, now=3.0),
            append(B, now=4.0),
            append(D, now=5.0),
            get(C, now=5.0),
            get(B, now=5.0),
            global_max=2,
            per_agent_max=10,
        ),
        case(
            "per_agent_fifo_before_global",
            append(A),
            append(B, now=2.0),
            append(C, "bob", now=3.0),
            append(A, now=4.0),
            append(D, now=5.0),
            get(A, now=5.0),
            get(B, now=5.0),
            get(C, "bob", now=5.0),
            global_max=3,
            per_agent_max=2,
        ),
        case(
            "ttl_strict_boundary_and_recreation",
            append(now=0.0),
            get(now=5.0),
            get(now=5.001),
            append(now=6.0),
            get(now=6.0),
            ttl_s=5,
        ),
        case(
            "capped_append_stale_behind_live",
            append(A, now=0.0),
            append(B, now=1.0),
            append(A, now=2.0),
            get(A, now=5.5),
            get(B, now=6.001),
            get(A, now=6.001),
            ttl_s=5,
            steps_max=1,
        ),
        case(
            "zero_step_cap_uses_creation_timestamp",
            append(now=0.0),
            get(now=0.0),
            get(now=5.0),
            get(now=5.001),
            steps_max=0,
            ttl_s=5,
        ),
        case("zero_global_cap_detaches_new_record", append(), get(), global_max=0),
        case("zero_per_agent_cap_and_unowned_record", append(), append(B, None), get(), get(B), per_agent_max=0),
        case("negative_global_cap_partial_error", append(), get(), global_max=-1),
        case("negative_per_agent_cap_partial_error", append(), get(), per_agent_max=-1),
        case(
            "details_scalar_and_nested_projection",
            append(
                details={
                    "s": "owned",
                    "int": 2**80,
                    "bool": True,
                    "none": None,
                    "float": 1.25,
                    "list": [1],
                    "dict": {"label": "owned"},
                }
            ),
            append(now=1.5, details={}),
            append(now=1.75),
            get(),
        ),
        case(
            "details_exact_size_and_ascii_escaping",
            append(details={"k": "é"}),
            append(now=1.5, details={"k": "éa"}),
            get(),
            details_max_bytes=15,
        ),
        case(
            "connect_expectations_and_observed_response",
            append(addon="network-guard", hook="response"),
            get(),
            append(B, addon="extra", hook="http_connect"),
            get(B),
            append(B, addon="network-guard", hook="http_connect", now=2.0),
            get(B),
        ),
        case(
            "record_step_opt_in_and_swallowed_error",
            record(flag=False),
            record(rid=None),
            record(flag="yes"),
            get(),
            record(append_error=True, now=2.0),
            get(now=2.0),
        ),
        case(
            "api_owned_foreign_missing_and_forged",
            append(),
            api(),
            api(agent="bob"),
            api(f"/trace?request_id={B}"),
            api(agent="bob", forged_agent="alice"),
            api(f"/trace/?request_id={A}&agent=bob", agent="alice", forged_agent="bob"),
            api(agent="alice", metadata_conflict="bob"),
        ),
        case(
            "api_query_projection",
            append(),
            append(A + "\n", now=1.25),
            api(f"/trace?request_id={A}&request_id="),
            api(f"/trace?request_id=&request_id={A}"),
            api(f"/trace?request_id={A}%0A"),
            api("/trace?request_id=%FF"),
            api(f"/trace?request_id={A}#ignored"),
            api(f"/trace?request_id={A.upper()}"),
        ),
        case(
            "api_method_auth_and_identity_order",
            api("/trace", method="POST", auth="missing"),
            api("/trace", method="PUT", auth="missing"),
            api("/trace", auth="missing"),
            api("/trace", auth="invalid"),
            api("/trace", agent=None),
            api(agent=None),
            api(agent=None, forged_agent="alice"),
        ),
        case("api_real_ttl_overflow_error", api(auth="missing"), api("/trace"), api(agent=None), api(), ttl_s=10**400),
    ]


def snapshot(store):
    return {
        "records": [asdict(record) for record in store._records.values()],
        "by_agent": [[name, list(ids)] for name, ids in store._by_agent.items()],
    }


def api_flow(spec, token, modules):
    _, api_module, _, tflow, _, unix_mode = modules
    flow = tflow.tflow(resp=False)
    flow.metadata.clear()
    flow.client_conn.peername = ("192.0.2.10", 0)
    agent = spec.get("agent", "alice")
    if agent is not None:
        flow.client_conn.proxy_mode = unix_mode.parse(f"unix:/owned/192.0.2.10_{agent}/proxy.sock")
    flow.request.url = "http://" + api_module.AGENT_API_HOST + spec["path"]
    flow.request.method = spec.get("method", "GET")
    flow.request.raw_content = b""
    flow.request.headers.clear()
    auth = spec.get("auth", "valid")
    if auth != "missing":
        flow.request.headers["authorization"] = "Bearer " + (token if auth == "valid" else "owned-invalid")
    if "forged_agent" in spec:
        flow.request.headers["X-SafeYolo-Agent"] = spec["forged_agent"]
    if "metadata_conflict" in spec:
        flow.metadata["agent"] = spec["metadata_conflict"]
    return flow


def observe(spec, token, modules):
    trace, api_module, taddons, tflow, audit_writer, _ = modules
    store = trace.TraceStore(**spec["settings"])
    handler = api_module.AgentAPI()
    outputs = []
    with (
        patch.object(trace, "_store", store),
        patch.object(trace, "time", SimpleNamespace(time=clock)),
        patch.object(audit_writer, "put_event", return_value=None),
        taddons.context(handler),
    ):
        for operation in spec["steps"]:
            CLOCK["now"] = operation["now"]
            kind = operation["op"]
            output = {"op": kind, "error_class": None}
            rid, agent = operation.get("rid", A), operation.get("agent", "alice")
            try:
                if kind == "append":
                    step = trace.Step(**{"ts": operation["now"], **operation["step"]})
                    store.append_step(rid, agent, step)
                elif kind == "get":
                    record = store.get(rid, agent)
                    output["found"] = record is not None
                    if record is not None:
                        output["serialise_error"] = None
                        try:
                            output["report_json"] = json.dumps(store.serialise(record))
                        except (TypeError, ValueError, OverflowError) as error:
                            output["serialise_error"] = type(error).__name__
                elif kind == "record":
                    flow = tflow.tflow(resp=False)
                    flow.metadata.clear()
                    flow.metadata["trace"] = operation["trace"]
                    flow.metadata["agent"] = agent
                    if rid is not None:
                        flow.metadata["request_id"] = rid
                    flow.client_conn.id = "owned-connection"
                    flow.request.url = "http://owned.invalid/"
                    flow.request.method = "GET"
                    if operation.get("append_error"):
                        with patch.object(store, "append_step", side_effect=RuntimeError("owned append failure")):
                            trace.record_step(flow, **operation["step"])
                    else:
                        trace.record_step(flow, **operation["step"])
                else:
                    assert kind == "api"
                    flow = api_flow(operation, token, modules)
                    asyncio.run(handler.request(flow))
                    assert flow.response is not None
                    output["api"] = {
                        "status": flow.response.status_code,
                        "body_text": flow.response.content.decode(),
                        "headers": list(flow.response.headers.items(multi=True)),
                        "query_pairs": list(flow.request.query.items(multi=True)),
                        "blocked_by": flow.metadata.get("blocked_by"),
                    }
            except (TypeError, ValueError, OverflowError, IndexError, StopIteration) as error:
                # Preserve reached source failures and partial state; a handler
                # that catches one still returns its actual HTTP response.
                output["error_class"] = type(error).__name__
            output["state"] = snapshot(store)
            outputs.append(output)
    return {"input": spec, "steps": outputs}


def check_contract(rows):
    rows = {row["input"]["name"]: row for row in rows}

    def steps(name):
        return rows[name]["steps"]

    def statuses(name):
        return [step["api"]["status"] for step in steps(name) if "api" in step]

    defaults = json.loads(steps("defaults_order_and_fields")[-1]["report_json"])
    assert list(defaults) == ["request_id", "agent_id", "created_at", "truncated", "steps", "not_loaded"]
    assert [step["addon"] for step in defaults["steps"]] == ["network-guard", "test-context"]
    assert "ts" not in defaults["steps"][0] and "outcome" not in defaults["steps"][1]
    latch = steps("owner_latch_none_fill_and_empty_nonfill")
    assert [latch[i]["found"] for i in (1, 2, 5, 6, 7, 8, 11)] == [False, False, True, False, False, False, False]
    assert len(latch[5]["state"]["records"][0]["steps"]) == 3
    fill = steps("late_owner_fill_omits_cap_until_next_record")
    assert fill[4]["found"] and fill[5]["found"]
    assert fill[5]["state"]["by_agent"] == [["alice", [A, B]]]
    assert not fill[7]["found"] and not fill[8]["found"] and fill[9]["found"]
    lru = steps("global_lru_append_but_not_get")
    assert not lru[4]["found"] and not lru[7]["found"] and lru[8]["found"]
    fifo = steps("per_agent_fifo_before_global")
    assert not fifo[5]["found"] and fifo[6]["found"] and fifo[7]["found"]
    ttl = steps("ttl_strict_boundary_and_recreation")
    assert ttl[1]["found"] and not ttl[2]["found"]
    assert json.loads(ttl[4]["report_json"])["created_at"] == 6.0
    stale = steps("capped_append_stale_behind_live")
    assert stale[3]["found"] and stale[3]["state"]["records"][1]["truncated"]
    assert not stale[4]["found"] and not stale[5]["found"]
    zero = steps("zero_step_cap_uses_creation_timestamp")
    assert json.loads(zero[1]["report_json"])["steps"] == []
    assert json.loads(zero[1]["report_json"])["truncated"] is True
    assert zero[2]["found"] and not zero[3]["found"]
    assert steps("zero_global_cap_detaches_new_record")[0]["state"]["records"] == []
    assert len(steps("zero_per_agent_cap_and_unowned_record")[1]["state"]["records"]) == 1
    assert steps("negative_global_cap_partial_error")[0]["error_class"] == "StopIteration"
    assert steps("negative_per_agent_cap_partial_error")[0]["error_class"] == "IndexError"
    details = json.loads(steps("details_scalar_and_nested_projection")[-1]["report_json"])["steps"]
    assert details[0]["details"] == {
        "s": "owned",
        "int": 2**80,
        "bool": True,
        "none": None,
        "float": "<float>",
        "list": "<list>",
        "dict": "<dict>",
    }
    assert details[1]["details"] == {} and "details" not in details[2]
    sizes = json.loads(steps("details_exact_size_and_ascii_escaping")[-1]["report_json"])["steps"]
    assert sizes[0]["details"] == {"k": "é"} and sizes[1]["details"] == {"_truncated": True}
    connect = steps("connect_expectations_and_observed_response")
    assert len(json.loads(connect[1]["report_json"])["not_loaded"]) == 5
    assert json.loads(connect[3]["report_json"])["not_loaded"] == [{"addon": "network-guard", "state": "not_loaded"}]
    assert json.loads(connect[5]["report_json"])["not_loaded"] == []
    records = steps("record_step_opt_in_and_swallowed_error")
    assert records[0]["state"]["records"] == [] and records[1]["state"]["records"] == []
    assert len(records[-1]["state"]["records"][0]["steps"]) == 1 and records[-2]["error_class"] is None
    assert statuses("api_owned_foreign_missing_and_forged") == [200, 404, 404, 404, 200, 403]
    assert statuses("api_query_projection") == [200, 400, 200, 400, 200, 400]
    assert statuses("api_method_auth_and_identity_order") == [405, 405, 401, 401, 400, 403, 403]
    assert statuses("api_real_ttl_overflow_error") == [401, 400, 403, 500]
    assert json.loads(steps("api_real_ttl_overflow_error")[-1]["api"]["body_text"]) == {
        "error": "Internal error: OverflowError"
    }


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    attempts = []

    def no_network(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("no network in trace source oracle")

    with tempfile.TemporaryDirectory(prefix="trace-source-") as temporary:
        directory = Path(temporary)
        token = secrets.token_hex(32)
        token_path = directory / "agent_token"
        token_path.write_text(token)
        with (
            patch.dict(
                os.environ,
                {
                    **ENV,
                    "SAFEYOLO_DATA_DIR": str(directory),
                    "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl"),
                    "MITMPROXY_LOG_PATH": str(directory / "unused-diagnostic.log"),
                },
            ),
            patch.object(socket, "getaddrinfo", side_effect=no_network),
            patch.object(socket, "create_connection", side_effect=no_network),
        ):
            # Dataclass factories capture time.time at definition. Bind the
            # actual source classes to the supplied clock at initial import;
            # subsequent sweep reads use the same function through trace.time.
            assert "safeyolo.core.trace" not in sys.modules
            with patch.object(time, "time", clock):
                from safeyolo.core import trace
            from mitmproxy.test import taddons, tflow

            from safeyolo.core import audit_writer
            from safeyolo.mitm_addons import agent_api
            from safeyolo.proxy_modes.unix_listener import UnixMode

            modules = trace, agent_api, taddons, tflow, audit_writer, UnixMode
            rows = [observe(spec, token, modules) for spec in cases()]
            check_contract(rows)
            encoded = json.dumps(rows)
            assert token not in encoded and token.encode().hex() not in encoded
            assert list(directory.iterdir()) == [token_path]
    assert not attempts and not directory.exists()
    paths = [
        "cli/src/safeyolo/core/trace.py",
        "cli/src/safeyolo/mitm_addons/agent_api.py",
        "cli/src/safeyolo/mitm_addons/request_id.py",
        "cli/src/safeyolo/core/identity.py",
        "cli/src/safeyolo/proxy_modes/unix_listener.py",
        "pdp/tokens.py",
        "tests/test_trace.py",
        "tests/test_agent_api.py",
    ]
    return {
        "scope": "actual source store and selected AgentAPI; source quirks retained; no runtime/probe claim",
        "rows": rows,
        "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = json.dumps(run(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        assert result == args.check.read_text(), "source oracle changed"
    if args.output:
        args.output.write_text(result)
    print(json.dumps({"source_trace_rows": 20}))
