"""Actual selected ProbeSink hooks and doctor classifier; no transport or full chain.

The classifier consumes the unchanged production six-addon manifest. Synthetic
steps describe classifier inputs, not execution receipts for those producers.
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
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
RID = "req-" + "a" * 32
HOST = "_safeyolo.probe.internal"
EXPECTED = ["service-gateway", "network-guard", "circuit-breaker", "credential-guard", "pattern-scanner", "test-context"]
TRACE_ENV = {
    "SAFEYOLO_TRACE_TTL_S": "300",
    "SAFEYOLO_TRACE_GLOBAL_MAX": "1000",
    "SAFEYOLO_TRACE_PER_AGENT_MAX": "200",
    "SAFEYOLO_TRACE_STEPS_MAX": "128",
    "SAFEYOLO_TRACE_DETAILS_MAX_BYTES": "4096",
}
SOURCE_PATHS = [
    "cli/src/safeyolo/core/probe.py",
    "cli/src/safeyolo/core/trace.py",
    "cli/src/safeyolo/mitm_addons/probe_sink.py",
    "cli/src/safeyolo/mitm_addons/__init__.py",
    "cli/src/safeyolo/commands/doctor.py",
    "tests/test_probe_sink.py",
    "cli/tests/test_doctor_traced_probe.py",
]


def now():
    return 100.0


def sink_cases():
    return [
        {"name": "canonical"},
        {"name": "mixed_case_other_method_path_port", "host": HOST.upper(), "method": "POST", "path": "/elsewhere?q=1", "port": 8123},
        {"name": "trailing_dot_reserved", "host": HOST + "."},
        {"name": "double_dot_inert", "host": HOST + ".."},
        {"name": "other_host_inert", "host": "owned.invalid"},
        {"name": "headers_hook_not_reached", "requestheaders": False},
        {"name": "request_id_absent", "request_id": None},
        {"name": "request_id_empty", "request_id": ""},
        {"name": "untraced_success", "traced": False},
        {"name": "preempted_block", "prior_status": 403, "blocked_by": "owned-guard"},
        {"name": "preempted_success_without_blocker", "prior_status": 200},
        {"name": "trace_append_failure", "record_error": True},
        {"name": "response_construction_failure", "response_error": True},
    ]


def response(flow):
    if flow.response is None:
        return None
    return {
        "status": flow.response.status_code,
        "body_text": flow.response.content.decode("utf-8"),
        "headers": [[k.decode("latin-1"), v.decode("latin-1")] for k, v in flow.response.headers.fields],
    }


def normalized_step(step):
    result = asdict(step)
    result.pop("ts")
    if result["duration_us"] is not None:
        result["duration_us"] = "<measured>"
    return result


def normalized_report(store, rid=RID):
    record = store.get(rid, "alice")
    if record is None:
        return None
    report = store.serialise(record)
    for item in report["steps"]:
        if item.get("duration_us") is not None:
            item["duration_us"] = "<measured>"
    return report


def observe_sink(spec, trace, probe_sink, http, tflow):
    store = trace.TraceStore()
    addon = probe_sink.ProbeSink()
    flow = tflow.tflow()
    flow.client_conn.id = "owned-probe-connection"
    flow.request = http.Request.make(spec.get("method", "GET"), "http://" + HOST + spec.get("path", "/__pipeline_probe"))
    flow.request.host = spec.get("host", HOST)
    flow.request.port = spec.get("port", 80)
    flow.metadata.clear()
    flow.metadata.update(agent="alice", trace=spec.get("traced", True))
    rid = spec.get("request_id", RID)
    if rid is not None:
        flow.metadata["request_id"] = rid
    if "blocked_by" in spec:
        flow.metadata["blocked_by"] = spec["blocked_by"]
    if "prior_status" in spec:
        flow.response = http.Response.make(spec["prior_status"], b"owned prior response", {"X-Owned": "prior"})
    prior = flow.response
    timeline = []
    real_append = store.append_step
    real_make = http.Response.make

    def append(rid, agent, item):
        timeline.append({"kind": "trace", "step": normalized_step(item), "accepted": not spec.get("record_error", False), "response": response(flow)})
        if spec.get("record_error"):
            raise RuntimeError("owned trace append failure")
        return real_append(rid, agent, item)

    def make(*args, **kwargs):
        if spec.get("response_error"):
            raise ValueError("owned response construction failure")
        return real_make(*args, **kwargs)

    error = None
    with patch.object(trace, "_store", store), patch.object(store, "append_step", side_effect=append), patch.object(http.Response, "make", side_effect=make):
        if spec.get("requestheaders", True):
            addon.requestheaders(flow)
        after_headers = {"metadata": copy.deepcopy(flow.metadata), "response": response(flow)}
        try:
            addon.request(flow)
        except (ValueError, TypeError) as exception:
            error = type(exception).__name__
        report = normalized_report(store, rid) if rid else None
    assert not any(k.startswith("_trace_hook_start:") for k in flow.metadata)
    return {
        "input": spec,
        "after_requestheaders": after_headers,
        "error_class": error,
        "metadata": copy.deepcopy(flow.metadata),
        "response": response(flow),
        "prior_response_retained": prior is not None and flow.response is prior,
        "trace": report,
        "timeline": timeline,
    }


def step(addon, *, hook="request", state="evaluated", outcome="owned_evaluation", **fields):
    return {"addon": addon, "hook": hook, "state": state, "outcome": outcome, **fields}


def classifier_cases():
    normal = [step(name) for name in EXPECTED]
    sink = step("probe-sink", outcome="probe_terminated")
    disabled = copy.deepcopy(normal)
    disabled[1] = step("network-guard", state="bypassed", outcome=None, reason="addon_disabled")
    disabled[2] = step("circuit-breaker", state="bypassed", outcome=None, reason="policy_disabled")
    response_only = copy.deepcopy(normal)
    response_only[1]["hook"] = "response"
    prior = copy.deepcopy(normal)
    prior[1] = step("network-guard", state="bypassed", outcome=None, reason="prior_response")
    first_error = copy.deepcopy(normal)
    first_error[2] = step("circuit-breaker", state="error", outcome=None, reason="ValueError")
    cases = [
        {"name": "all_six_and_sink", "steps": [*normal, sink]},
        {"name": "native_active_three_missing_producers", "steps": [normal[1], normal[2], normal[5], sink]},
        {"name": "loaded_explicitly_disabled", "steps": [*disabled, sink]},
        {"name": "response_only_is_not_request_evidence", "steps": [*response_only, sink]},
        {"name": "truncated_after_complete_manifest", "steps": [*normal, sink, step("owned-extra")], "steps_max": 7},
        {"name": "prior_response_warns", "steps": [*prior, step("probe-sink", outcome="probe_preempted")]},
        {"name": "wrong_manifest_order", "steps": [normal[1], normal[0], *normal[2:], sink]},
        {"name": "missing_sink_warns", "steps": normal},
        {"name": "preempted_sink_warns", "steps": [*normal, step("probe-sink", outcome="probe_preempted")]},
        {"name": "expected_first_error_fails", "steps": [*first_error, normal[2], sink]},
        {"name": "expected_error_after_success_is_not_graded", "steps": [*normal, step("circuit-breaker", state="error", outcome=None, reason="ValueError"), sink]},
        {"name": "extra_error_after_success_fails", "steps": [*normal, step("transport-guard"), step("transport-guard", state="error", outcome=None, reason="probe_reached_upstream"), sink]},
    ]
    return copy.deepcopy(cases)


def observe_classifier(spec, trace, doctor):
    store = trace.TraceStore(steps_max=spec.get("steps_max", 128))
    for item in spec["steps"]:
        store.append_step(RID, "alice", trace.Step(**item))
    report = normalized_report(store)
    verdict, findings, detail = doctor._classify_trace_steps(report)
    return {"input": spec, "trace_payload": report, "result": {"verdict": verdict, "findings": findings, "detail": detail}}


def check_contract(sinks, classifiers):
    by_name = {r["input"]["name"]: r for r in sinks}
    good = by_name["canonical"]
    assert good["after_requestheaders"]["response"] is None
    assert good["response"]["body_text"] == json.dumps({"probe_ok": True, "host": HOST, "request_id": RID})
    assert good["response"]["headers"] == [["Content-Type", "application/json"], ["X-SafeYolo-Request-Id", RID], ["content-length", str(len(good["response"]["body_text"]))]]
    assert "blocked_by" not in good["metadata"]
    assert good["timeline"][0]["response"] == good["response"]
    assert good["trace"]["steps"][0]["outcome"] == "probe_terminated"
    assert by_name["trailing_dot_reserved"]["response"]["status"] == 200
    assert by_name["trailing_dot_reserved"]["trace"]["steps"][0]["outcome"] == "probe_terminated"
    for name in ["double_dot_inert", "other_host_inert", "headers_hook_not_reached"]:
        assert by_name[name]["response"] is None and by_name[name]["trace"] is None
    assert by_name["mixed_case_other_method_path_port"]["response"]["status"] == 200
    for name, rid in [("request_id_absent", None), ("request_id_empty", "")]:
        row = by_name[name]
        assert json.loads(row["response"]["body_text"])["request_id"] == rid
        assert not any(k.lower() == "x-safeyolo-request-id" for k, _v in row["response"]["headers"])
        assert row["trace"] is None
    assert by_name["untraced_success"]["response"]["status"] == 200 and by_name["untraced_success"]["trace"] is None
    for name, blocker in [("preempted_block", "owned-guard"), ("preempted_success_without_blocker", None)]:
        row = by_name[name]
        assert row["prior_response_retained"] and row["response"] == row["after_requestheaders"]["response"]
        assert row["trace"]["steps"][0]["details"] == {"preempted_by": blocker}
    record_error = by_name["trace_append_failure"]
    assert record_error["error_class"] is None and record_error["response"]["status"] == 200 and record_error["trace"] is None
    assert not record_error["timeline"][0]["accepted"]
    construction_error = by_name["response_construction_failure"]
    assert construction_error["error_class"] == "ValueError" and construction_error["response"] is None
    assert construction_error["trace"]["steps"][0]["reason"] == "ValueError"
    expected = ["pass", "fail", "pass", "fail", "fail", "warn", "warn", "warn", "warn", "fail", "pass", "fail"]
    assert [row["result"]["verdict"] for row in classifiers] == expected
    reports = {r["input"]["name"]: r for r in classifiers}
    assert [v["addon"] for v in reports["native_active_three_missing_producers"]["trace_payload"]["not_loaded"]] == ["service-gateway", "credential-guard", "pattern-scanner"]
    disabled = reports["loaded_explicitly_disabled"]
    assert disabled["trace_payload"]["not_loaded"] == []
    assert [v["addon"] for v in disabled["result"]["detail"] if v.get("verdict") == "pass_reported"] == ["network-guard", "circuit-breaker"]
    response_only = reports["response_only_is_not_request_evidence"]
    assert response_only["trace_payload"]["not_loaded"] == []
    assert response_only["result"]["detail"][1]["state"] == "missing_from_trace"
    assert reports["truncated_after_complete_manifest"]["trace_payload"]["truncated"]


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    network_attempts = []

    def no_network(*_args, **_kwargs):
        network_attempts.append(True)
        raise AssertionError("selected source oracle must not access network")

    with tempfile.TemporaryDirectory(prefix="probe-doctor-source-") as temporary:
        directory = Path(temporary)
        with patch.dict(os.environ, {**TRACE_ENV, "SAFEYOLO_DATA_DIR": temporary, "SAFEYOLO_LOG_PATH": str(directory / "unused-audit")}), patch.object(socket, "getaddrinfo", side_effect=no_network), patch.object(socket, "create_connection", side_effect=no_network):
            assert "safeyolo.core.trace" not in sys.modules
            with patch.object(time, "time", now):
                from safeyolo.core import trace
            from mitmproxy import http
            from mitmproxy.test import tflow

            from safeyolo.commands import doctor
            from safeyolo.core import audit_writer, probe
            from safeyolo.mitm_addons import probe_sink

            assert trace.EXPECTED_ADDONS == EXPECTED
            hosts = [None, "", HOST, HOST.upper(), HOST + ".", HOST + "..", "prefix." + HOST, HOST + ".owned.invalid", "owned.invalid"]
            matcher = [{"host": host, "matches": probe.is_probe_host(host)} for host in hosts]
            assert [row["matches"] for row in matcher] == [False, False, True, True, True, False, False, False, False]
            audit_attempts = []
            with patch.object(trace, "time", SimpleNamespace(time=now, perf_counter_ns=time.perf_counter_ns)), patch.object(audit_writer, "put_event", side_effect=lambda entry: audit_attempts.append(entry)):
                sinks = [observe_sink(spec, trace, probe_sink, http, tflow) for spec in sink_cases()]
                classifiers = [observe_classifier(spec, trace, doctor) for spec in classifier_cases()]
            assert not audit_attempts
            assert trace.EXPECTED_ADDONS == EXPECTED
            check_contract(sinks, classifiers)
            assert list(directory.iterdir()) == []
            dependencies = {module.__name__: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() for module in [http, tflow]}
    assert not network_attempts and not directory.exists()
    return {
        "expected_addons": EXPECTED,
        "matcher": matcher,
        "sink_rows": sinks,
        "doctor_rows": classifiers,
        "canonical_audit_attempts": 0,
        "scope": "selected actual sink hooks and actual classifier over synthetic store reports; no full pipeline, fallback, transport or acceptance claim",
        "normalization": "non-null duration_us -> <measured>; fixed trace wall clock/default factories; synthetic connection ID",
        "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_PATHS},
        "dependency_sha256": dependencies,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    document = run()
    rendered = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    if args.check:
        assert args.check.read_text() == rendered, "source probe/doctor contract changed"
    if args.output:
        args.output.write_text(rendered)
    print(json.dumps({"sink_rows": len(document["sink_rows"]), "doctor_rows": len(document["doctor_rows"]), "matcher_inputs": len(document["matcher"])}))
