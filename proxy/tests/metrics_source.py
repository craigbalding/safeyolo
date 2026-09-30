"""Actual MetricsCollector hooks and reports with owned flows and fixed clocks.

No proxy, socket traffic or operational data is used. Report-only state seeds
are explicit input steps; they establish render/sort behavior, not transport
admission. Callback clock observations retain the reached mutation order.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import socket
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
GLOBALS = ("requests_total", "requests_success", "requests_blocked", "requests_error")


def op(hook, **values):
    return {"hook": hook, "now": 200.0, **values}


def reports(now=200.0):
    return [op("get_stats", forbid_clock=True), op("get_json", now=now), op("get_prometheus", now=now)]


def exchange(flow, status, *, host="owned.invalid", blocked_by=None):
    return [op("request", flow=flow, host=host, now=100.0),
            op("response", flow=flow, status=status, blocked_by=blocked_by, now=100.125)]


def case(name, *steps, start_time=1.0):
    return {"name": name, "start_time": start_time, "steps": list(steps)}


def cases():
    top_domains = {f"d{i:02}.invalid": {"requests": 11 + i % 3} for i in range(22)}
    big = 2**80
    return [
        case("pristine_reports", *reports()),
        case("request_metadata_after_counters", op("request", now=10.0), op("request", now=12.0),
             op("response", status=200, now=13.0), *reports()),
        case("successful_status_classes", *[step for status in (101, 200, 302, 399)
             for step in exchange(str(status), status)], *reports()),
        case("upstream_status_classes", *[step for status in (400, 401, 403, 404, 422, 429, 500, 502, 503, 504)
             for step in exchange(str(status), status)], *reports()),
        case("missing_start_and_repeated_response", op("response", status=200),
             op("response", status=200), *reports()),
        case("zero_start_time", op("request", now=0.0), op("response", status=200, now=9.0), *reports()),
        case("backward_latency", op("request", now=10.0), op("response", status=200, now=9.75), *reports()),
        case("absent_response_still_reads_clock", op("request", now=10.0),
             op("response", status=None, now=11.0), *reports()),
        case("blocked_absent_and_504", *exchange("absent", None, blocked_by="network-guard"),
             *exchange("timeout", 504, blocked_by="credential-guard"), *reports()),
        case("known_block_mapping", *[step for source in (
             "credential-guard", "yara-scanner", "pattern-scanner", "prompt-injection")
             for step in exchange(source, 200, blocked_by=source)], *reports()),
        case("generic_blocks_and_falsy_source", *[step for source in (
             "network-guard", "agent-api", "circuit-breaker", "network-guard")
             for step in exchange(source, 200, blocked_by=source)],
             *exchange("empty", 200, blocked_by=""), *reports()),
        case("response_host_changes", op("request", host="before.invalid", now=10.0),
             op("response", host="after.invalid", status=200, now=11.0), *reports()),
        case("get_stats_never_reads_clock", op("request", now=10.0), op("get_stats", forbid_clock=True),
             op("response", status=504, now=11.0), op("get_stats", forbid_clock=True)),
        case("stable_top20_and_all_problem_domains", op("seed_report", domains=top_domains,
             counters={"requests_total": sum(value["requests"] for value in top_domains.values())}), *reports()),
        case("problem_thresholds", op("seed_report", domains={
             "ten.invalid": {"requests": 10}, "eleven.invalid": {"requests": 11},
             "ninety.invalid": {"requests": 20, "successes": 18},
             "below.invalid": {"requests": 20, "successes": 17},
             "five.invalid": {"requests": 10, "successes": 10, "upstream_429s": 5},
             "six.invalid": {"requests": 10, "successes": 10, "upstream_429s": 6},
             "both.invalid": {"requests": 11, "successes": 9, "upstream_429s": 6}}), *reports()),
        case("prometheus_label_sanitizer_only", op("seed_report", domains={
             'quoted"\\name.invalid': {"requests": 3, "successes": 2},
             "line\r\n\t\x1b[31mred\x1b[0m\u2028é.invalid": {"requests": 2, "successes": 1},
             "d" * 255: {"requests": 1}}, blocks={
             "zeta": 1, 'quoted"\\source': 2, "line\n\t\x1b[31mred": 3, "s" * 66: 4}), *reports()),
        case("large_counters_and_numeric_reports", op("seed_report", counters={
             "requests_total": big + 7, "requests_success": big // 2,
             "requests_blocked": 13, "requests_error": 4}, domains={
             "large.invalid": {"requests": big + 7, "successes": big // 2,
                 "latency_sum_ms": 5.25, "latency_count": 2, "latency_max_ms": 4.35}},
             blocks={"network-guard": big}), *reports(now=200.25)),
        case("backward_report_clock", *reports(now=999.75), start_time=1000.0),
    ]


def state(collector):
    return {**{name: getattr(collector, name) for name in GLOBALS},
            "domains": {host: asdict(stats) for host, stats in collector._domain_stats.items()},
            "blocks_by_source": collector._blocks_by_source.copy()}


def flow_state(flows):
    return {name: {"host": flow.request.host, "metadata": copy.deepcopy(flow.metadata),
                   "status": flow.response.status_code if flow.response else None}
            for name, flow in flows.items()}


def set_flow(operation, flows, tflow, http):
    name = operation.get("flow", "flow")
    if name not in flows:
        flows[name] = tflow.tflow(resp=False)
        flows[name].request.host = "owned.invalid"
        flows[name].metadata.clear()
    flow = flows[name]
    if "host" in operation:
        flow.request.host = operation["host"]
    if "start" in operation:
        flow.metadata["metrics_start_time"] = operation["start"]
    if "blocked_by" in operation:
        flow.metadata["blocked_by"] = operation["blocked_by"]
    if operation["hook"] == "response":
        status = operation["status"]
        flow.response = http.Response.make(status, b"owned") if status is not None else None
    return flow


def observe(spec, metrics, tflow, http):
    init_timeline = []

    def initial_clock():
        init_timeline.append({"time": spec["start_time"]})
        return spec["start_time"]

    with patch.object(metrics, "time", SimpleNamespace(time=initial_clock)):
        collector = metrics.MetricsCollector()
    flows, steps = {}, []
    for operation in spec["steps"]:
        hook = operation["hook"]
        observations = []
        result = {"hook": hook, "error_class": None}
        if hook in ("request", "response"):
            flow = set_flow(operation, flows, tflow, http)

        def clock(operation=operation, observations=observations):
            observations.append({"time": operation["now"], "state": state(collector), "flows": flow_state(flows)})
            if operation.get("forbid_clock"):
                raise AssertionError("get_stats must not sample time")
            return operation["now"]

        with patch.object(metrics, "time", SimpleNamespace(time=clock)):
            if hook in ("request", "response"):
                getattr(collector, hook)(flow)
            elif hook == "seed_report":
                for name, value in operation.get("counters", {}).items():
                    assert name in GLOBALS
                    setattr(collector, name, value)
                for host, fields in operation["domains"].items():
                    collector._domain_stats[host] = metrics.DomainStats(**fields)
                collector._blocks_by_source.update(operation.get("blocks", {}))
            else:
                assert hook in ("get_stats", "get_json", "get_prometheus")
                value = getattr(collector, hook)()
                result["result_text"] = value if hook == "get_prometheus" else json.dumps(value, ensure_ascii=True)
        result.update(clock_observations=observations, state_after=state(collector), flows_after=flow_state(flows))
        steps.append(result)
    return {"input": spec, "init_timeline": init_timeline, "steps": steps}


def check_contract(rows):
    rows = {row["input"]["name"]: row for row in rows}

    def final(name):
        return rows[name]["steps"][-1]["state_after"]

    def report(name, hook="get_json"):
        text = next(step["result_text"] for step in rows[name]["steps"] if step["hook"] == hook)
        return text if hook == "get_prometheus" else json.loads(text)

    for row in rows.values():
        for step in row["steps"]:
            if step["hook"] in ("get_stats", "seed_report"):
                assert step["clock_observations"] == []
    repeated = rows["request_metadata_after_counters"]["steps"]
    assert repeated[0]["clock_observations"][0]["state"]["requests_total"] == 1
    assert repeated[0]["clock_observations"][0]["flows"]["flow"]["metadata"] == {}
    assert repeated[1]["clock_observations"][0]["state"]["requests_total"] == 2
    assert repeated[1]["clock_observations"][0]["flows"]["flow"]["metadata"] == {"metrics_start_time": 10.0}
    assert repeated[2]["clock_observations"][0]["state"]["requests_success"] == 0
    assert repeated[2]["state_after"]["domains"]["owned.invalid"]["latency_sum_ms"] == 1000.0
    assert final("successful_status_classes")["requests_success"] == 4
    upstream = final("upstream_status_classes")
    assert upstream["requests_error"] == 1 and upstream["requests_success"] == 0
    assert upstream["domains"]["owned.invalid"]["upstream_5xx"] == 4
    assert upstream["domains"]["owned.invalid"]["upstream_429s"] == 1
    for name in ("missing_start_and_repeated_response", "zero_start_time"):
        assert all(not step["clock_observations"] for step in rows[name]["steps"] if step["hook"] == "response")
    assert report("missing_start_and_repeated_response")["summary"]["success_rate"] == 2.0
    assert report("missing_start_and_repeated_response")["domains"]["owned.invalid"]["success_rate"] == 1.0
    zero = final("zero_start_time")["domains"]["owned.invalid"]
    assert type(zero["latency_sum_ms"]) is float and type(zero["latency_max_ms"]) is int
    backward = final("backward_latency")["domains"]["owned.invalid"]
    assert backward["latency_sum_ms"] == -250.0 and type(backward["latency_max_ms"]) is int
    absent = rows["absent_response_still_reads_clock"]["steps"][1]
    assert len(absent["clock_observations"]) == 1 and absent["state_after"]["requests_success"] == 0
    blocked = final("blocked_absent_and_504")
    assert blocked["requests_blocked"] == 2 and blocked["requests_error"] == 0
    assert blocked["domains"]["owned.invalid"]["latency_count"] == 0
    mapped = final("known_block_mapping")["domains"]["owned.invalid"]
    assert all(mapped[name] == 1 for name in ("blocked_credential", "blocked_yara", "blocked_pattern", "blocked_injection"))
    generic = final("generic_blocks_and_falsy_source")
    assert generic["blocks_by_source"] == {"network-guard": 2, "agent-api": 1, "circuit-breaker": 1}
    assert generic["requests_success"] == 1
    changed = final("response_host_changes")["domains"]
    assert changed["before.invalid"]["requests"] == 1 and changed["before.invalid"]["successes"] == 0
    assert changed["after.invalid"]["requests"] == 0 and changed["after.invalid"]["successes"] == 1
    top = report("stable_top20_and_all_problem_domains")
    assert len(top["domains"]) == 20 and len(top["problem_domains"]) == 22
    assert list(top["domains"])[:7] == [f"d{i:02}.invalid" for i in range(2, 22, 3)]
    text = report("stable_top20_and_all_problem_domains", "get_prometheus")
    assert [line.split('"')[1] for line in text.splitlines() if line.startswith("safeyolo_domain_requests_total{")] == [
        f"d{i:02}.invalid" for i in range(22)]
    problems = report("problem_thresholds")["problem_domains"]
    assert [item["domain"] for item in problems] == ["below.invalid", "eleven.invalid", "both.invalid", "six.invalid"]
    assert problems[2]["issues"] == ["low_success_rate:81.8%", "upstream_429s:6"]
    labels = report("prometheus_label_sanitizer_only", "get_prometheus")
    assert 'domain="quoted"\\name.invalid"' in labels
    assert 'domain="line?red?é.invalid"' in labels
    assert 'domain="' + "d" * 253 + '..."' in labels
    assert 'source="' + "s" * 64 + '..."' in labels
    assert str(2**80 + 7) in report("large_counters_and_numeric_reports", "get_prometheus")
    assert report("backward_report_clock")["uptime_seconds"] == -0.2


def run():
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    network_attempts = []

    def no_network(*_args, **_kwargs):
        network_attempts.append(True)
        raise AssertionError("no network in source metrics oracle")

    with tempfile.TemporaryDirectory(prefix="metrics-source-") as temporary:
        directory = Path(temporary)
        with (patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": str(directory),
              "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl"),
              "MITMPROXY_LOG_PATH": str(directory / "unused-diagnostic.log")}),
              patch.object(socket, "getaddrinfo", side_effect=no_network),
              patch.object(socket, "create_connection", side_effect=no_network)):
            from mitmproxy import http
            from mitmproxy.test import tflow

            from safeyolo.mitm_addons import metrics

            rows = [observe(spec, metrics, tflow, http) for spec in cases()]
            check_contract(rows)
            assert not list(directory.iterdir()), "Metrics unexpectedly wrote a file"
    assert not directory.exists() and not network_attempts
    paths = ["cli/src/safeyolo/mitm_addons/metrics.py", "cli/src/safeyolo/core/utils.py",
             "cli/src/safeyolo/core/audit_schema.py", "tests/test_metrics.py"]
    return {"scope": "actual reached hooks and report methods; explicit report-only seeds; no HTTP endpoint",
            "rows": rows, "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}}


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
    print(json.dumps({"source_metrics_rows": 18}))
