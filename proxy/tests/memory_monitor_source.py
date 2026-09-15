"""Actual MemoryMonitor hooks with fixed clocks and owned synthetic flows.

Process-memory sampling is replaced with stated KiB pairs. The real procfs
reader is inspected separately, never executed here. HTTP content properties
use mitmproxy's actual decoder; canonical events reach the final put_event seam.
No proxy, live socket, background writer or operational file is used.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import socket
import sys
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
SAMPLE = [1280, 2560]


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


def step(hook, now=10.0, **values):
    return {"hook": hook, "now": now, **values}


def case(name, *steps):
    steps = list(steps)
    if steps[-1]["hook"] != "get_stats":
        now = steps[-1]["now"]
        steps.append(step("get_stats", now[-1] if isinstance(now, list) else now))
    return {"name": name, "steps": steps}


def cases():
    connected = step("client_connected")
    request = step("request", 11, body="abc")
    return [
        case("pristine_stats", step("get_stats", 1000)),
        case("startup_two_clock_reads", step("running", [1000.25, 1000.75]), step("get_stats", 1001.9)),
        case("startup_submit_error", step("running", [1000.25, 1000.75], audit_error="RuntimeError")),
        case("repeated_running_preserves_state", step("running"), connected, request,
             step("websocket_start", 12), step("websocket_message", 13),
             step("running", [20.25, 20.75], memory=[3584, 4096]),
             step("get_stats", 21, memory=[4096, 5120])),
        case("decoded_http_bytes_and_first_domain", connected,
             step("request", 11, host="first.invalid", body="é!", encoding="gzip"),
             step("response", 12, body="reply", encoding="gzip"),
             step("request", 13, host="second.invalid", body="x"), step("get_stats", 15.9)),
        case("request_absent_and_empty_content", connected,
             step("request", 11, body=None), step("request", 12, body="")),
        case("request_decode_failure_before_periodic", connected,
             step("request", 60, host="failed.invalid", encoding="invalid_gzip")),
        case("unknown_request_skips_decode_but_emits_periodic",
             step("request", 60, encoding="invalid_gzip")),
        case("response_decode_failure_preserves_prior_bytes", connected, request,
             step("response", 12, body="ok"), step("response", 12.5, body=None),
             step("response", 13, encoding="invalid_gzip")),
        case("streamed_responses_skip_decode", connected, request,
             step("response", 12, encoding="invalid_gzip", stream=True),
             step("response", 13, encoding="invalid_gzip", stream="callable")),
        case("absent_and_unknown_response_skip_decode", step("response", absent=True),
             step("response", 11, encoding="invalid_gzip")),
        case("periodic_boundary_and_clock_rollback", step("running", 1000),
             step("client_connected", 1000),
             *(step("request", now) for now in [1059.999, 1060, 1180, 1180, 1170, 1239.999, 1240])),
        case("periodic_submit_failure_consumes_interval", step("running"), connected,
             step("request", 70, body="counted", audit_error="RuntimeError"),
             step("request", 71), step("request", 130)),
        case("empty_and_unknown_disconnect_no_event", connected,
             step("client_disconnected", 20), step("client_disconnected", 21)),
        case("disconnect_sanitizes_summary_and_truncates_negative_age",
             step("client_connected", 20.9), step("request", 10, host="owned.invalid\n\x1b[31m", body="abc"),
             step("response", 10, body="reply"), step("client_disconnected", 19.4)),
        case("disconnect_submit_error_removes_before_attempt", connected, request,
             step("client_disconnected", 20, audit_error="OSError"), step("client_disconnected", 21)),
        case("websocket_counts_messages_without_bytes", connected, request,
             step("response", 12, body="four"), step("websocket_start", 13, host="socket.invalid"),
             step("websocket_message", 14), step("websocket_message", 15), step("get_stats", 16),
             step("websocket_end", 20), step("client_disconnected", 21)),
        case("missing_websocket_edges_and_independent_cleanup", step("websocket_message"),
             step("websocket_end", 11), step("websocket_start", 12),
             step("client_disconnected", 13), step("get_stats", 14), step("websocket_end", 15)),
        case("duplicate_lifecycle_replaces_records", connected, request,
             step("websocket_start", 12), step("websocket_message", 13),
             step("client_connected", 14, client="peer"),
             step("websocket_start", 14, client="peer", host="peer.invalid"),
             step("client_connected", 14), step("websocket_start", 15, host="replacement.invalid"),
             step("websocket_message", 16), step("get_stats", 17),
             step("websocket_end", 18), step("client_disconnected", 19)),
        case("websocket_end_submit_error_removes_before_attempt", step("websocket_start", 20.9),
             step("websocket_message", 21), step("websocket_end", 19.4, audit_error="RuntimeError"),
             step("websocket_end", 22)),
        case("stable_top_ten_and_uncapped_websocket_order", step("populate", 10,
             counts=[2, 1, 2, 0, 3, 3, 1, 0, 4, 4, 2, 1]),
             step("request", 60, client="untracked"), step("get_stats", 61)),
        case("zero_start_and_negative_clock_ages", step("running", 0),
             step("client_connected", 20), step("websocket_start", 20), step("request", 10),
             step("get_stats", 9.5)),
        case("startup_sample_error_precedes_clock_state", step("running", memory_error="IndexError")),
        case("periodic_sample_error_retains_counters_and_interval", connected,
             step("request", 60, body="counted", memory_error="IndexError"), step("request", 61)),
    ]


def state(addon):
    return {"rss_start_kb": addon._rss_start_kb, "started": addon._started,
            "last_event_time": addon._last_event_time, "total_flows": addon._total_flows,
            "connections": [{"id": key, **asdict(value)} for key, value in addon._connections.items()],
            "websockets": [{"id": key, **asdict(value)} for key, value in addon._ws_sessions.items()]}


class Content:
    """Observe property access while retaining the actual HTTP decoder."""

    def __init__(self, message, spec, timeline, label):
        self.message, self.timeline, self.label = message, timeline, label
        self.host = spec.get("host", "owned.invalid")
        self.stream = (lambda _: None) if spec.get("stream") == "callable" else spec.get("stream", False)
        body = spec.get("body", "")
        raw = None if body is None else body.encode()
        if spec.get("encoding") == "gzip":
            raw = gzip.compress(raw, mtime=0)
            message.headers["content-encoding"] = "gzip"
        elif spec.get("encoding") == "invalid_gzip":
            raw = b"owned invalid gzip"
            message.headers["content-encoding"] = "gzip"
        message.raw_content = raw

    @property
    def content(self):
        self.timeline.append(self.label + ".content")
        return self.message.content


class Flow:
    @property
    def websocket(self):
        raise AssertionError("MemoryMonitor must not inspect WebSocket payload storage")


def flow(spec, timeline, http):
    owned = Flow()
    owned.client_conn = SimpleNamespace(id=spec.get("client", "conn"))
    owned.request = Content(http.Request.make("GET", "http://owned.invalid/"), spec, timeline, "request")
    owned.response = None if spec.get("absent") else Content(http.Response.make(200), spec, timeline, "response")
    return owned


def observe(spec, modules):
    memory, audit_writer, audit_schema, utils, http = modules
    addon = memory.MemoryMonitor()
    observations, attempts = [], []
    for index, operation in enumerate(spec["steps"]):
        timeline = []
        times = operation["now"] if isinstance(operation["now"], list) else [operation["now"]]
        time_index = 0

        def clock(times=times, timeline=timeline):
            nonlocal time_index
            value = times[min(time_index, len(times) - 1)]
            time_index += 1
            timeline.append({"time": value})
            return value

        def sample(operation=operation, timeline=timeline):
            value = operation.get("memory", SAMPLE)
            timeline.append({"sample_kb": value})
            if operation.get("memory_error"):
                raise IndexError("owned memory sample failure")
            return tuple(value)

        def put_event(entry, timeline=timeline, operation=operation, index=index):
            timeline.append("put_event:" + entry["event"])
            error = operation.get("audit_error")
            attempts.append({"step": index, "event": entry, "accepted": error is None,
                             "state_at_submit": state(addon)})
            if error:
                raise {"RuntimeError": RuntimeError, "OSError": OSError}[error]("owned submission failure")

        record = {"hook": operation["hook"], "error_class": None, "timeline": timeline}
        owned = flow(operation, timeline, http)
        with (
            patch.object(memory, "time", SimpleNamespace(time=clock)),
            patch.object(memory, "_read_proc_memory", side_effect=sample),
            patch.object(audit_writer, "put_event", side_effect=put_event),
            patch.object(audit_schema, "datetime", FixedDatetime),
            patch.object(utils, "datetime", FixedDatetime),
        ):
            try:
                hook = operation["hook"]
                if hook == "populate":
                    for number, count in enumerate(operation["counts"]):
                        item = flow({"client": f"c{number}", "host": f"h{number}.invalid"}, timeline, http)
                        addon.client_connected(item.client_conn)
                        for _ in range(count):
                            addon.request(item)
                        addon.websocket_start(item)
                elif hook == "get_stats":
                    record["stats_json"] = json.dumps(addon.get_stats())
                elif hook == "running":
                    addon.running()
                elif hook in {"client_connected", "client_disconnected"}:
                    getattr(addon, hook)(owned.client_conn)
                else:
                    getattr(addon, hook)(owned)
            except (ValueError, RuntimeError, OSError, IndexError) as error:
                record["error_class"] = type(error).__name__
        record["state_after"] = state(addon)
        observations.append(record)
    for attempt in attempts:
        event = attempt["event"]
        assert event["kind"] == "ops" and event["severity"] == "low" and event["addon"] == "memory-monitor"
        assert not {"request_id", "agent", "decision", "approval"} & event.keys()
        assert "attribution" not in event["details"]
    return {"input": spec, "steps": observations, "attempts": attempts}


def check_contract(rows):
    rows = {row["input"]["name"]: row for row in rows}

    def stats(name, index=-1):
        return json.loads(rows[name]["steps"][index]["stats_json"])

    def events(name):
        return [attempt["event"]["event"] for attempt in rows[name]["attempts"]]

    assert len(rows) == 24
    startup = rows["startup_two_clock_reads"]
    assert startup["steps"][0]["state_after"]["started"] == 1000.25
    assert startup["steps"][0]["state_after"]["last_event_time"] == 1000.75
    assert startup["steps"][0]["timeline"] == [{"sample_kb": SAMPLE}, {"time": 1000.25},
        {"time": 1000.75}, "put_event:ops.startup"]
    assert stats("startup_two_clock_reads")["rss_start_mb"] == 1.2
    assert rows["startup_submit_error"]["steps"][0]["error_class"] == "RuntimeError"
    counts = stats("decoded_http_bytes_and_first_domain")["connections"][0]
    assert (counts["domain"], counts["flows"], counts["bytes_sent"], counts["bytes_received"]) == ("first.invalid", 2, 4, 5)
    failure = rows["request_decode_failure_before_periodic"]["steps"][1]
    assert failure["error_class"] == "ValueError" and failure["timeline"] == ["request.content"]
    assert failure["state_after"]["total_flows"] == 1 and failure["state_after"]["last_event_time"] == 0
    assert failure["state_after"]["connections"][0]["domain"] == "failed.invalid"
    assert events("unknown_request_skips_decode_but_emits_periodic") == ["ops.memory"]
    for name in ("streamed_responses_skip_decode", "absent_and_unknown_response_skip_decode"):
        assert all("response.content" not in item["timeline"] for item in rows[name]["steps"])
    assert stats("response_decode_failure_preserves_prior_bytes")["connections"][0]["bytes_received"] == 2
    assert events("periodic_boundary_and_clock_rollback") == ["ops.startup", "ops.memory", "ops.memory", "ops.memory"]
    failed_periodic = rows["periodic_submit_failure_consumes_interval"]
    assert failed_periodic["steps"][2]["error_class"] == "RuntimeError"
    assert failed_periodic["steps"][2]["state_after"]["last_event_time"] == 70
    assert failed_periodic["steps"][3]["timeline"] == ["request.content", {"time": 71}]
    for name, collection, hook in [
        ("disconnect_submit_error_removes_before_attempt", "connections", "ops.memory.conn_closed"),
        ("websocket_end_submit_error_removes_before_attempt", "websockets", "ops.memory.ws_closed"),
    ]:
        assert events(name) == [hook]
        assert rows[name]["attempts"][0]["state_at_submit"][collection] == []
    assert events("empty_and_unknown_disconnect_no_event") == []
    ws = stats("websocket_counts_messages_without_bytes", 6)
    assert (ws["connections"][0]["bytes_sent"], ws["connections"][0]["bytes_received"], ws["websockets"][0]["messages"]) == (3, 4, 2)
    assert events("websocket_counts_messages_without_bytes") == ["ops.memory.ws_closed", "ops.memory.conn_closed"]
    assert stats("missing_websocket_edges_and_independent_cleanup", 4)["active_websockets"] == 1
    duplicate = stats("duplicate_lifecycle_replaces_records", 9)
    assert duplicate["total_flows"] == 1 and duplicate["connections"][0]["flows"] == 0
    replaced = rows["duplicate_lifecycle_replaces_records"]["steps"][9]["state_after"]
    assert [item["id"] for item in replaced["connections"]] == ["conn", "peer"]
    assert [item["id"] for item in replaced["websockets"]] == ["conn", "peer"]
    top = stats("stable_top_ten_and_uncapped_websocket_order")
    assert [item["domain"] for item in top["connections"]] == [f"h{i}.invalid" for i in [8, 9, 4, 5, 0, 2, 10, 1, 6, 11]]
    assert [item["domain"] for item in top["websockets"]] == [f"h{i}.invalid" for i in range(12)]
    negative = stats("zero_start_and_negative_clock_ages")
    assert negative["uptime_s"] == 0 and negative["connections"][0]["age_s"] == -10
    sample_start = rows["startup_sample_error_precedes_clock_state"]["steps"][0]
    assert sample_start["error_class"] == "IndexError"
    assert sample_start["timeline"] == [{"sample_kb": SAMPLE}]
    assert sample_start["state_after"]["started"] == sample_start["state_after"]["rss_start_kb"] == 0
    sample_periodic = rows["periodic_sample_error_retains_counters_and_interval"]["steps"][1]
    assert sample_periodic["error_class"] == "IndexError"
    assert sample_periodic["state_after"]["last_event_time"] == 60
    assert sample_periodic["state_after"]["connections"][0]["bytes_sent"] == len("counted")
    assert events("periodic_sample_error_retains_counters_and_interval") == []


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="memory-monitor-source-") as directory:
        os.environ.update(SAFEYOLO_LOG_PATH=directory + "/unused-audit.jsonl",
                          MITMPROXY_LOG_PATH=directory + "/unused-diagnostic.log", SAFEYOLO_DATA_DIR=directory)
        from mitmproxy import http

        from safeyolo.core import audit_schema, audit_writer, utils
        from safeyolo.mitm_addons import memory_monitor

        network_attempts = []

        def no_network(*_args, **_kwargs):
            network_attempts.append(True)
            raise AssertionError("no network is allowed in the selected MemoryMonitor controls")

        modules = memory_monitor, audit_writer, audit_schema, utils, http
        with (patch.object(socket, "getaddrinfo", side_effect=no_network),
              patch.object(socket, "create_connection", side_effect=no_network)):
            rows = [observe(spec, modules) for spec in cases()]
        assert not network_attempts
        check_contract(rows)
    paths = ["cli/src/safeyolo/mitm_addons/memory_monitor.py", "cli/src/safeyolo/core/utils.py",
             "cli/src/safeyolo/core/audit_schema.py", "tests/test_memory_monitor.py"]
    return {"memory_sampling": "stubbed _read_proc_memory; supplied KiB pairs; no procfs reads",
            "default_memory_kb": SAMPLE, "rows": rows,
            "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = run()
    if args.check:
        assert result == json.loads(args.check.read_text()), "source MemoryMonitor behavior changed"
    if args.output:
        args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"source_memory_rows": len(result["rows"])}))
