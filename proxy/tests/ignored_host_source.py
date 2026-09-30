"""Actual IgnoredHostLogger matching/lifecycle with owned connection facts.

Uses real in-memory ServerConnectionHookData, actual canonical write_event and
an explicitly synthetic final put_event sink. No connection is opened. Matching
rows are source evidence only, not a claim about the narrower native matcher.
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
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
HOST = "service.owned.invalid"
PATTERNS = [r"^service\.owned\.invalid:443$"]


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


def op(hook, **values):
    return {"hook": hook, "now": 10.0, **values}


def case(name, *steps):
    return {"name": name, "steps": list(steps)}


def cases():
    connect = op("server_connect")
    connected = op("server_connected")
    end = op("server_disconnected", now=10.125)
    return [
        case("candidate_order_and_exact_dedup", op("match", peer=["192.0.2.20", 443],
             patterns=[r"service\.owned", r"192\.0\.2\.20"]),
             op("match", peer=[HOST, 443]),
             op("match", peer=[HOST, 443], sni="SERVICE.OWNED.INVALID"),
             op("match", address=["other.invalid", 8443], sni=HOST, patterns=[r"owned\.invalid:8443$"])),
        case("missing_candidates_and_options", op("match", peer=None, address=None),
             op("match", missing_patterns=True), op("server_connect", patterns=[]),
             op("server_connect", missing_patterns=True)),
        case("invalid_regex_skipped_case_insensitive", op("match", patterns=["[", r"^SERVICE\.OWNED\.INVALID:443$"]),
             op("server_connect", patterns=["[", r"^SERVICE\.OWNED\.INVALID:443$"]), connected, end),
        case("source_search_and_advanced_regex", op("match", patterns=[r"vice\.owned"]),
             op("match", patterns=[r"^(?=service\.)[^:]+:443$"]), op("match", patterns=["["])),
        case("successful_lifecycle", connect, connected, end),
        case("unmatched_lifecycle", op("server_connect", patterns=[r"^other\.invalid:443$"]), connected, end),
        case("unknown_callbacks", connected, op("server_connect_error", error="owned refusal"), end),
        case("disconnect_before_connected", connect, end, connected, op("server_connect_error")),
        case("connect_error_pop_and_sanitization", connect,
             op("server_connect_error", error="owned refusal\n\x1b[31munsafe\x1b[0m"), end,
             op("server_connect_error", error="ignored repeat"),
             op("server_connect", id="empty"), op("server_connect_error", id="empty", error=""),
             op("server_connect", id="none"), op("server_connect_error", id="none", error=None)),
        case("start_submit_failure_retains_connected", connect,
             op("server_connected", audit_error="RuntimeError"), end, end),
        case("connect_error_submit_failure_pops", connect,
             op("server_connect_error", audit_error="RuntimeError", error="owned refusal"), connected, end),
        case("end_submit_failure_pops", connect, connected,
             op("server_disconnected", now=10.125, audit_error="OSError"), end),
        case("repeated_connected_and_single_end", connect, connected, connected, end, end),
        case("same_id_replacement_keeps_slot", connect, op("server_connect", id="second"), connected,
             op("server_connect", address=["replacement.invalid", 8443], sni=None, patterns=["replacement"], now=20.0),
             connected, op("server_disconnected", now=20.5), op("server_disconnected", id="second")),
        case("unmatched_reconnect_retains_original", connect, connected,
             op("server_connect", address=["other.invalid", 80], sni=None, now=20.0),
             op("server_disconnected", now=21.0, patterns=[])),
        case("emission_uses_current_client_facts", connect,
             op("server_connected", agent=None, client_ip=None, transport="udp"),
             op("server_disconnected", now=10.125, agent="bob", client_ip="192.0.2.11", transport="tcp",
                address=["changed.invalid", 9443], sni="changed.invalid", patterns=[])),
        case("duration_zero_backward_and_ties", op("server_connect", now=0.0), connected,
             op("server_disconnected", now=0.0005), op("server_connect", now=0.0), connected,
             op("server_disconnected", now=0.0015), connect, connected,
             op("server_disconnected", now=9.5)),
        case("clock_failures_preserve_assignment_and_pop", connect,
             op("server_connect", now=20.0, clock_error=True, address=["replacement.invalid", 8443],
                sni=None, patterns=["replacement"]), connected,
             op("server_disconnected", now=11.0, clock_error=True), end),
    ]


def state(addon):
    return [{"id": name, **asdict(session)} for name, session in addon._sessions.items()]


def data(spec, tflow, hook_data):
    server, client = tflow.tserver_conn(), tflow.tclient_conn()
    server.id = spec.get("id", "conn")
    address = spec.get("address", [HOST, 443])
    peer = spec.get("peer")
    server.address = tuple(address) if address is not None else None
    server.peername = tuple(peer) if peer is not None else None
    server.transport_protocol = spec.get("transport", "tcp")
    server.error = spec.get("error")
    client.sni = spec.get("sni", HOST)
    client_ip = spec.get("client_ip", "192.0.2.10")
    client.peername = (client_ip, 0) if client_ip is not None else None
    # Source reads only this trusted mode field. No caller header or lookup is
    # supplied, and no listener/identity-derivation behavior is claimed here.
    agent = spec.get("agent", "alice")
    client.proxy_mode = SimpleNamespace() if agent is None else SimpleNamespace(agent=agent)
    return hook_data(server=server, client=client)


def observe(spec, modules):
    ignored, audit_writer, audit_schema, utils, tflow, hook_data = modules
    addon = ignored.IgnoredHostLogger()
    observations, attempts = [], []
    for index, operation in enumerate(spec["steps"]):
        timeline = []
        record = {"hook": operation["hook"], "error_class": None, "timeline": timeline}
        owned = data(operation, tflow, hook_data)
        options = SimpleNamespace() if operation.get("missing_patterns") else SimpleNamespace(
            ignore_hosts=operation.get("patterns", PATTERNS))

        def clock(operation=operation, timeline=timeline):
            timeline.append({"monotonic": operation["now"], "state": state(addon)})
            if operation.get("clock_error"):
                raise RuntimeError("owned monotonic failure")
            return operation["now"]

        def put_event(entry, operation=operation, timeline=timeline, index=index):
            error = operation.get("audit_error")
            timeline.append("put_event:" + entry["event"])
            attempts.append({"step": index, "event": copy.deepcopy(entry), "event_json": json.dumps(entry),
                             "accepted": error is None, "state_at_submit": state(addon)})
            if error:
                raise {"RuntimeError": RuntimeError, "OSError": OSError}[error]("owned submission failure")

        with (patch.object(ignored.ctx, "options", options, create=True),
              patch.object(ignored, "time", SimpleNamespace(monotonic=clock)),
              patch.object(audit_writer, "put_event", side_effect=put_event),
              patch.object(audit_schema, "datetime", FixedDatetime),
              patch.object(utils, "datetime", FixedDatetime)):
            try:
                if operation["hook"] == "match":
                    record["candidates"] = ignored.IgnoredHostLogger._candidates(owned)
                    record["matched"] = ignored.IgnoredHostLogger._matched_destination(owned)
                else:
                    if operation["hook"] == "server_connect":
                        # A separate read of the same pure source matcher gives
                        # native lifecycle replay its selected input without
                        # introducing a second matching implementation.
                        record["selected_destination"] = addon._matched_destination(owned)
                    getattr(addon, operation["hook"])(owned)
            except (RuntimeError, OSError, ValueError, TypeError) as error:
                # These are explicit clock/submission or source conversion
                # specimens. Preserve reached state and the escaped category.
                record["error_class"] = type(error).__name__
        record["state_after"] = state(addon)
        observations.append(record)
    for attempt in attempts:
        event = attempt["event"]
        assert event["kind"] == "traffic" and event["addon"] == "ignored-host-logger"
        assert event["severity"] == ("low" if event["event"].endswith("_end") else "medium")
        assert not {"request_id", "decision", "approval"} & event.keys()
        assert "attribution" not in event["details"]
    return {"input": spec, "steps": observations, "attempts": attempts}


def check_contract(rows):
    rows = {row["input"]["name"]: row for row in rows}

    def events(name):
        return [attempt["event"] for attempt in rows[name]["attempts"]]

    matching = rows["candidate_order_and_exact_dedup"]["steps"]
    assert matching[0]["candidates"] == [("192.0.2.20", 443), (HOST, 443)]
    assert matching[0]["matched"] == ("192.0.2.20", 443)
    assert matching[1]["candidates"] == [(HOST, 443)]
    assert matching[2]["candidates"] == [(HOST, 443), ("SERVICE.OWNED.INVALID", 443)]
    assert matching[3]["matched"] == (HOST, 8443)
    assert all(step.get("matched") is None and not step["timeline"]
               for step in rows["missing_candidates_and_options"]["steps"])
    assert rows["invalid_regex_skipped_case_insensitive"]["steps"][0]["matched"] == (HOST, 443)
    assert [step["matched"] for step in rows["source_search_and_advanced_regex"]["steps"]] == [
        (HOST, 443), (HOST, 443), None]
    for name in ("unmatched_lifecycle", "unknown_callbacks", "disconnect_before_connected"):
        assert not events(name) and rows[name]["steps"][-1]["state_after"] == []
    success = rows["successful_lifecycle"]
    assert success["steps"][0]["timeline"] == [{"monotonic": 10.0, "state": []}]
    assert success["attempts"][0]["state_at_submit"][0]["connected"] is True
    assert success["steps"][2]["timeline"][0] == {"monotonic": 10.125, "state": []}
    assert success["attempts"][1]["state_at_submit"] == []
    assert events("successful_lifecycle")[1]["details"]["duration_ms"] == 125
    errors = events("connect_error_pop_and_sanitization")
    assert [event["details"]["error"] for event in errors] == ["owned refusal?unsafe?", "", ""]
    assert all(attempt["state_at_submit"] == []
               for attempt in rows["connect_error_pop_and_sanitization"]["attempts"])
    start_failure = rows["start_submit_failure_retains_connected"]
    assert start_failure["steps"][1]["error_class"] == "RuntimeError"
    assert start_failure["steps"][1]["state_after"][0]["connected"] is True
    assert [attempt["accepted"] for attempt in start_failure["attempts"]] == [False, True]
    for name in ("connect_error_submit_failure_pops", "end_submit_failure_pops"):
        assert rows[name]["attempts"][-1]["accepted"] is False
        assert rows[name]["attempts"][-1]["state_at_submit"] == []
        assert rows[name]["steps"][-1]["state_after"] == []
    assert [event["event"] for event in events("repeated_connected_and_single_end")] == [
        "traffic.passthrough_start", "traffic.passthrough_start", "traffic.passthrough_end"]
    replaced = rows["same_id_replacement_keeps_slot"]["steps"]
    assert [session["id"] for session in replaced[3]["state_after"]] == ["conn", "second"]
    assert replaced[3]["timeline"][0]["state"][0]["connected"] is True
    assert replaced[3]["state_after"][0] == {"id": "conn", "host": "replacement.invalid", "port": 8443,
                                            "started_at": 20.0, "connected": False}
    assert events("same_id_replacement_keeps_slot")[-1]["details"]["duration_ms"] == 500
    unmatched = rows["unmatched_reconnect_retains_original"]
    assert unmatched["steps"][2]["timeline"] == []
    assert unmatched["steps"][2]["state_after"][0]["started_at"] == 10.0
    assert events("unmatched_reconnect_retains_original")[-1]["details"]["duration_ms"] == 11000
    current = events("emission_uses_current_client_facts")
    assert "agent" not in current[0] and current[0]["details"] == {"port": 443, "transport": "udp", "client": None}
    assert current[1]["agent"] == "bob" and current[1]["host"] == HOST
    assert current[1]["details"] == {"port": 443, "transport": "tcp", "client": "192.0.2.11", "duration_ms": 125}
    assert [event["details"]["duration_ms"] for event in events("duration_zero_backward_and_ties")
            if event["event"].endswith("_end")] == [0, 2, 0]
    clocks = rows["clock_failures_preserve_assignment_and_pop"]["steps"]
    assert clocks[1]["error_class"] == "RuntimeError" and clocks[1]["state_after"][0]["host"] == HOST
    assert clocks[3]["error_class"] == "RuntimeError" and clocks[3]["state_after"] == []
    assert clocks[3]["timeline"] == [{"monotonic": 11.0, "state": []}]


def run():
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    network_attempts = []

    def no_network(*_args, **_kwargs):
        network_attempts.append(True)
        raise AssertionError("no network in ignored-host source oracle")

    with tempfile.TemporaryDirectory(prefix="ignored-host-source-") as temporary:
        directory = Path(temporary)
        with (patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": str(directory),
              "SAFEYOLO_LOG_PATH": str(directory / "unused-audit.jsonl"),
              "MITMPROXY_LOG_PATH": str(directory / "unused-diagnostic.log")}),
              patch.object(socket, "getaddrinfo", side_effect=no_network),
              patch.object(socket, "create_connection", side_effect=no_network)):
            from mitmproxy.proxy.server_hooks import ServerConnectionHookData
            from mitmproxy.test import tflow

            from safeyolo.core import audit_schema, audit_writer, utils
            from safeyolo.mitm_addons import ignored_host_logger

            modules = ignored_host_logger, audit_writer, audit_schema, utils, tflow, ServerConnectionHookData
            rows = [observe(spec, modules) for spec in cases()]
            check_contract(rows)
            assert not list(directory.iterdir()), "source unexpectedly wrote a file"
    assert not network_attempts and not directory.exists()
    paths = ["cli/src/safeyolo/mitm_addons/ignored_host_logger.py", "cli/src/safeyolo/core/utils.py",
             "cli/src/safeyolo/core/audit_schema.py", "cli/src/safeyolo/core/audit_writer.py",
             "tests/test_ignored_host_logger.py"]
    return {"scope": "source-only matching and actual lifecycle methods; final audit sink and clocks supplied",
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
    print(json.dumps({"source_ignored_host_rows": 18}))
