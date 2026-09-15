"""Actual AgentAPI explain requests over owned temporary audit files.

The real query decoder, identity resolver, retained-file selector, scanner and
response serializer run. A synthetic writer supplies only pending/drain inputs.
File recipes keep the 10,000-line boundary controls small and reproducible.
"""

from __future__ import annotations

import argparse
import asyncio
import builtins
import hashlib
import json
import logging
import os
import secrets
import socket
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
REQUEST_ID = "req-" + "1" * 32
OTHER_ID = "req-" + "2" * 32
BACKUPS = 3


def event(label, **fields):
    return {"request_id": REQUEST_ID, "agent": "alice", "event": label, **fields}


def line(value, repeat=1):
    return {"text": json.dumps(value) + "\n", "repeat": repeat}


def log_file(*parts, name="audit.jsonl"):
    return {"name": name, "parts": list(parts)}


def cases():
    filler = line(event("filler", request_id=OTHER_ID), 9999)
    over_limit = log_file(line(event("evicted")), filler, line(event("tail")))
    rows = [
        {"name": "missing_query", "query": ""},
        {"name": "invalid_id", "query": "request_id=req-123"},
        {"name": "terminal_lf", "query": "request_id=" + REQUEST_ID + "%0A",
         "files": [log_file(line(event("plain")), line(event("lf", request_id=REQUEST_ID + "\n")))]},
        {"name": "duplicate_first_valid", "query": f"request_id={REQUEST_ID}&request_id={OTHER_ID}",
         "files": [log_file(line(event("first")), line(event("second", request_id=OTHER_ID)))]},
        {"name": "duplicate_first_empty", "query": "request_id=&request_id=" + REQUEST_ID},
        {"name": "unresolved_identity", "resolved_identity": False},
        {"name": "no_retained_files"},
        {"name": "foreign_and_missing", "files": [log_file(
            line(event("foreign", agent="bob")),
            line({"request_id": REQUEST_ID, "event": "missing"}),
            line({"request_id": REQUEST_ID, "event": "nested", "attribution": {"agent": "alice"}}))]},
        {"name": "strict_filter_malformed_and_typed", "files": [log_file(
            {"text": "\n  \nnot JSON\n{\n", "repeat": 1},
            line(event("wrong_id", request_id=OTHER_ID)), line(event("wrong_agent", agent="bob")),
            line(event("typed_agent", agent=["alice"])), line(event("first")),
            line(event("typed", value=float("nan"), count=2**80)))]},
        {"name": "retention_order_suffix", "current": "audit.log", "files": [
            log_file(line(event("current_late", ts=9)), line(event("current_early", ts=1)), name="audit.log"),
            log_file(line(event("backup1", ts=99)), name="audit.jsonl.1"),
            log_file(line(event("backup2")), name="audit.jsonl.2"),
            log_file(line(event("backup3")), name="audit.jsonl.3"),
            log_file(line(event("wrong_suffix")), name="audit.log.1"),
            log_file(line(event("beyond_retention")), name="audit.jsonl.4")]},
        {"name": "backups_without_current", "files": [
            log_file(line(event("backup1")), name="audit.jsonl.1"),
            log_file(line(event("backup3")), name="audit.jsonl.3")]},
        {"name": "tail_at_limit", "files": [log_file(
            line(event("first")), line(event("filler", request_id=OTHER_ID), 9998), line(event("last")))]},
        {"name": "tail_over_limit", "files": [over_limit]},
        {"name": "read_error_continues", "open_error": "audit.jsonl", "files": [
            log_file(line(event("unread"))), log_file(line(event("backup")), name="audit.jsonl.1")]},
        {"name": "unicode_decode_error", "files": [
            {"name": "audit.jsonl", "hex": "ff0a"},
            log_file(line(event("unreached")), name="audit.jsonl.1")]},
        {"name": "nonobject_json", "files": [
            log_file(line([])), log_file(line(event("unreached")), name="audit.jsonl.1")]},
        {"name": "drain_creates_file", "pending": 1,
         "drain_files": [log_file(line(event("created")))]},
        {"name": "drain_appends_partial", "pending": 1, "files": [log_file(line(event("before")))],
         "drain_files": [log_file(line(event("after")))]},
        {"name": "pending_precedes_incomplete", "pending": 1, "drained": False, "files": [over_limit]},
        {"name": "error_precedes_pending_incomplete", "pending": 1, "drained": False,
         "open_error": "audit.jsonl", "files": [log_file(line(event("unread"))),
            {**over_limit, "name": "audit.jsonl.1"}]},
        {"name": "freshness_wait_exception", "pending": 1, "drain_error": True,
         "files": [log_file(line(event("available")))]},
        {"name": "universal_newlines_and_strip", "files": [log_file({"text":
            "\u00a0" + json.dumps(event("crlf")) + "\u2003\r\n"
            + json.dumps(event("cr")) + "\r" + json.dumps(event("lf")) + "\n"
            + json.dumps(event("unterminated")), "repeat": 1})]},
    ]
    return [{"query": "request_id=" + REQUEST_ID, "resolved_identity": True,
             "current": "audit.jsonl", "files": [], "pending": 0, "drained": True, **row} for row in rows]


def write_files(directory, recipes, *, append=False):
    for recipe in recipes:
        path = directory / recipe["name"]
        assert path.parent == directory
        data = bytes.fromhex(recipe["hex"]) if "hex" in recipe else "".join(
            part["text"] * part["repeat"] for part in recipe["parts"]
        ).encode()
        with path.open("ab" if append else "wb") as output:
            output.write(data)


def observe(spec, directory, token, modules):
    agent_api, audit_writer, utils, taddons, tflow, unix_mode = modules
    directory.mkdir()
    write_files(directory, spec["files"])
    api = agent_api.AgentAPI()
    flow = tflow.tflow(resp=False)
    flow.request.url = "http://_safeyolo.proxy.internal/explain" + ("?" + spec["query"] if spec["query"] else "")
    flow.request.method = "GET"
    flow.request.headers["Authorization"] = "Bearer " + token
    flow.request.headers["X-SafeYolo-Agent"] = "alice"
    flow.metadata["agent"] = "alice"
    if spec["resolved_identity"]:
        flow.client_conn.proxy_mode = unix_mode.parse("unix:/tmp/192.0.2.10_alice/proxy.sock")
        flow.client_conn.peername = ("192.0.2.10", 0)
    timeline, retained, scans = [], [], []

    def pending_count():
        timeline.append("pending_count")
        return spec["pending"]

    def wait_for_drain(timeout_s):
        timeline.append("wait_for_drain:" + str(timeout_s))
        assert timeout_s == 0.5
        if spec.get("drain_error"):
            raise RuntimeError("owned freshness failure")
        write_files(directory, spec.get("drain_files", []), append=True)
        return spec["drained"]

    def get_writer():
        timeline.append("get_writer")
        return SimpleNamespace(pending_count=pending_count, wait_for_drain=wait_for_drain)

    real_retained, real_scan = api._retained_audit_files, api._scan_audit_files

    def retained_files(current):
        timeline.append("retained_files")
        paths = real_retained(current)
        retained.extend(path.name for path in paths)
        return paths

    def scan(files, request_id, agent_id):
        timeline.append("scan")
        record = {"files": [path.name for path in files], "request_id": request_id, "agent": agent_id}
        scans.append(record)
        try:
            events, incomplete, read_error = real_scan(files, request_id, agent_id)
        except (UnicodeDecodeError, AttributeError) as error:
            record["error_type"] = type(error).__name__
            raise
        record.update(events_json=json.dumps(events), incomplete=incomplete, read_error=read_error)
        return events, incomplete, read_error

    def owned_open(path, *args, **kwargs):
        assert path.parent == directory
        timeline.append("open:" + path.name)
        if path.name == spec.get("open_error"):
            raise OSError("owned audit read failure")
        return builtins.open(path, *args, **kwargs)

    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_LOG_PATH": str(directory / spec["current"])}))
        for target, name, kwargs in (
            (audit_writer, "get_writer", {"side_effect": get_writer}),
            (utils, "SAFEYOLO_LOG_BACKUPS", {"new": BACKUPS}),
            (api, "_find_addon", {"return_value": None}),
            (api, "_retained_audit_files", {"side_effect": retained_files}),
            (api, "_scan_audit_files", {"side_effect": scan}),
            (agent_api, "open", {"side_effect": owned_open, "create": True}),
        ):
            stack.enter_context(patch.object(target, name, **kwargs))
        stack.enter_context(taddons.context(api))
        asyncio.run(api.request(flow))
    assert flow.response is not None
    body_text = flow.response.content.decode()
    result = {"status": flow.response.status_code, "body_text": body_text,
              "headers": [list(pair) for pair in flow.response.headers.items(multi=True)],
              "api_response": flow.metadata.get(agent_api.AGENT_API_RESPONSE_METADATA),
              "blocked_by": flow.metadata.get("blocked_by")}
    row = {"input": spec, "query_pairs": [list(pair) for pair in flow.request.query.items(multi=True)],
           "result": result, "timeline": timeline, "retained": retained, "scans": scans}
    assert result["api_response"] is True and result["blocked_by"] == "agent-api"
    assert flow.response.headers["content-length"] == str(len(flow.response.content))
    return row


def check_contract(rows):
    by_name = {row["input"]["name"]: row for row in rows}
    expected = {
        "terminal_lf": ("complete", ["lf"]), "duplicate_first_valid": ("complete", ["first"]),
        "no_retained_files": ("complete", []), "foreign_and_missing": ("complete", []),
        "strict_filter_malformed_and_typed": ("complete", ["first", "typed"]),
        "retention_order_suffix": ("complete", ["current_late", "current_early", "backup1", "backup2", "backup3"]),
        "backups_without_current": ("complete", ["backup1", "backup3"]),
        "tail_at_limit": ("complete", ["first", "last"]), "tail_over_limit": ("incomplete_search", ["tail"]),
        "read_error_continues": ("error", ["backup"]), "drain_creates_file": ("complete", ["created"]),
        "drain_appends_partial": ("complete", ["before", "after"]),
        "pending_precedes_incomplete": ("pending", ["tail"]),
        "error_precedes_pending_incomplete": ("error", ["tail"]),
        "freshness_wait_exception": ("complete", ["available"]),
        "universal_newlines_and_strip": ("complete", ["crlf", "cr", "lf", "unterminated"]),
    }
    for name, (status, labels) in expected.items():
        row = by_name[name]
        body = json.loads(row["result"]["body_text"])
        assert row["result"]["status"] == 200 and body["status"] == status, name
        assert [entry["event"] for entry in body["events"]] == labels, name
        assert row["timeline"][:2] == ["get_writer", "pending_count"], name
        if row["input"]["pending"]:
            assert row["timeline"][2:5] == ["wait_for_drain:0.5", "retained_files", "scan"], name
        incomplete = name in {"tail_over_limit", "pending_precedes_incomplete", "error_precedes_pending_incomplete"}
        assert (body.get("searched_lines_per_file") == 10000) == incomplete, name
    for name in ("missing_query", "invalid_id", "duplicate_first_empty", "unresolved_identity"):
        row = by_name[name]
        assert row["result"]["status"] == (403 if name == "unresolved_identity" else 400), name
        assert row["timeline"] == [] and row["scans"] == [], name
    for name, error in (("unicode_decode_error", "UnicodeDecodeError"), ("nonobject_json", "AttributeError")):
        row = by_name[name]
        assert row["result"]["status"] == 500, name
        assert json.loads(row["result"]["body_text"]) == {"error": "Internal error: " + error}, name
        assert row["scans"][0]["error_type"] == error, name
        assert "open:audit.jsonl.1" not in row["timeline"], name
    assert by_name["no_retained_files"]["result"] == by_name["foreign_and_missing"]["result"]
    assert by_name["terminal_lf"]["scans"][0]["request_id"] == REQUEST_ID + "\n"
    assert by_name["retention_order_suffix"]["retained"] == ["audit.log", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"]
    assert len(rows) == len(expected) + 6 == 22


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="agent-api-explain-source-") as directory:
        private = Path(directory)
        token = secrets.token_urlsafe(24)
        (private / "agent_token").write_text(token)
        os.environ.update(SAFEYOLO_DATA_DIR=directory, SAFEYOLO_LOG_PATH=directory + "/unused.jsonl",
                          MITMPROXY_LOG_PATH=directory + "/unused-diagnostic.log")
        from mitmproxy.test import taddons, tflow

        from safeyolo.core import audit_writer, utils
        from safeyolo.mitm_addons import agent_api
        from safeyolo.proxy_modes.unix_listener import UnixMode

        network_attempts = []

        def no_network(*_args, **_kwargs):
            network_attempts.append(True)
            raise AssertionError("no network is allowed in the selected explain controls")

        modules = (agent_api, audit_writer, utils, taddons, tflow, UnixMode)
        with (patch.object(socket, "getaddrinfo", side_effect=no_network),
              patch.object(socket, "create_connection", side_effect=no_network)):
            rows = [observe(spec, private / spec["name"], token, modules) for spec in cases()]
        assert not network_attempts
        check_contract(rows)
        encoded = json.dumps(rows, allow_nan=False)
        assert token not in encoded and token.encode().hex() not in encoded
    paths = ["cli/src/safeyolo/mitm_addons/agent_api.py", "cli/src/safeyolo/mitm_addons/request_id.py",
             "cli/src/safeyolo/core/identity.py", "cli/src/safeyolo/core/utils.py",
             "cli/src/safeyolo/core/audit_writer.py", "cli/src/safeyolo/core/flow_cache.py",
             "cli/src/safeyolo/proxy_modes/unix_listener.py", "pdp/tokens.py", "tests/test_agent_api.py"]
    return {"max_lines": agent_api.MAX_EXPLAIN_LINES, "backups": BACKUPS, "rows": rows,
            "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    if args.check:
        assert result == json.loads(args.check.read_text()), "source AgentAPI explain changed"
    if args.output:
        args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"source_explain_rows": len(result["rows"])}))
