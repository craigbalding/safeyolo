"""Finite actual FlowStore selections over a synthetic owned SQLite database.

No proxy, sockets, credentials, tokens, or operational flow data. The one v2
ownerless row is seeded explicitly after recording to exercise the existing
query boundary; it is not claimed to be ordinary recorder output. Error names
are observations of source exceptions, not replacement validation logic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import sys
import tempfile
from pathlib import Path

REPO = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(REPO / "cli/src")]

from safeyolo.storage.flow_store import FlowStore  # noqa: E402


def records():
    base = {
        "engagement_id": "owned-run",
        "agent_id": "alice",
        "evidence_owner": "alice",
        "trusted_transport_identity": "uds:alice",
        "initiator": "tool",
        "attribution_status": "resolved",
        "attribution_provenance_json": '{"synthetic": true}',
        "source_id": "owned-source",
        "run": "r1",
        "test": "t1",
        "role": "tester",
        "test_agent": "alice",
        "suite": "suite-a",
        "subject": "subject-a",
        "step": "step-a",
        "intent": "observe",
        "expect": "allow",
        "source_type": "http",
        "flow_state": "complete",
        "scheme": "http",
        "host": "alpha.invalid",
        "port": 80,
        "method": "GET",
        "path": "/items/one",
        "query_string": "q=one",
        "full_url": "http://alpha.invalid/items/one?q=one",
        "status_code": 200,
        "reason": "OK",
        "request_content_type": "text/plain",
        "response_content_type": "text/plain",
        "request_headers_json": '[["X-Fixture", "request-marker"]]',
        "response_headers_json": '[["X-Fixture", "response-marker"]]',
        "request_body": "request alpha beta",
        "response_body": "response alpha beta",
        "ts_end": 1001,
        "duration_ms": 1,
    }
    changes = [
        {},
        {
            "status_code": 404,
            "reason": "missing",
            "response_body": 'alpha quoted "word" host:name',
        },
        {
            "path": "/items/two",
            "method": "POST",
            "status_code": 503,
            "test": "t2",
            "intent": "retry",
        },
        {
            "agent_id": "bob",
            "evidence_owner": "bob",
            "trusted_transport_identity": "uds:bob",
            "test_agent": "bob",
        },
        {"engagement_id": "other-run", "host": "other.invalid", "path": "/other"},
        {
            "response_body": "é" * 513 + " alpha",
            "path": "/preview",
            "status_code": None,
        },
        {
            "response_content_type": "application/octet-stream",
            "response_body": "binary alpha",
            "path": "/binary",
        },
        {"path": "/quarantine", "attribution_status": "conflict"},
    ]
    return [
        dict(base, **change, request_id=f"query-{index}", ts_start=1000 + index * 10)
        for index, change in enumerate(changes)
    ]


def cases():
    return [
        ("summaries", "search_flows", {}),
        (
            "owner_and_engagement",
            "search_flows",
            {"evidence_owner": "alice", "engagement_id": "owned-run"},
        ),
        (
            "caller_agent_is_additional",
            "search_flows",
            {"evidence_owner": "alice", "agent_id": "bob"},
        ),
        (
            "all_context_predicates",
            "search_flows",
            {
                "evidence_owner": "alice",
                "trusted_transport_identity": "uds:alice",
                "initiator": "tool",
                "attribution_status": "resolved",
                "run": "r1",
                "test": "t2",
                "role": "tester",
                "test_agent": "alice",
                "suite": "suite-a",
                "subject": "subject-a",
                "step": "step-a",
                "intent": "retry",
                "expect": "allow",
                "source_type": "http",
                "flow_state": "complete",
                "method": "post",
                "host": "alpha.invalid",
                "status_code": "503",
            },
        ),
        (
            "like_headers_tag_and_query",
            "search_flows",
            {
                "path_contains": "items",
                "text_contains": "quoted",
                "request_header_contains": "request-marker",
                "response_header_contains": "response-marker",
                "tag": "review:one:two",
                "q": "host:name",
            },
        ),
        (
            "class_range",
            "search_flows",
            {"status_class": "4XX", "status_min": 400, "status_max": 450},
        ),
        (
            "inclusive_time_wildcard_path",
            "search_flows",
            {"from_ts": 1000, "to_ts": 1020, "path": "items/_ne", "tag": "review"},
        ),
        (
            "integer_grammar_and_capped_huge_limit",
            "search_flows",
            {"status_code": "\u2003+٢_٠٠\u2003", "limit": 10**100, "offset": "0"},
        ),
        ("preview_scalar_length", "search_flows", {"path": "preview"}),
        ("unknown_filter", "search_flows", {"zz": True, "aa": 1}),
        ("bool_integer", "search_flows", {"limit": True}),
        ("null_text", "search_flows", {"host": None}),
        ("negative_offset", "search_flows", {"offset": -1}),
        ("reversed_status", "search_flows", {"status_min": 300, "status_max": 200}),
        ("sqlite_integer_overflow", "search_flows", {"offset": 10**100}),
        (
            "endpoints_ignore_host_and_unknown",
            "get_endpoints",
            {
                "evidence_owner": "alice",
                "host": "absent.invalid",
                "unknown": True,
                "limit": -1,
                "offset": -2,
            },
        ),
        (
            "endpoints_context_time",
            "get_endpoints",
            {"evidence_owner": "alice", "test": "t1", "from_ts": 1000, "to_ts": 1010},
        ),
        ("endpoint_limit_is_not_normalized", "get_endpoints", {"limit": "2"}),
        (
            "facets_keep_every_filter",
            "get_facets",
            {
                "evidence_owner": "alice",
                "engagement_id": "owned-run",
                "status_code": "200",
            },
        ),
        ("facet_unknown_filter", "get_facets", {"q": "alpha"}),
        ("facet_string_iteration", "get_facets", "aa"),
        ("facet_allowed_list_then_object_error", "get_facets", ["host"]),
        (
            "response_fts_scope_and_time",
            "search_bodies",
            {
                "query": "alpha",
                "engagement_id": "owned-run",
                "evidence_owner": "alice",
                "from_ts": 1000,
                "to_ts": 1030,
            },
        ),
        (
            "request_fts_exact_path",
            "search_request_bodies",
            {
                "query": "request alpha",
                "engagement_id": "owned-run",
                "evidence_owner": "alice",
                "host": "alpha.invalid",
                "path": "/items/two",
            },
        ),
        (
            "fts_quotes_punctuation_and_python_space",
            "search_bodies",
            {
                "query": '"word"\x1chost:name',
                "engagement_id": "owned-run",
                "evidence_owner": "alice",
            },
        ),
        ("fts_missing_engagement", "search_bodies", {"query": "alpha"}),
        (
            "fts_falsy_query",
            "search_request_bodies",
            {"query": [], "engagement_id": "owned-run"},
        ),
        (
            "fts_nonstring_query",
            "search_bodies",
            {"query": ["alpha"], "engagement_id": "owned-run"},
        ),
        (
            "fts_whitespace_syntax_error",
            "search_bodies",
            {"query": "   ", "engagement_id": "owned-run"},
        ),
        ("lax_parameter_type", "get_endpoints", {"agent_id": ["alice"]}),
        ("lax_fractional_limit", "get_endpoints", {"limit": 1.5}),
        ("read_failure_preserves_rows", "search_flows", {}),
    ]


def typed_cases():
    return [
        (
            "ignored_nested_nonfinite",
            "get_endpoints",
            '{"unused":{"values":[NaN,Infinity,-Infinity]}}',
        ),
        ("positive_infinite_limit_is_capped", "get_endpoints", '{"limit":Infinity}'),
        ("nan_limit_reaches_sqlite", "get_endpoints", '{"limit":NaN}'),
        ("negative_infinite_time", "get_endpoints", '{"from_ts":-Infinity}'),
        ("nan_context_binds_null", "get_endpoints", '{"agent_id":NaN}'),
        ("strict_nan_integer", "search_flows", '{"status_code":NaN}'),
        ("strict_infinite_text", "get_facets", '{"host":Infinity}'),
        ("nan_query_missing_engagement", "search_bodies", '{"query":NaN}'),
        (
            "nan_query_with_engagement",
            "search_bodies",
            '{"query":NaN,"engagement_id":"owned-run"}',
        ),
        (
            "fts_ignores_nested_nonfinite",
            "search_request_bodies",
            '{"query":"request alpha","engagement_id":"owned-run","evidence_owner":"alice","unused":[NaN,Infinity]}',
        ),
    ]


def observe(store, name, method, filters):
    error = None
    validation = None
    output = None
    try:
        output = getattr(store, method)(filters)
    except (ValueError, TypeError, AttributeError, OverflowError, sqlite3.Error) as exc:
        error = type(exc).__name__
        validation = str(exc) if isinstance(exc, ValueError) else None
    return {
        "name": name,
        "method": method,
        "output": output,
        "exception": error,
        "validation": validation,
    }


def run():
    rows = []
    source_records = records()
    with tempfile.TemporaryDirectory(prefix="flow-query-source-") as temporary:
        directory = Path(temporary)
        store = FlowStore(str(directory / "flows.db"))
        store.init_db()
        try:
            for source_record in source_records:
                record = dict(source_record)
                for key in ("request_body", "response_body"):
                    record[key] = record[key].encode()
                store.record_flow(record)
            store.tag_flow(1, "review")
            store.tag_flow(2, "review", "one:two")
            # Authoritative v2 ownerless row; ordinary record_flow backfills owner.
            store._conn.execute("UPDATE flows SET evidence_owner=NULL WHERE id=8")
            store._conn.commit()
            for name, method, filters in cases():
                observed = observe(store, name, method, filters)
                # Preserve the initial fixture's exact field order.
                rows.append(
                    {
                        "name": name,
                        "method": method,
                        "filters": filters,
                        "output": observed["output"],
                        "exception": observed["exception"],
                        "validation": observed["validation"],
                    }
                )
            typed_rows = []
            for name, method, raw in typed_cases():
                observed = observe(store, name, method, json.loads(raw))
                observed["filters_json"] = raw
                typed_rows.append(observed)
            assert rows[0]["output"] == rows[-1]["output"]
        finally:
            store.close()
    assert not directory.exists()
    return {
        "source_sha256": hashlib.sha256(
            (REPO / "cli/src/safeyolo/storage/flow_store.py").read_bytes()
        ).hexdigest(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "records": source_records,
        "cases": rows,
        "typed_cases": typed_rows,
        "teardown": {"store_closed": True, "owned_directory_removed": True},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    if args.check:
        expected = json.loads(args.check.read_text())
        assert result == expected, "actual source flow query outputs changed"
        print(
            f"{len(result['cases'])}+{len(result['typed_cases'])} source query cases match"
        )
    elif args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
        print(
            f"{len(result['cases'])}+{len(result['typed_cases'])} source query cases frozen"
        )
    else:
        parser.error("choose --check or --output")
