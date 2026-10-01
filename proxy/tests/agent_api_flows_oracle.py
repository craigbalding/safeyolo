"""Actual AgentAPI auth/dispatch and real owned FlowStore; no listener or network.

Only recorder lookup and the audit queue are supplied by this fixture. Trusted
identity is resolved from a real UnixMode path. One explicitly quarantined v2
row documents the separately approved exact-owner correction.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(REPO / "cli/src"), str(REPO)]
from mitmproxy.test import taddons, tflow  # noqa: E402
from oracle_gzip import compress as oracle_gzip_compress  # noqa: E402

from safeyolo.mitm_addons.agent_api import AgentAPI  # noqa: E402
from safeyolo.proxy_modes.unix_listener import UnixMode  # noqa: E402
from safeyolo.storage.flow_store import FlowStore  # noqa: E402

TOKEN = "synthetic-owned-flow-api"


def records():
    result = []
    for index, owner in enumerate(("alice", "bob", "alice", "alice", "alice")):
        result.append(
            {
                "metadata": {
                    "request_id": f"flow-api-{index}",
                    "ts_start": 1000 + index,
                    "agent_id": owner,
                    "evidence_owner": owner,
                    "engagement_id": "owned-run",
                    "host": "owned.invalid",
                    "flow_state": "complete",
                    "path": "/plain",
                    "method": "POST",
                    "status_code": 200,
                    "request_content_type": "application/json",
                    "response_content_type": "text/plain",
                    "request_headers_json": '[["X-Proof", "a"], ["x-proof", "b"]]',
                    "context_json": '{"test": "synthetic"}',
                },
                "request_hex": b'{"needle": "request"}'.hex(),
                "response_hex": b"needle response \xff".hex(),
            }
        )
    result[3]["request_hex"] = result[3]["response_hex"] = ""
    result[4]["metadata"]["response_content_type"] = "application/octet-stream"
    return result


def cases():
    def c(
        name, path="search", method="POST", payload=b"{}", identity="alice", **kwargs
    ):
        return dict(
            name=name,
            path="/api/flows/" + path,
            method=method,
            input_hex=payload.hex(),
            identity=identity,
            available=True,
            content_encoding="",
            auth="valid",
            **kwargs,
        )

    return [
        c("search_default"),
        c(
            "search_get_duplicates",
            path="search?host=owned.invalid&host=wrong&limit=1",
            method="GET",
            payload=b"ignored",
        ),
        c("search_delete_body", method="DELETE", payload=b'{"limit":1}'),
        c(
            "search_legacy_additional",
            payload=b'{"agent_id":"bob","evidence_owner":"bob"}',
        ),
        c("search_nonobject", payload=b"[]", identity=None),
        c("search_unknown", payload=b'{"unknown":"value"}'),
        c("search_bad_limit", payload=b'{"limit":true}'),
        c("search_unresolved", identity=None),
        c("search_null", payload=b"null"),
        c("search_malformed", payload=b"{"),
        c("search_invalid_utf8", payload=b"\xff"),
        c("search_empty", payload=b""),
        c("search_utf16", payload='{"limit":1}'.encode("utf-16")),
        c("search_gzip", payload=oracle_gzip_compress(b'{"limit":1}')),
        c("search_bad_gzip", payload=b"broken"),
        c("search_bigint", payload=b'{"limit":9223372036854775808}'),
        c("search_integer_conversion", payload=b'{"limit":' + b"1" * 4301 + b"}"),
        c(
            "integer_duplicate_conversion",
            path="endpoints",
            payload=b'{"ignored":' + b"1" * 4301 + b',"ignored":0}',
        ),
        c(
            "integer_ignored_conversion",
            path="endpoints",
            payload=b'{"ignored":' + b"1" * 4301 + b"}",
        ),
        c(
            "integer_maximum",
            path="endpoints",
            payload=b'{"ignored":' + b"1" * 4300 + b"}",
        ),
        c(
            "long_float",
            path="endpoints",
            payload=b'{"ignored":' + b"1" * 4301 + b".0}",
        ),
        c("search_surrogate", payload=b'{"host":"\\ud800"}'),
        c("search_surrogate_query", path="search?host=%FF", method="GET"),
        c(
            "search_surrogate_query_unresolved",
            path="search?host=%FF",
            method="GET",
            identity=None,
        ),
        c("search_ignored_owner_query", path="search?evidence_owner=%FF", method="GET"),
        c("endpoints_default", path="endpoints"),
        c("endpoints_nonobject", path="endpoints", payload=b"[]"),
        c("endpoints_empty_string", path="endpoints", payload=b'""'),
        c("endpoints_string", path="endpoints", payload=b'"x"'),
        c(
            "endpoints_unresolved_nonobject",
            path="endpoints",
            payload=b"[]",
            identity=None,
        ),
        c("endpoints_ignored_nan", path="endpoints", payload=b'{"ignored":NaN}'),
        c(
            "endpoints_ignored_marker",
            path="endpoints",
            payload=b'{"ignored":{"$serde_json::private::Number":"1"}}',
        ),
        c("facets_default", path="facets"),
        c("facets_nonobject", path="facets", payload=b"false", identity=None),
        c("facets_unknown", path="facets", payload=b'{"unknown":0}'),
        c(
            "body_search",
            path="body-search",
            payload=b'{"engagement_id":"owned-run","query":"needle"}',
        ),
        c(
            "request_search",
            path="request-body-search",
            payload=b'{"engagement_id":"owned-run","query":"needle"}',
        ),
        c("fts_nonobject", path="body-search", payload=b"1", identity=None),
        c("fts_empty_string", path="body-search", payload=b'""'),
        c("fts_array", path="body-search", payload=b"[]"),
        c("fts_string", path="body-search", payload=b'"x"'),
        c("request_search_empty_string", path="request-body-search", payload=b'""'),
        c("request_search_array", path="request-body-search", payload=b"[]"),
        c("request_search_string", path="request-body-search", payload=b'"x"'),
        c("fts_no_engagement", path="body-search", identity=None),
        c(
            "fts_no_query",
            path="body-search",
            payload=b'{"engagement_id":"owned-run"}',
            identity=None,
        ),
        c(
            "fts_nan_query",
            path="body-search",
            payload=b'{"engagement_id":"owned-run","query":NaN}',
        ),
        c("detail", path="1", method="GET"),
        c("detail_post_ignores_body", path="1", payload=b"{"),
        c("detail_delete_ignores_body", path="1", method="DELETE", payload=b"\xff"),
        c("detail_foreign", path="2", method="GET"),
        c("detail_unresolved", path="1", method="GET", identity=None),
        c("detail_unicode", path="\u0661", method="GET"),
        c("detail_newline_anchor", path="1\n", method="GET"),
        c("detail_invalid_trailing_separator", path="1/\n", method="GET"),
        c("detail_percent_digits", path="%31", method="GET"),
        c("detail_bad_suffix", path="1/other", method="GET"),
        c("detail_overflow", path=str(2**64), method="GET", identity=None),
        c("detail_oversized_digits", path="1" * 4301, method="GET"),
        c("request_body", path="1/request-body", method="GET"),
        c("empty_body", path="4/request-body", method="GET"),
        c("binary_body", path="5/response-body", method="GET"),
        c("response_body", path="1/response-body", method="DELETE", payload=b"ignored"),
        c("body_foreign", path="2/response-body", method="GET"),
        c("missing_body", path="999/request-body", method="GET"),
        c("ownerless_source_defect", path="3", method="GET"),
        c("ownerless_body_source_defect", path="3/response-body", method="GET"),
        c("store_unavailable"),
        c("unauthenticated"),
        c("method_first", method="PUT"),
        c("post_only_get", path="endpoints", method="GET"),
    ]


async def run():
    logging.disable(logging.CRITICAL)
    events, rows = [], []
    with (
        tempfile.TemporaryDirectory(prefix="owned-flow-api-") as temporary,
        ExitStack() as stack,
    ):
        root = Path(temporary)
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temporary}))
        stack.enter_context(
            patch("safeyolo.core.audit_writer.put_event", side_effect=events.append)
        )
        for target in (
            "socket.getaddrinfo",
            "socket.create_connection",
            "socket.socket.connect",
        ):
            stack.enter_context(
                patch(target, side_effect=AssertionError("Unexpected source network"))
            )
        (root / "agent_token").write_text(TOKEN)
        store = FlowStore(str(root / "flows.sqlite"))
        store.init_db()
        for record in records():
            store.record_flow(
                dict(
                    record["metadata"],
                    request_body=bytes.fromhex(record["request_hex"]),
                    response_body=bytes.fromhex(record["response_hex"]),
                )
            )
        store._conn.execute(
            "UPDATE flows SET evidence_owner=NULL,attribution_status='conflict' WHERE id=3"
        )
        store._conn.commit()
        try:
            for spec in cases():
                name = spec["name"]
                if name in {"search_gzip", "search_bad_gzip"}:
                    spec["content_encoding"] = "gzip"
                if name == "store_unavailable":
                    spec["available"] = False
                    spec["input_hex"] = b"{".hex()
                if name in {"unauthenticated", "method_first"}:
                    spec["auth"] = "missing"
                api = AgentAPI()
                api._get_flow_store = (
                    lambda available=spec["available"]: store if available else None
                )
                api._find_addon = lambda _name: None
                events.clear()
                with taddons.context(api):
                    flow = tflow.tflow()
                    flow.client_conn.peername = ("127.0.0.1", 12345)
                    if spec["identity"] is not None:
                        flow.client_conn.proxy_mode = UnixMode.parse(
                            f"unix:{root}/127.0.0.1_{spec['identity']}/proxy.sock"
                        )
                    flow.request.url = "http://_safeyolo.proxy.internal/"
                    flow.request.path = spec["path"]
                    flow.request.method = spec["method"]
                    if spec["auth"] == "valid":
                        flow.request.headers["Authorization"] = "Bearer " + TOKEN
                    if spec["content_encoding"]:
                        flow.request.headers["Content-Encoding"] = spec[
                            "content_encoding"
                        ]
                    flow.request.raw_content = bytes.fromhex(spec["input_hex"])
                    exception = None
                    try:
                        await api.request(flow)
                    except ValueError as error:
                        # int(route digits) is intentionally outside the source handler try.
                        if name != "detail_oversized_digits":
                            raise
                        exception = type(error).__name__
                    rows.append(
                        dict(
                            spec,
                            exception=exception,
                            status=None
                            if flow.response is None
                            else flow.response.status_code,
                            text=None
                            if flow.response is None
                            else flow.response.content.decode(),
                            audit_events=len(events),
                        )
                    )
        finally:
            store.close()
    names = [
        "cli/src/safeyolo/mitm_addons/agent_api.py",
        "cli/src/safeyolo/storage/flow_store.py",
        "cli/src/safeyolo/core/identity.py",
        "cli/src/safeyolo/proxy_modes/unix_listener.py",
    ]
    return {
        "records": records(),
        "rows": rows,
        "source_sha256": {
            name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
            for name in names
        },
        "cleanup": {
            "store_closed": True,
            "temporary_directory_removed": not root.exists(),
        },
        "network_calls": 0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = asyncio.run(run())
    if args.check:
        assert result == json.loads(args.check.read_text()), (
            "Flow API source oracle changed"
        )
        print(f"{len(result['rows'])} source flow facade controls checked")
    else:
        print(json.dumps(result, indent=2))
