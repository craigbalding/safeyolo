"""Owned SQLite fixtures against the actual shipped FlowStore; no network."""

import json
import os
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "cli/src"))
from safeyolo.storage.flow_store import FlowStore  # noqa: E402

NOW = 1_000_123


def metadata(name):
    return {
        "request_id": name,
        "ts_start": 100,
        "engagement_id": "owned-test",
        "agent_id": "alice",
        "host": "owned.invalid",
        "flow_state": "complete",
        "path": "/plain",
        "method": "POST",
        "status_code": 200,
        "request_content_type": "application/json",
        "response_content_type": "text/plain",
        "request_headers_json": '[["X-Proof", "one"], ["X-Proof", "two"]]',
        "context_json": '{"run": "synthetic"}',
        "provenance_tags": {"z-last": "z", "a-first": "a"},
    }


def view(store, flow_id):
    output = {"flow": store.get_flow(flow_id)}
    for side in ("request", "response"):
        body = getattr(store, f"get_{side}_body")(flow_id)
        body["body_hex"] = body.pop("body").hex()
        output[side] = body
    row = store._conn.execute(
        "SELECT request_body_text_index,response_body_text_index,"
        "request_body_blob IS NULL,response_body_blob IS NULL FROM flows WHERE id=?",
        (flow_id,),
    ).fetchone()
    output["indexes"] = list(row)
    output["request_match"] = [
        r["request_id"]
        for r in store.search_request_bodies(
            {"engagement_id": "owned-test", "query": "needle"}
        )
    ]
    output["response_match"] = [
        r["request_id"]
        for r in store.search_bodies({"engagement_id": "owned-test", "query": "needle"})
    ]
    return output


def rollback_summary(store, flow_id):
    """Return stable cross-version facts without volatile timestamps."""
    flow = store.get_flow(flow_id)
    if flow is None:
        return None
    request = store.get_request_body(flow_id)
    response = store.get_response_body(flow_id)
    return {
        "request_id": flow["request_id"],
        "agent_id": flow["agent_id"],
        "evidence_owner": flow["evidence_owner"],
        "attribution_status": flow["attribution_status"],
        "request_body_hex": request["body"].hex(),
        "response_body_hex": response["body"].hex(),
        "tags": [
            {"tag": row["tag"], "value": row["value"]}
            for row in store.get_flow_tags(flow_id)
        ],
    }


def rollback_seed(path):
    """Write one source-version row and tag for the native reader."""
    store = FlowStore(str(path))
    store.init_db()
    record = metadata("python-seed")
    record.update(
        request_body=b"python request",
        response_body=b"python response",
        provenance_tags={"python-seed": "source"},
    )
    flow_id = store.record_flow(record)
    store.tag_flow(flow_id, "python-explicit", "source")
    result = rollback_summary(store, flow_id)
    store.close()
    return {"flow_id": flow_id, "summary": result}


def rollback_after_native(path):
    """Read a native row, then make a source-version tag update."""
    store = FlowStore(str(path))
    store.init_db()
    before = {
        "source_row": rollback_summary(store, 1),
        "native_row": rollback_summary(store, 2),
    }
    store.tag_flow(1, "python-after-native", "source")
    result = {
        "before": before,
        "after": rollback_summary(store, 1),
    }
    store.close()
    return result


def run_case(
    directory,
    name,
    settings=None,
    changes=None,
    request=b"needle request",
    response=b"needle response",
):
    settings = settings or {}
    record = metadata(name)
    record.update(changes or {})
    path = directory / f"{name}.sqlite3"
    store = FlowStore(str(path), **settings)
    store.init_db()
    spec = {
        "name": name,
        "settings_json": json.dumps(settings),
        "metadata": record,
        "request_hex": request.hex(),
        "response_hex": response.hex(),
    }
    try:
        with patch("time.time", return_value=NOW / 1000):
            flow_id = store.record_flow(
                dict(record, request_body=request, response_body=response)
            )
        spec["result"] = view(store, flow_id)
    except (TypeError, AttributeError, OverflowError, sqlite3.Error) as error:
        spec["error"] = type(error).__name__
    finally:
        store._conn.close()
    return spec


def matrix(directory):
    cases = [
        run_case(directory, "default"),
        run_case(directory, "identity", {"compress_bodies": False}),
        run_case(
            directory,
            "zero",
            {"max_request_body_bytes": 0, "max_response_body_bytes": 0},
        ),
        run_case(
            directory,
            "negative",
            {"max_request_body_bytes": -3, "max_response_body_bytes": -100},
        ),
        run_case(
            directory,
            "bool_limits",
            {"max_request_body_bytes": True, "max_response_body_bytes": False},
        ),
        run_case(
            directory,
            "huge",
            {"max_request_body_bytes": 10**100, "preview_text_chars": 10**100},
        ),
        run_case(
            directory,
            "float_unused_slice",
            {"max_request_body_bytes": 100.0, "preview_text_chars": 100.0},
        ),
        run_case(directory, "float_body_slice", {"max_request_body_bytes": 1.0}),
        run_case(directory, "float_preview_slice", {"preview_text_chars": 1.0}),
        run_case(
            directory,
            "nan",
            {
                "max_request_body_bytes": float("nan"),
                "preview_text_chars": float("nan"),
            },
        ),
        run_case(directory, "infinity", {"max_request_body_bytes": float("inf")}),
        run_case(
            directory, "negative_infinity", {"max_request_body_bytes": -float("inf")}
        ),
        run_case(directory, "bad_limit", {"max_request_body_bytes": "3"}),
        run_case(directory, "preview_negative", {"preview_text_chars": -3}),
        run_case(
            directory,
            "preview_unicode",
            {"preview_text_chars": 3},
            request="aé😀needle".encode(),
        ),
        run_case(
            directory,
            "invalid_utf8",
            request=bytes(range(256)) + b"\xe2\x82x\xed\xa0\x80\xf0\x90\x80\xff needle",
        ),
        run_case(
            directory,
            "empty_bad_preview",
            {"preview_text_chars": {}},
            request=b"",
            response=b"",
        ),
        run_case(
            directory,
            "binary_bad_preview",
            {"preview_text_chars": {}},
            {
                "request_content_type": "image/png",
                "response_content_type": "application/octet-stream",
            },
        ),
        run_case(
            directory,
            "falsy_ct",
            changes={"request_content_type": 0, "response_content_type": None},
        ),
        run_case(
            directory, "bad_ct_empty", changes={"request_content_type": 3}, request=b""
        ),
        run_case(
            directory, "truthy_compression", {"compress_bodies": {"enabled": False}}
        ),
        run_case(directory, "falsy_compression", {"compress_bodies": []}),
        run_case(
            directory,
            "ct_python_case",
            changes={
                "request_content_type": "APPLİCATİON/JſON",
                "response_content_type": "application/K+json",
            },
        ),
        run_case(
            directory,
            "ct_python_whitespace",
            changes={"request_content_type": "\x1ftext/plain\x1f ; x=y"},
        ),
        run_case(
            directory,
            "suffix_ct",
            changes={
                "request_content_type": "application/problem+json",
                "response_content_type": "application/vnd.owned+xml",
            },
        ),
        run_case(
            directory,
            "owner_compat",
            changes={
                "agent_id": None,
                "evidence_owner": "bob",
                "initiator": None,
                "attribution_status": None,
                "attribution_provenance_json": {"name": "é", "x": -0.0},
            },
        ),
        run_case(
            directory, "owner_empty", changes={"agent_id": "", "evidence_owner": ""}
        ),
        run_case(
            directory,
            "unknown_ignored",
            changes={"unknown": {"large": [None, 3]}, "provenance_tags": []},
        ),
        run_case(
            directory,
            "bad_tag",
            changes={"provenance_tags": {"first": "ok", "bad": []}},
        ),
        run_case(directory, "bad_tag_container", changes={"provenance_tags": [1]}),
        run_case(directory, "big_sql_integer", changes={"ts_start": 10**100}),
        run_case(directory, "required_null", changes={"host": None}),
    ]
    return cases


if __name__ == "__main__":
    mode, path = sys.argv[1:3]
    if mode == "matrix":
        result = matrix(Path(path))
    elif mode == "inspect":
        store = FlowStore(path)
        store.init_db()
        result = view(store, 1)
        store._conn.close()
    elif mode == "rollback-seed":
        result = rollback_seed(Path(path))
    elif mode == "rollback-after-native":
        result = rollback_after_native(Path(path))
    elif mode == "schema":
        store = FlowStore(path)
        store.init_db()
        result = [
            list(row)
            for row in store._conn.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE "
                "name IN ('flows','flow_fts','flow_request_fts','flow_tags') "
                "OR name LIKE 'idx_flow%' ORDER BY name"
            )
        ]
        store._conn.close()
    else:
        raise ValueError("unknown owned oracle mode")
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
