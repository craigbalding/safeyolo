"""Actual AgentAPI diff/tag dispatch with a real synthetic FlowStore, no network."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from agent_api_flows_oracle import REPO, TOKEN, records
from mitmproxy.test import taddons, tflow

from safeyolo.mitm_addons.agent_api import AgentAPI
from safeyolo.proxy_modes.unix_listener import UnixMode
from safeyolo.storage.flow_store import FlowStore


def cases():
    def c(
        name,
        path="diff",
        method="POST",
        raw='{"flow_id_a":1,"flow_id_b":4}',
        identity="alice",
        available=True,
        auth=True,
    ):
        return {
            "name": name,
            "path": "/api/flows/" + path,
            "method": method,
            "body": raw,
            "identity": identity,
            "available": available,
            "auth": auth,
        }

    def tag(name, raw, path="1/tag", **kwargs):
        return c(name, path=path, raw=raw, **kwargs)

    def delete(name, tag_name, **kwargs):
        return c(
            name, path="1/tag/" + tag_name, method="DELETE", raw="ignored", **kwargs
        )

    return [
        c("diff_changed"),
        c("diff_identical", raw='{"flow_id_a":1,"flow_id_b":1}'),
        c("diff_binary", raw='{"flow_id_a":1,"flow_id_b":5}'),
        c("diff_foreign", raw='{"flow_id_a":1,"flow_id_b":2}'),
        c("diff_ownerless_defect", raw='{"flow_id_a":1,"flow_id_b":3}'),
        c("diff_unresolved", identity=None),
        c("diff_missing", raw="{}"),
        c("diff_nonobject", raw="[1]"),
        c("diff_null", raw="null"),
        c("diff_bad_json", raw="{"),
        c("diff_float_bool", raw='{"flow_id_a":true,"flow_id_b":4.9}'),
        c("diff_unicode_int", raw='{"flow_id_a":" +٠١ ","flow_id_b":"0_4"}'),
        c("diff_nan", raw='{"flow_id_a":NaN,"flow_id_b":4}'),
        c("diff_inf", raw='{"flow_id_a":Infinity,"flow_id_b":4}'),
        c("diff_bad_second_before_owner", raw='{"flow_id_a":2,"flow_id_b":[]}'),
        c("diff_missing_second_before_range", raw='{"flow_id_a":18446744073709551616}'),
        c(
            "diff_first_owner_before_second_range",
            raw='{"flow_id_a":2,"flow_id_b":18446744073709551616}',
        ),
        c("diff_first_range", raw='{"flow_id_a":18446744073709551616,"flow_id_b":4}'),
        c(
            "diff_string_conversion",
            raw='{"flow_id_a":"' + "1" * 4301 + '","flow_id_b":4}',
        ),
        c("diff_absent", available=False, raw="{"),
        c("diff_get", method="GET", available=False),
        tag("tag_create", '{"tag":"color","value":"first"}'),
        tag("tag_replace", '{"tag":"color","value":"second"}'),
        c("detail_after_tag", path="1", method="GET", raw="ignored"),
        delete("tag_delete", "color"),
        delete("tag_missing", "color"),
        tag("tag_default", '{"tag":"empty-value"}'),
        tag("tag_bool", '{"tag":true,"value":false}'),
        delete("delete_bool_tag", "1"),
        tag("tag_nan_value", '{"tag":"nan","value":NaN}'),
        tag("tag_inf_value", '{"tag":"inf","value":Infinity}'),
        tag("tag_nan", '{"tag":NaN}'),
        tag("tag_null_value", '{"tag":"nullable","value":null}'),
        tag("tag_nonobject", "[1]"),
        tag("tag_empty_string", '""'),
        tag("tag_empty_array", "[]"),
        tag("tag_string", '"x"'),
        tag("tag_falsy", '{"tag":false}', path="2/tag"),
        tag("tag_empty", '{"tag":[]}', path="2/tag"),
        tag("tag_foreign", '{"tag":[1]}', path="2/tag"),
        tag("tag_bad_tag", '{"tag":[1]}'),
        tag("tag_bad_value", '{"tag":"color","value":{}}'),
        tag("tag_unresolved", '{"tag":"private"}', identity=None),
        tag("tag_ownerless_defect", '{"tag":"quarantine"}', path="3/tag"),
        tag("tag_plus", '{"tag":"a+b"}'),
        delete("delete_plus", "a+b"),
        tag("tag_space", '{"tag":"a b"}'),
        delete("delete_space", "a%20b"),
        tag("tag_slash", '{"tag":"a/b"}'),
        delete("delete_slash", "a%2Fb"),
        tag("tag_replacement", '{"tag":"�"}'),
        delete("delete_replacement", "%FF"),
        tag("tag_newline", '{"tag":"a\\n"}'),
        delete("delete_newline", "a\n"),
        c("tag_get_wrong", path="1/tag", method="GET", available=False),
        c("tag_delete_no_name", path="1/tag", method="DELETE", available=False),
        tag("tag_post_name_wrong", '{"tag":"x"}', path="1/tag/name", available=False),
        c("tag_put_auth_first", path="1/tag", method="PUT", auth=False),
        tag("tag_auth_first", "{", auth=False),
        tag("tag_absent_first", "{", available=False),
        tag("tag_missing_before_overflow", "{}", path=str(2**64) + "/tag"),
        tag("tag_overflow", '{"tag":"x"}', path=str(2**64) + "/tag"),
        c(
            "tag_oversized_id_wrong_method",
            path="1" * 4301 + "/tag",
            method="GET",
            available=False,
        ),
        c("delete_foreign", path="2/tag/color", method="DELETE"),
    ]


def normalize_times(value):
    if isinstance(value, dict):
        return {
            key: 1234 if key == "created_at" else normalize_times(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [normalize_times(child) for child in value]
    return value


async def run():
    logging.disable(logging.CRITICAL)
    observations = []
    with (
        tempfile.TemporaryDirectory(prefix="owned-flow-details-api-") as temporary,
        ExitStack() as stack,
    ):
        root = Path(temporary)
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temporary}))
        events = []
        stack.enter_context(
            patch("safeyolo.core.audit_writer.put_event", side_effect=events.append)
        )
        # Only the timestamp source is fixed; actual source SQL and return shapes run.
        stack.enter_context(
            patch("safeyolo.storage.flow_store.time.time", return_value=1.234)
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
                    if spec["auth"]:
                        flow.request.headers["Authorization"] = "Bearer " + TOKEN
                    flow.request.raw_content = spec["body"].encode()
                    exception = None
                    try:
                        await api.request(flow)
                    except ValueError as error:
                        if spec["name"] != "tag_oversized_id_wrong_method":
                            raise
                        exception = type(error).__name__
                    text = (
                        None
                        if flow.response is None
                        else flow.response.content.decode()
                    )
                    observations.append(
                        dict(
                            spec,
                            status=None
                            if flow.response is None
                            else flow.response.status_code,
                            text=text,
                            exception=exception,
                            audit_events=len(events),
                            tags=json.dumps(normalize_times(store.get_flow_tags(1))),
                        )
                    )
        finally:
            store.close()
    paths = [
        "cli/src/safeyolo/mitm_addons/agent_api.py",
        "cli/src/safeyolo/storage/flow_store.py",
    ]
    return {
        "rows": observations,
        "source_sha256": {
            name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
            for name in paths
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
            "Source diff/tag controls changed"
        )
        print(f"{len(result['rows'])} source diff/tag controls checked")
    else:
        print(json.dumps(result, indent=2))
