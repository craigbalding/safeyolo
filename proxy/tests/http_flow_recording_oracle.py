"""Actual source recorder/header projection with synthetic HTTPFlow objects.

No network or operator state. Only clock and enqueue are controlled: identity,
request-ID hygiene, content decoding, scope gates and record construction are
real source implementations. Context is an explicit already-applied input here;
real request application is exercised separately by native HTTP tests.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import platform
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]

from mitmproxy import http  # noqa: E402
from mitmproxy.flow import Error  # noqa: E402
from mitmproxy.test import taddons, tflow  # noqa: E402

from safeyolo.core import flow_writer  # noqa: E402
from safeyolo.mitm_addons.flow_recorder import FlowRecorder  # noqa: E402
from safeyolo.mitm_addons.request_id import RequestIdGenerator  # noqa: E402
from safeyolo.proxy_modes.unix_listener import UnixMode  # noqa: E402
from safeyolo.storage.flow_store import FlowStore  # noqa: E402

REQUEST_ID = "req-" + "0" * 32
CONTEXT = {"run": "owned-run", "agent": "declared-tool", "test": "t1", "role": "tester"}


def make_flow():
    flow = tflow.tflow(resp=False)
    flow.client_conn.peername = ("192.0.2.20", 41000)
    flow.client_conn.proxy_mode = UnixMode.parse(
        "unix:/tmp/192.0.2.20_alice/proxy.sock"
    )
    flow.request = http.Request.make(
        "POST", "http://127.0.0.2:12345/a;v?x=first&x=second&blank=&snow=%E2%98%83"
    )
    flow.request.headers = http.Headers(
        [
            (b"Host", b"logical.invalid:12345"),
            (b"X-Repeat", b"first"),
            (b"X-Middle", b"middle"),
            (b"x-repeat", b"second"),
            (b"Connection", b"X-Remove"),
            (b"X-Remove", b"private-hop"),
            (b"X-SafeYolo-Request-Id", b"caller-id"),
            (b"Content-Type", b"text/plain"),
        ]
    )
    flow.request.raw_content = b"request body"
    flow.response = http.Response.make(200)
    flow.response.reason = "Owned reason"
    flow.response.headers = http.Headers(
        [
            (b"X-Repeat", b"one"),
            (b"x-safeyolo-request-ID", b"upstream-id"),
            (b"X-Middle", b"middle"),
            (b"x-repeat", b"two"),
            (b"X-SAFEYOLO-REQUEST-ID", b"second-id"),
            (b"X-Bytes", b"\xff"),
            (b"Content-Type", b"text/plain"),
        ]
    )
    flow.response.raw_content = b"response body"
    flow.metadata["request_id"] = REQUEST_ID
    return flow


def run():
    # taddons installs log handlers tied to its temporary event loop. This
    # fixture observes counters/payloads directly and does not deliver logs.
    logging.disable(logging.CRITICAL)
    rows = []
    names = [
        "h1_pairs_url",
        "h2_empty_reason",
        "h1_latin1_reason",
        "invalid_authority_host",
        "ipv6_default_port",
        "ipv6_nondefault_port",
        "gzip_both",
        "streamed_absence",
        "request_decode_error",
        "response_decode_error",
        "no_context",
        "upstream_error_no_head",
        "upstream_error_with_head",
        "query_surrogate",
    ]
    with tempfile.TemporaryDirectory(prefix="http-record-source-") as temporary:
        store = FlowStore(str(Path(temporary) / "flows.db"))
        store.init_db()
        try:
            for name in names:
                recorder = FlowRecorder()
                recorder.store = store
                request_id = RequestIdGenerator()
                queued = []
                with (
                    taddons.context(recorder, request_id),
                    patch.object(flow_writer, "_writer", None),
                    patch.object(flow_writer, "put_record", side_effect=queued.append),
                    patch("time.time", return_value=1000.5),
                ):
                    flow = make_flow()
                    if name == "h2_empty_reason":
                        flow.request.http_version = "HTTP/2.0"
                        flow.response.http_version = "HTTP/2.0"
                        flow.response.reason = ""
                    elif name == "h1_latin1_reason":
                        flow.response.reason = b"Owned \xff\xe9"
                    elif name == "invalid_authority_host":
                        flow.request.headers["Host"] = "logical.invalid:badport"
                    elif name.startswith("ipv6_"):
                        suffix = "" if name == "ipv6_default_port" else ":12345"
                        flow.request.url = f"http://[::1]{suffix}/a"
                        flow.request.headers["Host"] = "logical.invalid:12345"
                    elif name == "gzip_both":
                        for message in (flow.request, flow.response):
                            message.headers["Content-Encoding"] = "gzip"
                            message.raw_content = gzip.compress(
                                message.raw_content, mtime=0
                            )
                    elif name == "streamed_absence":
                        flow.request.raw_content = None
                        flow.response.raw_content = None
                    elif name == "request_decode_error":
                        flow.request.headers["Content-Encoding"] = "gzip"
                        flow.request.raw_content = b"invalid gzip"
                    elif name == "response_decode_error":
                        flow.response.headers["Content-Encoding"] = "gzip"
                        flow.response.raw_content = b"invalid gzip"
                    elif name == "upstream_error_no_head":
                        flow.response = None
                        flow.error = Error("owned native error witness")
                    elif name == "upstream_error_with_head":
                        flow.response.raw_content = None
                        flow.error = Error("owned native error witness")
                    elif name == "query_surrogate":
                        flow.request.path = (
                            "/a?bad=%FF&%FF=first&%ff=second&%FE=last&bad=ignored"
                        )
                    request_id.request(flow)
                    if name != "no_context":
                        flow.metadata["test_context"] = dict(CONTEXT)
                    with patch("time.time", return_value=1001.25):
                        if name.startswith("upstream_error"):
                            recorder.error(flow)
                        else:
                            request_id.response(flow)
                            recorder.response(flow)
                    converted = []
                    for record in queued:
                        record = dict(record)
                        for key in ("request_body", "response_body"):
                            record[key + "_hex"] = record.pop(key).hex()
                        converted.append(record)
                    rows.append(
                        {
                            "name": name,
                            "records": converted,
                            "stats": recorder.get_stats(),
                        }
                    )
        finally:
            store.close()
    return {
        "source_sha256": hashlib.sha256(
            (ROOT / "cli/src/safeyolo/mitm_addons/flow_recorder.py").read_bytes()
        ).hexdigest(),
        "python": platform.python_version(),
        "cases": rows,
        "temporary_store_removed": not Path(temporary).exists(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = run()
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    elif args.check:
        assert json.loads(args.check.read_text()) == result
    else:
        parser.error("choose --output or --check")
    print(f"{len(result['cases'])} source recording projections checked")
