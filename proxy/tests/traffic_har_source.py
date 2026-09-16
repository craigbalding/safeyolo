"""Pure installed mitmproxy HAR observations over owned synthetic flows.

This source oracle records the installed ``save.har`` command and ``hardump``
option behavior for the native selected-flow HAR contract.  It constructs
HTTP, WebSocket, and non-HTTP objects directly with fixed addresses and
timestamps.  It never starts a proxy, listener, process, network request, or
generated command.  HAR structures are retained in full; archive bytes use
lengths, digests, and bounded prefixes/suffixes.

Run with ``--write`` to regenerate the adjacent JSON or ``--check`` to compare
it.  Without either flag, the observed document is printed.
"""

import argparse
import base64
import hashlib
import importlib.metadata
import json
import sys
import tempfile
import zlib
from pathlib import Path

from mitmproxy import connection, flow, http, tcp, version, websocket
from mitmproxy.addons import savehar
from mitmproxy.coretypes import multidict
from mitmproxy.net import encoding
from mitmproxy.net.http import headers as http_headers
from mitmproxy.tools import cmdline
from mitmproxy.tools import main as mitmproxy_main
from mitmproxy.utils import strutils

SOURCE_MODULES = {
    "mitmproxy/addons/savehar.py": savehar,
    "mitmproxy/connection.py": connection,
    "mitmproxy/flow.py": flow,
    "mitmproxy/http.py": http,
    "mitmproxy/coretypes/multidict.py": multidict,
    "mitmproxy/net/encoding.py": encoding,
    "mitmproxy/net/http/headers.py": http_headers,
    "mitmproxy/tools/cmdline.py": cmdline,
    "mitmproxy/tools/main.py": mitmproxy_main,
    "mitmproxy/utils/strutils.py": strutils,
    "mitmproxy/version.py": version,
    "mitmproxy/websocket.py": websocket,
}

FORMATS = (".har", ".zhar")
RICH_SERVER = ("198.51.100.30", 8443)


def header_fields(fields):
    """Build an installed Headers object from owned UTF-8 field recipes."""
    return http.Headers([(name.encode(), value.encode()) for name, value in fields])


def make_server(peername=RICH_SERVER, *, start=1.0, tcp_setup=2.0, tls_setup=3.0):
    return connection.Server(
        address=("upstream.fixture.invalid", 8443),
        peername=peername,
        timestamp_start=start,
        timestamp_tcp_setup=tcp_setup,
        timestamp_tls_setup=tls_setup,
    )


def make_client(index, *, start=1.0):
    return connection.Client(
        peername=(f"client{index}.fixture.invalid", 1234 + index),
        sockname=("proxy.fixture.invalid", 8080),
        timestamp_start=start,
    )


def make_request(spec):
    body = spec.get("body", b"")
    request = http.Request.make(
        spec["method"],
        spec["url"],
        body,
        headers=header_fields(spec.get("headers", [])),
    )
    if spec.get("body_missing", False):
        request.raw_content = None
    request.http_version = spec.get("http_version", "HTTP/1.1")
    request.timestamp_start = spec["timestamp_start"]
    request.timestamp_end = spec["timestamp_end"]
    return request


def make_response(spec):
    response = http.Response.make(
        spec.get("status", 200),
        spec.get("body", b""),
        headers=header_fields(spec.get("headers", [])),
    )
    if spec.get("body_missing", False):
        response.raw_content = None
    response.http_version = spec.get("http_version", "HTTP/1.1")
    if "reason" in spec:
        response.reason = spec["reason"]
    response.timestamp_start = spec["timestamp_start"]
    response.timestamp_end = spec.get("timestamp_end")
    return response


def make_http_flow(request_spec, server, response_spec=None, error=None, client_index=0):
    """Construct one HTTP flow from owned values with no live defaults."""
    owned = http.HTTPFlow(make_client(client_index), server)
    owned.request = make_request(request_spec)
    if response_spec is not None:
        owned.response = make_response(response_spec)
    if error is not None:
        owned.error = flow.Error(error, timestamp=30.0)
    return owned


def rich_flow():
    return make_http_flow(
        {
            "method": "POST",
            "url": "https://source.fixture.invalid:8443/rich?q=one&q=two&space=a%20b",
            "http_version": "HTTP/2",
            "headers": [
                ("X-Dup", "one"),
                ("x-dup", "two"),
                ("Cookie", "a=1; b=two"),
                ("Content-Type", "text/plain"),
            ],
            "body": b"request body",
            "timestamp_start": 4.0,
            "timestamp_end": 5.0,
        },
        make_server(),
        {
            "status": 299,
            "http_version": "HTTP/1.0",
            "reason": "Synthetic Reason",
            "headers": [
                ("Set-Cookie", "c=3; Path=/; Secure"),
                ("Set-Cookie", "d=4; HttpOnly"),
                ("X-Dup", "reply-one"),
                ("x-dup", "reply-two"),
                ("Content-Type", "text/plain"),
            ],
            "body": b"response body",
            "timestamp_start": 6.0,
            "timestamp_end": 7.0,
        },
    )


def empty_response_flow():
    return make_http_flow(
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/empty",
            "timestamp_start": 10.0,
            "timestamp_end": 11.0,
        },
        make_server(("198.51.100.31", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 204,
            "headers": [("Content-Type", "text/plain")],
            "body": b"",
            "timestamp_start": 11.0,
            "timestamp_end": 11.0,
        },
    )


def pending_request_flow(*, with_response):
    """Retain an unobserved request end with or without a reached response."""
    owned = rich_flow()
    owned.request.timestamp_end = None
    if not with_response:
        owned.response = None
    return owned


def tls_without_tcp_flow():
    """Supply only logical-target TLS facts, without claiming a parent runtime."""
    owned = rich_flow()
    owned.server_conn = make_server(None, start=1.0, tcp_setup=None, tls_setup=3.0)
    return owned


def request_body_empty_flow():
    return make_http_flow(
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/request-empty",
            "body": b"",
            "timestamp_start": 14.0,
            "timestamp_end": 15.0,
        },
        make_server(("198.51.100.40", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 200,
            "body": b"empty acknowledged",
            "timestamp_start": 15.0,
            "timestamp_end": 16.0,
        },
    )


def request_body_missing_flow():
    return make_http_flow(
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/request-missing",
            "body_missing": True,
            "timestamp_start": 17.0,
            "timestamp_end": 18.0,
        },
        make_server(("198.51.100.41", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 200,
            "body": b"missing acknowledged",
            "timestamp_start": 18.0,
            "timestamp_end": 19.0,
        },
    )


def missing_response_body_flow():
    return make_http_flow(
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/missing-body",
            "timestamp_start": 12.0,
            "timestamp_end": 13.0,
        },
        make_server(("198.51.100.32", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 200,
            "headers": [("Content-Type", "text/plain")],
            "body_missing": True,
            "timestamp_start": 13.0,
            "timestamp_end": 14.0,
        },
    )


def unavailable_response_flow(error=None):
    return make_http_flow(
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/unavailable",
            "timestamp_start": 20.0,
            "timestamp_end": 21.0,
        },
        make_server(None, start=None, tcp_setup=None, tls_setup=None),
        error=error,
    )


def encoded_flow():
    return make_http_flow(
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/encoded",
            "headers": [("Content-Encoding", "gzip"), ("Content-Type", "text/plain")],
            "body": b"encoded request",
            "timestamp_start": 31.0,
            "timestamp_end": 32.0,
        },
        make_server(("198.51.100.33", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 200,
            "headers": [("Content-Encoding", "gzip"), ("Content-Type", "text/plain")],
            "body": b"encoded response",
            "timestamp_start": 32.0,
            "timestamp_end": 33.0,
        },
    )


def binary_flow():
    binary_body = b"\x00\xff\x01a"
    return make_http_flow(
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/binary",
            "headers": [("Content-Type", "application/octet-stream")],
            "body": binary_body,
            "timestamp_start": 41.0,
            "timestamp_end": 42.0,
        },
        make_server(("198.51.100.34", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 200,
            "headers": [("Content-Type", "application/octet-stream")],
            "body": binary_body,
            "timestamp_start": 42.0,
            "timestamp_end": 43.0,
        },
    )


def non_utf8_charset_flow():
    body = b"left\xe9right"
    return make_http_flow(
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/latin1",
            "headers": [("Content-Type", "text/plain; charset=iso-8859-1")],
            "body": body,
            "timestamp_start": 44.0,
            "timestamp_end": 45.0,
        },
        make_server(("198.51.100.42", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 200,
            "headers": [("Content-Type", "text/plain; charset=iso-8859-1")],
            "body": b"reply\xe9",
            "timestamp_start": 45.0,
            "timestamp_end": 46.0,
        },
    )


def websocket_flow():
    owned = make_http_flow(
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/socket",
            "headers": [("Connection", "Upgrade"), ("Upgrade", "websocket")],
            "timestamp_start": 51.0,
            "timestamp_end": 52.0,
        },
        make_server(("198.51.100.35", 80), start=None, tcp_setup=None, tls_setup=None),
        {
            "status": 101,
            "headers": [("Upgrade", "websocket")],
            "body": b"",
            "timestamp_start": 52.0,
            "timestamp_end": 53.0,
        },
    )
    owned.websocket = websocket.WebSocketData(
        messages=[
            websocket.WebSocketMessage(1, True, b"outgoing", timestamp=61.0),
            websocket.WebSocketMessage(2, False, b"\xff\x00", timestamp=62.0, dropped=True),
            websocket.WebSocketMessage(1, False, b"incoming", timestamp=63.0, injected=True),
        ]
    )
    return owned


def timed_reused_flows():
    server = make_server(("198.51.100.36", 443), start=1.0, tcp_setup=2.0, tls_setup=3.0)
    first = make_http_flow(
        {
            "method": "GET",
            "url": "https://source.fixture.invalid/first",
            "timestamp_start": 4.0,
            "timestamp_end": 5.0,
        },
        server,
        {"status": 200, "body": b"first", "timestamp_start": 6.0, "timestamp_end": 7.0},
        client_index=1,
    )
    second = make_http_flow(
        {
            "method": "GET",
            "url": "https://source.fixture.invalid/second",
            "timestamp_start": 8.0,
            "timestamp_end": 9.0,
        },
        server,
        {"status": 200, "body": b"second", "timestamp_start": 10.0, "timestamp_end": 11.0},
        client_index=2,
    )
    return [first, second]


def non_http_flow():
    return tcp.TCPFlow(
        make_client(9),
        make_server(("198.51.100.39", 9000), start=None, tcp_setup=None, tls_setup=None),
    )


def all_flows():
    rich = rich_flow()
    empty = empty_response_flow()
    request_empty = request_body_empty_flow()
    request_missing = request_body_missing_flow()
    missing_body = missing_response_body_flow()
    unavailable = unavailable_response_flow()
    error = unavailable_response_flow("fixture timeout")
    encoded = encoded_flow()
    binary = binary_flow()
    latin1 = non_utf8_charset_flow()
    websocket_http = websocket_flow()
    timed = timed_reused_flows()
    return {
        "rich_http": rich,
        "empty_response": empty,
        "request_body_empty": request_empty,
        "request_body_missing": request_missing,
        "response_body_missing": missing_body,
        "response_unavailable": unavailable,
        "error_without_response": error,
        "encoded_text": encoded,
        "binary_bodies": binary,
        "latin1_charset": latin1,
        "websocket": websocket_http,
        "timed_first": timed[0],
        "timed_reused": timed[1],
        "non_http": non_http_flow(),
        "pending_request_with_response": pending_request_flow(with_response=True),
        "pending_request_without_response": pending_request_flow(with_response=False),
        "tls_without_tcp": tls_without_tcp_flow(),
    }


def summarize_bytes(value):
    """Record archive bytes without embedding an unbounded duplicate HAR."""
    result = {
        "length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "prefix_hex": value[:96].hex(),
        "suffix_hex": value[-96:].hex(),
    }
    return result


def archive_observations(flows):
    """Call the installed file command and observe both suffix modes."""
    with tempfile.TemporaryDirectory(prefix="owned-har-source-") as directory:
        private = Path(directory)
        observed = {}
        for suffix in FORMATS:
            path = private / f"selected{suffix}"
            savehar.SaveHar().export_har(flows, str(path))
            payload = path.read_bytes()
            observed[suffix] = summarize_bytes(payload)
            if suffix == ".har":
                decoded = payload
            else:
                decoded = zlib.decompress(payload)
            observed[suffix]["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
            observed[suffix]["decoded_trailing_newline"] = decoded.endswith(b"\n")
    return observed


def make_selection(name, selected_names, flows):
    exporter = savehar.SaveHar()
    har = exporter.make_har([flows[selected] for selected in selected_names])
    return {
        "name": name,
        "selected": selected_names,
        "entry_count": len(har["log"]["entries"]),
        "har": har,
    }


def source_hashes():
    return {
        name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        for name, module in SOURCE_MODULES.items()
    }


PUBLIC_SURFACE = {
    "command": {
        "name": "save.har",
        "arguments": ["flows: Sequence[flow.Flow]", "path: types.Path"],
        "behavior": "writes json.dumps(make_har(flows), indent=4).encode() to path",
    },
    "option": {
        "cli": "--set hardump=PATH",
        "name": "hardump",
        "type": "str",
        "default": "",
        "behavior": "save a HAR file with all flows on exit; flows are kept in memory",
    },
    "selection": {
        "command": "save.har receives the explicit selected flow sequence",
        "hardump_filter": "save_stream_filter optionally filters flows collected for hardump",
        "stock_mitmdump_filter_arg": "stock mitmdump positional filter_args sets view_filter and save_stream_filter",
        "safeyolo_entrypoint": "SafeYolo starts safeyolo.traffic_master, whose _make_parser calls cmdline.mitmproxy; this is distinct from stock mitmdump",
        "non_http": "make_har skips selected flows that are not HTTPFlow",
    },
    "archive_suffixes": {
        ".har": "indented UTF-8 JSON bytes without a trailing newline",
        ".zhar": "zlib.compress(json_bytes, 9)",
    },
}


def assert_rich_entry(selections):
    rich_entry = selections["http_body_variants"]["har"]["log"]["entries"][0]
    request = rich_entry["request"]
    response = rich_entry["response"]
    assert request["method"] == "POST"
    assert request["url"] == "https://source.fixture.invalid:8443/rich?q=one&q=two&space=a%20b"
    assert request["httpVersion"] == "HTTP/2"
    assert request["queryString"] == [
        {"name": "q", "value": "one"},
        {"name": "q", "value": "two"},
        {"name": "space", "value": "a b"},
    ]
    assert request["cookies"] == [{"name": "a", "value": "1"}, {"name": "b", "value": "two"}]
    assert request["headers"][:2] == [
        {"name": "X-Dup", "value": "one"},
        {"name": "x-dup", "value": "two"},
    ]
    assert response["status"] == 299 and response["statusText"] == "Synthetic Reason"
    assert response["httpVersion"] == "HTTP/1.0"
    assert response["cookies"] == [
        {"name": "c", "value": "3", "path": "/", "domain": "", "httpOnly": False, "secure": True},
        {"name": "d", "value": "4", "path": "/", "domain": "", "httpOnly": True, "secure": False},
    ]
    assert response["headers"][:4] == [
        {"name": "Set-Cookie", "value": "c=3; Path=/; Secure"},
        {"name": "Set-Cookie", "value": "d=4; HttpOnly"},
        {"name": "X-Dup", "value": "reply-one"},
        {"name": "x-dup", "value": "reply-two"},
    ]
    assert rich_entry["timings"] == {
        "connect": 1000.0,
        "ssl": 1000.0,
        "send": 1000.0,
        "receive": 1000.0,
        "wait": 1000.0,
    }
    assert rich_entry["time"] == 5000.0
    assert rich_entry["serverIPAddress"] == "198.51.100.30"


def assert_body_variants(selections):
    encoded = selections["http_body_variants"]["har"]["log"]["entries"][1]
    assert encoded["request"]["postData"]["text"] == "encoded request"
    assert encoded["response"]["content"]["text"] == "encoded response"
    assert encoded["response"]["content"]["size"] == 36
    assert encoded["response"]["content"]["compression"] == -20
    assert encoded["response"]["headers"][0] == {"name": "Content-Encoding", "value": "gzip"}

    binary = selections["http_body_variants"]["har"]["log"]["entries"][2]
    assert binary["request"]["bodySize"] == 4
    assert binary["request"]["postData"]["text"] == "\x00ÿ\x01a"
    assert binary["response"]["content"]["encoding"] == "base64"
    assert binary["response"]["content"]["text"] == base64.b64encode(b"\x00\xff\x01a").decode()


def assert_request_body_availability(selections):
    entries = selections["request_body_availability"]["har"]["log"]["entries"]
    empty_request = entries[0]["request"]
    missing_request = entries[1]["request"]
    assert empty_request["bodySize"] == 0
    assert empty_request["postData"]["text"] == ""
    assert missing_request["bodySize"] == 0
    assert missing_request["postData"]["text"] is None


def assert_charset_and_defaults(selections):
    latin1 = selections["charset_and_binary_request"]["har"]["log"]["entries"][0]
    assert latin1["request"]["postData"]["text"] == "leftéright"
    assert latin1["response"]["content"]["text"] == "replyé"

    unavailable = selections["failure_and_incomplete"]["har"]["log"]["entries"][0]
    assert "serverIPAddress" not in unavailable
    assert unavailable["timings"] == {
        "connect": -1.0,
        "ssl": -1.0,
        "send": 1000.0,
        "receive": 0,
        "wait": 0,
    }


def assert_body_availability(selections):
    empty = selections["body_availability"]["har"]["log"]["entries"][0]["response"]
    missing = selections["body_availability"]["har"]["log"]["entries"][1]["response"]
    assert empty["content"] == {"size": 0, "compression": 0, "mimeType": "text/plain", "text": ""}
    assert missing["content"] == empty["content"]
    unavailable = selections["failure_and_incomplete"]["har"]["log"]["entries"][0]["response"]
    error = selections["failure_and_incomplete"]["har"]["log"]["entries"][1]["response"]
    assert unavailable["status"] == 0 and unavailable["content"] == {}
    assert unavailable["_error"] is None
    assert error["status"] == 0 and error["_error"] == "fixture timeout"


def assert_websocket_and_selection(selections):
    websocket_entry = selections["websocket_and_selection"]["har"]["log"]["entries"][0]
    assert websocket_entry["_resourceType"] == "websocket"
    assert websocket_entry["_webSocketMessages"] == [
        {"type": "send", "time": 61.0, "opcode": 1, "data": "outgoing"},
        {"type": "receive", "time": 62.0, "opcode": 2, "data": "/wA="},
        {"type": "receive", "time": 63.0, "opcode": 1, "data": "incoming"},
    ]
    assert "dropped" not in websocket_entry["_webSocketMessages"][1]
    assert "injected" not in websocket_entry["_webSocketMessages"][2]

    reused = selections["connection_reuse"]["har"]["log"]["entries"]
    assert reused[0]["timings"]["connect"] == 1000.0
    assert reused[1]["timings"]["connect"] == -1.0
    assert reused[1]["timings"]["ssl"] == -1.0
    assert selections["websocket_and_selection"]["entry_count"] == 1
    assert selections["non_http_is_skipped"]["entry_count"] == 0
    assert selections["empty_selection"]["entry_count"] == 0


def assert_unobserved_phases_and_archive_reuse(selections):
    pending = selections["pending_request_timing"]["har"]["log"]["entries"]
    assert pending[0]["timings"] == {
        "connect": 1000.0,
        "ssl": 1000.0,
        "send": 0,
        "receive": 1000.0,
        "wait": 0,
    }
    assert pending[0]["time"] == 3000.0
    assert pending[0]["response"]["status"] == 299
    assert pending[1]["timings"] == {
        "connect": 1000.0,
        "ssl": 1000.0,
        "send": 0,
        "receive": 0,
        "wait": 0,
    }
    assert pending[1]["time"] == 2000.0
    assert pending[1]["response"]["status"] == 0

    tls_only = selections["tls_without_tcp_timing"]["har"]["log"]["entries"][0]
    assert tls_only["timings"] == {
        "connect": -1.0,
        "ssl": -1.0,
        "send": 1000.0,
        "receive": 1000.0,
        "wait": 1000.0,
    }
    assert tls_only["time"] == 3000.0
    assert "serverIPAddress" not in tls_only

    alone = selections["reused_connection_exported_alone"]["har"]["log"]["entries"]
    assert len(alone) == 1
    assert alone[0]["request"]["url"] == "https://source.fixture.invalid/second"
    assert alone[0]["timings"] == {
        "connect": 1000.0,
        "ssl": 1000.0,
        "send": 1000.0,
        "receive": 1000.0,
        "wait": 1000.0,
    }
    assert alone[0]["time"] == 5000.0
    assert alone[0]["serverIPAddress"] == "198.51.100.36"


def assert_archives(document):
    archive = document["archives"]
    assert archive[".har"]["decoded_sha256"] == archive[".har"]["sha256"]
    assert archive[".zhar"]["decoded_sha256"] == archive[".har"]["sha256"]
    assert archive[".zhar"]["sha256"] != archive[".har"]["sha256"]
    assert archive[".har"]["length"] > archive[".zhar"]["length"]
    assert not archive[".har"]["decoded_trailing_newline"]
    assert not archive[".zhar"]["decoded_trailing_newline"]
    assert archive[".zhar"]["prefix_hex"].startswith("78da")

    rich_har = next(
        selection["har"]
        for selection in document["selections"]
        if selection["name"] == "http_body_variants"
    )
    reconstructed = {
        "log": {
            "version": rich_har["log"]["version"],
            "creator": rich_har["log"]["creator"],
            "pages": rich_har["log"]["pages"],
            "entries": [rich_har["log"]["entries"][0]],
        }
    }
    har_bytes = json.dumps(reconstructed, indent=4).encode()
    compressed_bytes = zlib.compress(har_bytes, 9)
    for suffix, expected_bytes in ((".har", har_bytes), (".zhar", compressed_bytes)):
        expected = summarize_bytes(expected_bytes)
        for field in ("length", "sha256", "prefix_hex", "suffix_hex"):
            assert archive[suffix][field] == expected[field], (suffix, field)


def assert_contract(document):
    selections = {selection["name"]: selection for selection in document["selections"]}
    assert_rich_entry(selections)
    assert_body_variants(selections)
    assert_request_body_availability(selections)
    assert_charset_and_defaults(selections)
    assert_body_availability(selections)
    assert_websocket_and_selection(selections)
    assert_unobserved_phases_and_archive_reuse(selections)
    assert_archives(document)


def document():
    flows = all_flows()
    selections = [
        make_selection("empty_selection", [], flows),
        make_selection(
            "http_body_variants",
            ["rich_http", "encoded_text", "binary_bodies"],
            flows,
        ),
        make_selection(
            "body_availability",
            ["empty_response", "response_body_missing"],
            flows,
        ),
        make_selection(
            "request_body_availability",
            ["request_body_empty", "request_body_missing"],
            flows,
        ),
        make_selection(
            "failure_and_incomplete",
            ["response_unavailable", "error_without_response"],
            flows,
        ),
        make_selection(
            "charset_and_binary_request",
            ["latin1_charset", "binary_bodies"],
            flows,
        ),
        make_selection("websocket_and_selection", ["websocket", "non_http"], flows),
        make_selection("connection_reuse", ["timed_first", "timed_reused"], flows),
        make_selection("non_http_is_skipped", ["non_http"], flows),
        make_selection(
            "pending_request_timing",
            ["pending_request_with_response", "pending_request_without_response"],
            flows,
        ),
        make_selection("tls_without_tcp_timing", ["tls_without_tcp"], flows),
        make_selection("reused_connection_exported_alone", ["timed_reused"], flows),
    ]
    archives = archive_observations([flows["rich_http"]])
    result = {
        "schema": 1,
        "source": "installed_mitmproxy_savehar",
        "versions": {
            "python": sys.version.split()[0],
            "mitmproxy": importlib.metadata.version("mitmproxy"),
        },
        "source_sha256": source_hashes(),
        "public_surface": PUBLIC_SURFACE,
        "selections": selections,
        "archives": archives,
    }
    assert_contract(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write and args.check:
        parser.error("--write and --check are mutually exclusive")
    observed = document()
    rendered = json.dumps(observed, indent=2, ensure_ascii=True) + "\n"
    output = Path(__file__).with_suffix(".json")
    if args.write:
        output.write_text(rendered, encoding="utf-8")
        print(f"wrote {output}")
    elif args.check:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("traffic HAR fixture differs")
        print(f"matched {len(observed['selections'])} HAR selections / 2 archive suffixes")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
