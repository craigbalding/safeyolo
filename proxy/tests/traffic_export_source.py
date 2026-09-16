"""Pure installed mitmproxy export observations over synthetic HTTP flows.

The fixture is a source oracle for the native traffic-export migration.  It
constructs HTTPFlow, Request, Response, WebSocketData, and WebSocketMessage
objects directly, calls the installed export formatters, and emits compact,
deterministic JSON.  No proxy, listener, API, process, network, or generated
command is used.  Commands are recorded as text only.

Run normally to print the fixture or with ``--check`` to compare the adjacent
frozen JSON.  Large payloads stay compact through repeat/suffix recipes and
bounded output digests.
"""

import argparse
import gzip
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from mitmproxy import connection, exceptions, http, websocket
from mitmproxy.addons import export as export_module
from mitmproxy.net.http.http1 import assemble

SOURCE_FILES = {
    "mitmproxy/addons/export.py": export_module,
    "mitmproxy/http.py": http,
    "mitmproxy/net/http/http1/assemble.py": assemble,
    "mitmproxy/websocket.py": websocket,
}


def content(recipe):
    """Expand a compact content recipe into source bytes."""
    if recipe is None:
        return None
    if "hex" in recipe:
        value = bytes.fromhex(recipe["hex"])
    else:
        value = recipe.get("text", "").encode("utf-8", "surrogateescape")
    value = value * recipe.get("repeat", 1)
    value += recipe.get("suffix_text", "").encode("utf-8", "surrogateescape")
    if recipe.get("gzip", False):
        return gzip.compress(value, mtime=0)
    return value


def header_bytes(item):
    """Encode a header recipe, accepting UTF-8 text or explicit bytes."""
    if isinstance(item, str):
        return item.encode("utf-8", "surrogateescape")
    return bytes.fromhex(item["hex"])


def headers(fields):
    return http.Headers(
        [(header_bytes(name), header_bytes(value)) for name, value in fields]
    )


def make_request(recipe):
    request = http.Request.make(recipe["method"], recipe["url"], b"")
    request.http_version = recipe.get("http_version", "HTTP/1.1")
    request.headers = headers(recipe.get("headers", []))
    request.raw_content = content(recipe.get("body"))
    trailer_fields = recipe.get("trailers")
    request.trailers = None if trailer_fields is None else headers(trailer_fields)
    if "authority" in recipe:
        request.data.authority = header_bytes(recipe["authority"])
    return request


def make_response(recipe):
    response = http.Response.make(recipe.get("status", 200), b"")
    response.http_version = recipe.get("http_version", "HTTP/1.1")
    response.reason = recipe.get("reason", "")
    response.headers = headers(recipe.get("headers", []))
    response.raw_content = content(recipe.get("body"))
    trailer_fields = recipe.get("trailers")
    response.trailers = None if trailer_fields is None else headers(trailer_fields)
    return response


def make_flow(recipe):
    """Construct a flow from owned synthetic values only."""
    client = connection.Client(
        peername=("client.fixture.invalid", 1234),
        sockname=("proxy.fixture.invalid", 8080),
    )
    peername = recipe.get("server_peername")
    server = connection.Server(
        address=("upstream.fixture.invalid", 443),
        peername=None if peername is None else tuple(peername),
    )
    owned = http.HTTPFlow(client, server)
    owned.request = make_request(recipe["request"])
    if recipe.get("response") is not None:
        owned.response = make_response(recipe["response"])
    messages = recipe.get("websocket")
    if messages is not None:
        owned.websocket = websocket.WebSocketData(
            messages=[
                websocket.WebSocketMessage(
                    1 if message["type"] == "text" else 2,
                    message["from_client"],
                    content(message["body"]),
                    timestamp=float(index + 1),
                    dropped=message.get("dropped", False),
                    injected=message.get("injected", False),
                )
                for index, message in enumerate(messages)
            ]
        )
    return owned


def workflow(name, request, **parts):
    return {
        "name": name,
        "request": request,
        "response": parts.get("response"),
        "websocket": parts.get("websocket_messages"),
        "export_preserve_original_ip": parts.get("option", False),
        "server_peername": parts.get("server_peername"),
    }


BASE_REQUEST = {
    "method": "GET",
    "url": "http://source.fixture.invalid/fixture?x=1",
    "headers": [],
    "body": None,
}


WORKFLOWS = [
    workflow(
        "http_versions_custom_reason_absolute_target",
        {
            "method": "POST",
            "url": "https://source.fixture.invalid:8443/absolute",
            "http_version": "HTTP/2.0",
            "authority": "authority.fixture.invalid:8443",
            "headers": [["Host", "source.fixture.invalid:8443"], ["X-Request", "one"]],
            "body": {"text": "request-body"},
        },
        response={
            "status": 299,
            "http_version": "HTTP/1.0",
            "reason": "Synthetic Reason",
            "headers": [["X-Response", "yes"]],
            "body": {"text": "response-body"},
        },
    ),
    workflow(
        "duplicate_headers_host_removal_accept_encoding",
        {
            "method": "GET",
            "url": "https://source.fixture.invalid:443/repeated",
            "headers": [
                ["Host", "source.fixture.invalid"],
                ["X-Dup", "one"],
                ["x-dup", "two"],
                ["Content-Length", "999"],
                ["Accept-Encoding", "gzip"],
            ],
            "body": None,
        },
        response={
            "status": 204,
            "headers": [["X-Dup", "reply-one"], ["x-dup", "reply-two"]],
            "body": {"text": ""},
        },
    ),
    workflow(
        "post_present_empty_body",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/empty",
            "headers": [["Content-Encoding", "gzip"], ["Content-Length", "7"]],
            "body": {"text": ""},
        },
        response={"status": 201, "headers": [], "body": {"text": "created"}},
    ),
    workflow(
        "get_absent_encoded_body",
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/absent-encoded",
            "headers": [["Content-Encoding", "gzip"], ["Content-Length", "0"]],
            "body": None,
        },
    ),
    workflow(
        "get_nonempty_body",
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/get-body",
            "headers": [],
            "body": {"text": "get-body"},
        },
    ),
    workflow(
        "request_and_response_bodies_absent",
        {**BASE_REQUEST, "body": None},
    ),
    workflow(
        "response_only_raw_body",
        {**BASE_REQUEST, "body": None},
        response={"status": 202, "headers": [["X-Only", "response"]], "body": {"text": "only-response"}},
    ),
    workflow(
        "existing_response_body_absent_raw_fallback",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/response-absent",
            "headers": [],
            "body": {"text": "request-only"},
        },
        response={"status": 204, "headers": [["X-Response", "body-absent"]], "body": None},
    ),
    workflow(
        "decoded_gzip_request_response",
        {
            "method": "PUT",
            "url": "http://source.fixture.invalid/gzip",
            "headers": [["Content-Encoding", "gzip"], ["Content-Type", "text/plain"]],
            "body": {"text": "decoded-request", "gzip": True},
        },
        response={
            "status": 200,
            "headers": [["Content-Encoding", "gzip"], ["Content-Type", "text/plain"]],
            "body": {"text": "decoded-response", "gzip": True},
        },
    ),
    workflow(
        "malformed_content_encoding_raw_fallback",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/malformed",
            "headers": [["Content-Encoding", "gzip"]],
            "body": {"text": "RAW_MARKER"},
        },
        response={"status": 200, "headers": [], "body": {"text": "response"}},
    ),
    workflow(
        "invalid_content_encoding_type_error",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/type-error",
            "headers": [["Content-Encoding", "rot_13"]],
            "body": {"text": "marker"},
        },
    ),
    workflow(
        "binary_body_command_text_error_raw_available",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/binary",
            "headers": [["Content-Type", "application/json"]],
            "body": {"hex": "ff000161"},
        },
    ),
    workflow(
        "charset_decode_error_raw_available",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/charset",
            "headers": [["Content-Type", "text/plain; charset=ascii"]],
            "body": {"hex": "ff"},
        },
    ),
    workflow(
        "shell_quote_text_body",
        {
            "method": "PATCH",
            "url": "http://source.fixture.invalid/quote?x=a%20b&y=$HOME",
            "headers": [["X-Quote", "a'b $HOME `tick`"], ["X-Space", "two words"]],
            "body": {"text": 'it\'s $HOME `tick` "quoted" \\ slash'},
        },
    ),
    workflow(
        "shell_control_text_body",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/control",
            "headers": [["X-Control", "line\nnext"]],
            "body": {"text": "line\nnext\ttab\x01unit"},
        },
    ),
    workflow(
        "finite_chunked_trailers",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/chunked",
            "headers": [["Transfer-Encoding", "chunked"], ["Trailer", "X-Req-Trailer"]],
            "body": {"text": "chunk-body"},
            "trailers": [["X-Req-Trailer", "request-final"]],
        },
        response={
            "status": 200,
            "headers": [["Transfer-Encoding", "chunked"], ["Trailer", "X-Resp-Trailer"]],
            "body": {"text": "response-chunk"},
            "trailers": [["X-Resp-Trailer", "response-final"]],
        },
    ),
    workflow(
        "trailers_without_chunked_raw_value_error",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/bad-trailers",
            "headers": [],
            "body": {"text": "body"},
            "trailers": [["X-Trailer", "value"]],
        },
    ),
    workflow(
        "combined_websocket_direction_type_drop",
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/ws",
            "headers": [["Connection", "Upgrade"], ["Upgrade", "websocket"]],
            "body": {"text": ""},
        },
        response={"status": 101, "headers": [["Upgrade", "websocket"]], "body": {"text": ""}},
        websocket_messages=[
            {"type": "text", "from_client": True, "body": {"text": "outgoing"}, "dropped": False},
            {"type": "binary", "from_client": False, "body": {"hex": "ff00"}, "dropped": True},
            {"type": "text", "from_client": False, "body": {"text": "incoming"}, "dropped": False, "injected": True},
        ],
    ),
    workflow(
        "combined_websocket_beyond_64k",
        {
            "method": "GET",
            "url": "http://source.fixture.invalid/ws-large",
            "headers": [],
            "body": {"text": ""},
        },
        response={"status": 101, "headers": [], "body": {"text": ""}},
        websocket_messages=[
            {
                "type": "binary",
                "from_client": False,
                "body": {"text": "x", "repeat": 65534, "suffix_text": "NEEDLE"},
                "dropped": True,
            }
        ],
    ),
    workflow(
        "preserve_original_ip_true_source_control",
        {
            "method": "GET",
            "url": "https://source.fixture.invalid:443/resolve",
            "headers": [],
            "body": None,
        },
        option=True,
        server_peername=["192.0.2.44", 443],
    ),
]


FORMATS = ("curl", "httpie", "raw", "raw_request", "raw_response")


def output(value):
    """Represent text exactly and bytes exactly when bounded."""
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogateescape")
        return {
            "kind": "text",
            "text": value,
            "utf8_length": len(raw),
            "utf8_sha256": hashlib.sha256(raw).hexdigest(),
        }
    raw = bytes(value)
    result = {
        "kind": "bytes",
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if len(raw) <= 4096:
        result["hex"] = raw.hex()
    else:
        result["prefix_hex"] = raw[:128].hex()
        result["suffix_hex"] = raw[-128:].hex()
    return result


def exception_result(error):
    return {
        "error_type": type(error).__name__,
        "message": str(error),
    }


def invoke(format_name, owned, preserve_original_ip):
    """Call one installed formatter with an owned, temporary ctx.options."""
    original_ctx = export_module.ctx
    export_module.ctx = SimpleNamespace(
        options=SimpleNamespace(export_preserve_original_ip=preserve_original_ip)
    )
    try:
        value = export_module.formats[format_name](owned)
    except (exceptions.CommandError, TypeError, ValueError, UnicodeError) as error:
        return {"output": None, **exception_result(error)}
    finally:
        export_module.ctx = original_ctx
    return {"output": output(value), "error_type": None, "message": None}


def observe(spec):
    owned = make_flow(spec)
    return {
        "name": spec["name"],
        "input": spec,
        "formats": {
            format_name: invoke(
                format_name,
                owned,
                spec["export_preserve_original_ip"],
            )
            for format_name in FORMATS
        },
    }


def result(rows, name, format_name):
    return next(row for row in rows if row["name"] == name)["formats"][format_name]


def text_value(rows, name, format_name):
    value = result(rows, name, format_name)
    assert value["error_type"] is None, (name, format_name, value)
    assert value["output"]["kind"] == "text", (name, format_name, value)
    return value["output"]["text"]


def bytes_value(rows, name, format_name):
    value = result(rows, name, format_name)
    assert value["error_type"] is None, (name, format_name, value)
    assert value["output"]["kind"] == "bytes", (name, format_name, value)
    return bytes.fromhex(value["output"]["hex"])


def assert_error(rows, name, format_name, error_type):
    value = result(rows, name, format_name)
    assert value["output"] is None, (name, format_name, value)
    assert value["error_type"] == error_type, (name, format_name, value)
    assert value["message"], (name, format_name, value)


def assert_encoded_content_controls(rows):
    curl = text_value(rows, "duplicate_headers_host_removal_accept_encoding", "curl")
    assert "host:" not in curl.lower() and "content-length:" not in curl.lower()
    assert curl.count("-H 'X-Dup: one'") == 1 and "-H 'x-dup: two'" in curl
    assert "--compressed" in curl

    httpie = text_value(rows, "duplicate_headers_host_removal_accept_encoding", "httpie")
    assert "host:" not in httpie.lower() and "content-length:" not in httpie.lower()
    assert "X-Dup: one" in httpie and "x-dup: two" in httpie

    present_empty = text_value(rows, "post_present_empty_body", "httpie")
    assert "'Content-Encoding: gzip'" in present_empty
    assert "content-length:" not in present_empty.lower()
    present_empty_raw = bytes_value(rows, "post_present_empty_body", "raw_request")
    assert b"Content-Encoding: gzip\r\nContent-Length: 7\r\n" in present_empty_raw

    absent_encoded = text_value(rows, "get_absent_encoded_body", "curl")
    assert absent_encoded == (
        "curl -H 'Content-Encoding: gzip' http://source.fixture.invalid/absent-encoded"
    )
    assert "content-length:" not in absent_encoded.lower()
    assert_error(rows, "get_absent_encoded_body", "raw_request", "CommandError")


def assert_command_quoting(rows):
    control = text_value(rows, "shell_control_text_body", "curl")
    assert '"$(printf ' in control and "\\x01" in control
    quote = text_value(rows, "shell_quote_text_body", "curl")
    assert quote == (
        "curl -H 'X-Quote: a'\"'\"'b $HOME `tick`' -H 'X-Space: two words' "
        "-X PATCH 'http://source.fixture.invalid/quote?x=a%20b&y=$HOME' "
        "-d 'it'\"'\"'s $HOME `tick` \"quoted\" \\ slash'"
    )


def assert_websocket_contract(rows):
    combined = bytes_value(rows, "combined_websocket_direction_type_drop", "raw")
    expected_combined = (
        b"GET /ws HTTP/1.1\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: websocket\r\n\r\n"
        b"\r\n\r\n"
        b"HTTP/1.1 101 \r\n"
        b"Upgrade: websocket\r\n\r\n"
        b"\r\n\r\n"
        b"[OUTGOING] outgoing\n"
        b"[INCOMING] \xff\x00\n"
        b"[INCOMING] incoming"
    )
    assert combined == expected_combined
    assert_error(rows, "request_and_response_bodies_absent", "raw", "CommandError")
    assert bytes_value(rows, "response_only_raw_body", "raw").startswith(b"HTTP/1.1 202")

    response_absent = "existing_response_body_absent_raw_fallback"
    assert_error(rows, response_absent, "raw_response", "CommandError")
    assert result(rows, response_absent, "raw_response")["message"] == "Response content missing."
    assert bytes_value(rows, response_absent, "raw") == bytes_value(rows, response_absent, "raw_request")

    large = result(rows, "combined_websocket_beyond_64k", "raw")
    expected_large = (
        b"GET /ws-large HTTP/1.1\r\n\r\n"
        + b"\r\n\r\n"
        + b"HTTP/1.1 101 \r\n\r\n"
        + b"\r\n\r\n"
        + b"[INCOMING] "
        + b"x" * 65534
        + b"NEEDLE"
    )
    assert large["output"]["kind"] == "bytes"
    assert large["output"]["length"] == len(expected_large)
    assert large["output"]["sha256"] == hashlib.sha256(expected_large).hexdigest()
    assert large["output"]["prefix_hex"] == expected_large[:128].hex()
    assert large["output"]["suffix_hex"] == expected_large[-128:].hex()


def assert_contract(rows):
    """Independent checks for source behavior used by native replay."""
    assert_encoded_content_controls(rows)
    request = bytes_value(rows, "http_versions_custom_reason_absolute_target", "raw_request")
    assert request.startswith(b"POST https://authority.fixture.invalid:8443/absolute HTTP/2.0\r\n")
    response = bytes_value(rows, "http_versions_custom_reason_absolute_target", "raw_response")
    assert response.startswith(b"HTTP/1.0 299 Synthetic Reason\r\n")

    assert "decoded-request" in text_value(rows, "decoded_gzip_request_response", "curl")
    assert "Content-Encoding" not in bytes_value(rows, "decoded_gzip_request_response", "raw_request").decode()
    assert "RAW_MARKER" in text_value(rows, "malformed_content_encoding_raw_fallback", "httpie")
    assert_error(rows, "invalid_content_encoding_type_error", "curl", "TypeError")
    assert_error(rows, "invalid_content_encoding_type_error", "raw_request", "TypeError")
    assert_error(rows, "binary_body_command_text_error_raw_available", "curl", "CommandError")
    assert bytes_value(rows, "binary_body_command_text_error_raw_available", "raw_request").endswith(b"\xff\x00\x01a")
    assert_error(rows, "charset_decode_error_raw_available", "httpie", "CommandError")

    assert_command_quoting(rows)

    chunked = bytes_value(rows, "finite_chunked_trailers", "raw_request")
    assert b"a\r\nchunk-body\r\n0\r\nX-Req-Trailer: request-final\r\n\r\n" in chunked
    assert_error(rows, "trailers_without_chunked_raw_value_error", "raw_request", "ValueError")

    assert_websocket_contract(rows)

    resolved = text_value(rows, "preserve_original_ip_true_source_control", "curl")
    assert "--resolve 'source.fixture.invalid:443:[192.0.2.44]'" in resolved


def source_hashes():
    modules = dict(SOURCE_FILES)
    modules["mitmproxy/net/encoding.py"] = __import__("mitmproxy.net.encoding", fromlist=["encoding"])
    modules["mitmproxy/net/http/headers.py"] = __import__(
        "mitmproxy.net.http.headers", fromlist=["headers"]
    )
    modules["mitmproxy/utils/strutils.py"] = __import__(
        "mitmproxy.utils.strutils", fromlist=["strutils"]
    )
    return {
        name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        for name, module in modules.items()
    }


REPRESENTATION_DIFFERENCES = [
    {
        "name": "source_command_text",
        "source": "curl and httpie are shell command strings; the exporter does not execute them",
        "native": "native command output must remain text and must not imply execution",
    },
    {
        "name": "decoded_bodies",
        "source": "cleanup_request/cleanup_response copy each message; nonempty content decodes with strict=False and removes Content-Encoding, while missing or empty content leaves existing headers unchanged",
        "native": "native exports need an explicit decoded-versus-raw body rule; missing and empty bodies remain distinct",
    },
    {
        "name": "http_versions_and_reason",
        "source": "raw assembly preserves request/response HTTP versions and the response reason bytes",
        "native": "live native rows may not have these values; do not invent HTTP/1.1 or a status-derived reason",
    },
    {
        "name": "peer_ip_option",
        "source": "the finite true control can add curl --resolve from the synthetic server peername",
        "native": "actual peer address is unavailable in the current native snapshot; do not claim this source control is native parity",
    },
    {
        "name": "websocket_export",
        "source": "combined raw appends direction-prefixed payload bytes and omits type/drop/injected metadata",
        "native": "a native transcript must retain direction/type/drop independently when its workflow exposes those facts",
    },
    {
        "name": "chunked_trailers",
        "source": "raw assembly emits finite chunk framing and trailers; non-chunked trailers raise ValueError",
        "native": "native export should preserve the observed framing facts or report unavailable representation explicitly",
    },
]


def document():
    rows = [observe(spec) for spec in WORKFLOWS]
    assert_contract(rows)
    return {
        "schema": 2,
        "source": "installed_mitmproxy_export_functions",
        "versions": {
            "python": sys.version.split()[0],
            "mitmproxy": importlib.metadata.version("mitmproxy"),
        },
        "source_sha256": source_hashes(),
        "formats": list(FORMATS),
        "export_preserve_original_ip_default": False,
        "representation_differences": REPRESENTATION_DIFFERENCES,
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    observed = document()
    text = json.dumps(observed, indent=2, ensure_ascii=True) + "\n"
    if options.check:
        expected = Path(__file__).with_suffix(".json").read_text()
        if text != expected:
            raise SystemExit("traffic export fixture differs")
        count = sum(len(row["formats"]) for row in observed["rows"])
        print(f"matched {len(observed['rows'])} workflows / {count} export observations")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
