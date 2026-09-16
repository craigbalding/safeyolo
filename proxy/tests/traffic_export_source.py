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
        "explicit_default_https_port_path_query",
        {
            "method": "GET",
            "url": "https://source.fixture.invalid:443/default-https/path?x=one&y=two",
            "headers": [],
            "body": {"text": "https-default"},
        },
    ),
    workflow(
        "explicit_default_http_port_path_query",
        {
            "method": "GET",
            "url": "http://source.fixture.invalid:80/default-http/path?x=one&y=two",
            "headers": [],
            "body": {"text": "http-default"},
        },
    ),
    workflow(
        "header_bytes_valid_utf8_and_ff",
        {
            "method": "GET",
            "url": "https://source.fixture.invalid:443/header-bytes?x=one",
            "headers": [
                ["X-UTF8", {"hex": "636166c3a9"}],
                ["X-Byte", {"hex": "ff"}],
            ],
            "body": {"text": "header-body"},
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
        "charset_ascii_valid",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/ascii-valid",
            "headers": [["Content-Type", "text/plain; charset=ascii"]],
            "body": {"text": "ascii-body"},
        },
    ),
    workflow(
        "charset_utf8_spaced_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/utf8-spaced",
            "headers": [["Content-Type", "text/plain; charset=utf 8"]],
            "body": {"text": "utf8-spaced"},
        },
    ),
    workflow(
        "charset_windows_1252_declared",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/windows-1252",
            "headers": [["Content-Type", "text/plain; charset=windows-1252"]],
            "body": {"hex": "8082919293949697"},
        },
    ),
    workflow(
        "charset_windows_1252_cp1252_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp1252",
            "headers": [["Content-Type", "text/plain; charset=cp1252"]],
            "body": {"hex": "80ff"},
        },
    ),
    workflow(
        "charset_windows_1252_undefined",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/windows-1252-undefined",
            "headers": [["Content-Type", "text/plain; charset=windows-1252"]],
            "body": {"hex": "81"},
        },
    ),
    workflow(
        "charset_cp1250_undefined",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp1250-undefined",
            "headers": [["Content-Type", "text/plain; charset=cp1250"]],
            "body": {"hex": "81"},
        },
    ),
    workflow(
        "charset_cp1251_undefined",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp1251-undefined",
            "headers": [["Content-Type", "text/plain; charset=cp1251"]],
            "body": {"hex": "98"},
        },
    ),
    workflow(
        "charset_cp1254_undefined",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp1254-undefined",
            "headers": [["Content-Type", "text/plain; charset=cp1254"]],
            "body": {"hex": "81"},
        },
    ),
    workflow(
        "charset_shift_jis_declared",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/shift-jis",
            "headers": [["Content-Type", "text/plain; charset=shift_jis"]],
            "body": {"hex": "93fa967b"},
        },
    ),
    workflow(
        "charset_shift_jis_sjis_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/sjis",
            "headers": [["Content-Type", "text/plain; charset=sjis"]],
            "body": {"hex": "82a082a2"},
        },
    ),
    workflow(
        "charset_shift_jis_python_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/shift-jis-table",
            "headers": [["Content-Type", "text/plain; charset=shift_jis"]],
            "body": {"hex": "81608161817c8191819281ca"},
        },
    ),
    workflow(
        "charset_cp932_python_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp932-table",
            "headers": [["Content-Type", "text/plain; charset=cp932"]],
            "body": {"hex": "a0fdfeff81608740ed40fa40f040"},
        },
    ),
    workflow(
        "charset_iso8859_2_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/iso8859-2",
            "headers": [["Content-Type", "text/plain; charset=iso8859_2"]],
            "body": {"hex": "a1a2a3af"},
        },
    ),
    workflow(
        "charset_iso8859_15_declared",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/iso8859-15",
            "headers": [["Content-Type", "text/plain; charset=iso-8859-15"]],
            "body": {"hex": "a4a6bcb4be"},
        },
    ),
    workflow(
        "charset_gbk_source_normalization",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gbk",
            "headers": [["Content-Type", "text/plain; charset=gbk"]],
            "body": {"hex": "d6d0cec481308130"},
        },
    ),
    workflow(
        "charset_gb2312_source_normalization",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gb2312",
            "headers": [["Content-Type", "text/plain; charset=gb2312"]],
            "body": {"hex": "d6d0cec481308130"},
        },
    ),
    workflow(
        "charset_cp936_undefined",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp936-undefined",
            "headers": [["Content-Type", "text/plain; charset=cp936"]],
            "body": {"hex": "80"},
        },
    ),
    workflow(
        "charset_cp936_valid_sequence",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp936-valid",
            "headers": [["Content-Type", "text/plain; charset=cp936"]],
            "body": {"hex": "8180"},
        },
    ),
    workflow(
        "charset_cp936_rejected_gbk_tables",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp936-rejected",
            "headers": [["Content-Type", "text/plain; charset=cp936"]],
            "body": {"hex": "a8bc"},
        },
    ),
    workflow(
        "charset_euc_jp_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/euc-jp",
            "headers": [["Content-Type", "text/plain; charset=euc_jp"]],
            "body": {"hex": "c6fccbdc"},
        },
    ),
    workflow(
        "charset_euc_jp_python_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/euc-jp-table",
            "headers": [["Content-Type", "text/plain; charset=euc_jp"]],
            "body": {"hex": "a1c1a1c2a1dda1f1a1f2a2cc8fa2af8eb1"},
        },
    ),
    workflow(
        "charset_gb18030_python_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gb18030-table",
            "headers": [["Content-Type", "text/plain; charset=gb18030"]],
            "body": {"hex": "a8bca6d9a6dafe598135f4378130813090308130e3329a35"},
        },
    ),
    workflow(
        "charset_gb18030_malformed",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gb18030-malformed",
            "headers": [["Content-Type", "text/plain; charset=gb18030"]],
            "body": {"hex": "e3329a36"},
        },
    ),
    workflow(
        "charset_cp932_python_private_singles",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp932-private",
            "headers": [["Content-Type", "text/plain; charset=cp932"]],
            "body": {"hex": "80a0fdfeff"},
        },
    ),
    workflow(
        "charset_cp936_cross_boundary",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp936-cross",
            "headers": [["Content-Type", "text/plain; charset=cp936"]],
            "body": {"hex": "81a8bc40"},
        },
    ),
    workflow(
        "charset_gbk_unassigned_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/cp936-unassigned-table",
            "headers": [["Content-Type", "text/plain; charset=cp936"]],
            "body": {"hex": "a140"},
        },
    ),
    workflow(
        "charset_gb2312_registered_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gb2312-80",
            "headers": [["Content-Type", "text/plain; charset=gb2312-80"]],
            "body": {"hex": "a1a4a1aa"},
        },
    ),
    workflow(
        "charset_gb2312_unknown_separator",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gb-2312",
            "headers": [["Content-Type", "text/plain; charset=gb_2312"]],
            "body": {"hex": "8180"},
        },
    ),
    workflow(
        "charset_euc_jp_ss3_mapping",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/euc-jp-ss3",
            "headers": [["Content-Type", "text/plain; charset=euc_jp"]],
            "body": {"hex": "8fa2b7"},
        },
    ),
    workflow(
        "charset_euc_jp_unassigned_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/euc-jp-unassigned",
            "headers": [["Content-Type", "text/plain; charset=euc_jp"]],
            "body": {"hex": "ada1"},
        },
    ),
    workflow(
        "charset_gb18030_pair_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/gb18030-pairs",
            "headers": [["Content-Type", "text/plain; charset=gb18030"]],
            "body": {
                "hex": "a3a0a6d9a6daa6dba6dca6dda6dea6dfa6eca6eda6f3a8bcfe59fe61fe66fe67fe6dfe7efe90fea0"
            },
        },
    ),
    workflow(
        "charset_unknown_windows_31j",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/unknown-windows-31j",
            "headers": [["Content-Type", "text/plain; charset=windows-31j"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_unknown_windows_874",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/unknown-windows-874",
            "headers": [["Content-Type", "text/plain; charset=windows-874"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_unknown_windows_949",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/unknown-windows-949",
            "headers": [["Content-Type", "text/plain; charset=windows-949"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_unknown_x_mac_cyrillic",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/unknown-x-mac-cyrillic",
            "headers": [["Content-Type", "text/plain; charset=x-mac-cyrillic"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_unknown_x_sjis",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/unknown-x-sjis",
            "headers": [["Content-Type", "text/plain; charset=x-sjis"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_unknown_iso_2022_cn",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/unknown-iso-2022-cn",
            "headers": [["Content-Type", "text/plain; charset=iso-2022-cn"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_known_big5_unimplemented",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/known-big5",
            "headers": [["Content-Type", "text/plain; charset=big5"]],
            "body": {"hex": "81"},
        },
    ),
    workflow(
        "charset_big5_valid",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/big5-valid",
            "headers": [["Content-Type", "text/plain; charset=big5"]],
            "body": {"hex": "a440"},
        },
    ),
    workflow(
        "charset_big5_python_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/big5-table",
            "headers": [["Content-Type", "text/plain; charset=big5"]],
            "body": {"hex": "a145a14ec6a1c7e9"},
        },
    ),
    workflow(
        "charset_big5_big5_tw_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/big5-tw",
            "headers": [["Content-Type", "text/plain; charset=big5_tw"]],
            "body": {"hex": "a440"},
        },
    ),
    workflow(
        "charset_big5_csbig5_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/csbig5",
            "headers": [["Content-Type", "text/plain; charset=csbig5"]],
            "body": {"hex": "a440"},
        },
    ),
    workflow(
        "charset_big5_x_mac_trad_chinese_alias",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/x-mac-trad-chinese",
            "headers": [["Content-Type", "text/plain; charset=x_mac_trad_chinese"]],
            "body": {"hex": "a440"},
        },
    ),
    workflow(
        "charset_big5_malformed_after_valid_prefix",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/big5-malformed",
            "headers": [["Content-Type", "text/plain; charset=big5"]],
            "body": {"hex": "a4408140"},
        },
    ),
    workflow(
        "charset_known_hex_codec_unimplemented",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/known-hex-codec",
            "headers": [["Content-Type", "text/plain; charset=hex_codec"]],
            "body": {"text": "not hex"},
        },
    ),
    workflow(
        "charset_known_rot13_unimplemented",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/known-rot13",
            "headers": [["Content-Type", "text/plain; charset=rot_13"]],
            "body": {"text": "codec-category"},
        },
    ),
    workflow(
        "charset_koi8_u_table",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/koi8-u",
            "headers": [["Content-Type", "text/plain; charset=koi8_u"]],
            "body": {"hex": "aebe"},
        },
    ),
    workflow(
        "charset_shift_jis_malformed",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/shift-jis-malformed",
            "headers": [["Content-Type", "text/plain; charset=shift_jis"]],
            "body": {"hex": "82"},
        },
    ),
    workflow(
        "bom_utf16le_retains_bom",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/bom-utf16le",
            "headers": [["Content-Type", "text/plain"]],
            "body": {"hex": "fffe68006900"},
        },
    ),
    workflow(
        "bom_utf16be_retains_bom",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/bom-utf16be",
            "headers": [["Content-Type", "text/plain"]],
            "body": {"hex": "feff00680069"},
        },
    ),
    workflow(
        "bom_utf32le_retains_bom",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/bom-utf32le",
            "headers": [["Content-Type", "text/plain"]],
            "body": {"hex": "fffe00006800000069000000"},
        },
    ),
    workflow(
        "bom_utf32be_retains_bom",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/bom-utf32be",
            "headers": [["Content-Type", "text/plain"]],
            "body": {"hex": "0000feff0000006800000069"},
        },
    ),
    workflow(
        "html_in_body_charset_inference",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/html-encoding",
            "headers": [["Content-Type", "text/html"]],
            "body": {"hex": "3c6d65746120636861727365743d2769736f2d383835392d31273e636166e9"},
        },
    ),
    workflow(
        "xml_in_body_charset_inference",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/xml-encoding",
            "headers": [["Content-Type", "application/xml"]],
            "body": {
                "hex": "3c3f786d6c2076657273696f6e3d27312e302720656e636f64696e673d2769736f2d383835392d31273f3e3c783e636166e93c2f783e"
            },
        },
    ),
    workflow(
        "css_in_body_charset_inference",
        {
            "method": "POST",
            "url": "http://source.fixture.invalid/css-encoding",
            "headers": [["Content-Type", "text/css"]],
            "body": {
                "hex": "4063686172736574202269736f2d383835392d31223b202e78207b20636f6e74656e743a2022e9223b207d"
            },
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
    """Represent source text bytes safely and binary values exactly when bounded."""
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogateescape")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            representation = "utf8-surrogateescape"
            safe_text = None
        else:
            representation = "unicode"
            safe_text = value
        result = {
            "kind": "text",
            "representation": representation,
            "text": safe_text,
            "utf8_length": len(raw),
            "utf8_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if len(raw) <= 4096:
            result["utf8_hex"] = raw.hex()
        else:
            result["utf8_prefix_hex"] = raw[:128].hex()
            result["utf8_suffix_hex"] = raw[-128:].hex()
        return result
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
    assert value["output"]["representation"] == "unicode", (name, format_name, value)
    return value["output"]["text"]


def text_bytes_value(rows, name, format_name):
    value = result(rows, name, format_name)
    assert value["error_type"] is None, (name, format_name, value)
    output_value = value["output"]
    assert output_value["kind"] == "text", (name, format_name, value)
    assert output_value["utf8_hex"], (name, format_name, value)
    return bytes.fromhex(output_value["utf8_hex"])


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


def assert_url_and_header_bytes_controls(rows):
    assert text_value(rows, "explicit_default_https_port_path_query", "curl") == (
        "curl 'https://source.fixture.invalid/default-https/path?x=one&y=two' -d https-default"
    )
    assert text_value(rows, "explicit_default_https_port_path_query", "httpie") == (
        "http GET 'https://source.fixture.invalid/default-https/path?x=one&y=two' <<< https-default"
    )
    assert text_value(rows, "explicit_default_http_port_path_query", "curl") == (
        "curl 'http://source.fixture.invalid/default-http/path?x=one&y=two' -d http-default"
    )
    assert text_value(rows, "explicit_default_http_port_path_query", "httpie") == (
        "http GET 'http://source.fixture.invalid/default-http/path?x=one&y=two' <<< http-default"
    )

    for format_name in ("curl", "httpie"):
        value = result(rows, "header_bytes_valid_utf8_and_ff", format_name)
        assert value["output"]["representation"] == "utf8-surrogateescape", value
        assert value["output"]["text"] is None, value
        command_bytes = text_bytes_value(rows, "header_bytes_valid_utf8_and_ff", format_name)
        assert b"X-UTF8: caf\xc3\xa9" in command_bytes, (format_name, command_bytes)
        assert b"X-Byte: \xff" in command_bytes, (format_name, command_bytes)


def assert_text_decoding_controls(rows):
    assert "ascii-body" in text_value(rows, "charset_ascii_valid", "curl")
    assert text_value(rows, "charset_utf8_spaced_alias", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=utf 8' -X POST "
        "http://source.fixture.invalid/utf8-spaced -d utf8-spaced"
    )
    assert text_value(rows, "charset_windows_1252_declared", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=windows-1252' -X POST "
        "http://source.fixture.invalid/windows-1252 -d '€‚‘’“”–—'"
    )
    assert text_value(rows, "charset_windows_1252_cp1252_alias", "httpie") == (
        "http POST http://source.fixture.invalid/cp1252 "
        "'Content-Type: text/plain; charset=cp1252' <<< '€ÿ'"
    )
    for name, invalid_byte in (
        ("charset_windows_1252_undefined", b"\x81"),
        ("charset_cp1250_undefined", b"\x81"),
        ("charset_cp1251_undefined", b"\x98"),
        ("charset_cp1254_undefined", b"\x81"),
        ("charset_cp936_undefined", b"\x80"),
    ):
        assert_error(rows, name, "curl", "CommandError")
        assert_error(rows, name, "httpie", "CommandError")
        assert bytes_value(rows, name, "raw_request").endswith(b"\r\n" + invalid_byte)
    assert text_value(rows, "charset_shift_jis_declared", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=shift_jis' -X POST "
        "http://source.fixture.invalid/shift-jis -d '日本'"
    )
    assert text_value(rows, "charset_shift_jis_sjis_alias", "httpie") == (
        "http POST http://source.fixture.invalid/sjis "
        "'Content-Type: text/plain; charset=sjis' <<< 'あい'"
    )
    assert text_value(rows, "charset_shift_jis_python_table", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=shift_jis' -X POST "
        "http://source.fixture.invalid/shift-jis-table -d '〜‖−¢£¬'"
    )
    assert text_value(rows, "charset_cp932_python_table", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=cp932' -X POST "
        "http://source.fixture.invalid/cp932-table -d '\uf8f0\uf8f1\uf8f2\uf8f3\uff5e\u2460\u7e8a\u2170\ue000'"
    )
    assert text_value(rows, "charset_iso8859_2_alias", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=iso8859_2' -X POST "
        "http://source.fixture.invalid/iso8859-2 -d 'Ą˘ŁŻ'"
    )
    assert text_value(rows, "charset_iso8859_15_declared", "httpie") == (
        "http POST http://source.fixture.invalid/iso8859-15 "
        "'Content-Type: text/plain; charset=iso-8859-15' <<< '€ŠŒŽŸ'"
    )
    assert text_value(rows, "charset_gbk_source_normalization", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=gbk' -X POST "
        "http://source.fixture.invalid/gbk -d '中文\u0080'"
    )
    assert text_value(rows, "charset_gb2312_source_normalization", "httpie") == (
        "http POST http://source.fixture.invalid/gb2312 "
        "'Content-Type: text/plain; charset=gb2312' <<< '中文\u0080'"
    )
    assert text_value(rows, "charset_euc_jp_alias", "httpie") == (
        "http POST http://source.fixture.invalid/euc-jp "
        "'Content-Type: text/plain; charset=euc_jp' <<< '日本'"
    )
    assert text_value(rows, "charset_euc_jp_python_table", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=euc_jp' -X POST "
        "http://source.fixture.invalid/euc-jp-table -d '\u301c\u2016\u2212\u00a2\u00a3\u00ac\u02d8\uff71'"
    )
    assert text_value(rows, "charset_cp936_valid_sequence", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=cp936' -X POST "
        "http://source.fixture.invalid/cp936-valid -d '\u4e90'"
    )
    assert text_value(rows, "charset_cp932_python_private_singles", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=cp932' -X POST "
        "http://source.fixture.invalid/cp932-private -d '\u0080\uf8f0\uf8f1\uf8f2\uf8f3'"
    )
    assert text_value(rows, "charset_cp936_cross_boundary", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=cp936' -X POST "
        "http://source.fixture.invalid/cp936-cross -d '\u4efa\u7cbf'"
    )
    assert_error(rows, "charset_gbk_unassigned_table", "curl", "CommandError")
    assert text_value(rows, "charset_gb2312_registered_alias", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=gb2312-80' -X POST "
        "http://source.fixture.invalid/gb2312-80 -d '\u30fb\u2015'"
    )
    assert_error(rows, "charset_gb2312_unknown_separator", "curl", "CommandError")
    assert text_value(rows, "charset_euc_jp_ss3_mapping", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=euc_jp' -X POST "
        "http://source.fixture.invalid/euc-jp-ss3 -d '~'"
    )
    assert_error(rows, "charset_euc_jp_unassigned_table", "curl", "CommandError")
    assert text_value(rows, "charset_gb18030_pair_table", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=gb18030' -X POST "
        "http://source.fixture.invalid/gb18030-pairs -d "
        "'\ue5e5\ue78d\ue78e\ue78f\ue790\ue791\ue792\ue793\ue794\ue795\ue796\ue7c7\ue81e\ue826\ue82b\ue82c\ue832\ue843\ue854\ue864'"
    )
    assert_error(rows, "charset_cp936_rejected_gbk_tables", "curl", "CommandError")
    assert text_value(rows, "charset_gb18030_python_table", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=gb18030' -X POST "
        "http://source.fixture.invalid/gb18030-table -d '\ue7c7\ue78d\ue78e\ue81e\u1e3f\u0080\U00010000\U0010ffff'"
    )
    assert_error(rows, "charset_gb18030_malformed", "curl", "CommandError")
    assert "╝╬" in text_value(rows, "charset_koi8_u_table", "curl")
    assert_error(rows, "charset_shift_jis_malformed", "curl", "CommandError")
    malformed = bytes_value(rows, "charset_shift_jis_malformed", "raw_request")
    assert malformed.endswith(b"\r\n\x82")
    for name in (
        "charset_unknown_windows_31j",
        "charset_unknown_windows_874",
        "charset_unknown_windows_949",
        "charset_unknown_x_mac_cyrillic",
        "charset_unknown_x_sjis",
        "charset_unknown_iso_2022_cn",
    ):
        assert_error(rows, name, "curl", "CommandError")
        assert_error(rows, name, "httpie", "CommandError")
        assert bytes_value(rows, name, "raw_request").endswith(b"codec-category")
    assert_error(rows, "charset_known_big5_unimplemented", "curl", "CommandError")
    assert_error(rows, "charset_known_big5_unimplemented", "httpie", "CommandError")
    for name, path, header in (
        ("charset_big5_valid", "big5-valid", "big5"),
        ("charset_big5_big5_tw_alias", "big5-tw", "big5_tw"),
        ("charset_big5_csbig5_alias", "csbig5", "csbig5"),
        (
            "charset_big5_x_mac_trad_chinese_alias",
            "x-mac-trad-chinese",
            "x_mac_trad_chinese",
        ),
    ):
        assert text_value(rows, name, "curl") == (
            f"curl -H 'Content-Type: text/plain; charset={header}' -X POST "
            f"http://source.fixture.invalid/{path} -d '\u4e00'"
        )
        assert text_value(rows, name, "httpie") == (
            f"http POST http://source.fixture.invalid/{path} "
            f"'Content-Type: text/plain; charset={header}' <<< '\u4e00'"
        )
    assert text_value(rows, "charset_big5_python_table", "curl") == (
        "curl -H 'Content-Type: text/plain; charset=big5' -X POST "
        "http://source.fixture.invalid/big5-table -d '\u2022\uff64\u30fe\u2460'"
    )
    assert_error(rows, "charset_big5_malformed_after_valid_prefix", "curl", "CommandError")
    assert_error(rows, "charset_big5_malformed_after_valid_prefix", "httpie", "CommandError")
    assert bytes_value(rows, "charset_big5_malformed_after_valid_prefix", "raw_request").endswith(
        b"\r\n\xa4@\x81@"
    )
    assert_error(rows, "charset_known_hex_codec_unimplemented", "curl", "CommandError")
    assert_error(rows, "charset_known_hex_codec_unimplemented", "httpie", "CommandError")
    assert_error(rows, "charset_known_rot13_unimplemented", "curl", "TypeError")
    assert_error(rows, "charset_known_rot13_unimplemented", "httpie", "TypeError")
    for name in (
        "bom_utf16le_retains_bom",
        "bom_utf16be_retains_bom",
        "bom_utf32le_retains_bom",
        "bom_utf32be_retains_bom",
    ):
        assert "\ufeffhi" in text_value(rows, name, "curl"), name
        assert "\ufeffhi" in text_value(rows, name, "httpie"), name

    for name in ("html_in_body_charset_inference", "xml_in_body_charset_inference"):
        assert "café" in text_value(rows, name, "curl"), name
        assert "café" in text_value(rows, name, "httpie"), name
    for format_name in ("curl", "httpie"):
        assert 'content: "é"' in text_value(rows, "css_in_body_charset_inference", format_name)


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
    assert_url_and_header_bytes_controls(rows)
    assert_text_decoding_controls(rows)
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
        "source": "curl and httpie are shell command strings; this fixture records valid Unicode as text and surrogateescaped bytes as utf8_hex with representation utf8-surrogateescape",
        "native": "native command output must remain text and must not imply execution; replay must preserve command bytes without JSON lone surrogates",
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
        "native": "current main retains the observed peer address, but the native exporter does not implement curl --resolve and the candidate base snapshot lacks those peer facts",
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
    {
        "name": "content_encoding_inference",
        "source": "get_text gives BOMs highest priority, accepts declared ASCII, and infers declared HTML/XML/CSS encodings from in-body markers",
        "native": "native text commands need the demonstrated decoder behavior or an explicit unavailable result",
    },
    {
        "name": "declared_character_codecs",
        "source": "get_text dispatches declared labels through Python's strict codecs registry; gbk and gb2312 are first mapped to gb18030 by the installed source",
        "native": "encoding_rs-backed native decoding uses Python-derived byte tables for the admitted single-byte families, complete one/two-byte validity and mapping corrections for Shift_JIS/CP932/EUC-JP/GBK/GB2312/Big5, and source-version GB18030 pair/four-byte corrections; known Python labels remain explicit and unknown labels are decode failures",
        "remaining_gaps": "The compared domains are all 256 single-byte inputs for 27 admitted families, all 256 single-byte and 65,536 two-byte inputs for Big5, all structurally valid one/two-byte inputs for Shift_JIS, CP932, EUC-JP, GBK, and GB2312, and all 1,587,600 structural GB18030 four-byte sequences; exact CPython codecs outside the compared families still need a Rust table backend, including euc-kr, iso-8859-9, iso-8859-11, ISO-2022 variants, HZ, the CP437/720/737/850/852/855/857/858/860/861/862/863/864/865/869 DOS families, EBCDIC code pages, JOHAB, and Unicode escape codecs",
    },
]


def document():
    rows = [observe(spec) for spec in WORKFLOWS]
    assert_contract(rows)
    return {
        "schema": 4,
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
