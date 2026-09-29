"""Owned data and strict API mocks; no terminal or listener is started."""

import asyncio
import base64
import gzip
import io
import re
import threading
import zlib
from unittest.mock import create_autospec, patch

import brotlicffi
import pytest
import zstandard
from hypothesis import given, settings
from hypothesis import strategies as st
from prompt_toolkit.application import Application, create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.document import Document
from prompt_toolkit.input import DummyInput, create_pipe_input
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import Layout
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.output.color_depth import ColorDepth
from prompt_toolkit.output.vt100 import Vt100_Output
from prompt_toolkit.styles import DummyStyle
from prompt_toolkit.widgets import TextArea

from safeyolo.api import AdminAPI, APIError
from safeyolo.traffic_inspector import (
    BODY_PREVIEW_BYTES,
    LAST_ITEM,
    TAIL_CARDS,
    TAIL_FETCHES_PER_POLL,
    DetailSyntaxLexer,
    TrafficInspector,
    body_preview,
    bulk_export_filename,
    http_body_preview,
    http_header_lines,
    plain_text,
)


def flow(name="one", **changes):
    return {"id": name, "agent": "alice", "method": "GET", "url": "http://owned.invalid/",
            "state": "complete", "status": 200, "request_headers": [["X-Same", "first"], ["X-Same", "second"]],
            "response_headers": [], "request_body": {"available": True, "size": 0, "reason": None},
            "response_body": {"available": False, "size": None, "reason": "streamed_or_unavailable"},
            "metadata": {"test_agent": "declared", "test_id": "case"}, **changes}


def client():
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.traffic_flows.return_value = {"flows": [flow()], "scope": {"agent": "alice"}}
    api.traffic_flow.return_value = flow()
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: (
        preview(b"") if side == "request" else
        {"available": False, "size": 0, "reason": "streamed_or_unavailable",
         "data_base64": None, "preview_size": 0, "truncated": False}
    )
    return api


def preview(data: bytes, *, total: int | None = None) -> dict:
    total = len(data) if total is None else total
    return {"available": True, "size": total, "reason": None,
            "data_base64": base64.b64encode(data).decode(), "preview_size": len(data),
            "truncated": len(data) < total}


def test_plain_rendering_escapes_terminal_controls_without_parsing_markup():
    attack = "[bold]\x1b[2J\x1b]52;c;copied\x07\x9b31m\r\n\u202e"
    text = plain_text(attack)
    assert text == r"[bold]\x1b[2J\x1b]52;c;copied\x07\x9b31m\x0d\x0a\u202e"
    assert plain_text("one\ntwo\tend", multiline=True) == "one\ntwo\\x09end"


def test_body_preview_distinguishes_absent_empty_and_bounded_raw_bytes():
    assert body_preview({"available": False, "reason": "pending"}) == "absent: pending"
    assert body_preview({"available": True, "data_base64": ""}) == "(present, empty body)"
    raw = b"\xff\x1b]52;x\x07" + b"a" * BODY_PREVIEW_BYTES
    value = {"available": True, "data_base64": base64.b64encode(raw).decode()}
    text = body_preview(value)
    assert text.startswith(r"\xff\x1b]52;x\x07")
    assert "[preview: first" in text
    assert "\x1b" not in text
    with pytest.raises(ValueError, match="Invalid retained body"):
        body_preview({"available": True, "data_base64": "not base64!"})


def test_http_body_preview_content_type_charset_encoding_and_availability():
    assert http_body_preview({"available": False, "reason": "pending"}, [], pretty=True).startswith("pending:")
    assert http_body_preview({"available": False, "reason": "streamed_or_unavailable"}, [], pretty=True).startswith("absent:")
    assert http_body_preview(preview(b""), [], pretty=True) == "(present, empty body)"
    json_headers = [["Content-Type", "application/problem+json; charset=utf-8"]]
    compact = preview(b'{"one":1,"two":[2,3]}')
    assert '\n  "one": 1,' in http_body_preview(compact, json_headers, pretty=True)
    assert '{"one":1,"two":[2,3]}' in http_body_preview(compact, json_headers, pretty=False)
    deeply_nested = b"[" * 1200 + b"0" + b"]" * 1200
    nested_text = http_body_preview(preview(deeply_nested), json_headers, pretty=True)
    assert nested_text.startswith("[") and len(nested_text) < 33_000
    assert "café" in http_body_preview(preview("café".encode("latin-1")),
                                       [["Content-Type", "text/plain; charset=iso-8859-1"]], pretty=True)
    compressed = gzip.compress(b'{"ok":true}')
    assert '"ok": true' in http_body_preview(preview(compressed),
        [["Content-Type", "application/json"], ["Content-Encoding", "gzip"]], pretty=True)
    gzip_headers = [["Content-Type", "text/plain"], ["Content-Encoding", "gzip"]]
    assert http_body_preview(preview(gzip.compress(b"")), gzip_headers, pretty=True) == "(present, empty decoded body)"
    decoded_limit = http_body_preview(preview(gzip.compress(b"a" * (BODY_PREVIEW_BYTES + 1))), gzip_headers, pretty=True)
    assert "decoded preview truncated at 65536 bytes" in decoded_limit
    assert "retained preview truncated" not in decoded_limit
    incomplete = http_body_preview(preview(gzip.compress(b"text")[:-4]), gzip_headers, pretty=True)
    assert "encoded stream incomplete" in incomplete
    assert "decoded" in http_body_preview(preview(zlib.compress(b"decoded")),
        [["Content-Type", "text/plain"], ["Content-Encoding", "deflate"]], pretty=True)
    assert '"ok": true' in http_body_preview(preview(brotlicffi.compress(b'{"ok":true}')),
        [["Content-Type", "application/json"], ["Content-Encoding", "br"]], pretty=True)
    assert "binary" in http_body_preview(preview(b"\x00\xff"),
        [["Content-Type", "application/octet-stream"]], pretty=True)
    assert "preview truncated" in http_body_preview(preview(b"\x00\xff", total=20),
        [["Content-Type", "application/octet-stream"]], pretty=True)
    assert "binary" in http_body_preview(preview(b"abc"),
        [["Content-Type", "invalid"]], pretty=True)
    assert "unsupported or undecodable charset" in http_body_preview(preview(b"hello"),
        [["Content-Type", "text/plain; charset=no-such-charset"]], pretty=True)
    assert "retained preview truncated: 5 of 100 retained bytes" in http_body_preview(preview(b"short", total=100),
        [["Content-Type", "text/plain"]], pretty=True)


def test_http_preview_decodes_supported_codings_and_stacked_fields():
    payload = b'{"from":"Kali","ok":true}'
    headers = [["Content-Type", "application/problem+json"]]
    encoders = {
        "identity": lambda body: body,
        "gzip": gzip.compress,
        "deflate": zlib.compress,
        "br": brotlicffi.compress,
        "zstd": lambda body: zstandard.ZstdCompressor().compress(body),
    }
    for coding, encode in encoders.items():
        rendered = http_body_preview(preview(encode(payload)),
            [*headers, ["Content-Encoding", coding]], pretty=True)
        assert '"from": "Kali"' in rendered and '"ok": true' in rendered

    stacked = encoders["zstd"](encoders["br"](encoders["gzip"](payload)))
    rendered = http_body_preview(preview(stacked),
        [*headers, ["Content-Encoding", "GZIP, br"], ["content-encoding", " zstd "]], pretty=True)
    assert '"from": "Kali"' in rendered and '"ok": true' in rendered
    assert "malformed" not in rendered and "incomplete" not in rendered
    assert '"from":"Kali"' in http_body_preview(preview(stacked),
        [*headers, ["Content-Encoding", "gzip, br, zstd"]], pretty=False)
    partial_stack = gzip.compress(brotlicffi.compress(payload))
    recovered = http_body_preview(preview(partial_stack[:-1], total=len(partial_stack)),
        [*headers, ["Content-Encoding", "br, gzip"]], pretty=True)
    assert '"from": "Kali"' in recovered and "encoded stream incomplete (gzip)" in recovered

    for coding, encode in (("gzip", gzip.compress),
                           ("zstd", lambda body: zstandard.ZstdCompressor().compress(body))):
        members = encode(b"first ") + encode(b"second")
        assert http_body_preview(preview(members),
            [["Content-Type", "text/plain"], ["Content-Encoding", coding]], pretty=False) == "first second"


def test_http_preview_reports_incomplete_malformed_and_unsupported_codings():
    headers = [["Content-Type", "text/plain"]]
    payload = b"readable content before trailer"
    encoders = {
        "gzip": gzip.compress,
        "deflate": zlib.compress,
        "br": brotlicffi.compress,
        "zstd": lambda body: zstandard.ZstdCompressor().compress(body),
    }
    for coding, encode in encoders.items():
        encoded = encode(payload)
        rendered = http_body_preview(preview(encoded[:-1], total=len(encoded)),
            [*headers, ["Content-Encoding", coding]], pretty=False)
        assert "readable content" in rendered
        assert f"encoded stream incomplete ({coding})" in rendered
        assert "retained preview truncated" in rendered

    gzip_body = gzip.compress(payload)
    damaged_gzip = gzip_body[:-1] + bytes([gzip_body[-1] ^ 1])
    rendered = http_body_preview(preview(damaged_gzip),
        [*headers, ["Content-Encoding", "gzip"]], pretty=False)
    assert "readable content" in rendered and "malformed gzip stream" in rendered

    damaged_br = b"\x00" + brotlicffi.compress(payload)[1:]
    rendered = http_body_preview(preview(damaged_br),
        [*headers, ["Content-Encoding", "br"]], pretty=False, side="response")
    assert "malformed br stream" in rendered and "x export raw_response" in rendered
    assert "malformed br stream" in http_body_preview(preview(brotlicffi.compress(payload) + b"junk"),
        [*headers, ["Content-Encoding", "br"]], pretty=False)

    encoded_zstd = zstandard.ZstdCompressor(write_checksum=True).compress(payload)
    damaged_zstd = encoded_zstd[:-1] + bytes([encoded_zstd[-1] ^ 1])
    rendered = http_body_preview(preview(damaged_zstd),
        [*headers, ["Content-Encoding", "zstd"]], pretty=False)
    assert "malformed zstd stream" in rendered

    unsupported = http_body_preview(preview(b"private\x1b[2J"),
        [*headers, ["Content-Encoding", "rot13"]], pretty=True)
    assert "unsupported content encoding rot13" in unsupported
    assert "first retained bytes: 70 72" in unsupported and "\x1b" not in unsupported
    assert "malformed Content-Encoding header" in http_body_preview(preview(b"x"),
        [*headers, ["Content-Encoding", "gzip,,br"]], pretty=True)
    long_coding = http_body_preview(preview(b"x"),
        [*headers, ["Content-Encoding", "x" * 10_000]], pretty=True)
    assert len(long_coding) < 320 and "x export" in long_coding


def test_http_preview_bounds_expansion_for_each_coding():
    payload = b"a" * (BODY_PREVIEW_BYTES * 4)
    encoders = {
        "gzip": gzip.compress,
        "deflate": zlib.compress,
        "br": brotlicffi.compress,
        "zstd": lambda body: zstandard.ZstdCompressor().compress(body),
    }
    for coding, encode in encoders.items():
        rendered = http_body_preview(preview(encode(payload)),
            [["Content-Type", "text/plain"], ["Content-Encoding", coding]], pretty=False)
        assert "decoded preview truncated at 65536 bytes" in rendered
        assert "body preview truncated" in rendered
        assert len(rendered) < 34_000

    large_window = zstandard.ZstdCompressor(
        compression_params=zstandard.ZstdCompressionParameters.from_level(3, window_log=26),
    ).compressobj()
    encoded = large_window.compress(b"small") + large_window.flush()
    limited = http_body_preview(preview(encoded),
        [["Content-Type", "text/plain"], ["Content-Encoding", "zstd"]], pretty=False)
    assert "zstd window exceeds" in limited and "x export" in limited


@pytest.mark.parametrize(("media_type", "body"), [
    ("text/plain", b"plain text"),
    ("application/soap+xml", b"<root><ok>true</ok></root>"),
    ("text/html", b"<p>Hello</p>"),
    ("application/javascript", b"const value = 1;"),
    ("text/css", b"p { color: red; }"),
    ("text/event-stream", b"event: update\ndata: ready\n\n"),
])
def test_http_preview_reads_common_text_media_without_format_key(media_type, body):
    rendered = http_body_preview(preview(body), [["Content-Type", media_type]], pretty=False)
    assert rendered == body.decode()
    assert http_body_preview(preview(body), [["Content-Type", media_type]], pretty=True) == rendered


def test_http_preview_formats_structured_text_and_source_keeps_whitespace():
    compact = b'{"one":1,"two":[2,3]}'
    indented = b'{\n    "one": 1,\n    "two": [2, 3]\n}'
    json_headers = [["Content-Type", "application/json"]]
    assert http_body_preview(preview(compact), json_headers, pretty=False) == compact.decode()
    assert '\n  "one": 1,' in http_body_preview(preview(compact), json_headers, pretty=True)
    assert http_body_preview(preview(indented), json_headers, pretty=False) == indented.decode()
    assert '\n  "one": 1,' in http_body_preview(preview(indented), json_headers, pretty=True)

    ndjson = b'{"one":1}\n{"two":2}\n'
    ndjson_headers = [["Content-Type", "application/x-ndjson"]]
    assert http_body_preview(preview(ndjson), ndjson_headers, pretty=False) == ndjson.decode()
    formatted = http_body_preview(preview(ndjson), ndjson_headers, pretty=True)
    assert '{\n  "one": 1\n}\n{\n  "two": 2\n}' in formatted

    form = b"name=Alice+Lee&tag=one&tag=two&empty="
    form_headers = [["Content-Type", "application/x-www-form-urlencoded"]]
    assert http_body_preview(preview(form), form_headers, pretty=False) == form.decode()
    assert http_body_preview(preview(form), form_headers, pretty=True) == (
        "name = Alice Lee\ntag = one\ntag = two\nempty = "
    )


def test_http_preview_charset_binary_fallback_and_safe_export_hint():
    latin1 = "<p>café</p>".encode("latin-1")
    assert "café" in http_body_preview(preview(latin1),
        [["Content-Type", 'text/html; charset="iso-8859-1"']], pretty=False)
    utf16 = "<x>雪</x>".encode("utf-16-le")
    assert "雪" in http_body_preview(preview(utf16),
        [["Content-Type", "application/xml; charset=utf-16-le"]], pretty=True)
    assert "city = Montréal" in http_body_preview(preview(b"city=Montr%E9al"),
        [["Content-Type", "application/x-www-form-urlencoded; charset=iso-8859-1"]], pretty=True)

    controls = http_body_preview(preview(brotlicffi.compress(b"line\x1b[2J\x9b31m\nnext")),
        [["Content-Type", "text/plain; charset=latin-1"], ["Content-Encoding", "br"]], pretty=False)
    assert r"\x1b[2J\x9b31m" in controls and "\x1b" not in controls and "\x9b" not in controls

    binary = b"\x00\x1b[2J\xff"
    rendered = http_body_preview(preview(gzip.compress(binary)),
        [["Content-Type", "application/octet-stream"], ["Content-Encoding", "gzip"]],
        pretty=True, side="response")
    assert "application/octet-stream" in rendered and "retained bytes" in rendered
    assert "first decoded bytes: 00 1b 5b 32 4a ff" in rendered
    assert "x export raw_response" in rendered and "\x1b" not in rendered
    unknown = http_body_preview(preview(b"arbitrary"),
        [["Content-Type", "application/x-unknown"]], pretty=False, side="request")
    assert "binary or unknown body" in unknown and "x export raw_request" in unknown


def test_http_preview_keeps_text_when_a_character_crosses_the_preview_limit():
    headers = [["Content-Type", "text/plain; charset=utf-8"]]
    minimal = http_body_preview(preview(b"\xc3", total=2), headers, pretty=False)
    assert "retained preview truncated: 1 of 2 retained bytes" in minimal
    assert "unsupported or undecodable charset" not in minimal

    partial = http_body_preview(preview(b"hello\xc3", total=7), headers, pretty=False)
    assert partial.startswith("hello")
    assert "retained preview truncated: 6 of 7 retained bytes" in partial
    assert "unsupported or undecodable charset" not in partial

    text = b"a" * (BODY_PREVIEW_BYTES - 1) + "é".encode() + b"tail"
    identity = http_body_preview(preview(text[:BODY_PREVIEW_BYTES], total=len(text)), headers, pretty=False)
    assert identity.startswith("a")
    assert "retained preview truncated" in identity
    assert "unsupported or undecodable charset" not in identity

    compressed = http_body_preview(preview(gzip.compress(text)),
        [*headers, ["Content-Encoding", "gzip"]], pretty=False)
    assert compressed.startswith("a")
    assert "decoded preview truncated at 65536 bytes" in compressed
    assert "retained preview truncated" not in compressed
    assert "unsupported or undecodable charset" not in compressed

    assert "unsupported or undecodable charset" in http_body_preview(preview(b"hello\xc3"), headers, pretty=False)
    assert "unsupported or undecodable charset" in http_body_preview(preview(b"hello\xff", total=7), headers, pretty=False)
    assert "unsupported or undecodable charset" in http_body_preview(preview(b"hello\xed\xa0", total=8), headers, pretty=False)

    utf16 = http_body_preview(preview(b"A\x00B", total=4),
        [["Content-Type", "text/plain; charset=utf-16-le"]], pretty=False)
    assert utf16.startswith("A")
    assert "retained preview truncated: 3 of 4 retained bytes" in utf16


def test_http_preview_respects_utf8_bom_and_utf7_shift_boundaries():
    bom = b"\xef\xbb\xbf"
    utf8_sig_headers = [["Content-Type", "text/plain; charset=utf-8-sig"]]
    small = http_body_preview(preview(bom + b"hello\xc3", total=10), utf8_sig_headers, pretty=False)
    assert small.startswith("hello")
    assert "retained preview truncated: 9 of 10 retained bytes" in small
    assert "unsupported or undecodable charset" not in small

    text = bom + b"a" * (BODY_PREVIEW_BYTES - 4) + "é".encode() + b"tail"
    identity = http_body_preview(preview(text[:BODY_PREVIEW_BYTES], total=len(text)), utf8_sig_headers, pretty=False)
    assert identity.startswith("a")
    assert "retained preview truncated" in identity
    assert "unsupported or undecodable charset" not in identity
    compressed = http_body_preview(preview(gzip.compress(text)),
        [*utf8_sig_headers, ["Content-Encoding", "gzip"]], pretty=False)
    assert compressed.startswith("a")
    assert "decoded preview truncated at 65536 bytes" in compressed
    assert "retained preview truncated" not in compressed
    assert "unsupported or undecodable charset" not in compressed

    utf7_headers = [["Content-Type", "text/plain; charset=utf-7"]]
    shifted = b"pre+AOk-post"
    utf7 = http_body_preview(preview(shifted[:5], total=len(shifted)), utf7_headers, pretty=False)
    assert utf7.startswith("pre")
    assert "retained preview truncated: 5 of 12 retained bytes" in utf7
    assert "unsupported or undecodable charset" not in utf7

    withheld = b"+AOkA6QDp-pad"
    short_shift = http_body_preview(preview(withheld[:6], total=len(withheld)), utf7_headers, pretty=False)
    assert short_shift.startswith("é")
    assert "retained preview truncated: 6 of 13 retained bytes" in short_shift

    long_shift = ("é" * 40_000).encode("utf-7")
    long_identity = http_body_preview(preview(long_shift[:BODY_PREVIEW_BYTES], total=len(long_shift)),
        utf7_headers, pretty=False)
    assert long_identity.startswith("é" * 100)
    assert "retained preview truncated" in long_identity
    long_compressed = http_body_preview(preview(gzip.compress(long_shift)),
        [*utf7_headers, ["Content-Encoding", "gzip"]], pretty=False)
    assert long_compressed.startswith("é" * 100)
    assert "decoded preview truncated at 65536 bytes" in long_compressed
    assert "retained preview truncated" not in long_compressed

    for body, headers, total in (
        (bom + b"hello\xc3", utf8_sig_headers, None),
        (bom + b"hello\xed\xa0", utf8_sig_headers, 11),
        (shifted[:5], utf7_headers, None),
        (b"pre+!", utf7_headers, 6),
    ):
        assert "unsupported or undecodable charset" in http_body_preview(
            preview(body, total=total), headers, pretty=False,
        )


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=128), st.text(max_size=50))
def test_generated_payload_and_header_controls_never_reach_terminal(raw, header):
    rendered = http_body_preview(preview(raw), [["Content-Type", "text/plain; charset=latin-1"]], pretty=True)
    headers = http_header_lines([["X-Control", header]], hide_routine=False)
    for text in (rendered, *headers):
        assert "\x1b" not in text and "\x9b" not in text and "\r" not in text
    assert plain_text(header) in headers[0]


def test_http_preview_rejects_inconsistent_bounds():
    for value in (
        {**preview(b"one"), "size": 2},
        {**preview(b"one"), "preview_size": 2},
        {**preview(b"one"), "truncated": True},
        {**preview(b"one"), "data_base64": "!"},
        preview(b"x" * (BODY_PREVIEW_BYTES + 1)),
    ):
        with pytest.raises(ValueError, match="Invalid retained body preview"):
            http_body_preview(value, [["Content-Type", "text/plain"]], pretty=True)


def test_hidden_headers_summarize_names_without_values_and_restore_duplicates():
    headers = [["Accept", "first-secret"], ["aCcEpT", "second-secret"],
               ["Authorization", "Bearer visible"], ["Content-Type", "application/json"]]
    hidden = "\n".join(http_header_lines(headers, hide_routine=True))
    assert "Hidden routine headers (2): Accept ×2" in hidden
    assert "first-secret" not in hidden and "second-secret" not in hidden
    assert "Authorization: Bearer visible" in hidden and "Content-Type: application/json" in hidden
    shown = "\n".join(http_header_lines(headers, hide_routine=False))
    assert "Accept: first-secret\naCcEpT: second-secret" in shown


def test_selection_survives_newest_insert_and_clears_details_on_eviction():
    view = TrafficInspector(client())
    view.snapshot({"flows": [flow("two"), flow("one")], "scope": {}})
    view.select(1)
    view.detail = flow("one")
    view.body_values["request"] = preview(b"old preview")
    view.snapshot({"flows": [flow("three"), flow("two"), flow("one")], "scope": {}})
    assert view.selected == "one"
    assert view.body_values["request"] == preview(b"old preview")
    view.snapshot({"flows": [flow("three"), flow("two")], "scope": {}})
    assert view.selected == "three"
    assert view.detail is None and not view.body_values
    view.snapshot({"flows": [], "scope": {}})
    assert view.selected is None


def test_marked_flows_are_distinct_from_focus_and_hidden_marks_are_dropped():
    view = TrafficInspector(client())
    view.snapshot({"flows": [flow("one"), flow("two"), flow("three")], "scope": {}})
    view.toggle_mark()
    view.select(1)
    view.toggle_mark()

    assert view.selected == "two"
    assert view.marked == {"one", "two"}
    assert view.export_flow_ids() == ("one", "two")
    assert view.rows_text().splitlines()[:2] == [
        " * 200 complete alice GET http://owned.invalid/",
        ">* 200 complete alice GET http://owned.invalid/",
    ]
    assert "> focus" in view.help_text()
    assert "* marked" in view.help_text()
    assert "m mark/unmark" in view.help_text()
    assert "x export marked (or focused)" in view.help_text()

    # The refreshed scope/list is authoritative for marks as well as focus.
    view.snapshot({"flows": [flow("two", agent="bob")], "scope": {"agent": "bob"}})
    assert view.selected == "two"
    assert view.marked == {"two"}
    assert view.export_flow_ids() == ("two",)


def test_bulk_export_filename_is_stable_safe_and_distinguishes_normalized_ids():
    first = bulk_export_filename("flow/one?", "raw_request")
    second = bulk_export_filename("flow:one?", "raw_request")

    assert first == bulk_export_filename("flow/one?", "raw_request")
    assert first != second
    assert "/" not in first and "?" not in first
    assert first.endswith(".raw_request")


def test_detail_retains_duplicate_headers_metadata_and_body_facts():
    view = TrafficInspector(client())
    view.detail = flow(url="http://owned.invalid/\x1b[2J")
    view.body_values["request"] = preview(b"")
    view.body_values["response"] = {"available": False, "reason": "streamed_or_unavailable"}
    text = view.detail_text()
    assert "X-Same: first\nX-Same: second" in text
    assert "HTTP request" in text and "HTTP response" in text
    assert "Body: (present, empty body)" in text
    assert "Body: absent: streamed_or_unavailable" in text
    assert "SafeYolo metadata" in text
    assert '"test_agent": "declared"' in text
    assert r"\x1b[2J" in text and "\x1b" not in text


def test_selected_compressed_responses_keep_source_mode_across_flows():
    compact = b'{"flow":1}'
    indented = b'{\n    "flow": 2\n}'
    encoded = {"one": brotlicffi.compress(compact), "two": gzip.compress(indented)}
    rows = {
        name: flow(name, response_headers=[["Content-Type", "application/json"],
                                           ["Content-Encoding", coding]],
                   response_body={"available": True, "size": len(encoded[name]), "reason": None})
        for name, coding in (("one", "br"), ("two", "gzip"))
    }
    api = client()
    api.traffic_flows.return_value = {"flows": list(rows.values()), "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: (
        preview(encoded[flow_id]) if side == "response" else preview(b"")
    )
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        assert '"flow": 1' in view.detail_text()
        assert "p body formatted" in view.help_text()
        view.toggle_pretty()
        assert "Body: " + compact.decode() in view.detail_text()
        assert "p body source" in view.help_text()
        view.select(1)
        await view.refresh()
        assert "Body: " + indented.decode() in view.detail_text()
        view.toggle_pretty()
        assert '\n  "flow": 2\n' in view.detail_text()
        view.select(-1)
        await view.refresh()
        assert '"flow": 1' in view.detail_text()

    asyncio.run(run())
    assert api.traffic_body.call_count == 6
    assert all(call.kwargs == {"preview_bytes": BODY_PREVIEW_BYTES} for call in api.traffic_body.call_args_list)


def test_selected_body_colours_preserve_text_and_leave_other_sections_plain():
    request = b'<section role="banner">Hello</section>'
    response = b'{"count":2,"active":true,"message":"ok"}'
    row = flow(request_headers=[["Content-Type", "text/html"]],
               response_headers=[["Content-Type", "application/json"], ["Content-Encoding", "br"]])
    view = TrafficInspector(client())
    view.flows, view.selected, view.detail = [row], row["id"], row
    view.body_values = {"request": preview(request), "response": preview(brotlicffi.compress(response))}
    rows, detail = TextArea(), TextArea(lexer=view.detail_syntax)

    def styled_characters():
        view._show(rows, detail)
        document = Document(detail.text)
        lex_line = view.detail_syntax.lex_document(document)
        styles = []
        for line_number, line in enumerate(document.lines):
            fragments = lex_line(line_number)
            assert "".join(part for _, part in fragments) == line
            styles.extend(style for style, part in fragments for _ in part)
            if line_number < len(document.lines) - 1:
                styles.append("")
        assert len(styles) == len(detail.text)
        assert "\x1b" not in detail.text
        return styles

    def style_of(styles, value):
        return styles[detail.text.index(value)]

    styles = styled_characters()
    assert style_of(styles, "<section") == "ansicyan"
    assert style_of(styles, "section") == "ansiblue bold"
    assert style_of(styles, "role") == "ansicyan"
    assert style_of(styles, '"banner"') == "ansigreen"
    assert style_of(styles, '"count"') == "ansiblue bold"
    assert style_of(styles, "2,") == "ansiyellow"
    assert style_of(styles, "true") == "ansimagenta"
    assert style_of(styles, '"ok"') == "ansigreen"
    assert style_of(styles, "Content-Type:") == ""
    assert style_of(styles, "SafeYolo metadata") == ""
    assert DummyStyle().get_attrs_for_style_str("ansiblue bold").color == ""
    assert not DummyStyle().get_attrs_for_style_str("ansiblue bold").bold

    view.toggle_pretty()
    styles = styled_characters()
    assert response.decode() in detail.text
    assert style_of(styles, '"count"') == "ansiblue bold"

    row["response_headers"] = [["Content-Type", "application/octet-stream"]]
    view.body_values["response"] = preview(b"\x00\xff")
    styles = styled_characters()
    binary = detail.text.index("application/octet-stream · binary or unknown body")
    assert all(style == "" for style in styles[binary:binary + len("application/octet-stream")])
    assert "x export raw_response" in detail.text


@pytest.mark.parametrize(("media_type", "payload", "token", "style"), [
    ("application/problem+json", b'{"message":"ok"}', '"message"', "ansiblue bold"),
    ("application/x-ndjson", b'{"one":1}\n{"two":2}', '"two"', "ansiblue bold"),
    ("application/xml", b'<node id="1">text</node>', "node", "ansiblue bold"),
    ("text/javascript", b'const value = "hello";', "const", "ansimagenta"),
    ("text/css", b'.card { color: red; }', "card", "ansiblue bold"),
    ("application/x-www-form-urlencoded", b'name=one&flag=true', "name", "ansiblue bold"),
    ("text/event-stream", b'event: ping\ndata: hello\n\n', "event", "ansiblue bold"),
    ("text/plain", b'plain \x1b[2J text', r"\x1b", ""),
])
def test_selected_media_colours_keep_plain_text_fallback(media_type, payload, token, style):
    row = flow(response_headers=[["Content-Type", media_type]])
    view = TrafficInspector(client())
    view.detail = row
    view.body_values["response"] = preview(payload)
    text, spans = view._detail_render()
    view.detail_syntax.update(text, spans)
    document = Document(text)
    lex_line = view.detail_syntax.lex_document(document)
    styles = []
    for line_number, line in enumerate(document.lines):
        fragments = lex_line(line_number)
        assert "".join(part for _, part in fragments) == line
        styles.extend(fragment_style for fragment_style, part in fragments for _ in part)
        if line_number < len(document.lines) - 1:
            styles.append("")
    assert len(styles) == len(text)
    assert styles[text.index(token, text.index("Body: ", text.index("HTTP response")))] == style
    assert "\x1b" not in text
    assert DummyStyle().get_attrs_for_style_str(style).color == ""


def test_body_colours_leave_incomplete_stream_note_plain():
    row = flow(response_headers=[["Content-Type", "application/json"], ["Content-Encoding", "gzip"]])
    view = TrafficInspector(client())
    view.detail = row
    view.body_values["response"] = preview(gzip.compress(b'{"partial":1}')[:-4])
    text, spans = view._detail_render()
    view.detail_syntax.update(text, spans)
    document = Document(text)
    lex_line = view.detail_syntax.lex_document(document)
    styles = []
    for line_number, line in enumerate(document.lines):
        styles.extend(style for style, part in lex_line(line_number) for _ in part)
        if line_number < len(document.lines) - 1:
            styles.append("")
    assert styles[text.index('"partial"')] == "ansiblue bold"
    note = text.index("[encoded stream incomplete (gzip)]")
    assert all(style == "" for style in styles[note:note + len("[encoded stream incomplete (gzip)]")])


def test_detail_lexer_renders_colour_and_monochrome_terminal_text():
    payload = '{"count":2}'
    lexer = DetailSyntaxLexer()
    lexer.update(payload, [(0, len(payload), "application/json")])

    async def render(depth):
        stream = io.StringIO()
        output = Vt100_Output(stream, get_size=lambda: Size(rows=8, columns=80),
                              default_color_depth=depth, enable_cpr=False)
        area = TextArea(text=payload, lexer=lexer, read_only=True)
        with create_pipe_input() as keyboard:
            app = Application(layout=Layout(area), input=keyboard, output=output, full_screen=True)

            async def finish():
                await asyncio.sleep(0.05)
                app.exit()

            app.pre_run_callables.append(lambda: app.create_background_task(finish()))
            await asyncio.wait_for(app.run_async(), timeout=2)
        return stream.getvalue()

    colour = asyncio.run(render(ColorDepth.DEPTH_8_BIT))
    monochrome = asyncio.run(render(ColorDepth.DEPTH_1_BIT))
    for output in (colour, monochrome):
        assert 'count' in output and '2' in output
    colour_codes = re.findall(r"\x1b\[([\d;]*)m", colour)
    monochrome_codes = re.findall(r"\x1b\[([\d;]*)m", monochrome)
    assert any("34" in code.split(";") for code in colour_codes)
    assert all(not any(str(value) in code.split(";") for value in range(30, 38))
               for code in monochrome_codes)


def test_refresh_fetches_both_previews_once_and_updates_shared_scope():
    api = client()
    api.traffic_flow.return_value["response_headers"] = [["Content-Type", "text/plain"]]
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        assert [call.args for call in api.traffic_body.call_args_list] == [
            ("one", "request"), ("one", "response")]
        await view.refresh()
        assert api.traffic_body.call_count == 2
        view.request_body("response")
        api.traffic_body.side_effect = None
        api.traffic_body.return_value = preview(b"hello")
        await view.refresh()
        assert "Body: hello" in view.detail_text()
        view.set_scope("test_id", "new-case")
        await view.refresh()
        api.set_traffic_scope.assert_called_once_with(agent="alice", unattributed=False, test_id="new-case")
        view.pending_scope = {}
        await view.refresh()
        assert api.set_traffic_scope.call_args.kwargs == {}

    asyncio.run(run())
    api.traffic_body.assert_any_call("one", "response", preview_bytes=BODY_PREVIEW_BYTES)


def test_error_notice_omits_response_content_and_next_refresh_recovers():
    api = client()
    view = TrafficInspector(api)
    api.traffic_flows.side_effect = APIError("private traffic payload\x1b[2J", 503)
    asyncio.run(view.refresh())
    assert view.notice == "View unavailable (APIError 503); retrying"
    api.traffic_flows.side_effect = None
    asyncio.run(view.refresh())
    assert view.selected == "one" and "1 visible" in view.notice


def test_changed_body_facts_clear_fetched_snapshot():
    api = client()
    view = TrafficInspector(api)
    asyncio.run(view.refresh())
    assert "request" in view.body_values
    api.traffic_flow.return_value = flow(response_body={"available": True, "size": 4})
    api.traffic_body.side_effect = None
    api.traffic_body.return_value = preview(b"done")
    asyncio.run(view.refresh())
    assert view.body_values["response"] == preview(b"done")
    assert api.traffic_body.call_count == 3


def test_pending_body_refetches_only_when_facts_change_and_failure_retries_on_key():
    api = client()
    row = flow(response_body={"available": False, "size": 0, "reason": "pending"},
               response_headers=[["Content-Type", "text/plain"]])
    api.traffic_flow.return_value = row
    body_values = {"request": preview(b""), "response": {"available": False, "reason": "pending"}}

    def read(flow_id, side, *, preview_bytes):
        value = body_values[side]
        if isinstance(value, Exception):
            raise value
        return value

    api.traffic_body.side_effect = read
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        assert "pending: body capture" in view.detail_text()
        await view.refresh()
        assert api.traffic_body.call_count == 2
        row["response_body"] = {"available": True, "size": 4, "reason": None}
        body_values["response"] = APIError("private body", 503)
        await view.refresh()
        assert api.traffic_body.call_count == 3
        assert "retrieval failed (APIError 503)" in view.detail_text()
        assert "private body" not in view.detail_text()
        await view.refresh()
        assert api.traffic_body.call_count == 3
        body_values["response"] = preview(b"done")
        view.request_body("response")
        await view.refresh()
        assert "Body: done" in view.detail_text()
        assert api.traffic_body.call_count == 4

    asyncio.run(run())


@pytest.mark.parametrize("change", ["selection", "scope", "rejected_filter"])
def test_in_flight_body_preview_is_discarded_after_selection_or_scope_change(change):
    api = client()
    rows = {name: flow(name, request_headers=[["Content-Type", "text/plain"]]) for name in ("one", "two")}
    api.traffic_flows.return_value = {"flows": list(rows.values()), "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    started, release = threading.Event(), threading.Event()

    def read(flow_id, side, *, preview_bytes):
        if flow_id == "one" and side == "request" and not release.is_set():
            started.set()
            assert release.wait(2)
        return preview(flow_id.encode()) if side == "request" else {"available": False, "reason": "pending"}

    api.traffic_body.side_effect = read
    view = TrafficInspector(api)

    async def run():
        first = asyncio.create_task(view.refresh())
        assert await asyncio.to_thread(started.wait, 2)
        if change == "selection":
            view.select(1)
        elif change == "scope":
            scope = {"agent": "bob"}
            view.snapshot({"flows": [rows["one"]], "scope": scope})
            api.traffic_flows.return_value = {"flows": [rows["one"]], "scope": scope}
        else:
            view.set_filter("invalid")
            api.set_traffic_filter.side_effect = APIError("private filter", 400)
        release.set()
        await first
        assert not view.body_values
        assert [call.args for call in api.traffic_body.call_args_list] == [("one", "request")]
        if change == "rejected_filter":
            await view.refresh()
            assert view.notice == "View unavailable (APIError 400); retrying"
        await view.refresh()
        expected = "two" if change == "selection" else "one"
        assert view.body_values["request"] == preview(expected.encode())
        assert view.selected == expected

    asyncio.run(run())


def test_headless_real_application_polls_cancels_prompt_and_detaches():
    api = client()
    view = TrafficInspector(api)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                while view.detail is None:
                    await asyncio.sleep(0.01)
                keyboard.send_text("a")
                await asyncio.sleep(0.03)
                keyboard.send_text("discarded\x1b")
                await asyncio.sleep(0.04)
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    api.traffic_flows.assert_called()
    api.traffic_flow.assert_called_with("one")
    api.set_traffic_scope.assert_not_called()


def test_headless_pretty_and_header_keys_stay_selected_across_flows():
    api = client()
    rows = {
        "one": flow("one", request_headers=[["Accept", "first-secret"], ["ACCEPT", "second-secret"],
                                             ["Authorization", "Bearer visible"], ["Content-Type", "application/json"]],
                    response_headers=[["User-Agent", "routine-value"], ["Content-Type", "text/plain"]],
                    request_body={"available": True, "size": 7}, response_body={"available": True, "size": 4}),
        "two": flow("two", request_headers=[["Content-Type", "application/octet-stream"]],
                    response_headers=[["Content-Type", "text/plain; charset=iso-8859-1"]],
                    request_body={"available": True, "size": 2}, response_body={"available": True, "size": 4}),
    }
    bodies = {("one", "request"): b'{"x":1}', ("one", "response"): b"done",
              ("two", "request"): b"\x00\xff", ("two", "response"): "café".encode("latin-1")}
    api.traffic_flows.return_value = {"flows": list(rows.values()), "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: preview(bodies[flow_id, side])
    view = TrafficInspector(api)

    async def until(predicate):
        for _ in range(200):
            if predicate():
                return
            await asyncio.sleep(0.01)
        pytest.fail("TUI did not reach the expected state")

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await until(lambda: len(view.body_values) == 2)
                assert '\n  "x": 1\n' in view.detail_text()
                keyboard.send_text("h")
                await until(lambda: view.hide_routine_headers)
                hidden = view.detail_text()
                assert "Hidden routine headers (2): Accept ×2" in hidden
                assert "Hidden routine headers (1): User-Agent ×1" in hidden
                assert "first-secret" not in hidden and "second-secret" not in hidden
                assert "routine-value" not in hidden and "Authorization: Bearer visible" in hidden
                keyboard.send_text("p")
                await until(lambda: not view.pretty)
                assert '{"x":1}' in view.detail_text()
                keyboard.send_text("\x1b[B")
                await until(lambda: view.selected == "two" and len(view.body_values) == 2)
                assert "binary" in view.detail_text() and "café" in view.detail_text()
                assert "p body source" in view.help_text() and "h routine headers hidden" in view.help_text()
                keyboard.send_text("h")
                await until(lambda: not view.hide_routine_headers)
                keyboard.send_text("\x1b[A")
                await until(lambda: view.selected == "one" and len(view.body_values) == 2)
                shown = view.detail_text()
                assert "Accept: first-secret\nACCEPT: second-secret" in shown
                assert "User-Agent: routine-value" in shown
                assert "p body source" in view.help_text() and "h routine headers shown" in view.help_text()
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=5)

    asyncio.run(run())
    assert [call.args for call in api.traffic_body.call_args_list] == [
        ("one", "request"), ("one", "response"), ("two", "request"),
        ("two", "response"), ("one", "request"), ("one", "response"),
    ]
    assert all(call.kwargs == {"preview_bytes": BODY_PREVIEW_BYTES} for call in api.traffic_body.call_args_list)


def test_real_application_quit_binding_only_exits_ui():
    view = TrafficInspector(client())
    with create_app_session(input=DummyInput(), output=DummyOutput()):
        app = view.application()
    event = create_autospec(KeyPressEvent, instance=True, spec_set=True)
    event.app = create_autospec(Application, instance=True, spec_set=True)
    app.key_bindings.get_bindings_for_keys((Keys.ControlC,))[0].handler(event)
    event.app.exit.assert_called_once_with()
    view.api.traffic_flows.assert_not_called()


def test_api_helpers_keep_ids_within_the_route_and_validate_body_side():
    # Explicit URL and token avoid any receipt/default-file lookup.
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    assert not api.is_native
    with patch.object(AdminAPI, "_request", autospec=True) as request:
        api.traffic_flows()
        request.assert_called_with(api, "GET", "/admin/traffic/flows")
        api.traffic_flow("one/two?#")
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo%3F%23")
        api.traffic_body("one/two", "response")
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo/body?side=response")
        api.traffic_body("one/two", "request", preview_bytes=BODY_PREVIEW_BYTES)
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo/body?side=request&preview_bytes=65536")
        api.traffic_facets()
        request.assert_called_with(api, "GET", "/admin/traffic/facets")
        request.reset_mock()
        with pytest.raises(ValueError, match="body side"):
            api.traffic_body("one", "wrong")
        for limit in (-1, True, BODY_PREVIEW_BYTES + 1):
            with pytest.raises(ValueError, match="preview_bytes"):
                api.traffic_body("one", "request", preview_bytes=limit)
        request.assert_not_called()


def test_filter_api_preserves_expression_and_returns_accepted_scope():
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    accepted = {"status": "updated", "agent": "alice", "user_filter": "  ~m GET  ",
                "effective_filter": '~meta "^agent: alice$" & (~m GET)'}
    with patch.object(AdminAPI, "_request", autospec=True, spec_set=True) as request:
        request.return_value = accepted
        assert api.set_traffic_filter("  ~m GET  ") is accepted
        request.assert_called_once_with(api, "PUT", "/admin/traffic/filter", json={"user_filter": "  ~m GET  "})
        api.set_traffic_filter("")
        request.assert_called_with(api, "PUT", "/admin/traffic/filter", json={"user_filter": ""})


def test_invalid_filter_retains_view_and_scope_clear_keeps_authoritative_filter():
    api = client()
    accepted = {"agent": "alice", "user_filter": "~m GET", "effective_filter": 'agent alice & (~m GET)'}
    api.traffic_flows.return_value["scope"] = accepted
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        previous = view.flows, view.detail, view.scope, view.selected
        api.reset_mock()
        api.set_traffic_filter.side_effect = APIError("private search\x1b]52;value", 400)
        view.set_filter("~b private search\x1b]52;value")
        assert view.scope == accepted
        api.set_traffic_filter.assert_not_called()  # queued for the existing worker
        await view.refresh()
        assert (view.flows, view.detail, view.scope, view.selected) == previous
        assert view.notice == "View unavailable (APIError 400); retrying"
        assert view.pending_filter is None
        api.traffic_flows.assert_not_called()
        api.get_traffic_scope.assert_not_called()
        api.set_traffic_scope.assert_not_called()
        view.pending_scope = {}
        # A later accepted list is authoritative, including changes by another operator.
        api.traffic_flows.return_value = {"flows": [flow()], "scope": {
            "agent": None, "user_filter": "~m GET", "effective_filter": "(~m GET)",
        }}
        await view.refresh()
        api.set_traffic_scope.assert_called_once_with()
        assert api.set_traffic_filter.call_count == 1  # no automatic rejected-edit retry
        assert view.scope["user_filter"] == "~m GET" and view.scope["agent"] is None
        assert view.scope["effective_filter"] == "(~m GET)"
        assert "1 visible" in view.notice

    asyncio.run(run())


def test_headless_filter_editor_prefills_cancels_clears_and_preserves_whitespace():
    api = client()
    original = "  ~m GET  "
    api.traffic_flows.return_value["scope"] = {
        "agent": "alice", "user_filter": original, "effective_filter": "agent alice & (~m GET)",
    }

    def accepted(expression):
        scope = {"agent": "alice", "user_filter": expression,
                 "effective_filter": "agent alice" + (f" & ({expression.strip()})" if expression else "")}
        api.traffic_flows.return_value["scope"] = scope
        return {"status": "updated", **scope}

    api.set_traffic_filter.side_effect = accepted
    view = TrafficInspector(api)

    async def until(predicate):
        while not predicate():
            await asyncio.sleep(0.01)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await until(lambda: view.detail is not None)
                rows = app.layout.current_buffer
                keyboard.send_text("f")
                await until(lambda: app.layout.current_buffer is not rows)
                assert app.layout.current_buffer.text == original
                assert app.layout.current_buffer.cursor_position == len(original)
                keyboard.send_text("discarded\x1b")
                await until(lambda: app.layout.current_buffer is rows)
                api.set_traffic_filter.assert_not_called()
                keyboard.send_text("f")
                await until(lambda: app.layout.current_buffer is not rows)
                assert app.layout.current_buffer.text == original
                keyboard.send_text("\x01\x0b\r")  # Ctrl-A, Ctrl-K, Enter: clear only the filter
                await until(lambda: view.scope.get("user_filter") == "")
                api.set_traffic_filter.assert_called_once_with("")
                assert view.scope["agent"] == "alice" and view.selected == "one"
                keyboard.send_text("f")
                await until(lambda: app.layout.current_buffer is not rows)
                keyboard.send_text("  ~b marker  \r")
                await until(lambda: view.scope.get("user_filter") == "  ~b marker  ")
                assert view.scope["effective_filter"] == "agent alice & (~b marker)"
                assert view.selected == "one" and "f filter" in view.help_text()
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    assert [call.args for call in api.set_traffic_filter.call_args_list] == [("",), ("  ~b marker  ",)]
    api.set_traffic_scope.assert_not_called()


def test_accepted_filter_and_scope_remain_editable_when_flow_matching_fails():
    api = client()
    api.traffic_flows.return_value["scope"] = {
        "agent": "alice", "user_filter": "~m GET", "effective_filter": "agent alice & (~m GET)",
    }
    view = TrafficInspector(api)
    expression = "  ~b retained  "

    async def run():
        await view.refresh()
        previous_rows, previous_detail = view.flows, view.detail
        accepted = {"status": "updated", "agent": "alice", "user_filter": expression,
                    "effective_filter": "agent alice & (~b retained)"}
        api.set_traffic_filter.return_value = accepted
        api.traffic_flows.side_effect = APIError("private retained content", 500)
        view.set_filter(expression)
        await view.refresh()
        assert view.scope is accepted and view.scope["user_filter"] == expression
        assert view.flows == previous_rows and view.detail is None
        assert previous_detail is not None and not view.body_values
        assert view.notice == "View unavailable (APIError 500); retrying"
        view.pending_scope = {}
        accepted_unpinned = {**accepted, "agent": None, "effective_filter": "(~b retained)"}
        api.set_traffic_scope.return_value = accepted_unpinned
        await view.refresh()
        assert view.scope is accepted_unpinned
        assert view.scope["user_filter"] == expression
        assert view.flows == previous_rows and "APIError 500" in view.notice
        # Clearing still targets the actual active expression after a failed list read.
        cleared = {"status": "updated", "agent": None, "user_filter": "", "effective_filter": ""}
        api.set_traffic_filter.return_value = cleared
        api.traffic_flows.side_effect = None
        api.traffic_flows.return_value = {"flows": [flow()], "scope": cleared}
        view.set_filter("")
        await view.refresh()
        assert view.scope is cleared and "1 visible" in view.notice

    asyncio.run(run())
    assert [call.args for call in api.set_traffic_filter.call_args_list] == [(expression,), ("",)]
    api.set_traffic_scope.assert_called_once_with()


@pytest.mark.parametrize("already_attached", [False, True])
def test_list_failure_fetches_other_operators_filter_without_replacing_rows(already_attached):
    api = client()
    view = TrafficInspector(api)
    actual = {"agent": "bob", "user_filter": "  ~b changed  ", "effective_filter": "agent bob & (~b changed)"}

    async def run():
        if already_attached:
            await view.refresh()
        previous_rows, previous_detail, previous_selected = view.flows, view.detail, view.selected
        api.reset_mock()
        api.traffic_flows.side_effect = APIError("sensitive match failure", 500)
        api.get_traffic_scope.return_value = actual
        await view.refresh()
        assert view.scope is actual and view.scope["user_filter"] == "  ~b changed  "
        assert (view.flows, view.detail, view.selected) == (previous_rows, previous_detail, previous_selected)
        assert view.notice == "View unavailable (APIError 500); retrying"
        assert [call[0] for call in api.method_calls] == ["traffic_flows", "get_traffic_scope"]
        api.set_traffic_filter.assert_not_called()
        api.set_traffic_scope.assert_not_called()

    asyncio.run(run())


def test_failed_scope_recovery_keeps_previous_projection_and_original_list_error():
    api = client()
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        previous = view.flows, view.detail, view.scope, view.selected
        api.reset_mock()
        api.traffic_flows.side_effect = APIError("original private match error", 500)
        api.get_traffic_scope.side_effect = APIError("later private scope error", 503)
        await view.refresh()
        assert (view.flows, view.detail, view.scope, view.selected) == previous
        assert view.notice == "View unavailable (APIError 500); retrying"
        assert [call[0] for call in api.method_calls] == ["traffic_flows", "get_traffic_scope"]
        api.traffic_flow.assert_not_called()
        api.set_traffic_filter.assert_not_called()

    asyncio.run(run())


def websocket_session(**changes):
    return {"state": "open", "started": 1.25, "timestamp_end": None, "closed_by_client": None,
            "close_code": None, "close_reason": None,
            "messages_meta": {"count": 0, "contentLength": 0, "timestamp_last": None},
            "trimmed_messages": 0, **changes}


def message(message_id, size=1, **changes):
    return {"id": message_id, "type": "text", "from_client": True, "timestamp": 2.0,
            "dropped": False, "injected": False,
            "body": {"available": True, "size": size, "reason": None}, **changes}


def message_page(data=b"x", *, offset=0, total=None):
    total = len(data) if total is None else total
    return {"available": True, "offset": offset, "total_size": total, "size": len(data),
            "data_base64": base64.b64encode(data).decode(), "end": offset + len(data) == total, "reason": None}


def websocket_client(messages=None):
    api = client()
    session = websocket_session()
    row = flow(state="websocket_open", status=101, websocket=session)
    api.traffic_flows.return_value = {"flows": [row], "scope": {}}
    api.traffic_flow.return_value = row
    api.traffic_websocket_messages.return_value = {"websocket": session, "messages": messages or []}
    api.traffic_websocket_message_body.return_value = message_page()
    return api


def test_websocket_rendering_preserves_disposition_close_and_trimmed_history():
    api = websocket_client([message(7, 4, type="binary", from_client=False, dropped=True)])
    api.traffic_flow.return_value["error"] = "inspection_error"
    session = api.traffic_websocket_messages.return_value["websocket"]
    session.update(state="error", timestamp_end=5.0, close_code=1006,
                   close_reason="\x1b]52;c;secret\x07\n[bold]", trimmed_messages=3,
                   messages_meta={"count": 1, "contentLength": 4, "timestamp_last": 2.0})
    api.traffic_websocket_message_body.return_value = message_page(b"\xff\x1b\r\n")
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        assert "w opens transcript" in view.detail_text()
        view.toggle_websocket()
        await view.refresh()

    asyncio.run(run())
    assert "> 7 server→client binary 4 bytes @2.0 dropped" in view.rows_text()
    text = view.detail_text()
    assert "error: inspection_error" in text
    assert "state: error" in text and "timestamp_end: 5.0" in text
    assert "closed_by_client: None" in text and "close_code: 1006" in text
    assert "Retained: 1 messages / 4 bytes; trimmed from history: 3" in text
    assert "dropped: True" in text and "injected: False" in text
    assert "not a delivery receipt" in text
    assert "Message bytes [0:4) of 4 (decompressed/unmasked bytes" in text
    assert r"\xff\x1b\x0d" in text and "\x1b" not in text and "\r" not in text
    assert r"close_reason: \x1b]52;c;secret\x07\x0a[bold]" in text


def test_websocket_pages_are_fetched_once_and_keep_selection_when_messages_arrive():
    size = BODY_PREVIEW_BYTES * 2 + 3
    api = websocket_client([message(7, size)])
    payload = b"a" * BODY_PREVIEW_BYTES + b"b" * BODY_PREVIEW_BYTES + b"end"
    api.traffic_websocket_message_body.side_effect = lambda flow_id, message_id, offset: message_page(
        payload[offset:offset + BODY_PREVIEW_BYTES], offset=offset, total=size,
    )
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        await view.refresh()
        assert f"[0:{BODY_PREVIEW_BYTES}) of {size}" in view.detail_text()
        await view.refresh()
        assert api.traffic_websocket_message_body.call_count == 1
        api.traffic_websocket_messages.return_value["messages"].append(message(9))
        await view.refresh()
        assert view.transcript.selected == 7
        assert api.traffic_websocket_message_body.call_count == 1
        view.transcript.page(1)
        assert view.transcript.body == ""
        await view.refresh()
        assert f"[{BODY_PREVIEW_BYTES}:{BODY_PREVIEW_BYTES * 2}) of {size}" in view.detail_text()
        view.transcript.page(1)
        await view.refresh()
        assert view.transcript.body.endswith("end")
        assert f"[{BODY_PREVIEW_BYTES * 2}:{size})" in view.detail_text()
        view.transcript.page(-1)
        await view.refresh()
        assert view.transcript.body.endswith("b" * BODY_PREVIEW_BYTES)

    asyncio.run(run())
    assert [call.args for call in api.traffic_websocket_message_body.call_args_list] == [
        ("one", 7, 0), ("one", 7, BODY_PREVIEW_BYTES), ("one", 7, BODY_PREVIEW_BYTES * 2),
        ("one", 7, BODY_PREVIEW_BYTES),
    ]


def test_filter_refresh_preserves_visible_websocket_selection_and_cached_page():
    api = websocket_client([message(7)])
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        await view.refresh()
        previous_page = view.transcript.body
        api.reset_mock()
        view.set_filter("  ~b x  ")
        api.traffic_flows.return_value["scope"] = {"user_filter": "  ~b x  ", "effective_filter": "(~b x)"}
        await view.refresh()
        assert [call[0] for call in api.method_calls] == [
            "set_traffic_filter", "traffic_flows", "traffic_flow", "traffic_body",
            "traffic_body", "traffic_websocket_messages",
        ]
        assert view.websocket_mode and view.selected == "one" and view.transcript.selected == 7
        assert view.transcript.body == previous_page
        api.traffic_websocket_message_body.assert_not_called()
        api.set_traffic_scope.assert_not_called()
        # An accepted expression hiding the current row releases its client projection.
        api.traffic_flows.return_value = {"flows": [], "scope": {"user_filter": "~b missing", "effective_filter": "(~b missing)"}}
        view.set_filter("~b missing")
        await view.refresh()
        assert view.selected is None and not view.websocket_mode
        assert not view.transcript.messages and not view.transcript.body

    asyncio.run(run())


def test_trimmed_selection_and_changed_flow_clear_old_pages_and_http_controls_work():
    api = websocket_client([message(1), message(2)])
    api.traffic_websocket_message_body.side_effect = lambda flow_id, message_id, offset: message_page(str(message_id).encode())
    api.traffic_flow.return_value["request_headers"].append(["Content-Type", "text/plain"])
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: (
        preview(b"http") if side == "request" else
        {"available": False, "reason": "streamed_or_unavailable"}
    )
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        await view.refresh()
        view.select(1)
        assert view.transcript.selected == 2 and view.transcript.body == ""
        await view.refresh()
        assert view.transcript.body.endswith("2")
        api.traffic_websocket_messages.return_value["messages"] = [message(3)]
        api.traffic_websocket_messages.return_value["websocket"]["trimmed_messages"] = 2
        await view.refresh()
        assert view.transcript.selected == 3 and view.transcript.body.endswith("3")
        view.request_body("request")
        assert not view.websocket_mode
        await view.refresh()
        assert view.body_values["request"] == preview(b"http")
        assert "Body: http" in view.detail_text()
        assert view.selected == "one"
        view.toggle_websocket()
        await view.refresh()
        assert view.transcript.selected == 3
        view.snapshot({"flows": [flow("other")], "scope": {}})
        assert not view.websocket_mode and view.selected == "other"
        assert view.transcript.messages == [] and view.transcript.body == ""

    asyncio.run(run())
    assert api.traffic_body.call_count == 3
    api.traffic_body.assert_any_call("one", "request", preview_bytes=BODY_PREVIEW_BYTES)
    assert api.traffic_websocket_message_body.call_count == 3


def test_missing_page_and_storage_error_remain_explicit_and_recover_on_request():
    api = websocket_client([message(5)])
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        api.traffic_websocket_message_body.side_effect = APIError("sensitive payload\x1b", 404)
        await view.refresh()
        assert "APIError 404" in view.notice and "sensitive" not in view.notice
        assert view.transcript.body == ""
        await view.refresh()
        assert api.traffic_websocket_message_body.call_count == 1
        api.traffic_websocket_message_body.side_effect = None
        api.traffic_websocket_message_body.return_value = {
            "available": False, "offset": 0, "total_size": 1, "size": 0,
            "data_base64": None, "end": False, "reason": "storage_error",
        }
        view.transcript.page(-1)
        await view.refresh()
        assert "absent: storage_error" in view.detail_text()
        api.traffic_websocket_message_body.return_value = message_page()
        view.transcript.page(-1)
        await view.refresh()
        assert view.transcript.body.endswith("x")
        api.traffic_websocket_messages.return_value["messages"] = []
        await view.refresh()
        assert view.transcript.selected is None and view.transcript.body == ""
        assert "No retained WebSocket messages" in view.rows_text()

    asyncio.run(run())


def test_websocket_empty_bytes_and_invalid_page_contract():
    from safeyolo.traffic_inspector import websocket_page

    text = websocket_page(message_page(b""), 0)
    assert "bytes [0:0) of 0" in text and "present, empty body" in text
    for changes in ({"offset": 1}, {"size": 2}, {"end": False}, {"data_base64": "!"}):
        value = {**message_page(), **changes}
        with pytest.raises(ValueError):
            websocket_page(value, 0)
    with pytest.raises(ValueError, match="bounds"):
        websocket_page(message_page(b"x" * (BODY_PREVIEW_BYTES + 1)), 0)


def test_headless_application_navigates_websocket_pages_and_returns_to_http():
    api = websocket_client([message(1), message(2, BODY_PREVIEW_BYTES + 1)])
    api.traffic_websocket_message_body.side_effect = lambda flow_id, message_id, offset: message_page(
        b"x" if message_id == 1 or offset else b"a" * BODY_PREVIEW_BYTES,
        offset=offset, total=1 if message_id == 1 else BODY_PREVIEW_BYTES + 1,
    )
    view = TrafficInspector(api)

    async def until(predicate):
        while not predicate():
            await asyncio.sleep(0.01)

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await until(lambda: view.detail is not None)
                keyboard.send_text("w")
                await until(lambda: bool(view.transcript.body))
                keyboard.send_text("\x1b[B")
                await until(lambda: view.transcript.selected == 2 and bool(view.transcript.body))
                keyboard.send_text("]")
                await until(lambda: view.transcript.offset == BODY_PREVIEW_BYTES and bool(view.transcript.body))
                assert f"[{BODY_PREVIEW_BYTES}:{BODY_PREVIEW_BYTES + 1})" in view.detail_text()
                keyboard.send_text("\t\x1b[A")
                await asyncio.sleep(0.04)
                assert view.transcript.selected == 2  # detail scrolling does not select another message
                keyboard.send_text("[w")
                await until(lambda: not view.websocket_mode)
                assert view.selected == "one" and "HTTP" not in view.help_text()
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=3)

    asyncio.run(run())
    assert api.traffic_websocket_message_body.call_args_list[0].args == ("one", 1, 0)
    assert ("one", 2, BODY_PREVIEW_BYTES) in [call.args for call in api.traffic_websocket_message_body.call_args_list]
    assert api.traffic_body.call_count == 2
    api.set_traffic_scope.assert_not_called()


def test_websocket_api_helpers_quote_identifiers_and_validate_offsets():
    api = AdminAPI(base_url="http://owned.invalid", token="synthetic")
    with patch.object(AdminAPI, "_request", autospec=True, spec_set=True) as request:
        api.traffic_websocket_messages("one/two?#")
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo%3F%23/websocket/messages")
        api.traffic_websocket_message_body("one/two", 7)
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one%2Ftwo/websocket/messages/7/body?offset=0")
        api.traffic_websocket_message_body("one", "7/evil?", BODY_PREVIEW_BYTES)
        request.assert_called_with(api, "GET", "/admin/traffic/flows/one/websocket/messages/7%2Fevil%3F/body?offset=65536")
        request.reset_mock()
        for offset in (-1, 1.5, True, "0"):
            with pytest.raises(ValueError, match="offset"):
                api.traffic_websocket_message_body("one", 7, offset)
        request.assert_not_called()


def test_inflight_page_cannot_replace_new_message_selection():
    import threading

    api = websocket_client([message(1), message(2)])
    entered, release = threading.Event(), threading.Event()

    def read_page(flow_id, message_id, offset):
        if message_id == 1:
            entered.set()
            assert release.wait(timeout=2)
        return message_page(str(message_id).encode())

    api.traffic_websocket_message_body.side_effect = read_page
    view = TrafficInspector(api)

    async def run():
        await view.refresh()
        view.toggle_websocket()
        refresh = asyncio.create_task(view.refresh())
        try:
            while not entered.is_set():
                await asyncio.sleep(0.01)
            view.select(1)
            assert view.transcript.selected == 2 and view.transcript.body == ""
        finally:
            release.set()
            await refresh
        assert view.transcript.body == ""
        await view.refresh()
        assert view.transcript.body.endswith("2")

    asyncio.run(asyncio.wait_for(run(), timeout=3))
    assert [call.args for call in api.traffic_websocket_message_body.call_args_list] == [
        ("one", 1, 0), ("one", 2, 0),
    ]


def test_live_tail_follows_chronological_cards_and_updates_pending_response_in_place():
    rows = {
        "a": flow("a", started=100.0, response_completed=100.5,
                  request_headers=[["Content-Type", "application/json"]],
                  response_headers=[["Content-Type", "application/json"]],
                  request_body={"available": True, "size": 7},
                  response_body={"available": True, "size": 11}),
        "b": flow("b", started=101.0, state="pending", status=None,
                  request_headers=[["Content-Type", "application/json"]],
                  response_headers=[["Content-Type", "application/json"]],
                  request_body={"available": True, "size": 7},
                  response_body={"available": False, "reason": "pending"}),
    }
    bodies = {("a", "request"): b'{"n":1}', ("a", "response"): b'{"ok":true}',
              ("b", "request"): b'{"n":2}', ("b", "response"): b'{"ok":false}'}
    api = client()
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: (
        preview(bodies[flow_id, side]) if rows[flow_id][f"{side}_body"].get("available")
        else {"available": False, "reason": "pending"}
    )
    api.traffic_flows.return_value = {"flows": [rows["a"]], "scope": {"agent": "alice"}}
    view = TrafficInspector(api)
    view.toggle_tail()

    async def run():
        await view.refresh()
        assert view.selected == "a" and "→ request: {\"n\":1}" in view.rows_text()
        api.traffic_flows.return_value = {"flows": [rows["b"], rows["a"]], "scope": {"agent": "alice"}}
        await view.refresh()
        text = view.rows_text()
        assert text.index("→ request: {\"n\":1}") < text.index("→ request: {\"n\":2}")
        assert view.selected == "b" and text.count("→ request: {\"n\":2}") == 1
        assert "← response: [pending]" in text
        rows["b"].update(state="complete", status=201, response_completed=102.0,
                         response_body={"available": True, "size": len(bodies["b", "response"])})
        await view.refresh()
        text = view.rows_text()
        assert text.count("→ request: {\"n\":2}") == 1
        assert "201 complete" in text and "← response: {\"ok\":false}" in text
        assert view.selected == "b"

    asyncio.run(run())
    assert all(call.kwargs == {"preview_bytes": BODY_PREVIEW_BYTES} for call in api.traffic_body.call_args_list)


def test_live_tail_pause_resume_window_and_visible_snapshot_gaps():
    rows = [flow(str(index), started=float(index), request_body={"available": False, "reason": "pending"})
            for index in range(TAIL_CARDS + 5)]
    api = client()
    api.traffic_flows.return_value = {"flows": list(reversed(rows)), "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[int(flow_id)]
    view = TrafficInspector(api)
    view.toggle_tail()

    async def run():
        await view.refresh()
        assert view.selected == str(TAIL_CARDS + 4)
        assert f"showing {TAIL_CARDS} of {TAIL_CARDS + 5}" in view.rows_text()
        view.select(-TAIL_CARDS)
        paused = view.selected
        assert not view.tail_follow and "PAUSED · End resumes newest" in view.rows_text()
        rows.append(flow("new", started=1000.0))
        api.traffic_flows.return_value = {"flows": [rows[-1], *reversed(rows[:-1])], "scope": {"agent": "alice"}}
        await view.refresh()
        assert view.selected == paused and "#new " not in view.rows_text()
        view.resume_tail()
        await view.refresh()
        assert view.selected == "new" and view.tail_follow and "FOLLOW newest" in view.rows_text()
        assert "#new " in view.rows_text()
        api.traffic_flows.side_effect = APIError("secret\x1b[2J", 503)
        await view.refresh()
        assert "secret" not in view.notice
        api.traffic_flows.side_effect = None
        api.traffic_flows.return_value = {"flows": [rows[-1]], "scope": {"agent": "alice"}}
        await view.refresh()
        text = view.rows_text()
        assert "polling gap: 1 failed snapshot" in text
        assert "snapshot gap:" in text and "retention/filter view" in text
        assert "secret" not in text and "\x1b" not in text

    asyncio.run(run())


def test_live_tail_json_picker_last_item_independent_pins_missing_and_changed_chars():
    request = [
        b'{"messages":[{"content":"blue"}]}',
        b'{"messages":[{"content":"old"},{"content":"blues"}]}',
        b'{"messages":[{"content":"other"}]}',
        b'{"different":1}',
    ]
    response = [b'{"answer":{"value":1}}', b'{"answer":{"value":2}}',
                b'{"answer":{"value":3}}', b'{"answer":null}']
    rows = {
        str(index): flow(str(index), started=float(index + 1),
                         url="http://owned.invalid/chat?turn=" + str(index) if index != 2
                         else "http://owned.invalid/other",
                         request_headers=[["Content-Type", "application/json"]],
                         response_headers=[["Content-Type", "application/json"]],
                         request_body={"available": True, "size": len(request[index])},
                         response_body={"available": True, "size": len(response[index])})
        for index in range(4)
    }
    api = client()
    api.traffic_flows.return_value = {"flows": list(reversed(list(rows.values()))), "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: preview(
        (request if side == "request" else response)[int(flow_id)]
    )
    view = TrafficInspector(api)
    view.toggle_tail()

    async def run():
        await view.refresh()
        view.select(-3)
        await view.refresh()
        view.open_pin_picker("request")
        assert view.pin_picker_side == "request"
        view.move_pin_picker(1)  # messages
        view.descend_pin_picker()
        view.move_pin_picker(1)  # [last], distinct from [0]
        view.descend_pin_picker()
        view.move_pin_picker(1)  # content
        view.pin_picker_selection()
        assert view.tail_pins["request"] == ("messages", LAST_ITEM, "content")
        view.open_pin_picker("response")
        view.move_pin_picker(1)  # answer
        view.descend_pin_picker()
        view.move_pin_picker(1)  # value
        view.pin_picker_selection()
        assert view.tail_pins["response"] == ("answer", "value")
        for _ in range(3):
            await view.refresh()
        text, _, spans = view._tail_render()
        assert 'request $["messages"][last]["content"]: "blue"' in text
        assert 'request $["messages"][last]["content"]: Δ "blues"' in text
        assert 'response $["answer"]["value"]: 2' in text
        assert 'request $["messages"][last]["content"]: "other"' in text
        assert 'request $["messages"][last]["content"]: [missing path]' in text
        assert 'response $["answer"]["value"]: [missing path]' in text
        assert text.count("Δ ") == 1  # no comparison across /other or with a missing path
        assert any(text[start:end] == "s" for start, end in spans)
        assert any(text[start:end] == "Δ" for start, end in spans)
        view.tail_syntax.update(text, spans)
        document = Document(text)
        fragments = view.tail_syntax.lex_document(document)
        assert any("ansiyellow" in style and "s" in chunk
                   for line in range(len(document.lines)) for style, chunk in fragments(line))
        view.open_pin_picker("response")
        view.clear_pin_picker()
        assert view.tail_pins["request"] is not None and view.tail_pins["response"] is None

    asyncio.run(run())


def test_live_tail_fetch_budget_truncated_json_and_terminal_controls():
    rows = [flow(str(index), started=float(index),
                 request_headers=[["Content-Type", "application/json"]],
                 response_headers=[["Content-Type", "application/json"]],
                 request_body={"available": True, "size": BODY_PREVIEW_BYTES + 1},
                 response_body={"available": True, "size": BODY_PREVIEW_BYTES + 1})
            for index in range(20)]
    api = client()
    api.traffic_flows.return_value = {"flows": list(reversed(rows)), "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[int(flow_id)]
    payload = b'{"message":"\x1b[2J\x1b]52;c;secret"}'
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: preview(
        payload, total=BODY_PREVIEW_BYTES + 1
    )
    view = TrafficInspector(api)
    view.toggle_tail()
    asyncio.run(view.refresh())
    assert api.traffic_flow.call_count + api.traffic_body.call_count <= TAIL_FETCHES_PER_POLL + 3
    assert all(call.kwargs == {"preview_bytes": BODY_PREVIEW_BYTES} for call in api.traffic_body.call_args_list)
    text = view.rows_text()
    assert "\\x1b[2J" in text and "\x1b[2J" not in text
    view.open_pin_picker("request")
    assert view.pin_picker_side is None
    assert "no complete JSON preview" in view._notice_hold


def test_headless_live_tail_keys_pause_choose_pin_resume_and_drilldown():
    rows = {
        "old": flow("old", started=1.0, request_headers=[["Content-Type", "application/json"]],
                    request_body={"available": True, "size": 7}),
        "new": flow("new", started=2.0, request_headers=[["Content-Type", "application/json"]],
                    request_body={"available": True, "size": 7}),
    }
    api = client()
    api.traffic_flows.return_value = {"flows": [rows["new"], rows["old"]], "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: (
        preview(b'{"n":1}') if side == "request" else {"available": False, "reason": "streamed_or_unavailable"}
    )
    view = TrafficInspector(api)

    async def until(predicate):
        for _ in range(200):
            if predicate():
                return
            await asyncio.sleep(0.01)
        pytest.fail("Tail key sequence did not reach the expected state")

    async def run():
        with create_pipe_input() as keyboard, create_app_session(input=keyboard, output=DummyOutput()):
            app = view.application()
            app.ttimeoutlen = 0.01

            async def operator():
                await until(lambda: view.detail is not None)
                keyboard.send_text("l")
                await until(lambda: view.tail_mode and view.selected == "new")
                keyboard.send_text("\x1b[A")
                await until(lambda: not view.tail_follow and view.selected == "old")
                keyboard.send_text("R")
                await until(lambda: view.pin_picker_side == "request")
                keyboard.send_text("\x1b[B\r")
                await until(lambda: view.tail_pins["request"] == ("n",))
                keyboard.send_text("\x1b[F")
                await until(lambda: view.tail_follow and view.selected == "new")
                keyboard.send_text("\t")
                await until(lambda: view.tail_detail_open and not view.tail_follow)
                assert "HTTP request" in view.detail_text()
                keyboard.send_text("\t")
                await until(lambda: not view.tail_detail_open)
                keyboard.send_text("q")

            app.pre_run_callables.append(lambda: app.create_background_task(operator()))
            await asyncio.wait_for(app.run_async(), timeout=4)

    asyncio.run(run())


def test_live_tail_discards_inflight_card_body_after_filter_change():
    rows = {
        "old": flow("old", started=1.0, request_headers=[["Content-Type", "application/json"]],
                    request_body={"available": True, "size": 17}),
        "new": flow("new", started=2.0, request_headers=[["Content-Type", "application/json"]],
                    request_body={"available": True, "size": 7}),
    }
    api = client()
    api.traffic_flows.return_value = {"flows": [rows["new"], rows["old"]], "scope": {"agent": "alice"}}
    api.traffic_flow.side_effect = lambda flow_id: rows[flow_id]
    entered, release = threading.Event(), threading.Event()

    def read(flow_id, side, *, preview_bytes):
        if flow_id == "old" and side == "request":
            entered.set()
            assert release.wait(2)
            return preview(b'{"private":"old"}')
        return preview(b'{"n":1}') if side == "request" else {"available": False, "reason": "pending"}

    api.traffic_body.side_effect = read
    view = TrafficInspector(api)
    view.toggle_tail()

    async def run():
        first = asyncio.create_task(view.refresh())
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            view.set_filter("~m POST")
        finally:
            release.set()
            await first
        assert "old" not in view.tail_cards or "request" not in view.tail_cards["old"].bodies
        accepted = {"agent": "alice", "user_filter": "~m POST"}
        api.set_traffic_filter.return_value = accepted
        api.traffic_flows.return_value = {"flows": [rows["new"]], "scope": accepted}
        await view.refresh()
        assert "old" not in view.tail_cards
        assert "private" not in view.rows_text()
        assert view.tail_pins == {"request": None, "response": None}

    asyncio.run(asyncio.wait_for(run(), timeout=3))


def test_live_tail_root_pin_keeps_null_array_and_object_distinct():
    payload = [b"null"]
    row = flow("shape", started=1.0, request_headers=[],
               request_body={"available": True, "size": len(payload[0])})
    api = client()
    api.traffic_flows.return_value = {"flows": [row], "scope": {"agent": "alice"}}
    api.traffic_flow.return_value = row
    api.traffic_body.side_effect = lambda flow_id, side, *, preview_bytes: (
        preview(payload[0]) if side == "request" else {"available": False, "reason": "pending"}
    )
    view = TrafficInspector(api)
    view.toggle_tail()

    async def run():
        await view.refresh()
        view.open_pin_picker("request")
        assert view.pin_picker_side == "request" and "$ = null" in view.detail_text()
        view.pin_picker_selection()
        assert view.tail_pins["request"] == ()
        assert "→ request $: null" in view.rows_text()
        for body, expected in ((b"[1,2]", "[1,2]"), (b'{"ok":true}', '{"ok":true}')):
            payload[0] = body
            row["request_body"] = {"available": True, "size": len(body)}
            await view.refresh()
            assert f"→ request $: {expected}" in view.rows_text()
        payload[0] = b'{"x":"\\u001b[2J"}'
        row["request_body"] = {"available": True, "size": len(payload[0])}
        await view.refresh()
        assert r"\u001b[2J" in view.rows_text() and "\x1b[2J" not in view.rows_text()

    asyncio.run(run())
