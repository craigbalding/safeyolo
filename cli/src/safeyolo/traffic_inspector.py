"""Read-only terminal inspection of the proxy-owned HTTP and WebSocket view."""

from __future__ import annotations

import asyncio
import base64
import binascii
import codecs
import difflib
import hashlib
import io
import json
import math
import os
import sys
import tempfile
import time
import unicodedata
import zlib
from collections import Counter
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import brotlicffi
import zstandard
from prompt_toolkit.application import Application, get_app
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.containers import DynamicContainer
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.widgets import TextArea
from pygments.lexers import CssLexer, HtmlLexer, JavascriptLexer, JsonLexer, XmlLexer
from pygments.token import Keyword, Literal, Name, Operator, Punctuation

from .api import AdminAPI, APIError, ExportCancelled, ExportPublicationState, TrafficExportResult

# Rendering limits leave the proxy's retained model and full-body route unchanged.
BODY_PREVIEW_BYTES = 64 * 1024
DETAIL_PREVIEW_CHARS = 128 * 1024
BODY_PREVIEW_CHARS = 32 * 1024
HTTP_SECTION_CHARS = 48 * 1024
MAX_ENCODING_STAGES = 16
ZSTD_MAX_WINDOW_BYTES = 32 * 1024 * 1024
# Only ordinary negotiation fields. Keep Host, connection/framing, cache,
# security, tracing and content description headers visible for diagnosis.
ROUTINE_HEADERS = frozenset({"accept", "accept-encoding", "accept-language", "user-agent"})
EXPORT_FORMATS = ("raw", "raw_request", "raw_response", "curl", "httpie", "har", "zhar")
TAIL_CARDS = 40
TAIL_FETCHES_PER_POLL = 12
TAIL_VALUE_CHARS = 220
TAIL_BODY_CHARS = 180
TAIL_PICKER_LINES = 24
LAST_ITEM = object()
JSON_UNAVAILABLE = object()


def plain_text(value: object, *, multiline: bool = False) -> str:
    """Make traffic printable without interpreting terminal controls or markup."""
    result = []
    for char in str(value):
        if char == "\n" and multiline:
            result.append(char)
        elif unicodedata.category(char).startswith("C") or char in {"\u2028", "\u2029"}:
            code = ord(char)
            result.append(f"\\x{code:02x}" if code < 256 else f"\\u{code:04x}")
        else:
            result.append(char)
    return "".join(result)


def body_facts(value: dict | None) -> str:
    value = value or {}
    if value.get("available"):
        return f"retained: {plain_text(value.get('size'))} bytes"
    return f"absent: {plain_text(value.get('reason') or 'not available')}"


def body_preview(value: dict) -> str:
    """Display a bounded preview; preserve missing versus present-empty bodies."""
    if not value.get("available"):
        return body_facts(value)
    try:
        raw = base64.b64decode(value["data_base64"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("Invalid retained body response") from exc
    preview = raw[:BODY_PREVIEW_BYTES].decode("utf-8", errors="backslashreplace")
    rendered = plain_text(preview, multiline=True) if raw else "(present, empty body)"
    if len(raw) > BODY_PREVIEW_BYTES:
        rendered += f"\n[preview: first {BODY_PREVIEW_BYTES} of {len(raw)} bytes]"
    return rendered


def _limited_text(value: str, limit: int, label: str) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n[{label} preview truncated; export for full evidence]"


def _content_type(headers: list) -> tuple[str, str]:
    values = [value for name, value in headers if name.lower() == "content-type"]
    if len(values) != 1:
        return "application/octet-stream", "utf-8"
    if "/" not in values[0].split(";", 1)[0]:
        return "application/octet-stream", "utf-8"
    message = Message()
    message["Content-Type"] = values[0]
    return message.get_content_type(), message.get_param("charset") or "utf-8"


def _content_encodings(headers: list) -> list[str]:
    values = [value for name, value in headers if name.lower() == "content-encoding"]
    if not values:
        return []
    return [coding.strip().lower() for value in values for coding in value.split(",")]


def _binary_fallback(raw: bytes, total: int, summary: str, side: str | None,
                     *, decoded: bytes | None = None) -> str:
    sample = (raw if decoded is None else decoded)[:16].hex(" ") or "none"
    kind = "retained" if decoded is None else "decoded"
    truncated = " · preview truncated" if len(raw) < total else ""
    export = f"raw_{side}" if side in {"request", "response"} else "raw_request/raw_response"
    summary_text = plain_text(summary[:160]) + ("…" if len(summary) > 160 else "")
    return (f"{summary_text} · "
            f"{len(raw)} of {total} retained bytes{truncated} · first {kind} bytes: {sample} · x export {export}")


def _decode_zlib(raw: bytes, coding: str) -> tuple[bytes, str | None]:
    window = 16 + zlib.MAX_WBITS if coding == "gzip" else zlib.MAX_WBITS
    decoder = zlib.decompressobj(window)
    output = bytearray()
    # Feed the trailer separately so a bad checksum does not hide text already
    # recovered from the compressed payload.
    payload_end = max(0, len(raw) - (8 if coding == "gzip" else 4))
    chunks = [raw[pos:min(pos + 512, payload_end)] for pos in range(0, payload_end, 512)]
    chunks.append(raw[payload_end:])
    member_finished = False
    for chunk in chunks:
        pending = chunk
        while pending:
            if member_finished:
                if coding != "gzip":
                    return bytes(output), "malformed"
                decoder = zlib.decompressobj(window)
                member_finished = False
            try:
                output.extend(decoder.decompress(pending, BODY_PREVIEW_BYTES + 1 - len(output)))
            except zlib.error:
                return bytes(output), "malformed"
            if len(output) > BODY_PREVIEW_BYTES or decoder.unconsumed_tail:
                return bytes(output[:BODY_PREVIEW_BYTES]), "display_limit"
            member_finished = decoder.eof
            next_pending = decoder.unused_data if member_finished else b""
            if next_pending == pending:
                return bytes(output), "malformed"
            pending = next_pending
    return bytes(output), None if member_finished else "stream_incomplete"


def _decode_brotli(raw: bytes) -> tuple[bytes, str | None]:
    decoder = brotlicffi.Decompressor()
    output = bytearray()
    for pos in range(0, len(raw), 512):
        try:
            output.extend(decoder.decompress(
                raw[pos:pos + 512], output_buffer_limit=BODY_PREVIEW_BYTES + 1 - len(output),
            ))
        except brotlicffi.error:
            return bytes(output), "malformed"
        if len(output) > BODY_PREVIEW_BYTES:
            return bytes(output[:BODY_PREVIEW_BYTES]), "display_limit"
        if not decoder.can_accept_more_data():
            return bytes(output), "malformed"
        if decoder.is_finished() and pos + 512 < len(raw):
            return bytes(output), "malformed"
    return bytes(output), None if decoder.is_finished() else "stream_incomplete"


def _verify_zstd_stream(raw: bytes) -> str | None:
    """Check frame completion with small input steps and bounded output counting."""
    decoder = None
    output_size = 0
    for pos in range(len(raw)):
        pending = raw[pos:pos + 1]
        while pending:
            if decoder is None:
                decoder = zstandard.ZstdDecompressor(max_window_size=ZSTD_MAX_WINDOW_BYTES).decompressobj()
            try:
                output_size += len(decoder.decompress(pending))
            except zstandard.ZstdError as exc:
                return "resource_limit" if "too much memory" in str(exc).lower() else "malformed"
            if output_size > BODY_PREVIEW_BYTES:
                return "display_limit"
            if decoder.eof:
                next_pending = decoder.unused_data
                if next_pending == pending:
                    return "malformed"
                pending = next_pending
                decoder = None
            else:
                pending = b""
    return None if decoder is None else "stream_incomplete"


def _decode_zstd(raw: bytes) -> tuple[bytes, str | None]:
    output = bytearray()
    try:
        parameters = zstandard.get_frame_parameters(raw)
        if parameters.window_size > ZSTD_MAX_WINDOW_BYTES:
            return b"", "resource_limit"
        decompressor = zstandard.ZstdDecompressor(max_window_size=ZSTD_MAX_WINDOW_BYTES)
        with decompressor.stream_reader(io.BytesIO(raw), read_across_frames=True) as reader:
            while len(output) <= BODY_PREVIEW_BYTES:
                chunk = reader.read(min(8192, BODY_PREVIEW_BYTES + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
        if len(output) > BODY_PREVIEW_BYTES:
            return bytes(output[:BODY_PREVIEW_BYTES]), "display_limit"
        # The stream reader can return EOF for a retained prefix of a frame.
        # A separate bounded pass checks completion, including multiple frames.
        return bytes(output), _verify_zstd_stream(raw)
    except zstandard.ZstdError as exc:
        error = str(exc).lower()
        if "not enough data for frame parameters" in error:
            return bytes(output), "stream_incomplete"
        if "too much memory" in error:
            return bytes(output), "resource_limit"
        return bytes(output), "malformed"


def _decode_coding(raw: bytes, coding: str) -> tuple[bytes, str | None]:
    if coding in {"gzip", "deflate"}:
        return _decode_zlib(raw, coding)
    if coding == "br":
        return _decode_brotli(raw)
    return _decode_zstd(raw)


def _decode_note(coding: str, state: str) -> str:
    if state == "display_limit":
        return f"decoded preview truncated at {BODY_PREVIEW_BYTES} bytes ({coding})"
    if state == "stream_incomplete":
        return f"encoded stream incomplete ({coding})"
    return f"malformed {coding} stream"


def _decoded_content(raw: bytes, codings: list[str]) -> tuple[bytes | None, list[str]]:
    if len(codings) > MAX_ENCODING_STAGES:
        return None, [f"content encoding has more than {MAX_ENCODING_STAGES} stages"]
    if any(not coding for coding in codings):
        return None, ["malformed Content-Encoding header"]
    for coding in codings:
        if coding not in {"identity", "gzip", "deflate", "br", "zstd"}:
            return None, [f"unsupported content encoding {coding}"]
    notes = []
    decoded = raw
    input_incomplete = False
    for coding in reversed(codings):
        if coding == "identity":
            continue
        decoded, state = _decode_coding(decoded, coding)
        if state == "resource_limit":
            return None, [f"zstd window exceeds {ZSTD_MAX_WINDOW_BYTES} byte viewer limit"]
        if state == "malformed" and input_incomplete:
            state = "stream_incomplete"
        if state:
            notes.append(_decode_note(coding, state))
        if state in {"malformed", "stream_incomplete"} and not decoded:
            return None, notes
        input_incomplete |= state in {"display_limit", "stream_incomplete"}
    return decoded, notes


def _http_preview_bytes(value: dict) -> tuple[bytes, int, bool]:
    try:
        raw = base64.b64decode(value["data_base64"], validate=True)
        total, preview_size, truncated = (value[key] for key in ("size", "preview_size", "truncated"))
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("Invalid retained body preview") from exc
    if (type(total) is not int or total < 0 or type(preview_size) is not int
            or preview_size != len(raw) or len(raw) > BODY_PREVIEW_BYTES or len(raw) > total
            or type(truncated) is not bool or truncated is not (len(raw) < total)):
        raise ValueError("Invalid retained body preview")
    return raw, total, truncated


def _pretty_json(content: str) -> str:
    try:
        value = json.loads(content)
        parts = []
        length = 0
        for part in json.JSONEncoder(ensure_ascii=False, indent=2).iterencode(value):
            remaining = BODY_PREVIEW_CHARS + 1 - length
            parts.append(part[:remaining])
            length += min(len(part), remaining)
            if length > BODY_PREVIEW_CHARS:
                break
        return "".join(parts)
    except (ValueError, TypeError, RecursionError):
        return content  # Incomplete or invalid JSON remains readable as text.


def _pretty_ndjson(content: str) -> str:
    parts = []
    length = 0
    for line in content.splitlines():
        formatted = _pretty_json(line) if line.strip() else line
        remaining = BODY_PREVIEW_CHARS + 1 - length
        parts.append(formatted[:remaining])
        length += min(len(formatted), remaining)
        if length > BODY_PREVIEW_CHARS:
            break
        parts.append("\n")
        length += 1
    return "".join(parts).removesuffix("\n")


def _pretty_form(content: str, charset: str) -> str:
    try:
        fields = parse_qsl(content, keep_blank_values=True, encoding=charset,
                           errors="strict", max_num_fields=256)
    except (ValueError, LookupError, UnicodeError):
        return content
    return "\n".join(f"{name} = {value}" for name, value in fields) if fields else content


def _readable_media_type(media_type: str) -> bool:
    return (media_type.startswith("text/") or media_type.endswith(("+json", "+xml"))
            or media_type in {"application/json", "application/xml", "application/javascript",
                              "application/ecmascript", "application/x-javascript", "application/x-ndjson",
                              "application/ndjson", "application/x-www-form-urlencoded"})


def _format_content(content: str, media_type: str, charset: str, pretty: bool) -> str:
    if not pretty:
        return content
    if media_type == "application/json" or media_type.endswith("+json"):
        return _pretty_json(content)
    if media_type in {"application/x-ndjson", "application/ndjson", "text/x-ndjson"}:
        return _pretty_ndjson(content)
    if media_type == "application/x-www-form-urlencoded":
        return _pretty_form(content, charset)
    return content


def _http_preview_notes(raw_size: int, total: int, truncated: bool, decode_notes: list[str]) -> str:
    notes = []
    if truncated:
        notes.append(f"[retained preview truncated: {raw_size} of {total} retained bytes; export for full evidence]")
    notes.extend(f"[{note}]" for note in decode_notes)
    return "\n" + "\n".join(notes) if notes else ""


def _decode_text_preview(decoded: bytes, charset: str, *, incomplete: bool) -> str | None:
    try:
        return decoded.decode(charset)
    except UnicodeDecodeError as exc:
        # A bounded slice may end inside a character or shift sequence. The
        # full decode distinguishes incomplete tails from invalid UTF-8 ranges;
        # the incremental decode checks all bytes before the pending tail.
        if (not incomplete or exc.reason not in {
                "unexpected end of data", "truncated data", "incomplete multibyte sequence",
                "unterminated shift sequence",
        }):
            return None
        try:
            codecs.getincrementaldecoder(charset)(errors="strict").decode(decoded, final=False)
            # UTF-7 can buffer a whole open shift despite complete characters
            # inside it. The checks above leave only the incomplete tail to omit.
            return decoded.decode(charset, errors="ignore")
        except (LookupError, UnicodeError, TypeError):
            return None
    except (LookupError, UnicodeError, TypeError):
        return None


def _http_body_preview(value: dict, headers: list, *, pretty: bool, side: str | None) -> tuple[str, int | None]:
    """Return the preview and length of readable content before any diagnostic notes."""
    if not value.get("available"):
        reason = plain_text(value.get("reason") or "not available")
        text = "pending: body capture is still in progress" if reason == "pending" else f"absent: {reason}"
        return text, None
    raw, total, truncated = _http_preview_bytes(value)
    if total == 0:
        return "(present, empty body)", None
    media_type, charset = _content_type(headers)
    decoded, decode_notes = _decoded_content(raw, _content_encodings(headers))
    if decoded is None:
        return _binary_fallback(raw, total, f"{media_type} · {'; '.join(decode_notes)}", side), None
    if not _readable_media_type(media_type):
        reason = "binary or unknown body"
        if decode_notes:
            reason += "; " + "; ".join(decode_notes)
        return _binary_fallback(raw, total, f"{media_type} · {reason}", side, decoded=decoded), None
    if not decoded:
        text = "(present, empty decoded body)" if not truncated and not decode_notes else "(no decoded bytes in retained preview)"
        content_length = None
    else:
        content = _decode_text_preview(decoded, charset, incomplete=truncated or bool(decode_notes))
        if content is None:
            reason = f"unsupported or undecodable charset {charset}"
            if decode_notes:
                reason += "; " + "; ".join(decode_notes)
            return _binary_fallback(raw, total, f"{media_type} · {reason}", side), None
        content = _format_content(content, media_type, charset, pretty)
        text = _limited_text(plain_text(content, multiline=True), BODY_PREVIEW_CHARS, "body")
        content_length = min(len(text), BODY_PREVIEW_CHARS)
    return text + _http_preview_notes(len(raw), total, truncated, decode_notes), content_length


def http_body_preview(value: dict, headers: list, *, pretty: bool, side: str | None = None) -> str:
    """Render one bounded HTTP preview without changing retained or exported bytes."""
    return _http_body_preview(value, headers, pretty=pretty, side=side)[0]


def _body_syntax_lexer(media_type: str):
    if media_type == "application/json" or media_type.endswith("+json") or media_type in {
        "application/x-ndjson", "application/ndjson", "text/x-ndjson",
    }:
        return JsonLexer
    if media_type == "text/html" or media_type == "application/xhtml+xml":
        return HtmlLexer
    if media_type == "application/xml" or media_type.endswith("+xml") or media_type == "text/xml":
        return XmlLexer
    if media_type in {"application/javascript", "application/ecmascript", "application/x-javascript",
                      "text/javascript"}:
        return JavascriptLexer
    if media_type == "text/css":
        return CssLexer
    return None


_SYNTAX_STYLES = (
    (Name.Tag, "ansiblue bold"), (Name.Class, "ansiblue bold"),
    (Name.Attribute, "ansicyan"), (Literal.String, "ansigreen"),
    (Literal.Number, "ansiyellow"), (Keyword, "ansimagenta"),
    (Punctuation, "ansicyan"), (Operator, "ansicyan"),
)


def _syntax_style(token) -> str:
    for family, style in _SYNTAX_STYLES:
        if token in family:
            return style
    return ""


def _form_syntax_ranges(content: str):
    offset = 0
    for line in content.splitlines(keepends=True):
        if " = " in line:
            key, separator, value = line.partition(" = ")
            yield offset, offset + len(key), "ansiblue bold"
            yield offset + len(key), offset + len(key) + len(separator), "ansicyan"
            yield offset + len(key) + len(separator), offset + len(key) + len(separator) + len(value.rstrip("\n")), "ansigreen"
        else:
            field_offset = offset
            for field in line.rstrip("\n").split("&"):
                key, separator, _ = field.partition("=")
                yield field_offset, field_offset + len(key), "ansiblue bold"
                if separator:
                    yield field_offset + len(key), field_offset + len(key) + 1, "ansicyan"
                    yield field_offset + len(key) + 1, field_offset + len(field), "ansigreen"
                field_offset += len(field) + 1
        offset += len(line)


def _event_stream_syntax_ranges(content: str):
    offset = 0
    for line in content.splitlines(keepends=True):
        name, separator, _ = line.partition(":")
        if separator and name in {"event", "data", "id", "retry"}:
            yield offset, offset + len(name), "ansiblue bold"
            yield offset + len(name), offset + len(name) + 1, "ansicyan"
        offset += len(line)


def _body_syntax_ranges(content: str, media_type: str):
    lexer = _body_syntax_lexer(media_type)
    if lexer is not None:
        for offset, token, value in lexer(stripnl=False, ensurenl=False).get_tokens_unprocessed(content):
            style = _syntax_style(token)
            if style:
                yield offset, offset + len(value), style
    elif media_type == "application/x-www-form-urlencoded":
        yield from _form_syntax_ranges(content)
    elif media_type == "text/event-stream":
        yield from _event_stream_syntax_ranges(content)


class DetailSyntaxLexer(Lexer):
    """Apply colour only to the selected HTTP body ranges in a plain-text detail pane."""

    def __init__(self):
        self.text = ""
        self.body_spans: tuple[tuple[int, int, str], ...] = ()
        self._fragments: list[list[tuple[str, str]]] | None = None

    def update(self, text: str, body_spans: list[tuple[int, int, str]]) -> None:
        spans = tuple(body_spans)
        if text != self.text or spans != self.body_spans:
            self.text = text
            self.body_spans = spans
            self._fragments = None

    def lex_document(self, document):
        lines = document.lines
        if document.text != self.text:
            return lambda line_number: [("", lines[line_number])]
        if self._fragments is not None:
            fragments = self._fragments
            return lambda line_number: fragments[line_number]
        styles = [""] * len(document.text)
        for start, end, media_type in self.body_spans:
            for offset, stop, style in _body_syntax_ranges(document.text[start:end], media_type):
                token_start = start + offset
                token_end = min(start + stop, end)
                if token_start < token_end:
                    styles[token_start:token_end] = [style] * (token_end - token_start)

        fragments = []
        offset = 0
        for line in lines:
            styled_line = []
            if line:
                run_start = 0
                current_style = styles[offset]
                for index in range(1, len(line)):
                    style = styles[offset + index]
                    if style != current_style:
                        styled_line.append((current_style, line[run_start:index]))
                        run_start, current_style = index, style
                styled_line.append((current_style, line[run_start:]))
            fragments.append(styled_line or [("", "")])
            offset += len(line) + 1
        self._fragments = fragments
        return lambda line_number: fragments[line_number]


def http_header_lines(headers: list, *, hide_routine: bool) -> list[str]:
    visible = []
    hidden = Counter()
    names = {}
    for name, value in headers:
        normalized = name.lower()
        if hide_routine and normalized in ROUTINE_HEADERS:
            hidden[normalized] += 1
            names.setdefault(normalized, name)
        else:
            visible.append(f"{plain_text(name)}: {plain_text(value)}")
    if not visible:
        visible.append("(none visible)")
    if hide_routine:
        summary = ", ".join(f"{plain_text(names[name])} ×{count}" for name, count in hidden.items()) or "none"
        visible.insert(0, f"Hidden routine headers ({sum(hidden.values())}): {summary}")
    return visible


def bulk_export_filename(flow_id: str, format_name: str) -> str:
    """Return a stable, filesystem-safe name for one selected flow export."""
    safe_id = "".join(
        char if char.isascii() and (char.isalnum() or char in "-_") else "-"
        for char in flow_id
    ).strip("-_")
    if not safe_id:
        safe_id = "flow"
    digest = hashlib.sha256(flow_id.encode("utf-8")).hexdigest()
    return f"{safe_id[:48]}-{digest}.{format_name}"


def websocket_page(value: dict, offset: int) -> str:
    """Validate and describe a page without confusing it with HTTP encoding."""
    fields = [value.get(key) for key in ("offset", "total_size", "size")]
    if any(type(field) is not int or field < 0 for field in fields):
        raise ValueError("Invalid WebSocket page bounds")
    actual, total, size = fields
    if actual != offset or size > BODY_PREVIEW_BYTES or actual + size > total:
        raise ValueError("Invalid WebSocket page bounds")
    heading = f"Message bytes [{actual}:{actual + size}) of {total} (decompressed/unmasked bytes, UTF-8 preview)"
    if not value.get("available"):
        return heading + "\n" + body_facts(value) + "\n[Use [ or ] to retry this page.]"
    rendered = body_preview(value)
    # Body responses are bounded pages; validate actual length/end before using
    # them for navigation instead of silently truncating an invalid response.
    raw = base64.b64decode(value["data_base64"], validate=True)
    if len(raw) != size or value.get("end") is not (actual + size == total):
        raise ValueError("Invalid WebSocket page length")
    return heading + "\n" + rendered


class WebSocketTranscript:
    """Selected retained message and one fetched page, separate from polling."""

    def __init__(self):
        self.session: dict = {}
        self.messages: list[dict] = []
        self.selected: int | None = None
        self.offset = 0
        self.pending = False
        self.body = ""

    def snapshot(self, document: dict) -> None:
        messages = document.get("messages")
        session = document.get("websocket")
        if not isinstance(messages, list) or not isinstance(session, dict):
            raise ValueError("Invalid WebSocket transcript response")
        ids = [row.get("id") if isinstance(row, dict) else None for row in messages]
        if any(type(key) is not int or key < 0 for key in ids) or len(set(ids)) != len(ids):
            raise ValueError("Invalid WebSocket message IDs")
        self.session, self.messages = session, messages
        self._select(self.selected if self.selected in ids else next(iter(ids), None))

    def _select(self, message_id: int | None) -> None:
        if message_id != self.selected:
            self.selected, self.offset, self.body = message_id, 0, ""
            self.pending = message_id is not None

    def select(self, offset: int) -> None:
        ids = [row["id"] for row in self.messages]
        if ids:
            index = ids.index(self.selected) if self.selected in ids else 0
            self._select(ids[max(0, min(len(ids) - 1, index + offset))])

    def selected_message(self) -> dict | None:
        return next((row for row in self.messages if row["id"] == self.selected), None)

    def page(self, direction: int) -> None:
        row = self.selected_message()
        if row is not None:
            size = row.get("body", {}).get("size", 0)
            last = max(0, (size - 1) // BODY_PREVIEW_BYTES) * BODY_PREVIEW_BYTES
            self.offset = max(0, min(last, self.offset + direction * BODY_PREVIEW_BYTES))
            self.body, self.pending = "", True

    def rows_text(self) -> str:
        lines = []
        for row in self.messages:
            mark = ">" if row["id"] == self.selected else " "
            direction = "client→server" if row.get("from_client") else "server→client"
            flags = " dropped" if row.get("dropped") else ""
            flags += " injected" if row.get("injected") else ""
            lines.append(plain_text(f"{mark} {row['id']} {direction} {row.get('type')} "
                                    f"{row.get('body', {}).get('size')} bytes @{row.get('timestamp')}{flags}"))
        return "\n".join(lines) or "No retained WebSocket messages. w returns to HTTP."

    def detail_text(self) -> str:
        lines = ["WebSocket session", *(f"{key}: {plain_text(self.session.get(key))}" for key in
                  ("state", "started", "timestamp_end", "closed_by_client", "close_code", "close_reason"))]
        meta = self.session.get("messages_meta", {})
        lines.append(f"Retained: {plain_text(meta.get('count', len(self.messages)))} messages / "
                     f"{plain_text(meta.get('contentLength', 0))} bytes; "
                     f"trimmed from history: {plain_text(self.session.get('trimmed_messages', 0))}")
        row = self.selected_message()
        if row is not None:
            lines.extend(["\nSelected message", *(f"{key}: {plain_text(row.get(key))}" for key in
                          ("id", "type", "from_client", "timestamp", "dropped", "injected"))])
            lines.append("Dropped is the inspection disposition, not a delivery receipt.")
            lines.append("\n" + (self.body or "Page not fetched yet. Use [ or ] to request/retry."))
        return "\n".join(lines)


def _short_line(value: object, limit: int) -> str:
    text = plain_text(value)
    return text if len(text) <= limit else text[:limit] + "… [preview]"


def _json_preview(body: dict | None, headers: list) -> object:
    """Parse only a complete, bounded JSON preview through the HTTP decoder."""
    if not body or not body.get("available"):
        return JSON_UNAVAILABLE
    _, charset = _content_type(headers)
    raw, _, truncated = _http_preview_bytes(body)
    decoded, notes = _decoded_content(raw, _content_encodings(headers))
    if truncated or decoded is None or notes:
        return JSON_UNAVAILABLE
    content = _decode_text_preview(decoded, charset, incomplete=False)
    if content is None:
        return JSON_UNAVAILABLE
    try:
        return json.loads(content)
    except (ValueError, TypeError, RecursionError):
        return JSON_UNAVAILABLE


def _json_at(value: object, path: tuple) -> tuple[bool, object]:
    for part in path:
        if part is LAST_ITEM:
            if not isinstance(value, list) or not value:
                return False, None
            value = value[-1]
        elif isinstance(value, dict) and isinstance(part, str) and part in value:
            value = value[part]
        elif isinstance(value, list) and type(part) is int and 0 <= part < len(value):
            value = value[part]
        else:
            return False, None
    return True, value


def _json_path_text(path: tuple) -> str:
    parts = ["$"]
    for part in path:
        if part is LAST_ITEM:
            parts.append("[last]")
        elif type(part) is int:
            parts.append(f"[{part}]")
        else:
            parts.append("[" + json.dumps(part, ensure_ascii=True) + "]")
    return "".join(parts)


def _json_children(value: object, path: tuple) -> list[tuple]:
    found, node = _json_at(value, path)
    if not found:
        return []
    if isinstance(node, dict):
        return [(*path, key) for key in node]
    if isinstance(node, list):
        return ([(*path, LAST_ITEM)] if node else []) + [(*path, index) for index in range(len(node))]
    return []


def _json_value_text(value: object, limit: int = TAIL_VALUE_CHARS) -> tuple[str, bool]:
    """Bound JSON serialization before any terminal text is assembled."""
    try:
        encoded = json.JSONEncoder(ensure_ascii=True, separators=(",", ":")).iterencode(value)
        parts = []
        remaining = limit + 1
        for part in encoded:
            parts.append(part[:remaining])
            remaining -= min(len(part), remaining)
            if remaining == 0:
                break
        text = "".join(parts)
    except (TypeError, ValueError, RecursionError):
        return "[JSON value unavailable]", False
    truncated = len(text) > limit
    return text[:limit] + ("… [preview]" if truncated else ""), truncated


def _endpoint(row: dict) -> tuple[str, str]:
    url = str(row.get("url") or "")
    try:
        parsed = urlsplit(url)
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else parsed.path
    except ValueError:
        endpoint = url.split("?", 1)[0].split("#", 1)[0]
    return str(row.get("method") or ""), endpoint


def _changed_spans(previous: str, current: str) -> list[tuple[int, int]]:
    return [(start, end) for operation, _, _, start, end in
            difflib.SequenceMatcher(None, previous, current, autojunk=False).get_opcodes()
            if operation != "equal" and start != end]


@dataclass
class TailCard:
    signature: tuple | None = None
    detail: dict | None = None
    detail_error: str | None = None
    bodies: dict[str, dict] = field(default_factory=dict)
    body_signatures: dict[str, tuple] = field(default_factory=dict)
    body_errors: dict[str, str] = field(default_factory=dict)
    body_texts: dict[str, str] = field(default_factory=dict)
    json_values: dict[str, object] = field(default_factory=dict)


class TailChangeLexer(Lexer):
    """Colour changed request characters; the visible Δ also works without colour."""

    def __init__(self):
        self.text = ""
        self.spans: tuple[tuple[int, int], ...] = ()

    def update(self, text: str, spans: list[tuple[int, int]]) -> None:
        self.text, self.spans = text, tuple(spans)

    def lex_document(self, document):
        if document.text != self.text:
            return lambda line_number: [("", document.lines[line_number])]
        offset = 0
        fragments = []
        for line in document.lines:
            styles = [""] * len(line)
            for start, end in self.spans:
                for position in range(max(start, offset), min(end, offset + len(line))):
                    styles[position - offset] = "ansiyellow bold underline"
            pieces = []
            for char, style in zip(line, styles, strict=True):
                if pieces and pieces[-1][0] == style:
                    pieces[-1] = (style, pieces[-1][1] + char)
                else:
                    pieces.append((style, char))
            fragments.append(pieces or [("", "")])
            offset += len(line) + 1
        return lambda line_number: fragments[line_number]


class TrafficInspector:
    """One client projection; scope and retained traffic remain proxy-owned."""

    def __init__(self, api: AdminAPI):
        self.api = api
        self.flows: list[dict] = []
        self.scope: dict = {}
        self.selected: str | None = None
        self.marked: set[str] = set()
        self.detail: dict | None = None
        self.body_values: dict[str, dict] = {}
        self.body_errors: dict[str, str] = {}
        self.body_attempted: set[str] = set()
        self.body_facts: dict[str, tuple[dict, object, object]] = {}
        self.pretty = True
        self.hide_routine_headers = False
        self._selection_revision = 0
        self.notice = "Connecting…"
        self.pending_scope: dict | None = None
        self.pending_filter: str | None = None
        self.pending_export: tuple[str | tuple[str, ...], str, Path] | None = None
        self._export_cancel_event: ExportPublicationState | None = None
        self.export_report = ""
        self._notice_hold: str | None = None
        self.websocket_mode = False
        self.transcript = WebSocketTranscript()
        self.detail_syntax = DetailSyntaxLexer()
        self.tail_syntax = TailChangeLexer()
        self.tail_mode = False
        self.tail_follow = True
        self.tail_detail_open = False
        self.tail_pins: dict[str, tuple | None] = {"request": None, "response": None}
        self.tail_cards: dict[str, TailCard] = {}
        self.tail_known_ids: set[str] | None = None
        self.tail_departed = 0
        self.tail_failed_polls = 0
        self.tail_poll_interrupted = False
        self.tail_revision = 0
        self.pin_picker_side: str | None = None
        self.pin_picker_root: object | None = None
        self.pin_picker_prefix: tuple = ()
        self.pin_picker_index = 0
        self.wake = asyncio.Event()

    def select(self, offset: int) -> None:
        if self.websocket_mode:
            self.transcript.select(offset)
            self.wake.set()
            return
        rows = self._tail_visible() if self.tail_mode else self.flows
        if not rows:
            return
        ids = [row["id"] for row in rows]
        index = ids.index(self.selected) if self.selected in ids else (len(ids) - 1 if self.tail_mode else 0)
        if self.tail_mode:
            self.tail_follow = False
        self._select(ids[max(0, min(len(ids) - 1, index + offset))])
        self.wake.set()

    def _select(self, flow_id: str | None) -> None:
        if flow_id != self.selected:
            self.selected = flow_id
            self.close_pin_picker()
            self._clear_selected_detail()
            self.websocket_mode = False
            self.transcript = WebSocketTranscript()

    def _tail_visible(self) -> list[dict]:
        if not self.flows:
            return []
        if self.tail_follow or self.selected is None:
            start = 0
        else:
            ids = [row["id"] for row in self.flows]
            index = ids.index(self.selected) if self.selected in ids else 0
            start = max(0, min(index - TAIL_CARDS // 2, len(self.flows) - TAIL_CARDS))
        return list(reversed(self.flows[start:start + TAIL_CARDS]))

    def toggle_tail(self) -> None:
        self.tail_mode = not self.tail_mode
        self.close_pin_picker()
        self.tail_detail_open = False
        if self.tail_mode:
            self.tail_known_ids = None
            if self.tail_follow:
                self._select(self.flows[0]["id"] if self.flows else None)
        self.wake.set()

    def resume_tail(self) -> None:
        if self.tail_mode:
            self.tail_follow = True
            self.tail_detail_open = False
            self._select(self.flows[0]["id"] if self.flows else None)
            self.wake.set()

    def _reset_tail_snapshot(self) -> None:
        self.tail_revision += 1
        self.tail_cards.clear()
        self.tail_known_ids = None
        self.tail_departed = 0
        self.tail_failed_polls = 0
        self.tail_poll_interrupted = False
        self.close_pin_picker()

    def _tail_poll_failed(self) -> None:
        if self.tail_mode:
            self.tail_failed_polls += 1

    def close_pin_picker(self) -> None:
        self.pin_picker_side = None
        self.pin_picker_root = None
        self.pin_picker_prefix = ()
        self.pin_picker_index = 0

    def open_pin_picker(self, side: str) -> None:
        if not self.tail_mode or self.detail is None or side not in self.body_values:
            self._hold_notice("Choose a loaded JSON request or response in tail mode")
            return
        try:
            value = _json_preview(self.body_values[side], self.detail.get(f"{side}_headers", []))
        except (TypeError, ValueError):
            value = JSON_UNAVAILABLE
        if value is JSON_UNAVAILABLE:
            self._hold_notice("Selected side has no complete JSON preview; retry or export the body")
            return
        self.pin_picker_side = side
        self.pin_picker_root = value
        self.pin_picker_prefix = ()
        self.pin_picker_index = 0
        self.tail_follow = False
        self.tail_detail_open = True
        self.wake.set()

    def _pin_picker_choices(self) -> list[tuple]:
        return [self.pin_picker_prefix, *_json_children(self.pin_picker_root, self.pin_picker_prefix)]

    def move_pin_picker(self, offset: int) -> None:
        choices = self._pin_picker_choices()
        self.pin_picker_index = max(0, min(len(choices) - 1, self.pin_picker_index + offset))
        self.wake.set()

    def descend_pin_picker(self) -> None:
        path = self._pin_picker_choices()[self.pin_picker_index]
        if _json_children(self.pin_picker_root, path):
            self.pin_picker_prefix, self.pin_picker_index = path, 0
        self.wake.set()

    def ascend_pin_picker(self) -> None:
        if self.pin_picker_prefix:
            child = self.pin_picker_prefix
            self.pin_picker_prefix = child[:-1]
            self.pin_picker_index = self._pin_picker_choices().index(child)
        self.wake.set()

    def pin_picker_selection(self) -> None:
        if self.pin_picker_side is not None:
            self.tail_pins[self.pin_picker_side] = self._pin_picker_choices()[self.pin_picker_index]
            self.close_pin_picker()
            self.tail_detail_open = False
            self.wake.set()

    def clear_pin_picker(self) -> None:
        if self.pin_picker_side is not None:
            self.tail_pins[self.pin_picker_side] = None
            self.close_pin_picker()
            self.tail_detail_open = False
            self.wake.set()

    def _pin_picker_text(self) -> str:
        side = self.pin_picker_side
        choices = self._pin_picker_choices()
        start = max(0, min(self.pin_picker_index - TAIL_PICKER_LINES // 2,
                           len(choices) - TAIL_PICKER_LINES))
        lines = [f"Pin {side} JSON from selected exchange",
                 "↑↓/PgUp/PgDn choose · → open subtree · ← parent · Enter pin · Backspace clear pin · Esc cancel",
                 f"{len(choices)} choices here · showing {start + 1}–{min(len(choices), start + TAIL_PICKER_LINES)}"]
        for index in range(start, min(len(choices), start + TAIL_PICKER_LINES)):
            path = choices[index]
            _, value = _json_at(self.pin_picker_root, path)
            sample, _ = _json_value_text(value, 100)
            marker = ">" if index == self.pin_picker_index else " "
            lines.append(f"{marker} {_short_line(_json_path_text(path), 120)} = {sample}")
        return "\n".join(lines)

    def _clear_selected_detail(self) -> None:
        self._selection_revision += 1
        self.detail = None
        self.body_values.clear()
        self.body_errors.clear()
        self.body_attempted.clear()
        self.body_facts.clear()

    def snapshot(self, document: dict) -> None:
        rows = document.get("flows")
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
            raise ValueError("Invalid traffic list response")
        scope = document.get("scope", {})
        if scope != self.scope:
            self._clear_selected_detail()
            self._reset_tail_snapshot()
        self.flows = rows
        self.scope = scope
        ids = [row["id"] for row in rows]
        if self.tail_mode:
            current_ids = set(ids)
            if self.tail_known_ids is not None:
                self.tail_departed += len(self.tail_known_ids - current_ids)
            self.tail_known_ids = current_ids
        # Marks are a view-local convenience, never an authority grant. Drop
        # anything that a refreshed scope, filter, or retention pass hid.
        self.marked.intersection_update(ids)
        if self.tail_mode and not self.tail_follow and self.selected not in ids:
            next_selected = ids[-1] if ids else None
        else:
            next_selected = self.selected if self.selected in ids else next(iter(ids), None)
        self._select(next_selected)
        if self.tail_mode and self.tail_follow:
            self._select(next(iter(ids), None))

    def toggle_mark(self) -> None:
        """Mark or unmark the focused visible flow for a later bulk export."""
        if self.websocket_mode:
            self._hold_notice("Return to the flow list before marking exports")
        elif self.selected is None:
            self._hold_notice("Select a flow before marking exports")
        elif self.selected in self.marked:
            self.marked.remove(self.selected)
            self._hold_notice(f"Unmarked flow {plain_text(self.selected)}")
        else:
            self.marked.add(self.selected)
            self._hold_notice(f"Marked flow {plain_text(self.selected)}")
        self.wake.set()

    def export_flow_ids(self) -> tuple[str, ...]:
        """Freeze visible marks, or the focused flow when no mark is present."""
        marked = tuple(row["id"] for row in self.flows if row["id"] in self.marked)
        if marked:
            return marked
        return (self.selected,) if self.selected is not None else ()

    def request_body(self, side: str) -> None:
        self.websocket_mode = False
        if self.selected and side in {"request", "response"}:
            self._selection_revision += 1
            self.body_values.pop(side, None)
            self.body_errors.pop(side, None)
            self.body_attempted.discard(side)
            card = self.tail_cards.get(self.selected)
            if card is not None:
                card.bodies.pop(side, None)
                card.body_errors.pop(side, None)
                card.body_signatures.pop(side, None)
            self.wake.set()

    def set_scope(self, field: str, value: str) -> None:
        self._selection_revision += 1
        self.tail_revision += 1
        if field == "agent":
            self.pending_scope = {"agent": value or None}
        else:
            self.pending_scope = {"agent": self.scope.get("agent"),
                                  "unattributed": self.scope.get("unattributed", False),
                                  "test_id": value or None}
        self.wake.set()

    def set_filter(self, expression: str) -> None:
        self._selection_revision += 1
        self.tail_revision += 1
        self.pending_filter = expression
        self.wake.set()

    def toggle_pretty(self) -> None:
        self.pretty = not self.pretty
        self.wake.set()

    def toggle_headers(self) -> None:
        self.hide_routine_headers = not self.hide_routine_headers
        self.wake.set()

    def queue_export(self, flow_id: str, format_name: str, destination: str) -> None:
        """Queue one local export using the flow ID selected at confirmation."""
        self.queue_exports((flow_id,), format_name, destination)

    def queue_exports(self, flow_ids: tuple[str, ...], format_name: str, destination: str) -> None:
        """Queue a focused or marked selection without widening its scope."""
        if format_name not in EXPORT_FORMATS:
            self._hold_notice("Export format is invalid")
            return
        if not destination.strip():
            self._hold_notice("Export destination is empty")
            return
        flow_ids = tuple(dict.fromkeys(flow_ids))
        if not flow_ids:
            self._hold_notice("Select a flow before exporting")
            return
        path = Path(destination).expanduser()
        if len(flow_ids) > 1 and not path.is_dir():
            self._hold_notice("Bulk export destination must be an existing directory")
            return
        self.pending_export = (flow_ids if len(flow_ids) > 1 else flow_ids[0]), format_name, path
        self.export_report = ""
        if len(flow_ids) == 1:
            self._hold_notice(f"Export queued for flow {plain_text(flow_ids[0])}")
        else:
            self._hold_notice(f"Bulk export queued for {len(flow_ids)} marked flows")
        self.wake.set()

    def cancel_export(self) -> None:
        """Cancel queued or active export work before detaching the UI.

        The worker serializes this request with its final publication commit;
        after that commit, a successful result remains authoritative.
        """
        self.pending_export = None
        if self._export_cancel_event is not None:
            self._export_cancel_event.set()

    def _hold_notice(self, notice: str) -> None:
        self._notice_hold = notice
        self.notice = notice

    async def _export_one(
        self,
        flow_id: str,
        format_name: str,
        destination: Path,
        cancel_event: ExportPublicationState,
    ) -> tuple[str, TrafficExportResult | None, str | None]:
        """Write one scoped export and retain only categorical failure details."""
        try:
            result = await asyncio.to_thread(
                self.api.traffic_export,
                flow_id,
                format_name,
                destination,
                cancel_event=cancel_event,
            )
        except ExportCancelled:
            return "canceled", None, "canceled"
        except asyncio.CancelledError:
            cancel_event.set()
            raise
        except APIError as exc:
            status = f" {exc.status_code}" if exc.status_code is not None else ""
            return "failed", None, f"APIError{status}"
        except (OSError, TypeError, ValueError) as exc:
            return "failed", None, type(exc).__name__
        if not isinstance(result, TrafficExportResult):
            return "failed", None, "invalid result"
        return "exported", result, None

    async def _run_single_export(
        self,
        flow_id: str,
        format_name: str,
        destination: Path,
        cancel_event: ExportPublicationState,
    ) -> None:
        state, result, reason = await self._export_one(flow_id, format_name, destination, cancel_event)
        if state == "canceled":
            self._hold_notice("Export canceled; destination unchanged")
        elif state == "failed":
            assert reason is not None
            if reason.startswith("APIError"):
                self._hold_notice(f"Export unavailable ({reason}); destination unchanged")
            else:
                self._hold_notice(f"Export failed ({reason}); destination unchanged")
        else:
            assert result is not None
            warning = f"; {result.cleanup_warning}" if result.cleanup_warning else ""
            self._hold_notice(
                f"Exported flow {plain_text(flow_id)} to {plain_text(destination)} "
                f"({result.bytes_written} bytes){warning}"
            )

    async def _bulk_export_outcomes(
        self,
        flow_ids: tuple[str, ...],
        format_name: str,
        destination: Path,
        cancel_event: ExportPublicationState,
    ) -> list[tuple[str, Path, str, TrafficExportResult | None, str | None]]:
        outcomes: list[tuple[str, Path, str, TrafficExportResult | None, str | None]] = []
        for index, flow_id in enumerate(flow_ids):
            path = destination / bulk_export_filename(flow_id, format_name)
            # A batch never replaces an existing path. A later selected flow
            # may still export, so a collision is a truthful partial failure.
            if path.exists() or path.is_symlink():
                outcomes.append((flow_id, path, "failed", None, "destination exists"))
                continue
            state, result, reason = await self._export_bulk_one(
                flow_id, format_name, path, cancel_event
            )
            outcomes.append((flow_id, path, state, result, reason))
            if state == "canceled":
                outcomes.extend(
                    (
                        remaining,
                        destination / bulk_export_filename(remaining, format_name),
                        "not started",
                        None,
                        "canceled before export",
                    )
                    for remaining in flow_ids[index + 1:]
                )
                break
        return outcomes

    async def _export_bulk_one(
        self,
        flow_id: str,
        format_name: str,
        destination: Path,
        cancel_event: ExportPublicationState,
    ) -> tuple[str, TrafficExportResult | None, str | None]:
        """Publish one batch result only if its deterministic name stays unused."""
        result: TrafficExportResult | None = None
        published = False
        try:
            with tempfile.TemporaryDirectory(prefix=".traffic-export-", dir=destination.parent) as temporary:
                staged = Path(temporary) / "export"
                state, result, reason = await self._export_one(
                    flow_id, format_name, staged, cancel_event
                )
                if state != "exported":
                    return state, result, reason
                try:
                    # link(2) creates the final name only when it is still absent;
                    # unlike replace, it cannot overwrite another selected export.
                    os.link(staged, destination)
                    published = True
                except FileExistsError:
                    return "failed", None, "destination exists"
                except OSError:
                    return "failed", None, "destination link failed"
        except OSError:
            if published:
                return "exported", result, None
            return "failed", None, "destination staging failed"
        return "exported", result, None

    def _report_bulk_export(
        self,
        flow_ids: tuple[str, ...],
        outcomes: list[tuple[str, Path, str, TrafficExportResult | None, str | None]],
    ) -> None:
        exported = sum(state == "exported" for _, _, state, _, _ in outcomes)
        failed = sum(state == "failed" for _, _, state, _, _ in outcomes)
        not_started = sum(state == "not started" for _, _, state, _, _ in outcomes)
        canceled = any(state == "canceled" for _, _, state, _, _ in outcomes)
        lines = ["Bulk export report:"]
        for flow_id, path, state, result, reason in outcomes:
            label = plain_text(flow_id)
            target = plain_text(path)
            if state == "exported":
                assert result is not None
                warning = f"; {result.cleanup_warning}" if result.cleanup_warning else ""
                lines.append(f"exported {label} -> {target} ({result.bytes_written} bytes){warning}")
            else:
                lines.append(f"{state} {label} -> {target} ({reason}; destination unchanged)")
        self.export_report = "\n".join(lines)
        if canceled:
            self._hold_notice(
                f"Bulk export canceled: {exported}/{len(flow_ids)} flows exported; "
                f"{failed} failed; {not_started} not started"
            )
        else:
            self._hold_notice(
                f"Bulk export complete: {exported}/{len(flow_ids)} flows exported; {failed} failed"
            )

    async def _run_bulk_export(
        self,
        flow_ids: tuple[str, ...],
        format_name: str,
        destination: Path,
        cancel_event: ExportPublicationState,
    ) -> None:
        outcomes = await self._bulk_export_outcomes(flow_ids, format_name, destination, cancel_event)
        self._report_bulk_export(flow_ids, outcomes)

    async def _run_export(self, request: tuple[str | tuple[str, ...], str, Path]) -> None:
        flow_ids, format_name, destination = request
        if isinstance(flow_ids, str):
            flow_ids = (flow_ids,)
        cancel_event = ExportPublicationState()
        self._export_cancel_event = cancel_event
        try:
            if len(flow_ids) == 1:
                await self._run_single_export(flow_ids[0], format_name, destination, cancel_event)
            else:
                await self._run_bulk_export(flow_ids, format_name, destination, cancel_event)
        finally:
            self._export_cancel_event = None

    def toggle_websocket(self) -> None:
        if self.websocket_mode:
            self.websocket_mode = False
        elif self.detail is not None and isinstance(self.detail.get("websocket"), dict):
            self.websocket_mode = True
        else:
            self.notice = "Selected flow has no WebSocket session."
        self.wake.set()

    async def _refresh_detail(self) -> None:
        flow_id = self.selected
        if flow_id is not None:
            revision = self._selection_revision
            detail = await asyncio.to_thread(self.api.traffic_flow, flow_id)
            if not isinstance(detail, dict):
                raise ValueError("Invalid traffic detail response")
            if self.selected == flow_id and self._selection_revision == revision:
                for side in ("request", "response"):
                    key = f"{side}_body"
                    facts = detail.get(key)
                    if not isinstance(facts, dict):
                        facts = {}
                    signature = (facts.copy(), detail.get(f"{side}_completed"), detail.get("state"))
                    if signature != self.body_facts.get(side):
                        self.body_values.pop(side, None)
                        self.body_errors.pop(side, None)
                        self.body_attempted.discard(side)
                        self.body_facts[side] = signature
                self.detail = detail

    async def _refresh_body_previews(self) -> None:
        flow_id = self.selected
        if flow_id is None or self.detail is None:
            return
        revision = self._selection_revision
        for side in ("request", "response"):
            if self.selected != flow_id or self._selection_revision != revision:
                return
            if side in self.body_attempted:
                continue
            self.body_attempted.add(side)
            headers = self.detail.get(f"{side}_headers", [])
            await self._fetch_body_preview(flow_id, side, revision, headers)

    async def _fetch_body_preview(self, flow_id: str, side: str, revision: int, headers: list) -> None:
        try:
            value = await asyncio.to_thread(self.api.traffic_body, flow_id, side, preview_bytes=BODY_PREVIEW_BYTES)
            if self.selected != flow_id or self._selection_revision != revision:
                if self.selected == flow_id:
                    self.body_attempted.discard(side)
                return
            if not isinstance(value, dict):
                raise ValueError("Invalid retained body preview")
            http_body_preview(value, headers, pretty=self.pretty)
        except (APIError, ValueError, TypeError) as exc:
            status = exc.status_code if isinstance(exc, APIError) else None
            error = f"{type(exc).__name__}{f' {status}' if status else ''}"
            if self.selected == flow_id and self._selection_revision == revision:
                self.body_errors[side] = error
            return
        self.body_values[side] = value

    async def _refresh_tail_detail(self, row: dict, card: TailCard, revision: int, budget: int) -> int:
        flow_id = row["id"]
        signature = (row.get("status"), row.get("state"), row.get("request_completed"),
                     row.get("response_head_observed"), row.get("response_completed"),
                     repr(row.get("request_body")), repr(row.get("response_body")))
        if flow_id == self.selected and self.detail is not None:
            if card.signature != signature:
                card.json_values.clear()
                card.body_texts.clear()
            card.detail, card.signature, card.detail_error = self.detail, signature, None
            return 0
        if card.signature == signature or budget == 0:
            return 0
        try:
            detail = await asyncio.to_thread(self.api.traffic_flow, flow_id)
            if not isinstance(detail, dict) or detail.get("id") != flow_id:
                raise ValueError("Invalid traffic detail response")
        except (APIError, TypeError, ValueError) as exc:
            if revision == self.tail_revision:
                card.signature, card.detail, card.detail_error = signature, None, type(exc).__name__
            return 1
        if revision == self.tail_revision and self.tail_mode:
            card.json_values.clear()
            card.body_texts.clear()
            card.detail, card.signature, card.detail_error = detail, signature, None
        return 1

    async def _refresh_tail_side(self, row: dict, card: TailCard, side: str,
                                 revision: int, budget: int) -> int:
        facts = row.get(f"{side}_body")
        signature = (repr(facts), row.get(f"{side}_completed"), row.get("state"))
        if card.body_signatures.get(side) != signature:
            card.bodies.pop(side, None)
            card.body_errors.pop(side, None)
            card.body_texts.pop(side, None)
            card.json_values.pop(side, None)
        if row["id"] == self.selected and side in self.body_values:
            card.bodies[side], card.body_signatures[side] = self.body_values[side], signature
            return 0
        if row["id"] == self.selected and side in self.body_errors:
            card.body_errors[side], card.body_signatures[side] = self.body_errors[side], signature
            return 0
        if not isinstance(facts, dict) or not facts.get("available"):
            card.body_signatures[side] = signature
            return 0
        if side in card.bodies or side in card.body_errors or budget == 0:
            return 0
        try:
            body = await asyncio.to_thread(self.api.traffic_body, row["id"], side,
                                           preview_bytes=BODY_PREVIEW_BYTES)
            if not isinstance(body, dict):
                raise ValueError("Invalid retained body preview")
            http_body_preview(body, card.detail.get(f"{side}_headers", []), pretty=False)
        except (APIError, TypeError, ValueError) as exc:
            if revision == self.tail_revision:
                card.body_errors[side], card.body_signatures[side] = type(exc).__name__, signature
            return 1
        if revision == self.tail_revision and self.tail_mode:
            card.bodies[side], card.body_signatures[side] = body, signature
        return 1

    async def _refresh_tail_cards(self) -> None:
        visible = self._tail_visible()
        visible_ids = {row["id"] for row in visible}
        self.tail_cards = {flow_id: card for flow_id, card in self.tail_cards.items() if flow_id in visible_ids}
        # The selected card is reused from the detail pane. Then fill newer
        # cards first, with one shared budget for all other Admin requests.
        selected = next((row for row in visible if row["id"] == self.selected), None)
        candidates = ([selected] if selected is not None else []) + [
            row for row in reversed(visible) if row["id"] != self.selected
        ]
        budget = TAIL_FETCHES_PER_POLL
        revision = self.tail_revision
        for row in candidates:
            if budget == 0 or not self.tail_mode or revision != self.tail_revision:
                return
            card = self.tail_cards.setdefault(row["id"], TailCard())
            budget -= await self._refresh_tail_detail(row, card, revision, budget)
            if revision != self.tail_revision or card.detail is None:
                continue
            for side in ("request", "response"):
                budget -= await self._refresh_tail_side(row, card, side, revision, budget)

    async def _refresh_websocket(self) -> None:
        flow_id, transcript = self.selected, self.transcript
        document = await asyncio.to_thread(self.api.traffic_websocket_messages, flow_id)
        if self.selected != flow_id or not self.websocket_mode:
            return
        transcript.snapshot(document)
        if transcript.pending:
            message_id, offset = transcript.selected, transcript.offset
            transcript.pending = False
            value = await asyncio.to_thread(self.api.traffic_websocket_message_body, flow_id, message_id, offset)
            if self.transcript is transcript and (transcript.selected, transcript.offset) == (message_id, offset):
                transcript.body = websocket_page(value, offset)

    async def _refresh_flows(self) -> None:
        try:
            document = await asyncio.to_thread(self.api.traffic_flows)
        except APIError:
            # Another operator's accepted filter may make list evaluation fail.
            # Recover its editable expression without hiding the original error.
            try:
                scope = await asyncio.to_thread(self.api.get_traffic_scope)
            except (APIError, ValueError, TypeError):
                pass  # Keep the prior scope and report the original list failure.
            else:
                if isinstance(scope, dict):
                    if scope != self.scope:
                        self._reset_tail_snapshot()
                    self.scope = scope
            self._tail_poll_failed()
            raise
        except (ValueError, TypeError):
            self._tail_poll_failed()
            raise
        try:
            self.snapshot(document)
        except (ValueError, TypeError):
            self._tail_poll_failed()
            raise
        if self.tail_mode and self.tail_failed_polls:
            self.tail_poll_interrupted = True

    async def refresh(self) -> None:
        """One worker serializes this mutable AdminAPI client's requests."""
        try:
            if self.pending_scope is not None:
                scope, self.pending_scope = self.pending_scope, None
                accepted = await asyncio.to_thread(self.api.set_traffic_scope, **scope)
                if accepted != self.scope:
                    self._clear_selected_detail()
                    self._reset_tail_snapshot()
                self.scope = accepted
            if self.pending_filter is not None:
                expression, self.pending_filter = self.pending_filter, None
                accepted = await asyncio.to_thread(self.api.set_traffic_filter, expression)
                if accepted != self.scope:
                    self._clear_selected_detail()
                    self._reset_tail_snapshot()
                self.scope = accepted
            await self._refresh_flows()
            await self._refresh_detail()
            await self._refresh_body_previews()
            if self.tail_mode:
                await self._refresh_tail_cards()
            if self.websocket_mode and self.selected:
                await self._refresh_websocket()
            if self.pending_export is not None:
                request, self.pending_export = self.pending_export, None
                await self._run_export(request)
            if self._notice_hold is None:
                self.notice = (
                    f"{len(self.flows)} visible flows · {len(self.marked)} marked · shared scope · q detaches"
                )
            else:
                self.notice = self._notice_hold
                self._notice_hold = None
        except (APIError, ValueError, TypeError) as exc:
            # Show only the category/status: an HTTP error body may contain traffic.
            status = exc.status_code if isinstance(exc, APIError) else None
            self.notice = f"View unavailable ({type(exc).__name__}{f' {status}' if status else ''}); retrying"

    def rows_text(self) -> str:
        if self.websocket_mode:
            return self.transcript.rows_text()
        if self.tail_mode:
            return self._tail_render()[0]
        lines = []
        for row in self.flows:
            focus = ">" if row["id"] == self.selected else " "
            marked = "*" if row["id"] in self.marked else " "
            text = f"{focus}{marked} {row.get('status') or '-'} {row.get('state', '')} {row.get('agent') or '-'} {row.get('method', '')} {row.get('url', '')}"
            lines.append(plain_text(text))
        return "\n".join(lines) or "No matching flows. Scope is shared with other clients."

    def _tail_body_content(self, row: dict, side: str) -> tuple[str, object | None, str]:
        facts = row.get(f"{side}_body")
        if not isinstance(facts, dict):
            return "[body facts unavailable]", None, ""
        if not facts.get("available"):
            reason = facts.get("reason") or "not available"
            return ("[pending]" if reason == "pending" else f"[absent: {_short_line(reason, 80)}]"), None, ""
        card = self.tail_cards.get(row["id"])
        error = (f"detail unavailable: {card.detail_error}" if card and card.detail_error else
                 f"preview failed: {card.body_errors[side]}; r/s retries" if card and side in card.body_errors else None)
        if error:
            return f"[{error}]", None, ""
        if card is None or side not in card.bodies or card.detail is None:
            return "[loading preview…]", None, ""
        body = card.bodies[side]
        headers = card.detail.get(f"{side}_headers", [])
        path = self.tail_pins[side]
        if path is None:
            if side not in card.body_texts:
                text = http_body_preview(body, headers, pretty=False, side=side)
                card.body_texts[side] = _short_line(text, TAIL_BODY_CHARS)
            return card.body_texts[side], None, ""
        return self._tail_pinned_content(card, side, body, headers, path)

    def _tail_pinned_content(self, card: TailCard, side: str, body: dict,
                             headers: list, path: tuple) -> tuple[str, object | None, str]:
        if side not in card.json_values:
            try:
                card.json_values[side] = _json_preview(body, headers)
            except (TypeError, ValueError):
                card.json_values[side] = JSON_UNAVAILABLE
        root = card.json_values[side]
        if root is JSON_UNAVAILABLE:
            return "[complete JSON preview unavailable]", None, ""
        found, value = _json_at(root, path)
        if not found:
            return "[missing path]", (False, None), ""
        shown, _ = _json_value_text(value)
        return shown, (True, value), shown

    def _tail_card_header(self, row: dict) -> str:
        started = row.get("started")
        valid_started = type(started) in {int, float} and math.isfinite(started)
        try:
            stamp = time.strftime("%H:%M:%S", time.localtime(started)) if valid_started else "--:--:--"
        except (OverflowError, OSError, ValueError):
            stamp = "--:--:--"
        finished = row.get("response_completed") or row.get("ended")
        if type(finished) not in {int, float} or not math.isfinite(finished):
            finished = time.time()
        elapsed = f"{max(0, finished - started):.1f}s" if valid_started else "?s"
        status = row.get("status") if row.get("status") is not None else "pending"
        mark = ">" if row["id"] == self.selected else " "
        return (f"{mark} {stamp} #{_short_line(row['id'], 20)} {_short_line(row.get('agent') or '-', 32)} "
                f"{_short_line(row.get('method') or '-', 12)} {_short_line(row.get('url') or '-', 100)} "
                f"· {_short_line(status, 12)} {_short_line(row.get('state') or '', 20)} · {elapsed}")

    def _tail_render(self) -> tuple[str, list[int], list[tuple[int, int]]]:
        lines: list[str] = []
        card_offsets: list[int] = []
        spans: list[tuple[int, int]] = []
        length = 0

        def append(line: str) -> int:
            nonlocal length
            start = length
            lines.append(line)
            length += len(line) + 1
            return start

        append("LIVE TAIL · " + ("FOLLOW newest" if self.tail_follow else "PAUSED · End resumes newest")
               + " · polled view; unseen exchanges possible")
        if self.tail_poll_interrupted:
            append(f"[polling gap: {self.tail_failed_polls} failed snapshot(s); unseen exchanges possible]")
        if self.tail_departed:
            append(f"[snapshot gap: {self.tail_departed} previously visible flow(s) left retention/filter view]")
        visible = self._tail_visible()
        if len(self.flows) > len(visible):
            append(f"[showing {len(visible)} of {len(self.flows)} matching flows; older cards outside window]")
        if not visible:
            append("No matching flows. Scope and filter are shared with other clients.")
        previous: tuple[tuple[str, str], object | None, str] | None = None
        for row in visible:
            if lines:
                append("")
            card_offsets.append(length)
            append(self._tail_card_header(row))
            request, current_value, current_text = self._tail_body_content(row, "request")
            req_path = self.tail_pins["request"]
            same_endpoint = previous is not None and previous[0] == _endpoint(row)
            changed = bool(req_path is not None and same_endpoint and previous[1] is not None
                           and current_value is not None and previous[1] != current_value)
            req_prefix = "  → request" + (f" {_short_line(_json_path_text(req_path), 100)}" if req_path is not None else "")
            req_prefix += ": " + ("Δ " if changed else "")
            offset = append(req_prefix + request)
            if changed and previous is not None:
                marker = offset + len(req_prefix) - len("Δ ")
                spans.append((marker, marker + 1))
                spans.extend((offset + len(req_prefix) + start, offset + len(req_prefix) + end)
                             for start, end in _changed_spans(previous[2], current_text))
            previous = (_endpoint(row), current_value, current_text)
            response, _, _ = self._tail_body_content(row, "response")
            resp_path = self.tail_pins["response"]
            resp_prefix = "  ← response" + (f" {_short_line(_json_path_text(resp_path), 100)}" if resp_path is not None else "")
            append(resp_prefix + ": " + response)
        return "\n".join(lines), card_offsets, spans

    def _with_export_report(self, text: str) -> str:
        return text + (f"\n\n{self.export_report}" if self.export_report else "")

    def _http_body_text(self, row: dict, side: str) -> tuple[str, int | None]:
        if side in self.body_errors:
            key = "r" if side == "request" else "s"
            return f"retrieval failed ({self.body_errors[side]}); {key} retries", None
        if side in self.body_values:
            return _http_body_preview(
                self.body_values[side], row.get(f"{side}_headers", []), pretty=self.pretty, side=side
            )
        facts = row.get(f"{side}_body")
        if isinstance(facts, dict) and facts.get("reason") == "pending":
            return "pending: body capture is still in progress", None
        return "loading retained preview…", None

    def _http_section(self, row: dict, side: str) -> tuple[str, tuple[int, int, str] | None]:
        if side == "request":
            first = f"{plain_text(row.get('method'))} {_limited_text(plain_text(row.get('url')), 2048, 'URL')}"
        else:
            first = f"Status: {plain_text(row.get('status'))}"
        headers = _limited_text(
            "\n".join(http_header_lines(row.get(f"{side}_headers", []), hide_routine=self.hide_routine_headers)),
            12 * 1024,
            "headers",
        )
        body, content_length = self._http_body_text(row, side)
        prefix = f"HTTP {side}\n{first}\nHeaders:\n{headers}\nBody: "
        section = _limited_text(prefix + body, HTTP_SECTION_CHARS, side)
        media_type, _ = _content_type(row.get(f"{side}_headers", []))
        syntax_media = _body_syntax_lexer(media_type) is not None or media_type in {
            "application/x-www-form-urlencoded", "text/event-stream",
        }
        if content_length is None or not syntax_media:
            return section, None
        body_end = min(len(prefix) + content_length, HTTP_SECTION_CHARS)
        span = (len(prefix), body_end, media_type) if len(prefix) < body_end else None
        return section, span

    def _metadata_section(self, row: dict) -> str:
        lines = ["SafeYolo metadata"]
        for key in (
            "id", "connection_id", "agent", "state", "started", "request_completed",
            "response_head_observed", "response_completed", "ended", "error", "upstream",
        ):
            lines.append(f"{key}: {plain_text(row.get(key))}")
        if isinstance(row.get("websocket"), dict):
            lines.append("WebSocket session: " + plain_text(row["websocket"].get("state")) + " · w opens transcript")
        lines.append("metadata: " + plain_text(json.dumps(row.get("metadata", {}), ensure_ascii=True)))
        return _limited_text("\n".join(lines), 32 * 1024, "metadata")

    def _detail_render(self) -> tuple[str, list[tuple[int, int, str]]]:
        if self.pin_picker_side is not None:
            return self._pin_picker_text(), []
        if self.websocket_mode:
            error = plain_text((self.detail or {}).get("error"))
            text = f"error: {error}\n\n" + self.transcript.detail_text()
            return self._with_export_report(text), []
        row = self.detail
        if row is None:
            text = ("Loading selected exchange and both body previews…" if self.selected else
                    "Select a flow with Up/Down. Body previews load automatically.")
            return self._with_export_report(text), []
        request, request_span = self._http_section(row, "request")
        response, response_span = self._http_section(row, "response")
        separator = "\n\n──────── HTTP exchange ────────\n\n"
        text = request + separator + response
        text += "\n\n──────── SafeYolo ────────\n" + self._metadata_section(row)
        spans = []
        if request_span is not None:
            spans.append(request_span)
        if response_span is not None:
            start, end, media_type = response_span
            shift = len(request) + len(separator)
            spans.append((start + shift, end + shift, media_type))
        if len(text) > DETAIL_PREVIEW_CHARS:
            text = text[:DETAIL_PREVIEW_CHARS] + "\n[detail preview truncated]"
            spans = [(start, min(end, DETAIL_PREVIEW_CHARS), media_type)
                     for start, end, media_type in spans if start < DETAIL_PREVIEW_CHARS]
        return self._with_export_report(text), spans

    def detail_text(self) -> str:
        return self._detail_render()[0]

    def _show(self, rows: TextArea, detail: TextArea) -> None:
        rows.wrap_lines = self.tail_mode and not self.websocket_mode
        detail_text, body_spans = self._detail_render()
        self.detail_syntax.update(detail_text, body_spans)
        if self.tail_mode and not self.websocket_mode:
            rows_text, card_offsets, tail_spans = self._tail_render()
            self.tail_syntax.update(rows_text, tail_spans)
        else:
            rows_text, card_offsets = self.rows_text(), []
            self.tail_syntax.update(rows_text, [])
        for area, text in ((rows, rows_text), (detail, detail_text)):
            if area.text != text:
                position = area.buffer.cursor_position
                area.text = text
                area.buffer.cursor_position = min(position, len(text))
        selected = self.transcript.selected if self.websocket_mode else self.selected
        items = (self.transcript.messages if self.websocket_mode else
                 self._tail_visible() if self.tail_mode else self.flows)
        if selected is not None:
            index = next((i for i, row in enumerate(items) if row["id"] == selected), None)
            if index is not None:
                if self.tail_mode and not self.websocket_mode:
                    rows.buffer.cursor_position = (len(rows.text) if self.tail_follow else card_offsets[index])
                else:
                    rows.buffer.cursor_position = sum(len(line) + 1 for line in rows.text.splitlines()[:index])

    def _finish_prompt(
        self,
        buffer,
        prompt_field: list[str],
        export_flows: list[tuple[str, ...]],
        export_format: list[str],
        rows: TextArea,
        prompt: TextArea,
    ) -> bool:
        field = prompt_field.pop()
        if field == "user_filter":
            self.set_filter(buffer.text)
        elif field in {"agent", "test_id"}:
            self.set_scope(field, buffer.text)
        elif field == "export_format":
            return self._finish_export_format(buffer, prompt_field, export_flows, export_format, rows, prompt)
        else:
            flow_ids = export_flows.pop()
            format_name = export_format.pop()
            self.queue_exports(flow_ids, format_name, buffer.text)
        get_app().layout.focus(rows)
        prompt.text, prompt.prompt = "", ""
        return False

    def _finish_export_format(
        self,
        buffer,
        prompt_field: list[str],
        export_flows: list[tuple[str, ...]],
        export_format: list[str],
        rows: TextArea,
        prompt: TextArea,
    ) -> bool:
        format_name = buffer.text.strip()
        flow_ids = export_flows.pop()
        if format_name not in EXPORT_FORMATS:
            self._hold_notice("Export format must be raw, raw_request, raw_response, curl, httpie, har, or zhar")
            get_app().layout.focus(rows)
            prompt.text, prompt.prompt = "", ""
            return False
        export_flows.append(flow_ids)
        export_format.append(format_name)
        prompt_field.append("export_path")
        prompt.text = ""
        prompt.buffer.cursor_position = 0
        if len(flow_ids) == 1:
            prompt.prompt = "Local destination path (Escape cancels): "
        else:
            prompt.prompt = "Existing destination directory for marked exports (Escape cancels): "
        return False

    def _add_export_binding(
        self,
        bindings: KeyBindings,
        browsing: Condition,
        rows: TextArea,
        prompt: TextArea,
        prompt_field: list[str],
        export_flows: list[tuple[str, ...]],
    ) -> None:
        @bindings.add("x", filter=browsing)
        def export(event) -> None:
            flow_ids = self.export_flow_ids()
            if not flow_ids:
                self._hold_notice("Select a flow before exporting")
                return
            export_flows.append(flow_ids)
            prompt_field.append("export_format")
            prompt.text = ""
            prompt.buffer.cursor_position = 0
            prompt.prompt = "Format [raw/raw_request/raw_response/curl/httpie/har/zhar] (Escape cancels): "
            event.app.layout.focus(prompt)

    def _bindings(self, rows: TextArea, detail: TextArea, prompt: TextArea) -> KeyBindings:
        prompt_field: list[str] = []
        export_flows: list[tuple[str, ...]] = []
        export_format: list[str] = []
        bindings = KeyBindings()

        def finish_prompt(buffer) -> bool:
            return self._finish_prompt(buffer, prompt_field, export_flows, export_format, rows, prompt)

        prompt.accept_handler = finish_prompt

        browsing = Condition(lambda: not prompt_field and self.pin_picker_side is None)
        pinning = Condition(lambda: self.pin_picker_side is not None)
        listing = browsing & Condition(lambda: get_app().layout.has_focus(rows))

        @bindings.add("q", filter=browsing)
        @bindings.add("c-c")
        def quit_view(event) -> None:
            self.cancel_export()
            event.app.exit()

        @bindings.add("up", filter=listing)
        @bindings.add("down", filter=listing)
        def move(event) -> None:
            self.select({"up": -1, "down": 1}[event.key_sequence[0].key])
            self._show(rows, detail)
        self._tail_bindings(bindings, browsing, listing, rows, detail)
        self._pin_bindings(bindings, pinning, rows, detail)

        @bindings.add("tab", filter=browsing)
        def focus(event) -> None:
            if self.tail_mode and not self.websocket_mode:
                self.tail_detail_open = not self.tail_detail_open
                if self.tail_detail_open:
                    self.tail_follow = False
                event.app.layout.focus(detail if self.tail_detail_open else rows)
                self._show(rows, detail)
            else:
                event.app.layout.focus(detail if event.app.layout.has_focus(rows) else rows)

        @bindings.add("r", filter=browsing)
        @bindings.add("s", filter=browsing)
        def body(event) -> None:
            self.request_body({"r": "request", "s": "response"}[event.key_sequence[0].key])

        self._display_bindings(bindings, browsing, rows, detail)

        @bindings.add("m", filter=browsing)
        def mark(event) -> None:
            self.toggle_mark()
            self._show(rows, detail)

        @bindings.add("c", filter=browsing)
        def clear(event) -> None:
            self._selection_revision += 1
            self.pending_scope = {}
            self.wake.set()

        @bindings.add("a", filter=browsing)
        @bindings.add("t", filter=browsing)
        @bindings.add("f", filter=browsing)
        def scope(event) -> None:
            field = {"a": "agent", "t": "test_id", "f": "user_filter"}[event.key_sequence[0].key]
            prompt_field.append(field)
            prompt.text = self.scope.get("user_filter", "") if field == "user_filter" else ""
            prompt.buffer.cursor_position = len(prompt.text)
            prompt.prompt = "User filter (empty clears filter): " if field == "user_filter" else f"{field} (empty clears): "
            event.app.layout.focus(prompt)

        self._add_export_binding(bindings, browsing, rows, prompt, prompt_field, export_flows)

        @bindings.add("escape", filter=Condition(lambda: bool(prompt_field)))
        def cancel_prompt(event) -> None:
            prompt_field.clear()
            export_flows.clear()
            export_format.clear()
            prompt.text, prompt.prompt = "", ""
            event.app.layout.focus(rows)

        self._websocket_bindings(bindings, browsing, rows, detail)
        return bindings

    def _tail_bindings(self, bindings: KeyBindings, browsing: Condition, listing: Condition,
                       rows: TextArea, detail: TextArea) -> None:
        tail_listing = listing & Condition(lambda: self.tail_mode and not self.websocket_mode)
        tail_browsing = browsing & Condition(lambda: self.tail_mode and not self.websocket_mode)

        @bindings.add("pageup", filter=tail_listing)
        @bindings.add("pagedown", filter=tail_listing)
        def move_page(event) -> None:
            self.select({"pageup": -5, "pagedown": 5}[event.key_sequence[0].key])
            self._show(rows, detail)

        @bindings.add("home", filter=tail_listing)
        def oldest(event) -> None:
            self.select(-TAIL_CARDS)
            self._show(rows, detail)

        @bindings.add("end", filter=tail_browsing)
        def resume(event) -> None:
            self.resume_tail()
            event.app.layout.focus(rows)
            self._show(rows, detail)

        @bindings.add("l", filter=browsing)
        def tail(event) -> None:
            self.toggle_tail()
            event.app.layout.focus(rows)
            self._show(rows, detail)

        @bindings.add("R", filter=tail_browsing)
        @bindings.add("S", filter=tail_browsing)
        def choose_pin(event) -> None:
            self.open_pin_picker({"R": "request", "S": "response"}[event.key_sequence[0].key])
            if self.pin_picker_side is not None:
                event.app.layout.focus(detail)
            self._show(rows, detail)

    def _pin_bindings(self, bindings: KeyBindings, pinning: Condition,
                      rows: TextArea, detail: TextArea) -> None:
        @bindings.add("up", filter=pinning)
        @bindings.add("down", filter=pinning)
        def picker_move(event) -> None:
            self.move_pin_picker({"up": -1, "down": 1}[event.key_sequence[0].key])
            self._show(rows, detail)

        @bindings.add("pageup", filter=pinning)
        @bindings.add("pagedown", filter=pinning)
        def picker_page(event) -> None:
            self.move_pin_picker({"pageup": -TAIL_PICKER_LINES, "pagedown": TAIL_PICKER_LINES}[
                event.key_sequence[0].key
            ])
            self._show(rows, detail)

        @bindings.add("right", filter=pinning)
        def picker_descend(event) -> None:
            self.descend_pin_picker()
            self._show(rows, detail)

        @bindings.add("left", filter=pinning)
        def picker_ascend(event) -> None:
            self.ascend_pin_picker()
            self._show(rows, detail)

        @bindings.add("enter", filter=pinning)
        def picker_pin(event) -> None:
            self.pin_picker_selection()
            event.app.layout.focus(rows)
            self._show(rows, detail)

        @bindings.add("backspace", filter=pinning)
        def picker_clear(event) -> None:
            self.clear_pin_picker()
            event.app.layout.focus(rows)
            self._show(rows, detail)

        @bindings.add("escape", filter=pinning)
        def picker_cancel(event) -> None:
            self.close_pin_picker()
            self.tail_detail_open = False
            event.app.layout.focus(rows)
            self._show(rows, detail)

    def _display_bindings(self, bindings: KeyBindings, browsing: Condition, rows: TextArea, detail: TextArea) -> None:
        @bindings.add("p", filter=browsing)
        def pretty(event) -> None:
            self.toggle_pretty()
            self._show(rows, detail)

        @bindings.add("h", filter=browsing)
        def headers(event) -> None:
            self.toggle_headers()
            self._show(rows, detail)

    def _websocket_bindings(self, bindings: KeyBindings, browsing: Condition, rows: TextArea, detail: TextArea) -> None:
        @bindings.add("w", filter=browsing)
        def websocket(event) -> None:
            self.toggle_websocket()
            self._show(rows, detail)

        @bindings.add("[", filter=browsing & Condition(lambda: self.websocket_mode))
        @bindings.add("]", filter=browsing & Condition(lambda: self.websocket_mode))
        def page(event) -> None:
            self.transcript.page({"[": -1, "]": 1}[event.key_sequence[0].key])
            self.wake.set()
            self._show(rows, detail)

    async def _poll(self, app: Application, rows: TextArea, detail: TextArea) -> None:
        try:
            while True:
                self.wake.clear()
                await self.refresh()
                self._show(rows, detail)
                app.invalidate()
                try:
                    await asyncio.wait_for(self.wake.wait(), timeout=1)
                except TimeoutError:
                    pass
        finally:
            self.cancel_export()

    def help_text(self) -> str:
        if self.pin_picker_side is not None:
            return "↑↓/PgUp/PgDn choose · → subtree · ← parent · Enter pin · Backspace clear pin · Esc cancel"
        view = "w HTTP · [/] message page · r/s retry HTTP body" if self.websocket_mode else "r/s retry body · w WebSocket"
        body_mode = "formatted" if self.pretty else "source"
        headers = "hidden" if self.hide_routine_headers else "shown"
        tail = ("" if self.websocket_mode else
                "l list · End resume · ↑↓/PgUp/PgDn pause · R/S pin JSON · Tab detail/cards · "
                if self.tail_mode else "l live tail · ")
        return (
            f"{tail}p body {body_mode} · h routine headers {headers} · ↑↓ select · > focus · * marked · "
            f"Tab pane · PgUp/PgDn scroll · {view} · m mark/unmark · "
            "x export marked (or focused) · f filter · a/t scope · c clear scope · q detach"
        )

    def application(self) -> Application:
        detail = TextArea(read_only=True, scrollbar=True, wrap_lines=True, lexer=self.detail_syntax)
        rows = TextArea(read_only=True, scrollbar=True, wrap_lines=False, lexer=self.tail_syntax)
        prompt = TextArea(height=1, multiline=False)
        split_view = VSplit([rows, Window(width=1, char="│"), detail])
        traffic_view = DynamicContainer(lambda: (
            detail if self.tail_detail_open else rows
        ) if self.tail_mode and not self.websocket_mode else split_view)
        app = Application(
            layout=Layout(HSplit([
                Window(FormattedTextControl(lambda: plain_text(self.notice)), height=1),
                Window(FormattedTextControl(lambda: "Scope: " + plain_text(self.scope.get("effective_filter") or "all traffic")), height=1),
                traffic_view,
                Window(FormattedTextControl(self.help_text), height=1),
                prompt,
            ]), focused_element=rows),
            key_bindings=self._bindings(rows, detail, prompt), full_screen=True,
        )
        app.pre_run_callables.append(lambda: app.create_background_task(self._poll(app, rows, detail)))
        return app


def inspect_traffic(api: AdminAPI) -> None:
    """Attach a terminal client without acquiring any proxy shutdown ownership."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("Traffic inspection needs a terminal; use --no-attach to update scope only.")
    view = TrafficInspector(api)
    try:
        view.application().run()
    except (KeyboardInterrupt, EOFError):
        # Closing the UI is a detach. No lifecycle operation belongs here.
        pass
    finally:
        view.cancel_export()
