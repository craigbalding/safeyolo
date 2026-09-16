"""Read-only terminal inspection of the proxy-owned HTTP and WebSocket view."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import sys
import unicodedata
from pathlib import Path

from prompt_toolkit.application import Application, get_app
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import TextArea

from .api import AdminAPI, APIError, ExportCancelled, ExportPublicationState, TrafficExportResult

# Rendering limits leave the proxy's retained model and body response unchanged.
BODY_PREVIEW_BYTES = 64 * 1024
DETAIL_PREVIEW_CHARS = 128 * 1024
EXPORT_FORMATS = ("raw", "raw_request", "raw_response", "curl", "httpie")


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


class TrafficInspector:
    """One client projection; scope and retained traffic remain proxy-owned."""

    def __init__(self, api: AdminAPI):
        self.api = api
        self.flows: list[dict] = []
        self.scope: dict = {}
        self.selected: str | None = None
        self.detail: dict | None = None
        self.body = ""
        self.notice = "Connecting…"
        self.pending_scope: dict | None = None
        self.pending_filter: str | None = None
        self.pending_body: tuple[str, str] | None = None
        self.pending_export: tuple[str, str, Path] | None = None
        self._export_cancel_event: ExportPublicationState | None = None
        self._notice_hold: str | None = None
        self.websocket_mode = False
        self.transcript = WebSocketTranscript()
        self.wake = asyncio.Event()

    def select(self, offset: int) -> None:
        if self.websocket_mode:
            self.transcript.select(offset)
            self.wake.set()
            return
        if not self.flows:
            return
        ids = [row["id"] for row in self.flows]
        index = ids.index(self.selected) if self.selected in ids else 0
        self._select(ids[max(0, min(len(ids) - 1, index + offset))])
        self.wake.set()

    def _select(self, flow_id: str | None) -> None:
        if flow_id != self.selected:
            self.selected, self.detail, self.body = flow_id, None, ""
            self.pending_body = None
            self.websocket_mode = False
            self.transcript = WebSocketTranscript()

    def snapshot(self, document: dict) -> None:
        rows = document.get("flows")
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
            raise ValueError("Invalid traffic list response")
        self.flows = rows
        self.scope = document.get("scope", {})
        ids = [row["id"] for row in rows]
        self._select(self.selected if self.selected in ids else next(iter(ids), None))

    def request_body(self, side: str) -> None:
        self.websocket_mode = False
        if self.selected:
            self.pending_body = self.selected, side
            self.wake.set()

    def set_scope(self, field: str, value: str) -> None:
        if field == "agent":
            self.pending_scope = {"agent": value or None}
        else:
            self.pending_scope = {"agent": self.scope.get("agent"),
                                  "unattributed": self.scope.get("unattributed", False),
                                  "test_id": value or None}
        self.wake.set()

    def set_filter(self, expression: str) -> None:
        self.pending_filter = expression
        self.wake.set()

    def queue_export(self, flow_id: str, format_name: str, destination: str) -> None:
        """Queue one local export using the flow ID selected at confirmation."""
        if format_name not in EXPORT_FORMATS:
            self._hold_notice("Export format is invalid")
            return
        if not destination.strip():
            self._hold_notice("Export destination is empty")
            return
        self.pending_export = flow_id, format_name, Path(destination).expanduser()
        self._hold_notice(f"Export queued for flow {plain_text(flow_id)}")
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

    async def _run_export(self, request: tuple[str, str, Path]) -> None:
        flow_id, format_name, destination = request
        cancel_event = ExportPublicationState()
        self._export_cancel_event = cancel_event
        try:
            result = await asyncio.to_thread(
                self.api.traffic_export,
                flow_id,
                format_name,
                destination,
                cancel_event=cancel_event,
            )
        except ExportCancelled:
            self._hold_notice("Export canceled; destination unchanged")
        except asyncio.CancelledError:
            cancel_event.set()
            raise
        except APIError as exc:
            status = f" {exc.status_code}" if exc.status_code is not None else ""
            self._hold_notice(f"Export unavailable (APIError{status}); destination unchanged")
        except (OSError, TypeError, ValueError) as exc:
            self._hold_notice(f"Export failed ({type(exc).__name__}); destination unchanged")
        else:
            if not isinstance(result, TrafficExportResult):
                self._hold_notice("Export failed (invalid result); destination unchanged")
            else:
                warning = f"; {result.cleanup_warning}" if result.cleanup_warning else ""
                self._hold_notice(
                    f"Exported flow {plain_text(flow_id)} to {plain_text(destination)} "
                    f"({result.bytes_written} bytes){warning}"
                )
        finally:
            self._export_cancel_event = None

    def toggle_websocket(self) -> None:
        if self.websocket_mode:
            self.websocket_mode = False
        elif self.detail is not None and isinstance(self.detail.get("websocket"), dict):
            self.websocket_mode = True
            self.pending_body = None
        else:
            self.notice = "Selected flow has no WebSocket session."
        self.wake.set()

    async def _refresh_detail(self) -> None:
        flow_id = self.selected
        if flow_id is not None:
            detail = await asyncio.to_thread(self.api.traffic_flow, flow_id)
            if not isinstance(detail, dict):
                raise ValueError("Invalid traffic detail response")
            if self.selected == flow_id:
                if self.detail is not None and any(
                    detail.get(key) != self.detail.get(key)
                    for key in ("state", "request_body", "response_body")
                ):
                    self.body = ""
                self.detail = detail

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
                    self.scope = scope
            raise
        self.snapshot(document)

    async def refresh(self) -> None:
        """One worker serializes this mutable AdminAPI client's requests."""
        try:
            if self.pending_scope is not None:
                scope, self.pending_scope = self.pending_scope, None
                self.scope = await asyncio.to_thread(self.api.set_traffic_scope, **scope)
            if self.pending_filter is not None:
                expression, self.pending_filter = self.pending_filter, None
                self.scope = await asyncio.to_thread(self.api.set_traffic_filter, expression)
            await self._refresh_flows()
            await self._refresh_detail()
            if self.websocket_mode and self.selected:
                await self._refresh_websocket()
            if self.pending_body is not None:
                requested, self.pending_body = self.pending_body, None
                flow_id, side = requested
                value = await asyncio.to_thread(self.api.traffic_body, flow_id, side)
                if self.selected == flow_id:
                    self.body = f"{side.title()} body (fetched snapshot: encoded bytes, UTF-8 preview)\n{body_preview(value)}"
            if self.pending_export is not None:
                request, self.pending_export = self.pending_export, None
                await self._run_export(request)
            if self._notice_hold is None:
                self.notice = f"{len(self.flows)} visible flows · shared scope · q detaches"
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
        lines = []
        for row in self.flows:
            mark = ">" if row["id"] == self.selected else " "
            text = f"{mark} {row.get('status') or '-'} {row.get('state', '')} {row.get('agent') or '-'} {row.get('method', '')} {row.get('url', '')}"
            lines.append(plain_text(text))
        return "\n".join(lines) or "No matching flows. Scope is shared with other clients."

    def detail_text(self) -> str:
        if self.websocket_mode:
            error = plain_text((self.detail or {}).get("error"))
            return f"error: {error}\n\n" + self.transcript.detail_text()
        row = self.detail
        if row is None:
            return "Select a flow with Up/Down. Bodies are fetched only with r/s."
        lines = [f"{key}: {plain_text(row.get(key))}" for key in
                 ("id", "connection_id", "agent", "method", "url", "status", "state", "started", "ended", "error")]
        for side in ("request", "response"):
            lines.append(f"\n{side.title()} body: {body_facts(row.get(f'{side}_body'))}")
            lines.append(f"{side.title()} headers:")
            for name, value in row.get(f"{side}_headers", []):
                lines.append(f"{plain_text(name)}: {plain_text(value)}")
        if isinstance(row.get("websocket"), dict):
            lines.append("\nWebSocket session: " + plain_text(row["websocket"].get("state")) + " · w opens transcript")
        lines.append("\nMetadata: " + plain_text(json.dumps(row.get("metadata", {}), ensure_ascii=True)))
        text = "\n".join(lines)
        if len(text) > DETAIL_PREVIEW_CHARS:
            text = text[:DETAIL_PREVIEW_CHARS] + "\n[detail preview truncated]"
        return text + ("\n\n" + self.body if self.body else "")

    def _show(self, rows: TextArea, detail: TextArea) -> None:
        for area, text in ((rows, self.rows_text()), (detail, self.detail_text())):
            if area.text != text:
                position = area.buffer.cursor_position
                area.text = text
                area.buffer.cursor_position = min(position, len(text))
        selected = self.transcript.selected if self.websocket_mode else self.selected
        items = self.transcript.messages if self.websocket_mode else self.flows
        if selected is not None:
            index = next(i for i, row in enumerate(items) if row["id"] == selected)
            rows.buffer.cursor_position = sum(len(line) + 1 for line in rows.text.splitlines()[:index])

    def _finish_prompt(
        self,
        buffer,
        prompt_field: list[str],
        export_flow: list[str],
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
            return self._finish_export_format(buffer, prompt_field, export_flow, export_format, rows, prompt)
        else:
            flow_id = export_flow.pop()
            format_name = export_format.pop()
            self.queue_export(flow_id, format_name, buffer.text)
        get_app().layout.focus(rows)
        prompt.text, prompt.prompt = "", ""
        return False

    def _finish_export_format(
        self,
        buffer,
        prompt_field: list[str],
        export_flow: list[str],
        export_format: list[str],
        rows: TextArea,
        prompt: TextArea,
    ) -> bool:
        format_name = buffer.text.strip()
        flow_id = export_flow.pop()
        if format_name not in EXPORT_FORMATS:
            self._hold_notice("Export format must be raw, raw_request, raw_response, curl, or httpie")
            get_app().layout.focus(rows)
            prompt.text, prompt.prompt = "", ""
            return False
        export_flow.append(flow_id)
        export_format.append(format_name)
        prompt_field.append("export_path")
        prompt.text = ""
        prompt.buffer.cursor_position = 0
        prompt.prompt = "Local destination path (Escape cancels): "
        return False

    def _add_export_binding(
        self,
        bindings: KeyBindings,
        browsing: Condition,
        rows: TextArea,
        prompt: TextArea,
        prompt_field: list[str],
        export_flow: list[str],
    ) -> None:
        @bindings.add("x", filter=browsing)
        def export(event) -> None:
            if self.selected is None:
                self._hold_notice("Select a flow before exporting")
                return
            export_flow.append(self.selected)
            prompt_field.append("export_format")
            prompt.text = ""
            prompt.buffer.cursor_position = 0
            prompt.prompt = "Format [raw/raw_request/raw_response/curl/httpie] (Escape cancels): "
            event.app.layout.focus(prompt)

    def _bindings(self, rows: TextArea, detail: TextArea, prompt: TextArea) -> KeyBindings:
        prompt_field: list[str] = []
        export_flow: list[str] = []
        export_format: list[str] = []
        bindings = KeyBindings()

        def finish_prompt(buffer) -> bool:
            return self._finish_prompt(buffer, prompt_field, export_flow, export_format, rows, prompt)

        prompt.accept_handler = finish_prompt

        browsing = Condition(lambda: not prompt_field)
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

        @bindings.add("tab", filter=browsing)
        def focus(event) -> None:
            event.app.layout.focus(detail if event.app.layout.has_focus(rows) else rows)

        @bindings.add("r", filter=browsing)
        @bindings.add("s", filter=browsing)
        def body(event) -> None:
            self.request_body({"r": "request", "s": "response"}[event.key_sequence[0].key])

        @bindings.add("c", filter=browsing)
        def clear(event) -> None:
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

        self._add_export_binding(bindings, browsing, rows, prompt, prompt_field, export_flow)

        @bindings.add("escape", filter=Condition(lambda: bool(prompt_field)))
        def cancel_prompt(event) -> None:
            prompt_field.clear()
            export_flow.clear()
            export_format.clear()
            prompt.text, prompt.prompt = "", ""
            event.app.layout.focus(rows)

        self._websocket_bindings(bindings, browsing, rows, detail)
        return bindings

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
        view = "w HTTP · [/] message page · r/s HTTP body" if self.websocket_mode else "r/s body · w WebSocket"
        return f"↑↓ select · Tab pane · PgUp/PgDn scroll · {view} · x export · f filter · a/t scope · c clear scope · q detach"

    def application(self) -> Application:
        detail = TextArea(read_only=True, scrollbar=True, wrap_lines=True)
        rows = TextArea(read_only=True, scrollbar=True, wrap_lines=False)
        prompt = TextArea(height=1, multiline=False)
        app = Application(
            layout=Layout(HSplit([
                Window(FormattedTextControl(lambda: plain_text(self.notice)), height=1),
                Window(FormattedTextControl(lambda: "Scope: " + plain_text(self.scope.get("effective_filter") or "all traffic")), height=1),
                VSplit([rows, Window(width=1, char="│"), detail]),
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
