"""Read-only terminal inspection of the proxy-owned ordinary HTTP view."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import sys
import unicodedata

from prompt_toolkit.application import Application, get_app
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import TextArea

from .api import AdminAPI, APIError

# Rendering limits leave the proxy's retained model and body response unchanged.
BODY_PREVIEW_BYTES = 64 * 1024
DETAIL_PREVIEW_CHARS = 128 * 1024


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
        self.pending_body: tuple[str, str] | None = None
        self.wake = asyncio.Event()

    def select(self, offset: int) -> None:
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

    def snapshot(self, document: dict) -> None:
        rows = document.get("flows")
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
            raise ValueError("Invalid traffic list response")
        self.flows = rows
        self.scope = document.get("scope", {})
        ids = [row["id"] for row in rows]
        self._select(self.selected if self.selected in ids else next(iter(ids), None))

    def request_body(self, side: str) -> None:
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

    async def refresh(self) -> None:
        """One worker serializes this mutable AdminAPI client's requests."""
        try:
            if self.pending_scope is not None:
                scope, self.pending_scope = self.pending_scope, None
                await asyncio.to_thread(self.api.set_traffic_scope, **scope)
            self.snapshot(await asyncio.to_thread(self.api.traffic_flows))
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
            if self.pending_body is not None:
                requested, self.pending_body = self.pending_body, None
                flow_id, side = requested
                value = await asyncio.to_thread(self.api.traffic_body, flow_id, side)
                if self.selected == flow_id:
                    self.body = f"{side.title()} body (fetched snapshot: encoded bytes, UTF-8 preview)\n{body_preview(value)}"
            self.notice = f"{len(self.flows)} visible flows · shared scope · q detaches"
        except (APIError, ValueError, TypeError) as exc:
            # Show only the category/status: an HTTP error body may contain traffic.
            status = exc.status_code if isinstance(exc, APIError) else None
            self.notice = f"View unavailable ({type(exc).__name__}{f' {status}' if status else ''}); retrying"

    def rows_text(self) -> str:
        lines = []
        for row in self.flows:
            mark = ">" if row["id"] == self.selected else " "
            text = f"{mark} {row.get('status') or '-'} {row.get('state', '')} {row.get('agent') or '-'} {row.get('method', '')} {row.get('url', '')}"
            lines.append(plain_text(text))
        return "\n".join(lines) or "No matching flows. Scope is shared with other clients."

    def detail_text(self) -> str:
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
        if self.selected:
            index = next(i for i, row in enumerate(self.flows) if row["id"] == self.selected)
            rows.buffer.cursor_position = sum(len(line) + 1 for line in rows.text.splitlines()[:index])

    def _bindings(self, rows: TextArea, detail: TextArea, prompt: TextArea) -> KeyBindings:
        prompt_field: list[str] = []
        bindings = KeyBindings()

        def finish_prompt(buffer) -> bool:
            self.set_scope(prompt_field.pop(), buffer.text)
            get_app().layout.focus(rows)
            prompt.prompt = ""
            return False

        prompt.accept_handler = finish_prompt

        browsing = Condition(lambda: not prompt_field)
        listing = browsing & Condition(lambda: get_app().layout.has_focus(rows))

        @bindings.add("q", filter=browsing)
        @bindings.add("c-c")
        def quit_view(event) -> None:
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
        def scope(event) -> None:
            field = {"a": "agent", "t": "test_id"}[event.key_sequence[0].key]
            prompt_field.append(field)
            prompt.prompt = f"{field} (empty clears): "
            event.app.layout.focus(prompt)

        @bindings.add("escape", filter=Condition(lambda: bool(prompt_field)))
        def cancel_prompt(event) -> None:
            prompt_field.clear()
            prompt.text, prompt.prompt = "", ""
            event.app.layout.focus(rows)

        return bindings

    async def _poll(self, app: Application, rows: TextArea, detail: TextArea) -> None:
        while True:
            self.wake.clear()
            await self.refresh()
            self._show(rows, detail)
            app.invalidate()
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=1)
            except TimeoutError:
                pass

    def application(self) -> Application:
        detail = TextArea(read_only=True, scrollbar=True, wrap_lines=True)
        rows = TextArea(read_only=True, scrollbar=True, wrap_lines=False)
        prompt = TextArea(height=1, multiline=False)
        app = Application(
            layout=Layout(HSplit([
                Window(FormattedTextControl(lambda: plain_text(self.notice)), height=1),
                Window(FormattedTextControl(lambda: "Scope: " + plain_text(self.scope.get("effective_filter") or "all traffic")), height=1),
                VSplit([rows, Window(width=1, char="│"), detail]),
                Window(FormattedTextControl("↑↓ select · Tab pane · PgUp/PgDn scroll · r/s body · a/t scope · c clear · q detach"), height=1),
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
    try:
        TrafficInspector(api).application().run()
    except (KeyboardInterrupt, EOFError):
        # Closing the UI is a detach. No lifecycle operation belongs here.
        pass
