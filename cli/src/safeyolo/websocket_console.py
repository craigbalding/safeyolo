"""Bounded, presentation-only WebSocket rendering for the native console.

Mitmproxy 12.2's console renderer formats every retained WebSocket message on
each rebuild. SafeYolo shares that event loop with the proxy and mitmweb, so a
large transcript can stall all three frontends. This module replaces only the
native ``FlowDetails`` body after mitmproxy constructs its console window. The
underlying flow and its messages are never changed.

The integration touches a deliberately small set of private console details.
``install_bounded_websocket_renderer`` validates that shape before installing
the renderer so a future mitmproxy upgrade fails explicitly instead of silently
restoring the unbounded path.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

import mitmproxy_rs.syntax_highlight
import urwid
from mitmproxy import contentviews, http
from mitmproxy.tools.console import flowview as console_flowview
from mitmproxy.tools.console import searchable
from mitmproxy.websocket import WebSocketMessage

WEBSOCKET_CONSOLE_MAX_MESSAGES = 200
WEBSOCKET_CONSOLE_MAX_BYTES = 2 * 1024 * 1024
WEBSOCKET_CONSOLE_MAX_FRAME_BYTES = 64 * 1024


@dataclass(slots=True)
class _RenderedMessage:
    index: int
    message: WebSocketMessage
    content: bytes
    signature: tuple[Any, ...]
    render_bytes: int
    widget: urwid.Text


@dataclass(slots=True)
class _WebSocketWindow:
    flow_id: str
    viewmode: str
    total_count: int
    entries: deque[_RenderedMessage]
    render_bytes: int
    view: searchable.Searchable
    close_signature: tuple[Any, ...] | None = None
    intercepted: bool = False


def _message_signature(message: WebSocketMessage) -> tuple[Any, ...]:
    return (
        message.type,
        message.from_client,
        message.dropped,
        message.injected,
        id(message.content),
        len(message.content),
    )


def _render_cost(message: WebSocketMessage) -> int:
    return min(len(message.content), WEBSOCKET_CONSOLE_MAX_FRAME_BYTES)


def _exact_bytes(value: int) -> str:
    return f"{value:,} bytes"


def _clear_search_highlight(view: searchable.Searchable) -> None:
    """Restore Searchable's wrapped widget before mutating its walker.

    Mitmproxy stores the highlighted walker index separately. Deleting or
    replacing that element without first restoring its ``Highlight.backup``
    leaves a stale index that crashes the next search navigation.
    """
    offset = view.current_highlight
    if offset is None:
        return
    view.current_highlight = None
    if 0 <= offset < len(view.walker):
        highlighted = view.walker[offset]
        if isinstance(highlighted, searchable.Highlight):
            view.walker[offset] = highlighted.backup


class BoundedWebSocketFlowDetails(console_flowview.FlowDetails):
    """Mitmproxy flow details with a bounded WebSocket presentation window."""

    def __init__(self, master: Any) -> None:
        super().__init__(master)
        self._websocket_window: _WebSocketWindow | None = None
        self._websocket_force_rebuild = False

    def contentview_changed(self, view: Any) -> None:
        """Invalidate only the bounded window when a content view reloads."""
        self._websocket_force_rebuild = True
        super().contentview_changed(view)

    def view_websocket_messages(self) -> searchable.Searchable:
        flow = self.flow
        assert isinstance(flow, http.HTTPFlow)
        assert flow.websocket is not None

        messages = flow.websocket.messages
        if not messages:
            self._websocket_window = None
            view = self.last_displayed_websocket_messages
            if view is None:
                view = searchable.Searchable([])
                self.last_displayed_websocket_messages = view
            _clear_search_highlight(view)
            view.walker[:] = [urwid.Text(("highlight", "No messages."))]
            return view

        viewmode = self.master.commands.call("console.flowview.mode")
        state = self._websocket_window
        if not self._can_append(state, flow, viewmode):
            return self._rebuild(flow, viewmode)

        assert state is not None
        if len(messages) > state.total_count:
            if not self._append_new_messages(state, flow):
                return self._rebuild(flow, viewmode)
        else:
            self._remove_suffix(state)

        self._update_notice(state)
        self._add_suffix(state, flow)
        return state.view

    def _can_append(
        self,
        state: _WebSocketWindow | None,
        flow: http.HTTPFlow,
        viewmode: str,
    ) -> bool:
        if self._websocket_force_rebuild or state is None:
            return False
        if state.flow_id != flow.id or state.viewmode != viewmode:
            return False

        assert flow.websocket is not None
        messages = flow.websocket.messages
        if len(messages) < state.total_count:
            return False
        if state.total_count and (
            state.entries[-1].index != state.total_count - 1
            or messages[state.total_count - 1] is not state.entries[-1].message
        ):
            return False

        # Editing or replacing a visible message must refresh it. This scan is
        # bounded by the console window, never by the full transcript.
        for entry in state.entries:
            if (
                entry.index >= len(messages)
                or messages[entry.index] is not entry.message
                or _message_signature(entry.message) != entry.signature
            ):
                return False
        return True

    def _append_new_messages(
        self,
        state: _WebSocketWindow,
        flow: http.HTTPFlow,
    ) -> bool:
        assert flow.websocket is not None
        messages = flow.websocket.messages
        added_count = len(messages) - state.total_count
        if added_count > WEBSOCKET_CONSOLE_MAX_MESSAGES:
            return False

        added_bytes = 0
        for index in range(state.total_count, len(messages)):
            added_bytes += _render_cost(messages[index])
            if added_bytes > WEBSOCKET_CONSOLE_MAX_BYTES:
                return False

        self._remove_suffix(state)
        for index in range(state.total_count, len(messages)):
            entry = self._render_message(messages[index], index, flow, state.viewmode)
            state.entries.append(entry)
            state.render_bytes += entry.render_bytes
            state.view.walker.append(entry.widget)

            while (
                len(state.entries) > WEBSOCKET_CONSOLE_MAX_MESSAGES
                or state.render_bytes > WEBSOCKET_CONSOLE_MAX_BYTES
            ):
                evicted = state.entries.popleft()
                state.render_bytes -= evicted.render_bytes
                del state.view.walker[2]

        state.total_count = len(messages)
        return True

    def _rebuild(
        self,
        flow: http.HTTPFlow,
        viewmode: str,
    ) -> searchable.Searchable:
        assert flow.websocket is not None
        messages = flow.websocket.messages
        selected: list[tuple[int, WebSocketMessage]] = []
        selected_bytes = 0
        lower = max(0, len(messages) - WEBSOCKET_CONSOLE_MAX_MESSAGES)

        for index in range(len(messages) - 1, lower - 1, -1):
            message = messages[index]
            cost = _render_cost(message)
            if selected and selected_bytes + cost > WEBSOCKET_CONSOLE_MAX_BYTES:
                break
            selected.append((index, message))
            selected_bytes += cost

        entries = deque(
            self._render_message(message, index, flow, viewmode)
            for index, message in reversed(selected)
        )
        view = self.last_displayed_websocket_messages
        if view is None:
            view = searchable.Searchable([])
            self.last_displayed_websocket_messages = view

        state = _WebSocketWindow(
            flow_id=flow.id,
            viewmode=viewmode,
            total_count=len(messages),
            entries=entries,
            render_bytes=sum(entry.render_bytes for entry in entries),
            view=view,
        )
        self._websocket_window = state
        self._websocket_force_rebuild = False
        _clear_search_highlight(view)
        view.walker[:] = [
            self._contentview_status_bar(viewmode.capitalize(), viewmode),
            self._notice_widget(state),
            *(entry.widget for entry in entries),
        ]
        self._add_suffix(state, flow)
        return view

    def _render_message(
        self,
        message: WebSocketMessage,
        index: int,
        flow: http.HTTPFlow,
        viewmode: str,
    ) -> _RenderedMessage:
        original_content = message.content
        render_bytes = _render_cost(message)
        if render_bytes < len(original_content):
            rendered_message = WebSocketMessage(
                message.type,
                message.from_client,
                original_content[:render_bytes],
                timestamp=message.timestamp,
                dropped=message.dropped,
                injected=message.injected,
            )
        else:
            rendered_message = message

        pretty = contentviews.prettify_message(rendered_message, flow, viewmode)
        chunks = mitmproxy_rs.syntax_highlight.highlight(
            pretty.text,
            language=pretty.syntax_highlight,
        )
        marker = (
            self.FROM_CLIENT_MARKER
            if message.from_client
            else self.TO_CLIENT_MARKER
        )
        markup: list[Any] = [marker, *chunks]
        if render_bytes < len(original_content):
            omitted = len(original_content) - render_bytes
            markup.extend(
                [
                    "\n",
                    (
                        "highlight",
                        "[Console frame limit: showing "
                        f"{_exact_bytes(render_bytes)} of "
                        f"{_exact_bytes(len(original_content))}; "
                        f"{_exact_bytes(omitted)} omitted from this widget only. "
                        "The full frame is retained.]",
                    ),
                ]
            )

        return _RenderedMessage(
            index=index,
            message=message,
            content=original_content,
            signature=_message_signature(message),
            render_bytes=render_bytes,
            widget=urwid.Text(markup),
        )

    def _notice_widget(self, state: _WebSocketWindow) -> urwid.Text:
        shown = len(state.entries)
        omitted = state.total_count - shown
        if omitted:
            scope = (
                f"Showing newest {shown} of {state.total_count} WebSocket messages; "
                f"{omitted} older messages omitted from the native console."
            )
        else:
            scope = f"Showing all {shown} WebSocket messages."
        return urwid.Text(
            (
                "highlight",
                f"{scope} Formatting window: at most "
                f"{WEBSOCKET_CONSOLE_MAX_MESSAGES} messages / "
                f"{_exact_bytes(WEBSOCKET_CONSOLE_MAX_BYTES)} total / "
                f"{_exact_bytes(WEBSOCKET_CONSOLE_MAX_FRAME_BYTES)} per frame. "
                "The full transcript remains retained for mitmweb and evidence.",
            )
        )

    def _update_notice(self, state: _WebSocketWindow) -> None:
        _clear_search_highlight(state.view)
        state.view.walker[1] = self._notice_widget(state)

    @staticmethod
    def _close_signature(flow: http.HTTPFlow) -> tuple[Any, ...] | None:
        assert flow.websocket is not None
        if flow.websocket.closed_by_client is None:
            return None
        return (
            flow.websocket.closed_by_client,
            flow.websocket.close_code,
            flow.websocket.close_reason,
        )

    def _close_widget(self, flow: http.HTTPFlow) -> urwid.Text | None:
        assert flow.websocket is not None
        if flow.websocket.closed_by_client is None:
            return None
        marker = (
            self.FROM_CLIENT_MARKER
            if flow.websocket.closed_by_client
            else self.TO_CLIENT_MARKER
        )
        level = (
            "alert"
            if flow.websocket.close_code in (1000, 1001, 1005)
            else "error"
        )
        return urwid.Text(
            [
                marker,
                (
                    level,
                    "Connection closed: "
                    f"{flow.websocket.close_code} {flow.websocket.close_reason}",
                ),
            ]
        )

    def _remove_suffix(self, state: _WebSocketWindow) -> None:
        _clear_search_highlight(state.view)
        if state.close_signature is not None:
            state.view.walker.pop()
        elif state.intercepted and state.entries:
            state.view.walker[len(state.entries) + 1] = state.entries[-1].widget
        state.close_signature = None
        state.intercepted = False

    def _add_suffix(
        self,
        state: _WebSocketWindow,
        flow: http.HTTPFlow,
    ) -> None:
        _clear_search_highlight(state.view)
        close = self._close_widget(flow)
        if close is not None:
            state.view.walker.append(close)
        state.close_signature = self._close_signature(flow)

        if flow.intercepted and (close is not None or state.entries):
            target = len(state.view.walker) - 1
            markup = state.view.walker[target].get_text()[0]
            state.view.walker[target] = urwid.Text(("intercept", markup))
            state.intercepted = True


def _compatibility_error(detail: str) -> RuntimeError:
    return RuntimeError(
        "mitmproxy console internals are incompatible with SafeYolo's bounded "
        f"WebSocket renderer: {detail}"
    )


def install_bounded_websocket_renderer(master: Any) -> None:
    """Replace stock flow-detail bodies after mitmproxy builds its window."""
    window = getattr(master, "window", None)
    stacks = getattr(window, "stacks", None)
    if not isinstance(stacks, list) or not stacks:
        raise _compatibility_error("Window.stacks is unavailable")

    targets: list[tuple[Any, console_flowview.FlowDetails]] = []
    for stack in stacks:
        windows = getattr(stack, "windows", None)
        if not isinstance(windows, dict) or "flowview" not in windows:
            raise _compatibility_error("WindowStack.windows['flowview'] is unavailable")
        flow_view = windows["flowview"]
        body = getattr(flow_view, "body", None)
        if isinstance(body, BoundedWebSocketFlowDetails):
            continue
        if not isinstance(flow_view, console_flowview.FlowView):
            raise _compatibility_error("flowview is not mitmproxy FlowView")
        if not isinstance(body, console_flowview.FlowDetails):
            raise _compatibility_error("FlowView.body is not mitmproxy FlowDetails")
        for attribute in (
            "_contentview_status_bar",
            "FROM_CLIENT_MARKER",
            "TO_CLIENT_MARKER",
        ):
            if not hasattr(body, attribute):
                raise _compatibility_error(f"FlowDetails.{attribute} is unavailable")
        if not hasattr(searchable, "Highlight") or not hasattr(
            searchable.Searchable,
            "set_highlight",
        ):
            raise _compatibility_error("Searchable highlight state is unavailable")
        targets.append((flow_view, body))

    replacements: list[BoundedWebSocketFlowDetails] = []
    try:
        replacements = [BoundedWebSocketFlowDetails(master) for _ in targets]
        for (flow_view, old_body), replacement in zip(
            targets,
            replacements,
            strict=True,
        ):
            contentviews.registry.on_change.disconnect(old_body.contentview_changed)
            flow_view.body = replacement
    except Exception as exc:
        for replacement in replacements:
            contentviews.registry.on_change.disconnect(replacement.contentview_changed)
        if isinstance(exc, RuntimeError) and str(exc).startswith(
            "mitmproxy console internals are incompatible"
        ):
            raise
        raise _compatibility_error(str(exc)) from exc
