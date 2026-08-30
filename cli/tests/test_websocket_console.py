"""Contracts for SafeYolo's bounded native WebSocket presentation."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from mitmproxy import contentviews, options
from mitmproxy.test import tflow
from mitmproxy.tools.console import flowview as console_flowview
from mitmproxy.tools.web import app
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode

from safeyolo.traffic_master import TrafficMaster, WebFrontend
from safeyolo.websocket_console import (
    WEBSOCKET_CONSOLE_MAX_BYTES,
    WEBSOCKET_CONSOLE_MAX_FRAME_BYTES,
    WEBSOCKET_CONSOLE_MAX_MESSAGES,
    BoundedWebSocketFlowDetails,
    install_bounded_websocket_renderer,
)


async def _construct_master() -> TrafficMaster:
    return TrafficMaster(options.Options())


def _master_and_flow(
    count: int,
    size: int,
) -> tuple[TrafficMaster, object, dict[str, str]]:
    master = asyncio.run(_construct_master())
    flow = tflow.twebsocketflow(messages=False)
    assert flow.websocket is not None
    flow.websocket.messages = [
        WebSocketMessage(
            Opcode.TEXT,
            bool(index % 2),
            (f"message-{index}:".encode() + b"x" * size)[:size],
            timestamp=946681203 + index,
        )
        for index in range(count)
    ]
    master.view.add([flow])
    mode = {"value": "raw"}
    master.commands.call = lambda _command: mode["value"]  # type: ignore[method-assign]
    return master, flow, mode


def test_thousands_of_messages_build_only_the_bounded_newest_window() -> None:
    master, flow, _mode = _master_and_flow(3_997, 900)
    assert flow.websocket is not None
    original_messages = tuple(flow.websocket.messages)
    original_contents = tuple(message.content for message in original_messages)
    details = BoundedWebSocketFlowDetails(master)

    view = details.view_websocket_messages()
    state = details._websocket_window

    assert state is not None
    assert len(state.entries) == WEBSOCKET_CONSOLE_MAX_MESSAGES
    assert state.render_bytes <= WEBSOCKET_CONSOLE_MAX_BYTES
    assert state.entries[0].index == 3_997 - WEBSOCKET_CONSOLE_MAX_MESSAGES
    assert state.entries[-1].index == 3_996
    assert "Showing newest 200 of 3997" in view.walker[1].text
    assert "3797 older messages omitted" in view.walker[1].text
    assert all(
        current is original
        for current, original in zip(
            flow.websocket.messages,
            original_messages,
            strict=True,
        )
    )
    assert all(
        message.content is original
        for message, original in zip(
            flow.websocket.messages,
            original_contents,
            strict=True,
        )
    )


def test_one_oversized_frame_is_copied_only_to_the_per_frame_limit() -> None:
    master, flow, _mode = _master_and_flow(0, 0)
    assert flow.websocket is not None
    payload = b"z" * (10 * 1024 * 1024)
    message = WebSocketMessage(Opcode.BINARY, True, payload)
    flow.websocket.messages = [message]
    details = BoundedWebSocketFlowDetails(master)
    formatted: list[WebSocketMessage] = []

    def prettify(bounded_message, _flow, _viewmode):
        formatted.append(bounded_message)
        return SimpleNamespace(text="bounded frame", syntax_highlight=None)

    with (
        patch(
            "safeyolo.websocket_console.contentviews.prettify_message",
            side_effect=prettify,
            autospec=True,
        ),
        patch(
            "safeyolo.websocket_console.mitmproxy_rs.syntax_highlight.highlight",
            return_value=["bounded frame"],
            autospec=True,
        ),
    ):
        view = details.view_websocket_messages()

    assert len(formatted) == 1
    assert formatted[0] is not message
    assert len(formatted[0].content) == WEBSOCKET_CONSOLE_MAX_FRAME_BYTES
    assert message.content is payload
    assert len(message.content) == 10 * 1024 * 1024
    rendered = view.walker[2].text
    assert "showing 65,536 bytes of 10,485,760 bytes" in rendered
    assert "10,420,224 bytes omitted from this widget only" in rendered
    assert "The full frame is retained" in rendered


@pytest.mark.parametrize(
    ("initial_count", "message_size"),
    [
        (WEBSOCKET_CONSOLE_MAX_MESSAGES, 32),
        (50, 50_000),
    ],
)
def test_live_append_formats_one_widget_and_evicts_incrementally(
    initial_count: int,
    message_size: int,
) -> None:
    master, flow, _mode = _master_and_flow(initial_count, message_size)
    assert flow.websocket is not None
    details = BoundedWebSocketFlowDetails(master)
    view = details.view_websocket_messages()
    state = details._websocket_window
    assert state is not None
    first_index = state.entries[0].index

    flow.websocket.messages.append(
        WebSocketMessage(Opcode.TEXT, True, b"n" * message_size)
    )
    with patch.object(
        details,
        "_render_message",
        side_effect=details._render_message,
        autospec=True,
    ) as render:
        updated = details.view_websocket_messages()

    state = details._websocket_window
    assert state is not None
    assert updated is view
    assert render.call_count == 1
    assert state.entries[0].index == first_index + 1
    assert state.entries[-1].message is flow.websocket.messages[-1]
    assert len(state.entries) <= WEBSOCKET_CONSOLE_MAX_MESSAGES
    assert state.render_bytes <= WEBSOCKET_CONSOLE_MAX_BYTES
    assert len(flow.websocket.messages) == initial_count + 1


def test_content_view_change_rebuilds_only_the_bounded_window() -> None:
    master, _flow, mode = _master_and_flow(4_000, 64)
    details = BoundedWebSocketFlowDetails(master)
    view = details.view_websocket_messages()
    mode["value"] = "hex stream"

    with patch.object(
        details,
        "_render_message",
        side_effect=details._render_message,
        autospec=True,
    ) as render:
        updated = details.view_websocket_messages()

    assert updated is view
    assert render.call_count == WEBSOCKET_CONSOLE_MAX_MESSAGES
    assert details._websocket_window is not None
    assert details._websocket_window.viewmode == "hex stream"


def test_search_highlight_is_cleared_before_eviction_notice_and_rebuild() -> None:
    master, flow, mode = _master_and_flow(WEBSOCKET_CONSOLE_MAX_MESSAGES, 32)
    assert flow.websocket is not None
    details = BoundedWebSocketFlowDetails(master)
    view = details.view_websocket_messages()
    view.set_search("message-0")
    assert view.current_highlight == 2

    flow.websocket.messages.append(
        WebSocketMessage(Opcode.TEXT, True, b"newest live message")
    )
    assert details.view_websocket_messages() is view
    assert view.current_highlight is None
    view.find_next(False)
    assert view.current_highlight is None

    view.set_search("message-1:")
    assert view.current_highlight == 2
    mode["value"] = "hex stream"
    assert details.view_websocket_messages() is view
    assert view.current_highlight is None
    view.find_next(False)


def test_full_model_remains_available_to_mitmweb_and_evidence_consumers() -> None:
    master, flow, _mode = _master_and_flow(2_500, 128)
    assert flow.websocket is not None
    transcript = tuple(
        (message.from_client, message.timestamp, message.content)
        for message in flow.websocket.messages
    )
    details = BoundedWebSocketFlowDetails(master)

    details.view_websocket_messages()
    web_json = app.flow_to_json(flow)
    frontend = WebFrontend.__new__(WebFrontend)
    frontend.master = master
    with patch(
        "safeyolo.traffic_master.app.ClientConnection.broadcast_flow",
        autospec=True,
    ) as broadcast:
        frontend.view_update(flow)

    assert web_json["websocket"]["messages_meta"] == {
        "contentLength": sum(len(item[2]) for item in transcript),
        "count": len(transcript),
        "timestamp_last": transcript[-1][1],
    }
    broadcast.assert_called_once_with("flows/update", flow)
    assert tuple(
        (message.from_client, message.timestamp, message.content)
        for message in flow.websocket.messages
    ) == transcript


def test_private_console_integration_is_guarded_and_replaces_only_details() -> None:
    master = asyncio.run(_construct_master())
    master.ui = SimpleNamespace(get_cols_rows=lambda: (120, 40))
    first = console_flowview.FlowView(master)
    second = console_flowview.FlowView(master)
    old_bodies = (first.body, second.body)
    master.window = SimpleNamespace(
        stacks=[
            SimpleNamespace(windows={"flowview": first}),
            SimpleNamespace(windows={"flowview": second}),
        ]
    )

    install_bounded_websocket_renderer(master)

    assert first.header.__class__ is console_flowview.FlowViewHeader
    assert second.header.__class__ is console_flowview.FlowViewHeader
    assert isinstance(first.body, BoundedWebSocketFlowDetails)
    assert isinstance(second.body, BoundedWebSocketFlowDetails)
    assert first.body is not old_bodies[0]
    assert second.body is not old_bodies[1]
    receivers = [
        receiver
        for reference in contentviews.registry.on_change.receivers
        if (receiver := reference()) is not None
    ]
    assert old_bodies[0].contentview_changed not in receivers
    assert old_bodies[1].contentview_changed not in receivers
    assert first.body.contentview_changed in receivers
    assert second.body.contentview_changed in receivers

    installed_bodies = (first.body, second.body)
    install_bounded_websocket_renderer(master)
    assert (first.body, second.body) == installed_bodies

    master.window = SimpleNamespace(stacks=[])
    with pytest.raises(RuntimeError, match="Window.stacks is unavailable"):
        install_bounded_websocket_renderer(master)


def test_realistic_transcript_returns_control_to_shared_master_promptly() -> None:
    master, flow, _mode = _master_and_flow(4_000, 900)
    details = BoundedWebSocketFlowDetails(master)
    callbacks: list[str] = []

    async def exercise() -> float:
        loop = asyncio.get_running_loop()
        for component in ("console", "mitmweb", "proxy", "admin"):
            loop.call_soon(callbacks.append, component)
        started = time.perf_counter()
        details.view_websocket_messages()
        elapsed = time.perf_counter() - started
        await asyncio.sleep(0)
        return elapsed

    elapsed = asyncio.run(exercise())

    assert callbacks == ["console", "mitmweb", "proxy", "admin"]
    assert elapsed < 2.0
    assert details._websocket_window is not None
    assert details._websocket_window.total_count == len(flow.websocket.messages)
