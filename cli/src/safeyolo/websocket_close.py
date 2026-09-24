"""Complete both WebSocket close legs with the locked mitmproxy layer.

mitmproxy 12.2.3 echoes the first Close to both peers and immediately closes
both transports. This private-layer integration retains its message handling
while waiting for the other peer's own Close. Review it with a dependency bump.
"""

from __future__ import annotations

import time
from importlib.metadata import version

import wsproto.events
from mitmproxy import websocket
from mitmproxy.proxy import commands, events, layer
from mitmproxy.proxy.layers import websocket as websocket_layer
from mitmproxy.proxy.utils import expect
from wsproto import ConnectionState
from wsproto.frame_protocol import Opcode

CLOSE_REPLY_SECONDS = 10


def _end_close(self, close, from_client, *, reply=None, destination=None):
    self.flow.websocket.timestamp_end = time.time()
    self.flow.websocket.closed_by_client = from_client
    self.flow.websocket.close_code = close.code
    self.flow.websocket.close_reason = close.reason
    if reply is not None:
        yield destination.send2(reply)
    for ws in (self.server_ws, self.client_ws):
        yield commands.CloseConnection(ws.conn)
    yield websocket_layer.WebsocketEndHook(self.flow)
    self.flow.live = False
    self._handle_event = self.done


@expect(events.DataReceived, events.ConnectionClosed, events.Wakeup,
        websocket_layer.WebSocketMessageInjected)
def _relay_messages(self, event) -> layer.CommandGenerator[None]:
    assert self.flow.websocket

    if isinstance(event, events.Wakeup):
        if event.command is getattr(self, "_close_wakeup", None):
            _, from_client = self._first_close
            missing = wsproto.events.CloseConnection(code=1006)
            yield from _end_close(self, missing, from_client)
        return

    if isinstance(event, events.ConnectionEvent):
        from_client = event.connection == self.context.client
        injected = False
    elif isinstance(event, websocket_layer.WebSocketMessageInjected):
        from_client = event.message.from_client
        injected = True
    else:
        raise AssertionError(f"Unexpected event: {event}")

    from_str = "client" if from_client else "server"
    if from_client:
        src_ws, dst_ws = self.client_ws, self.server_ws
    else:
        src_ws, dst_ws = self.server_ws, self.client_ws

    if isinstance(event, events.DataReceived):
        src_ws.receive_data(event.data)
    elif isinstance(event, events.ConnectionClosed):
        src_ws.receive_data(None)
    elif isinstance(event, websocket_layer.WebSocketMessageInjected):
        fragmentizer = websocket_layer.Fragmentizer([], event.message.type == Opcode.TEXT)
        src_ws._events.extend(fragmentizer(event.message.content))
    else:  # pragma: no cover
        raise AssertionError(f"Unexpected event: {event}")

    for ws_event in src_ws.events():
        if isinstance(ws_event, wsproto.events.CloseConnection):
            first = getattr(self, "_first_close", None)
            if first is not None:
                first_event, first_from_client = first
                if (from_client != first_from_client
                        and isinstance(event, events.DataReceived)
                        and src_ws.state is ConnectionState.CLOSED):
                    yield from _end_close(self, first_event, first_from_client,
                                          reply=ws_event, destination=dst_ws)
                else:
                    # EOF or a protocol error is not the peer's Close frame.
                    missing = wsproto.events.CloseConnection(code=1006)
                    yield from _end_close(self, missing, first_from_client)
                return
            elif src_ws.state is ConnectionState.REMOTE_CLOSING:
                self._first_close = (ws_event, from_client)
                yield dst_ws.send2(ws_event)
                self._close_wakeup = commands.RequestWakeup(CLOSE_REPLY_SECONDS)
                yield self._close_wakeup
            else:
                # Preserve mitmproxy's immediate failure close for EOF and
                # malformed frames. 1006 is local and cannot be sent on wire.
                if ws_event.code != 1006:
                    for ws in (self.server_ws, self.client_ws):
                        if ws.state in {ConnectionState.OPEN, ConnectionState.REMOTE_CLOSING}:
                            yield ws.send2(ws_event)
                yield from _end_close(self, ws_event, from_client)
                return
            continue

        if getattr(self, "_first_close", None) is not None:
            # No application or control frame is admitted after Close.
            continue

        if isinstance(ws_event, wsproto.events.Message):
            is_text = isinstance(ws_event.data, str)
            if is_text:
                typ = Opcode.TEXT
                src_ws.frame_buf[-1] += ws_event.data.encode()
            else:
                typ = Opcode.BINARY
                src_ws.frame_buf[-1] += ws_event.data

            if ws_event.message_finished:
                content = b"".join(src_ws.frame_buf)
                fragmentizer = websocket_layer.Fragmentizer(src_ws.frame_buf, is_text)
                src_ws.frame_buf = [b""]
                message = websocket.WebSocketMessage(
                    typ, from_client, content, injected=injected
                )
                self.flow.websocket.messages.append(message)
                yield websocket_layer.WebsocketMessageHook(self.flow)
                if not message.dropped:
                    for msg in fragmentizer(message.content):
                        yield dst_ws.send2(msg)
            elif ws_event.frame_finished:
                src_ws.frame_buf.append(b"")
        elif isinstance(ws_event, (wsproto.events.Ping, wsproto.events.Pong)):
            yield commands.Log(
                f"Received WebSocket {ws_event.__class__.__name__.lower()} from {from_str} "
                f"(payload: {bytes(ws_event.payload)!r})"
            )
            yield dst_ws.send2(ws_event)
        else:  # pragma: no cover
            raise AssertionError(f"Unexpected WebSocket event: {ws_event}")


@expect(events.DataReceived, events.ConnectionClosed, events.Wakeup,
        websocket_layer.WebSocketMessageInjected)
def _done(self, _) -> layer.CommandGenerator[None]:
    yield from ()


def install_websocket_close_handshake() -> None:
    """Install the reviewed close path before any WebSocket is accepted."""
    if version("mitmproxy") != "12.2.3":
        raise RuntimeError("WebSocket close integration requires reviewed mitmproxy 12.2.3")
    websocket_layer.WebsocketLayer.relay_messages = _relay_messages
    websocket_layer.WebsocketLayer.done = _done
