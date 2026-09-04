"""Connection-boundary validation for raw HTTP/2 requests."""

from __future__ import annotations

import asyncio
import re
import tomllib
from importlib.metadata import version
from pathlib import Path

import h2.config
import h2.connection
import h2.errors
import h2.events
import pytest
from mitmproxy import http, options
from mitmproxy.proxy import mode_specs, server
from mitmproxy.proxy.layers import HttpLayer
from mitmproxy.proxy.layers.http import HTTPMode
from packaging.version import Version

PROJECT_ROOT = Path(__file__).parents[1]


def _test_options() -> options.Options:
    """Build the small option surface used by mitmproxy's server layer."""
    result = options.Options()
    for name, option_type, default in (
        ("store_streamed_bodies", bool, False),
        ("connection_strategy", str, "lazy"),
        ("keep_host_header", bool, False),
        ("validate_inbound_headers", bool, True),
        ("proxy_debug", bool, False),
    ):
        result.add_option(name, option_type, default, "")
    return result


async def _serve_request(headers: list[tuple[bytes, bytes]]) -> tuple[list[object], dict[str, int]]:
    """Run one raw h2 request through mitmproxy's live server handler."""
    hooks = {"request": 0, "requestheaders": 0, "server_connect": 0}
    handler_tasks: set[asyncio.Task[None]] = set()
    received: list[object] = []
    opts = _test_options()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        current = asyncio.current_task()
        assert current is not None
        handler_tasks.add(current)
        try:

            def next_layer(nextlayer):
                # The fixture deliberately sends h2 prior knowledge bytes. A
                # production listener obtains this value from TLS ALPN; setting
                # it here selects the same Http2Server in the raw fixture.
                nextlayer.context.client.alpn = b"h2"
                nextlayer.layer = HttpLayer(nextlayer.context, HTTPMode.regular)

            def requestheaders(_flow: http.HTTPFlow) -> None:
                hooks["requestheaders"] += 1

            def request(flow: http.HTTPFlow) -> None:
                hooks["request"] += 1
                # Keep the valid control hermetic: a response from the request
                # hook means the server layer has no reason to open upstream.
                flow.response = http.Response.make(204)

            def server_connect(_data) -> None:
                hooks["server_connect"] += 1

            await server.SimpleConnectionHandler(
                reader,
                writer,
                opts,
                mode_specs.ProxyMode.parse("regular"),
                {
                    "next_layer": next_layer,
                    "requestheaders": requestheaders,
                    "request": request,
                    "server_connect": server_connect,
                },
            ).handle_client()
        finally:
            handler_tasks.discard(current)

    listener = await asyncio.start_server(handle, "127.0.0.1", 0)
    assert listener.sockets
    port = listener.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = h2.connection.H2Connection(
        config=h2.config.H2Configuration(
            client_side=True,
            header_encoding=False,
            validate_outbound_headers=False,
        )
    )
    client.initiate_connection()
    client.send_headers(1, headers=headers, end_stream=True)
    writer.write(client.data_to_send())
    await writer.drain()

    try:
        for _ in range(20):
            data = await asyncio.wait_for(reader.read(65535), timeout=1)
            if not data:
                break
            received.extend(client.receive_data(data))
            if any(
                isinstance(event, (h2.events.ResponseReceived, h2.events.ConnectionTerminated)) for event in received
            ):
                break
    finally:
        writer.close()
        await writer.wait_closed()
        listener.close()
        await listener.wait_closed()
        if handler_tasks:
            await asyncio.wait_for(asyncio.gather(*handler_tasks), timeout=2)

    return received, hooks


COMMON_HEADERS = [
    (b":method", b"GET"),
    (b":scheme", b"http"),
    (b":authority", b"example.test"),
    (b":path", b"/"),
]


@pytest.mark.asyncio
async def test_http2_malformed_headers_stop_at_connection_boundary() -> None:
    """Reject duplicate Host and conflicting content-length before hooks/upstream."""
    cases = (
        COMMON_HEADERS
        + [(b"host", b"example.test"), (b"host", b"example.test")],
        COMMON_HEADERS + [(b"content-length", b"1"), (b"content-length", b"2")],
    )

    for headers in cases:
        events, hooks = await _serve_request(headers)

        terminations = [event for event in events if isinstance(event, h2.events.ConnectionTerminated)]
        assert terminations, events
        assert all(event.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR for event in terminations)
        assert hooks == {"request": 0, "requestheaders": 0, "server_connect": 0}


@pytest.mark.asyncio
async def test_http2_valid_request_reaches_request_hook() -> None:
    events, hooks = await _serve_request(COMMON_HEADERS)

    assert any(isinstance(event, h2.events.ResponseReceived) for event in events)
    assert hooks == {"request": 1, "requestheaders": 1, "server_connect": 0}


def test_runtime_h2_version_and_override_declarations_are_synchronized() -> None:
    assert Version(version("h2")) == Version("4.4.1")

    with (PROJECT_ROOT / "pyproject.toml").open("rb") as stream:
        project_overrides = tomllib.load(stream)["tool"]["uv"]["override-dependencies"]

    install_script = (PROJECT_ROOT / "install.sh").read_text()
    match = re.search(r"UV_OVERRIDES=\(\n(?P<body>.*?)\n\)", install_script, re.S)
    assert match, "install.sh UV_OVERRIDES declaration not found"
    install_overrides = re.findall(r'^\s+"([^"]+)"$', match.group("body"), re.M)

    assert install_overrides == project_overrides
    assert project_overrides[0] == "h2==4.4.1"
