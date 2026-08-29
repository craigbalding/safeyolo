from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from safeyolo.coord import mattermost_actions as actions

TRUSTED_AGENT_ID = "ag-" + "1" * 32


def listener_config(port: int = 0) -> actions.ActionIngressConfig:
    return actions.ActionIngressConfig(
        bind_host="127.0.0.1",
        bind_port=port,
        public_base_url="https://actions.example/coord",
        capability_ttl_seconds=3600,
        trusted_agent_ids=(TRUSTED_AGENT_ID,),
    )


async def raw_request(port: int, request: bytes) -> tuple[int, dict[str, Any]]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    writer.write_eof()
    status_line = await reader.readline()
    status = int(status_line.split(b" ", 2)[1])
    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in {b"\r\n", b"\n", b""}:
            break
        name, value = line.decode("ascii").rstrip("\r\n").split(":", 1)
        headers[name.lower()] = value.strip()
    body = await reader.readexactly(int(headers["content-length"]))
    writer.close()
    await writer.wait_closed()
    return status, json.loads(body)


@pytest.mark.asyncio
async def test_listener_serves_only_bounded_health_and_callback_paths() -> None:
    received: list[dict[str, Any]] = []

    async def callback(payload: dict[str, Any]) -> actions.CallbackHTTPResponse:
        received.append(payload)
        return actions.CallbackHTTPResponse(200, {"ephemeral_text": "accepted"})

    listener = actions.MattermostActionListener(listener_config(), callback, lambda: {"adapter": "ready"})
    assert await listener.start()
    assert listener.healthy
    assert listener.bound_port is not None
    port = listener.bound_port
    try:
        status, body = await raw_request(
            port,
            b"GET /coord/mattermost/healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        assert (status, body) == (
            200,
            {"adapter": "ready", "listener": "healthy"},
        )

        encoded = b'{"context":{"action":"approve"}}'
        request = (
            b"POST /coord/mattermost/actions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n" + f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded
        )
        status, body = await raw_request(port, request)
        assert (status, body) == (200, {"ephemeral_text": "accepted"})
        assert received == [{"context": {"action": "approve"}}]

        status, body = await raw_request(
            port,
            b"GET /coord/mattermost/actions?secret=x HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        assert (status, body) == (404, {"error": "not found"})
    finally:
        await listener.close()
    assert listener.state == "stopped"
    assert not listener.healthy


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        (b"POST /coord/mattermost/actions HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}"),
        (
            b"POST /coord/mattermost/actions HTTP/1.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}"
        ),
        (
            b"POST /coord/mattermost/actions HTTP/1.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
        ),
        (b"POST /coord/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n"),
        (b"POST /coord/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{}"),
        (
            b"POST /coord/mattermost/actions HTTP/1.1\r\n"
            b"Content-Type: application/json\r\nContent-Length: 13\r\n\r\n"
            b'{"x":1,"x":2}'
        ),
    ],
)
async def test_listener_rejects_malformed_ambiguous_or_oversized_requests(
    raw: bytes,
) -> None:
    called = False

    async def callback(_payload: dict[str, Any]) -> actions.CallbackHTTPResponse:
        nonlocal called
        called = True
        return actions.CallbackHTTPResponse(200, {})

    listener = actions.MattermostActionListener(listener_config(), callback, lambda: {})
    assert await listener.start()
    assert listener.bound_port is not None
    try:
        status, body = await raw_request(listener.bound_port, raw)
    finally:
        await listener.close()
    assert (status, body) == (400, {"error": "invalid request"})
    assert not called


@pytest.mark.asyncio
async def test_listener_timeout_is_bounded_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(actions, "REQUEST_TIMEOUT_SECONDS", 0.01)
    listener = actions.MattermostActionListener(
        listener_config(),
        lambda _payload: asyncio.sleep(0),  # type: ignore[arg-type]
        lambda: {},
    )
    assert await listener.start()
    assert listener.bound_port is not None
    reader, writer = await asyncio.open_connection("127.0.0.1", listener.bound_port)
    writer.write(b"POST /coord/mattermost/actions HTTP/1.1\r\n")
    await writer.drain()
    status_line = await asyncio.wait_for(reader.readline(), timeout=1)
    try:
        assert status_line.startswith(b"HTTP/1.1 400 ")
    finally:
        writer.close()
        await writer.wait_closed()
        await listener.close()


@pytest.mark.asyncio
async def test_listener_duplicate_bind_shutdown_and_restart_are_clean() -> None:
    async def callback(_payload: dict[str, Any]) -> actions.CallbackHTTPResponse:
        return actions.CallbackHTTPResponse(200, {})

    first = actions.MattermostActionListener(listener_config(), callback, lambda: {})
    assert await first.start()
    assert first.bound_port is not None
    second = actions.MattermostActionListener(listener_config(first.bound_port), callback, lambda: {})
    assert not await second.start()
    assert second.state == "failed"
    assert second.last_error == "listener bind failed: OSError"

    await first.close()
    assert await second.start()
    assert second.healthy
    await second.close()
    assert await second.start()
    await second.close()


def test_public_callback_url_canonicalization_is_fail_closed() -> None:
    assert actions.canonical_public_base_url("https://EXAMPLE.COM:8443/coord/") == "https://example.com:8443/coord"
    for value in (
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/a//b",
        "https://example.com/a/../b",
        "https://example.com/%2e%2e",
        "https://example.com/path?capability=secret",
        "https://example.com/path#fragment",
    ):
        with pytest.raises(ValueError):
            actions.canonical_public_base_url(value)
