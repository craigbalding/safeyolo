"""Live NATS acceptance test for the full-duplex operator chat."""

from __future__ import annotations

import asyncio
import io

import pytest
from prompt_toolkit import PromptSession
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from rich.console import Console

from safeyolo.commands import coord
from safeyolo.coord import api, nats_client
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.identity import new_operation_id


@pytest.mark.timeout(20)
def test_chat_receives_and_sends_after_two_nats_ping_intervals(nats_env, monkeypatch):
    """The prompt must not stop nats-py's ping and receive tasks."""
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    asyncio.run(api.create_room("live-chat"))
    api.grant(
        "live-chat",
        "operator",
        "operator",
        operation_id=new_operation_id(),
    )
    agent_id = "ag-aaaa000000000000000000000000aaaa"
    api.grant(
        "live-chat",
        "agent",
        agent_id,
        operation_id=new_operation_id(),
    )

    real_connect = nats_client.nats.connect

    async def connect_with_short_pings(*args, **kwargs):
        kwargs["ping_interval"] = 0.05
        kwargs["max_outstanding_pings"] = 2
        return await real_connect(*args, **kwargs)

    monkeypatch.setattr(nats_client.nats, "connect", connect_with_short_pings)
    rendered = io.StringIO()
    monkeypatch.setattr(
        coord,
        "console",
        Console(file=rendered, force_terminal=False, width=100),
    )

    async def run_chat() -> None:
        with create_pipe_input() as pipe_input:
            session = PromptSession(input=pipe_input, output=DummyOutput())
            monkeypatch.setattr("prompt_toolkit.PromptSession", lambda: session)
            chat_task = asyncio.create_task(coord._interactive_session("live-chat", 0))

            # Wait until the production receiver owns a real NATS connection.
            for _ in range(100):
                client = nats_client._connection.client
                if client is not None and client.is_connected:
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("chat did not connect to NATS")

            # This is longer than two configured ping intervals. A blocked
            # event loop would let the server discard the client here.
            await asyncio.sleep(0.2)
            await api.send(
                "live-chat",
                "agent",
                agent_id,
                "received after idle",
                notify="room",
            )
            for _ in range(100):
                if "received after idle" in rendered.getvalue():
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("chat did not render the message received after idle")

            pipe_input.send_text("sent after idle\n:q\n")
            await asyncio.wait_for(chat_task, timeout=3.0)

            page = await api.read_room("live-chat", "operator", "operator", since_sequence=0)
            assert [message["body"] for message in page["messages"]] == [
                "received after idle",
                "sent after idle",
            ]
            assert client.is_connected
            await nats_client.close()

    asyncio.run(run_chat())
    assert "Traceback" not in rendered.getvalue()
