"""Live NATS acceptance test for the full-duplex operator chat."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import pty
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from prompt_toolkit import PromptSession
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from rich.console import Console

from safeyolo.commands import coord
from safeyolo.coord import api, nats_client
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.identity import new_operation_id


def _wait_for_pty_output(
    fd: int,
    transcript: bytearray,
    start: int,
    expected: bytes,
    *,
    timeout: float = 5.0,
) -> int:
    """Read one real terminal until new output contains ``expected``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = transcript.find(expected, start)
        if found >= 0:
            return found + len(expected)
        readable, _, _ = select.select([fd], [], [], 0.1)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        transcript.extend(chunk)
    tail = bytes(transcript[-4000:]).decode("utf-8", errors="replace")
    pytest.fail(f"terminal did not show {expected!r}; output tail:\n{tail}")


def _test_process_env() -> dict[str, str]:
    project_root = Path(__file__).resolve().parents[2]
    cli_src = project_root / "cli" / "src"
    current = os.environ.get("PYTHONPATH")
    pythonpath = [str(cli_src), str(project_root)]
    if current:
        pythonpath.append(current)
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(pythonpath),
        "PYTHONUNBUFFERED": "1",
        "PROMPT_TOOLKIT_NO_CPR": "1",
        "TERM": "xterm-256color",
    }


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


@pytest.mark.timeout(30)
def test_real_chat_receives_after_operator_sends(nats_env):
    """One real CLI process must keep receiving after its first send."""
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    room = "live-chat-pty"
    agent_id = "ag-bbbb000000000000000000000000bbbb"

    async def prepare_room() -> None:
        await api.create_room(room)
        await nats_client.close()

    asyncio.run(prepare_room())
    api.grant(room, "operator", "operator", operation_id=new_operation_id())
    api.grant(room, "agent", agent_id, operation_id=new_operation_id())

    env = _test_process_env()
    cli_code = f"import sys; from safeyolo.cli import app; sys.argv = ['safeyolo', 'coord', 'chat', {room!r}]; app()"
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, "-c", cli_code], env)

    transcript = bytearray()
    position = 0
    child_reaped = False
    try:
        position = _wait_for_pty_output(fd, transcript, position, b"op>")

        os.write(fd, b"first operator line\n")
        position = _wait_for_pty_output(fd, transcript, position, b"message accepted")
        position = _wait_for_pty_output(fd, transcript, position, b"op>")

        # Keep a draft open while a separate process publishes through the
        # production Coord API and real NATS server.
        os.write(fd, b"draft survives")
        peer_code = f"""
import asyncio
from safeyolo.coord import api, nats_client

async def main():
    await api.send(
        {room!r},
        "agent",
        {agent_id!r},
        "reply after first send",
        sender_agent_name="test-peer",
        notify="none",
    )
    await nats_client.close()

asyncio.run(main())
"""
        peer = subprocess.run(
            [sys.executable, "-c", peer_code],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert peer.returncode == 0, peer.stderr

        position = _wait_for_pty_output(fd, transcript, position, b"reply after first send")
        os.write(fd, b" continues\n")
        position = _wait_for_pty_output(fd, transcript, position, b"message accepted")
        position = _wait_for_pty_output(fd, transcript, position, b"op>")
        os.write(fd, b":q\n")
        _wait_for_pty_output(fd, transcript, position, b"detached")
        _, status = os.waitpid(pid, 0)
        child_reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        os.close(fd)
        if not child_reaped:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)

    async def read_messages() -> list[str]:
        page = await api.read_room(room, "operator", "operator", since_sequence=0, limit=10)
        await nats_client.close()
        return [message["body"] for message in page["messages"]]

    assert asyncio.run(read_messages()) == [
        "first operator line",
        "reply after first send",
        "draft survives continues",
    ]
    assert b"Traceback" not in transcript
