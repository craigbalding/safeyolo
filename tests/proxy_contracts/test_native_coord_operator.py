"""Native G5 inputs, PTY drafts, withheld PubAck and room/event observation.

The Python driver owns one disposable installed instance and real pinned NATS.
Product commands run without a Python import path. These are host/UDS probes;
the Ubuntu guest witness in tests/nested-linux/operator_coord_acceptance.py
supplies the actual guest observation. Readiness is 15 seconds and each PTY
observation is bounded to the existing 10-second chat fixture deadline.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import json
import os
import pty
import select
import shlex
import struct
import subprocess
import termios
import time
from contextlib import contextmanager
from pathlib import Path

import nats
import pytest

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_native_policy_cli import native_instance

REPO = Path(__file__).resolve().parents[2]
ROOM = "operator-chat"
POLICY = '''[controls.network]
enabled=false
[agents.alice]
agent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
[agents.bob]
agent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
[[permissions]]
action='network:request'
resource='*'
effect='allow'
'''


@pytest.fixture
def instance(tmp_path):
    with native_instance(tmp_path, source=POLICY, agent_api=True) as instance:
        instance.environment["SAFEYOLO_NATS_TEST_INSTANCE"] = f"native-chat-{tmp_path.name}"
        instance.environment["TERM"] = "xterm-256color"
        arguments = ["coord", "start"]
        if binary := os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
            arguments += ["--binary", binary]
        result = instance.cli(*arguments)
        assert result.returncode == 0, result.stderr
        instance.nats = json.loads(result.stdout)
        try:
            for args in (("room", "create", ROOM), ("grant", ROOM, "alice"), ("grant", ROOM, "bob")):
                result = instance.cli("coord", *args)
                assert result.returncode == 0, result.stderr
            yield instance
        finally:
            stopped = instance.cli("coord", "stop")
            assert stopped.returncode == 0, stopped.stderr
            assert json.loads(instance.cli("coord", "status").stdout)["state"] == "stopped"


def cli(instance, *args, input=None):
    return subprocess.run(
        [str(instance.root / "bin/safeyolo"), "--root", str(instance.root), "coord", *args],
        cwd=instance.root.parent, env=instance.environment, input=input,
        capture_output=True, text=isinstance(input, str) or input is None, timeout=15,
    )


def history(instance, room=ROOM):
    result = cli(instance, "history", room)
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def agent_send(instance, body, room=ROOM, **extra):
    payload = json.dumps({"body": body, "notify": "none", **extra}).encode()
    status, _, raw = request(instance.paths["alice"], f"http://_safeyolo.proxy.internal/api/coord/rooms/{room}/send",
                          method="POST", body=payload,
                          headers={"Authorization": f"Bearer {(instance.root / 'data/agent_token').read_text().strip()}"})
    assert status == 200, raw
    return json.loads(raw)


async def stream_control(instance, no_ack=None):
    # Only this driver reads the fixture's host-local NATS credential. Neither
    # the guest command nor test output receives it.
    credential = (instance.root / "data/coord/nats/creds").read_text().strip()
    connection = await nats.connect(f"nats://127.0.0.1:{instance.nats['client_port']}",
                                    user="safeyolo", password=credential)
    try:
        js = connection.jetstream()
        streams = await js.streams_info()
        stream = next(s for s in streams if s.config.name.startswith("ROOM_"))
        if no_ack is not None:
            stream.config.no_ack = no_ack
            await js.update_stream(config=stream.config)
        return (await js.stream_info(stream.config.name)).state.messages
    finally:
        await connection.close()


@contextmanager
def terminal(instance):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    process = subprocess.Popen(
        [str(instance.root / "bin/safeyolo"), "--root", str(instance.root), "coord", "chat", ROOM, "--to", "bob"],
        cwd=instance.root.parent, env=instance.environment,
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
    )
    os.close(slave)
    buffer = bytearray()

    def until(marker, timeout=10):
        deadline = time.monotonic() + timeout
        while marker not in buffer and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    buffer.extend(os.read(master, 65536))
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    # Linux reports EIO when the PTY slave has closed. Expose
                    # captured diagnostics instead of losing the failure.
                    raise AssertionError(bytes(buffer)) from None
            assert process.poll() is None, bytes(buffer)
        assert marker in buffer, bytes(buffer)
        captured = bytes(buffer)
        buffer.clear()
        return captured

    try:
        yield process, master, until
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        os.close(master)


def test_scripted_inputs_payloads_authority_and_rejections(instance, tmp_path):
    body = "first café\nsecond\r\x1b[31m\n"
    message = tmp_path / "message.txt"
    message.write_bytes(body.encode())
    for args, input in ((("send", ROOM, body, "--to", "bob", "--content-type", "text/plain"), None),
                        (("send", ROOM, "--file", str(message)), None),
                        (("send", ROOM, "--stdin"), body.encode())):
        result = cli(instance, *args, input=input)
        assert result.returncode == 0, result.stderr
    messages = history(instance)
    assert [m["body"] for m in messages] == [body] * 3
    assert [m["content_type"] for m in messages] == ["text/plain", "text/markdown", "text/markdown"]
    assert all(m["sender_kind"] == "operator" and m["sender_agent_id"] is None for m in messages)
    assert messages[0]["attention_intent"] == {
        "mode": "targeted", "agent_ids": ["ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    }
    for args, input in ((("send", ROOM), None), (("send", ROOM, " "), None),
                        (("send", ROOM, "x", "--file", str(message)), None),
                        (("send", ROOM, "--stdin", "--file", str(message)), b"x"),
                        (("send", ROOM, "--stdin"), b""), (("send", ROOM, "--stdin"), b"\xff"),
                        (("send", ROOM, "x", "--content-type", "application/json"), None),
                        (("send", ROOM, "x", "--to", "unknown"), None),
                        (("chat", ROOM), None)):
        assert cli(instance, *args, input=input).returncode != 0
    assert len(history(instance)) == 3
    result = agent_send(instance, "forged operator", sender_kind="operator", sender_agent_id="operator")
    assert result["envelope"]["sender_kind"] == "agent"
    assert result["envelope"]["sender_agent_name"] == "alice"


def test_pty_draft_receive_unknown_count_and_later_send(instance):
    prefix = "横e\u0301 " * 30  # More than one terminal row, with combining text.
    with terminal(instance) as (process, fd, until):
        until(b"op> ")
        os.write(fd, (prefix + "draft café tail").encode())
        agent_send(instance, "arrives mid-draft\x1b]52;c;CANARY\x07\r\u202e")
        output = until(b"arrives mid-draft")
        assert b"\x1b]52;c;CANARY" not in output and b"\\x1b]52;c;CANARY\\x07\\x0d" in output
        # Move back four characters and insert while the draft is redrawn.
        os.write(fd, b"\x1b[D" * 4 + b"complete " + b"\r")
        until(b"message accepted;")
        agent_send(instance, "reply after send")
        until(b"reply after send")
        asyncio.run(stream_control(instance, no_ack=True))
        before = asyncio.run(stream_control(instance))
        os.write(fd, b"ack withheld marker\r")
        until(b"message acceptance is UNKNOWN")
        assert asyncio.run(stream_control(instance)) == before + 1
        asyncio.run(stream_control(instance, no_ack=False))
        os.write(fd, b"later independent marker\r")
        until(b"message accepted;")
        os.write(fd, b":q\r")
        process.wait(timeout=5)
        assert process.returncode == 0
    messages = history(instance)
    operator = [m for m in messages if m["sender_kind"] == "operator"]
    assert [m["body"] for m in operator] == [prefix + "draft café complete tail", "ack withheld marker", "later independent marker"]
    assert all(m["sender_agent_id"] is None and m["sender_agent_name"] is None for m in operator)
    assert all(m["attention_intent"]["mode"] == "targeted" for m in operator)


def test_clipboard_editor_confirmation_and_cancellation(instance):
    instance.environment["PATH"] += ":/usr/bin:/bin"
    clipboard = instance.root / "bin/pbpaste"
    clipboard.write_text("#!/bin/sh\nprintf 'clipboard café\\nsecond line\\n'\n")
    clipboard.chmod(0o755)
    editor = instance.root / "bin/fixture-editor"
    editor.write_text('#!/bin/sh\nprintf "editor café\\nlast line\\n" > "$1"\n')
    editor.chmod(0o755)
    instance.environment["EDITOR"] = str(editor)
    instance.environment["VISUAL"] = ""
    with terminal(instance) as (process, fd, until):
        until(b"op> ")
        os.write(fd, b":paste\r")
        until(b"send? [Y/n]")
        os.write(fd, b"n\r")
        until(b"cancelled")
        assert history(instance) == []
        os.write(fd, b":p\r")
        until(b"send? [Y/n]")
        os.write(fd, b"y\r")
        until(b"message accepted;")
        os.write(fd, b":edit\r")
        until(b"send? [Y/n]")
        os.write(fd, b"\r")
        until(b"message accepted;")
        clipboard.write_text("#!/bin/sh\nprintf '\\377\\n'\n")
        os.write(fd, b":paste\r")
        until(b"send? [Y/n]")
        os.write(fd, b"y\r")
        until(b"message accepted;")
        os.write(fd, b":q\r")
        process.wait(timeout=5)
        assert process.returncode == 0
    assert [m["body"] for m in history(instance)] == [
        "clipboard café\nsecond line\n", "editor café\nlast line\n", "\ufffd\n",
    ]


def test_watch_timeline_payload_modes_and_cursor_reconnect(instance):
    event = json.dumps({"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "coord",
                         "tool": "send", "status": "completed", "arguments": {"room_name": ROOM,
                         "body": "hidden body", "token": "synthetic-secret"}, "result": "hidden result"}})
    agent_send(instance, event)
    result = cli(instance, "watch", ROOM, "--once")
    assert "completed coord.send status=completed room=operator-chat" in result.stdout
    assert "hidden" not in result.stdout and "synthetic-secret" not in result.stdout
    raw = cli(instance, "watch", ROOM, "--once", "--raw")
    assert event in raw.stdout
    canonical = cli(instance, "watch", ROOM, "--once", "--json")
    assert json.loads(canonical.stdout)["body"] == event
    marker = json.loads(canonical.stdout)["sequence"]
    # Real connection loss: stop the owned NATS process, restart its same
    # endpoint/store and observe only messages beyond the saved cursor.
    process = subprocess.Popen([str(instance.root / "bin/safeyolo"), "--root", str(instance.root),
                                "coord", "watch", ROOM, "--since", str(marker), "--json"],
                               env=instance.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert instance.cli("coord", "stop").returncode == 0
        result = instance.cli("coord", "start", "--client-port", str(instance.nats["client_port"]),
                              "--monitor-port", str(instance.nats["monitor_port"]))
        assert result.returncode == 0, result.stderr
        agent_send(instance, "after reconnect")
        assert select.select([process.stdout], [], [], 10)[0]
        resumed = json.loads(process.stdout.readline())
        assert resumed["body"] == "after reconnect" and resumed["sequence"] > marker
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_local_jsonl_and_maintained_factory_wrapper(instance, tmp_path):
    event = json.dumps({"type": "item.completed", "item": {"type": "command_execution", "command": "printf marker", "exit_code": 0}})
    result = cli(instance, "watch", "--jsonl", "-", input=event + "\n")
    assert "TOOL    completed command rc=0 printf marker" in result.stdout
    # Exercise the actual wrapper and its owned tmux panes, rather than a
    # substituted viewer. PATH supplies ordinary shell tools, not uv.
    env = dict(instance.environment, PATH=f"{instance.root / 'bin'}:/usr/bin:/bin",
               SAFEYOLO_FACTORY_CLI=str(instance.root / "bin/safeyolo"),
               SAFEYOLO_FACTORY_REPO=str(REPO), SAFEYOLO_FACTORY_INSTANCE_ROOT=str(instance.root),
               SAFEYOLO_FACTORY_CONFIG_DIR=str(instance.root), SAFEYOLO_FACTORY_WATCH_WINDOW="native-watch")
    for room in ("relay-agent", "forge-agent", "lens-agent"):
        assert instance.cli("coord", "room", "create", room).returncode == 0
        assert instance.cli("coord", "grant", room, "alice").returncode == 0
    session = f"chat-{hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]}"
    tmux = str(instance.root / "bin/tmux")
    subprocess.run([tmux, "-L", session, "new-session", "-d", "-s", session], env=env, check=True)
    try:
        # Run from this isolated tmux server's own pane so TMUX points at the
        # correct server. No operator session or existing factory is touched.
        command = shlex.join(["/bin/bash", str(REPO / "scripts/watch_backlog_factory.sh"), "start"])
        subprocess.run([tmux, "-L", session, "send-keys", "-t", session, command, "Enter"], env=env, check=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            panes = subprocess.run([tmux, "-L", session, "list-panes", "-t", f"{session}:native-watch", "-F", "#{pane_id}"],
                                   env=env, capture_output=True, text=True)
            if panes.returncode == 0 and len(panes.stdout.splitlines()) == 3:
                break
            time.sleep(0.1)
        assert panes.returncode == 0, panes.stderr
        agent_send(instance, event, room="forge-agent")
        for pane in panes.stdout.splitlines():
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                captured = subprocess.run([tmux, "-L", session, "capture-pane", "-J", "-p", "-t", pane], env=env,
                                          capture_output=True, text=True, check=True).stdout
                if "completed command rc=0 printf marker" in captured:
                    break
                time.sleep(0.1)
            if "completed command rc=0 printf marker" in captured:
                break
        assert "completed command rc=0 printf marker" in captured
    finally:
        subprocess.run([tmux, "-L", session, "kill-server"], env=env, check=True)


def test_retained_pi_event_formats():
    artifact = Path(os.environ.get("SAFEYOLO_NATIVE_ARTIFACTS", str(REPO / "proxy/target/debug"))) / "safeyolo"
    for case in json.loads((REPO / "tests/proxy_contracts/coord_watch_events.json").read_text()):
        result = subprocess.run([str(artifact), "coord", "watch", "--jsonl", "-"],
                                input=json.dumps(case["event"]) + "\n", capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert case["label"] in result.stdout and case["text"] in result.stdout
