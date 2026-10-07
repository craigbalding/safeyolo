"""Observe native operator/guest Coord exchange on an owned Ubuntu systrap guest.

Run this host-side Python test driver with a disposable installed root, its
already running native proxy and one booted systrap guest. No model or Python
guest command is used. The root must contain this exact candidate's host and
guest executables. The driver creates one fixture room, sends exact markers,
checks guest attribution and the native timeline, then stops the selected
guest, proxy and Coord. Other instances are outside the selected root.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import select
import shlex
import struct
import subprocess
import termios
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    cli = root / "bin/safeyolo"

    def command(*arguments, check=True):
        result = subprocess.run([str(cli), "--root", str(root), *arguments],
                                capture_output=True, text=True, timeout=30)
        if check:
            assert result.returncode == 0, result.stderr
            return result.stdout
        return result

    host = command("--version").strip()
    assert f"commit={args.commit} " in host, host
    state = json.loads(command("agent", "status", args.agent))
    assert state["runtime_state"] == "running" and state["control_state"] == "ready", state
    assert json.loads(command("coord", "status"))["state"] == "running"
    guest = "/home/agent/.safeyolo/safeyolo-coord"

    def shell(script):
        return command("agent", "shell", args.agent, "-c", script)

    try:
        identity = shell(f"{guest} --version").strip()
        assert f"commit={args.commit} " in identity, identity
        room = f"g5-{args.agent}"
        command("coord", "room", "create", room)
        command("coord", "grant", room, args.agent)
        outbound = "G5 operator → actual guest\nexact payload"
        command("coord", "send", room, outbound, "--to", args.agent, "--content-type", "text/plain")

        def call(tool, payload):
            source = shlex.quote(json.dumps(payload, ensure_ascii=False))
            return json.loads(shell(f"printf '%s' {source} | {guest} call {shlex.quote(tool)}"))

        received = call("read_room", {"room_name": room, "since_sequence": 0})
        operator = next(m for m in received["messages"] if m["body"] == outbound)
        assert operator["sender_kind"] == "operator" and operator["sender_agent_id"] is None
        forged = shlex.quote(json.dumps({"room_name": room, "body": "forged guest", "sender_kind": "operator"}))
        refused = command("agent", "shell", args.agent, "-c",
                          f"printf '%s' {forged} | {guest} call send", check=False)
        assert refused.returncode != 0 and "unknown argument sender_kind" in refused.stderr, refused

        # The same operator PTY observes actual guest arrival while its draft
        # is unfinished, then sends and receives another actual guest reply.
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        chat = subprocess.Popen([str(cli), "--root", str(root), "coord", "chat", room, "--to", args.agent],
                                stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                                env={**os.environ, "TERM": "xterm-256color"})
        os.close(slave)

        def until(marker):
            buffer = bytearray()
            deadline = time.monotonic() + 10
            while marker not in buffer and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    buffer.extend(os.read(master, 65536))
                assert chat.poll() is None, bytes(buffer)
            assert marker in buffer, bytes(buffer)

        inbound = "G5 actual guest → operator"
        draft = "G5 unfinished café draft"
        reply = "G5 actual guest reply after send"
        try:
            until(b"op> ")
            os.write(master, draft.encode())
            sent = call("send", {"room_name": room, "body": inbound, "notify": "none"})
            assert sent["envelope"]["sender_kind"] == "agent", sent
            assert sent["envelope"]["sender_agent_name"] == args.agent, sent
            until(inbound.encode())
            os.write(master, b"\r")
            until(b"message accepted;")
            call("send", {"room_name": room, "body": reply, "notify": "none"})
            until(reply.encode())
            os.write(master, b":q\r")
            chat.wait(timeout=5)
            assert chat.returncode == 0
        finally:
            if chat.poll() is None:
                chat.terminate()
                chat.wait(timeout=5)
            os.close(master)
        history = [json.loads(line) for line in command("coord", "history", room).splitlines()]
        assert [m["body"] for m in history] == [outbound, inbound, draft, reply], history
        assert history[1]["sender_agent_id"] == sent["envelope"]["sender_agent_id"]
        assert history[2]["sender_kind"] == "operator" and history[2]["sender_agent_id"] is None
        timeline = command("coord", "watch", room, "--once")
        assert "OP" in timeline and inbound in timeline
        print(json.dumps({"host": host, "guest": identity, "room": room,
                          "messages": [{k: m[k] for k in ("msg_id", "sequence", "sender_kind", "sender_agent_id", "sender_agent_name", "body")} for m in history]}, ensure_ascii=False))
    finally:
        # Stop all three owned lifetimes. Proxy stop alone leaves a guest live.
        command("agent", "stop", args.agent)
        assert json.loads(command("agent", "status", args.agent))["runtime_state"] == "stopped"
        command("stop")
        command("coord", "stop")
        assert json.loads(command("coord", "status"))["state"] == "stopped"


if __name__ == "__main__":
    main()
