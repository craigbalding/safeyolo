"""Finite terminal fixture. Files coordinate detached output without a viewer."""

import json
import os
import select
import signal
import sys
import termios
import time
import tty
from pathlib import Path


def main():
    root = Path(sys.argv[1])
    initial = termios.tcgetattr(0)
    tty.setraw(0)

    def wait(name):
        deadline = time.monotonic() + 20
        while not (root / name).exists():
            assert time.monotonic() < deadline, f"fixture deadline: {name}"
            time.sleep(0.01)

    def write(text):
        os.write(1, text.encode())

    def resized(_number, _frame):
        (root / "resized.json").write_text(json.dumps(list(os.get_terminal_size(0))))

    signal.signal(signal.SIGWINCH, resized)
    try:
        write("INITIAL-ATTACHED\r\n")
        (root / "initial").touch()
        wait("produce-detached")
        for number in range(250):
            write(f"DETACHED-NORMAL-{number:03d}\r\n")
        write("\x1b[6;9H\x1b[6n")
        reply = bytearray()
        deadline = time.monotonic() + 3
        while not reply.endswith(b"R"):
            assert time.monotonic() < deadline, "detached cursor query did not complete"
            if select.select([0], [], [], 0.05)[0]:
                reply.extend(os.read(0, 64))
        (root / "query.json").write_text(json.dumps({"reply": reply.hex()}))
        write("\x1b[?1049h\x1b[2J\x1b[HALT-DETACHED-IDLE")
        (root / "idle-alt").touch()
        wait("leave-alt")
        write("\x1b[?1049l\r\nAFTER-ALT-IDLE\x1b[?2004h")
        (root / "idle-normal").touch()
        data = bytearray()
        deadline = time.monotonic() + 20
        while not data.endswith(b"\x03"):
            assert time.monotonic() < deadline, "fixture input deadline"
            if select.select([0], [], [], 0.05)[0]:
                data.extend(os.read(0, 4096))
        (root / "input.json").write_text(json.dumps({"input": data.hex()}))
        write("\r\nINPUT-RECEIVED\r\n")
    finally:
        termios.tcsetattr(0, termios.TCSANOW, initial)
    raise SystemExit(7)


if __name__ == "__main__":
    main()
