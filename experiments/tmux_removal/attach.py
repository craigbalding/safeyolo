"""Attach a real terminal to the prototype. Ctrl-] detaches the viewer."""

import codecs
import json
import os
import select
import signal
import socket
import sys
import termios
import tty


def main():
    with socket.socket(socket.AF_UNIX) as client:
        client.connect(sys.argv[1])

        def send(**request):
            client.sendall(json.dumps(request).encode() + b"\n")

        def resize(_number=None, _frame=None):
            size = os.get_terminal_size(0)
            send(op="resize", rows=size.lines, cols=size.columns)

        original = termios.tcgetattr(0)
        previous = signal.signal(signal.SIGWINCH, resize)
        decoder = codecs.getincrementaldecoder("utf-8")()
        pending = bytearray()
        try:
            tty.setraw(0)
            os.write(1, b"\x1b[?1049h")
            resize()
            send(op="attach")
            while True:
                readable, _, _ = select.select([0, client], [], [])
                if client in readable:
                    data = client.recv(65536)
                    if not data:
                        return 1
                    pending.extend(data)
                    while b"\n" in pending:
                        line, _, remainder = pending.partition(b"\n")
                        pending = bytearray(remainder)
                        frame = json.loads(line)
                        os.write(1, frame["screen"].encode())
                        if frame["exit"] is not None:
                            return frame["exit"]
                if 0 in readable:
                    data = os.read(0, 4096)
                    if not data or b"\x1d" in data:
                        return 0
                    text = decoder.decode(data)
                    if text:
                        send(op="input", text=text)
        finally:
            signal.signal(signal.SIGWINCH, previous)
            termios.tcsetattr(0, termios.TCSANOW, original)
            os.write(1, b"\x1b[0m\x1b[?25h\x1b[?2004l\x1b[?1049l")


if __name__ == "__main__":
    raise SystemExit(main())
