"""Owned test helper: OpenSSH stdin/stdout to an admitted UDS CONNECT stream."""

import argparse
import os
import socket
import sys
import threading


def bridge(path, authority):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(path)
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            byte = stream.recv(1)
            if not byte:
                raise RuntimeError("CONNECT closed before response")
            head.extend(byte)
        if head.split(b" ", 2)[1] != b"200":
            raise RuntimeError("CONNECT was not admitted")
        stream.settimeout(None)

        def upload():
            try:
                while data := os.read(sys.stdin.fileno(), 65536):
                    stream.sendall(data)
                stream.shutdown(socket.SHUT_WR)
            except OSError:
                # The foreground reader observes termination of this SSH session.
                return

        sender = threading.Thread(target=upload, daemon=True)
        sender.start()
        while data := stream.recv(65536):
            remaining = memoryview(data)
            while remaining:
                remaining = remaining[os.write(sys.stdout.fileno(), remaining):]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket")
    parser.add_argument("authority")
    arguments = parser.parse_args()
    bridge(arguments.socket, arguments.authority)
