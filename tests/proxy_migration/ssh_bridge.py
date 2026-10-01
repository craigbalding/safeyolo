"""Owned test helper: OpenSSH stdin/stdout to an admitted UDS CONNECT stream."""

import argparse
import os
import socket
import sys
import threading


def bridge(path, authority, *, tcp_proxy=False, test_context=None):
    if test_context and any(character in test_context for character in "\r\n"):
        raise ValueError("test context must fit one CONNECT header")
    with socket.socket(socket.AF_INET if tcp_proxy else socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(("127.0.0.1", int(path)) if tcp_proxy else path)
        context_header = f"X-SafeYolo-Test-Context: {test_context}\r\n" if test_context else ""
        stream.sendall((f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                        f"{context_header}\r\n").encode())
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
    parser.add_argument("--tcp-proxy", action="store_true", help="Use the guest localhost proxy port")
    parser.add_argument("--test-context", help="Attach the caller's finite test context to CONNECT")
    arguments = parser.parse_args()
    bridge(arguments.socket, arguments.authority, tcp_proxy=arguments.tcp_proxy,
           test_context=arguments.test_context)
