#!/usr/bin/env python3
"""Test-only stand-in for the platform stream subprocess, backed by a local origin."""

import os
import socket
import sys
import threading


def main() -> int:
    if (
        sys.argv[-2:] != ["proofspot", "8088"]
        or os.path.exists(os.environ["PROVIDER_STOP_MARKER"])
    ):
        os.write(1, b"\x00")
        return 1
    try:
        connection = socket.create_connection(
            ("127.0.0.1", int(os.environ["PROVIDER_FIXTURE_PORT"])), timeout=5
        )
    except OSError:
        os.write(1, b"\x00")
        return 1
    connection.settimeout(None)
    os.write(1, b"\x01")

    def upload() -> None:
        try:
            while data := os.read(0, 65536):
                connection.sendall(data)
        except OSError:
            pass
        finally:
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=upload, daemon=True).start()
    try:
        while data := connection.recv(65536):
            os.write(1, data)
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
