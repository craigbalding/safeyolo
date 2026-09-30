#!/usr/bin/env python3
"""Run the real Python provider handoff with a local test platform stream."""

import os
import socket
import sys

from safeyolo import provider_stream


class LocalRelay:
    def __init__(self, connection: socket.socket):
        self.connection = connection
        self.stdin = connection.makefile("wb", buffering=0)
        self.stdout = connection.makefile("rb", buffering=0)

    def wait(self, timeout=None):
        self.stdin.close()
        self.stdout.close()
        self.connection.close()
        return 0

    def terminate(self):
        self.wait()

    def kill(self):
        self.wait()


class LocalPlatform:
    def is_sandbox_running(self, name):
        assert name == "proofspot"
        return not os.path.exists(os.environ["PROVIDER_STOP_MARKER"])

    def popen_port_forward(self, name, port):
        assert (name, port) == ("proofspot", 8088)
        connection = socket.create_connection(
            ("127.0.0.1", int(os.environ["PROVIDER_FIXTURE_PORT"])), timeout=5
        )
        connection.settimeout(None)
        return LocalRelay(connection)


def main() -> int:
    assert sys.argv[1:5] == ["-I", "-B", "-m", "safeyolo.provider_stream"]
    provider_stream.get_platform = LocalPlatform
    sys.argv = ["safeyolo.provider_stream", *sys.argv[-2:]]
    return provider_stream.main()


if __name__ == "__main__":
    raise SystemExit(main())
