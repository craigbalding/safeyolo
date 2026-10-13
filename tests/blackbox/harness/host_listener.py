#!/usr/bin/env python3
"""Host-side TCP listener for blackbox isolation tests.

Binds to 127.0.0.1 on an OS-assigned port, prints the port to stdout
(flushed), then accepts connections and closes them. The purpose is
to give the in-VM test_host_listener_unreachable a *live* listener to
try to reach — distinguishing "sandbox can't route to host" from
"nothing is listening on the probed port."

In the UDS-only isolation architecture this is redundant with
test_arbitrary_host_port_unreachable because structural isolation
blocks packets before they reach any port. But the listener test
remains valuable as a regression guard: if the implementation ever
regains a routable path to the host, this test will catch it.
"""
import os
import socket
from pathlib import Path


def listener_endpoint(directory: Path) -> tuple[str, int]:
    """Read the actual host listener address and port supplied by the runner."""
    return ((directory / "host-listener-address").read_text().strip(),
            int((directory / "host-listener-port").read_text().strip()))


def refuse_listener() -> dict:
    """Observe a failed guest connection to the runner's actual endpoint."""
    host, port = listener_endpoint(Path("/safeyolo"))
    try:
        connection = socket.create_connection((host, port), timeout=3)
    except OSError as error:
        return {"host": host, "port": port, "uid": os.geteuid(),
                "connected": False, "error": str(error)}
    connection.close()
    raise AssertionError(f"guest reached the live host listener at {host}:{port}")


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    port = s.getsockname()[1]
    print(port, flush=True)
    while True:
        try:
            conn, _ = s.accept()
            conn.close()
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    main()
