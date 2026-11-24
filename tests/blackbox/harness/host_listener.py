#!/usr/bin/env python3
"""Host-owned TCP/UDP observers for blackbox isolation tests.

Binds to 127.0.0.1 on an OS-assigned port, prints the port to stdout
(flushed), then records bytes and sends a deliberately invalid protocol reply.
The purpose is
to give the in-VM test_host_listener_unreachable a *live* listener to
try to reach — distinguishing "sandbox can't route to host" from
"nothing is listening on the probed port."

In the UDS-only isolation architecture this is redundant with
test_arbitrary_host_port_unreachable because structural isolation
blocks packets before they reach any port. But the listener test
remains valuable as a regression guard: if the implementation ever
regains a routable path to the host, this test will catch it.
"""
import hashlib
import json
import os
import socket
import socketserver
import threading
import time
import uuid
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


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class DeliveryReceiver:
    """Record received bytes independently of the client's reported result."""

    def __init__(self, address: str, transport: str, port: int = 0):
        self.rows: list[dict] = []
        self.changed = threading.Condition()
        self.errors: list[str] = []
        self.closed = False
        receiver = self

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer
                     if transport == "tcp" else socketserver.UDPServer):
            address_family = socket.AF_INET6 if ":" in address else socket.AF_INET
            daemon_threads = False

            def handle_error(self, request, client_address):
                receiver.errors.append("receiver request failed")

        class Request(socketserver.BaseRequestHandler):
            def handle(self):
                if transport == "tcp":
                    self.request.settimeout(2)
                    data = self.request.recv(65536)
                else:
                    data = self.request[0]
                with receiver.changed:
                    receiver.rows.append({"bytes": len(data), "sha256": digest(data)})
                    receiver.changed.notify_all()
                if transport == "tcp":
                    # Not HTTP or TLS: a client can fail after bytes arrived.
                    try:
                        self.request.sendall(b"not an HTTP response\n")
                    except (BrokenPipeError, ConnectionResetError):
                        # Delivery was already recorded; a client can close
                        # without reading the deliberately invalid reply.
                        pass

        self.server = Server((address, port), Request)
        self.endpoint = {"address": address, "port": self.server.server_address[1],
                         "transport": transport}
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02})

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "receiver did not stop"

    def control(self) -> dict:
        """Send a unique host payload and wait for its actual observation."""
        marker = ("host-control-" + uuid.uuid4().hex).encode()
        expected = digest(marker)
        send_payload(self.endpoint, marker)
        deadline = time.monotonic() + 3
        with self.changed:
            while not any(row["sha256"] == expected for row in self.rows):
                remaining = deadline - time.monotonic()
                assert remaining > 0, "owned receiver did not observe its positive control"
                self.changed.wait(remaining)
        return {"sha256": expected, "bytes": len(marker)}

    def assert_no_delivery(self, controls: list[dict]) -> None:
        assert not self.errors, self.errors
        assert sorted(self.rows, key=lambda row: row["sha256"]) == sorted(controls, key=lambda row: row["sha256"]), (
            "unauthorized delivery at owned receiver (sanitized observations): " + json.dumps(self.rows))


def send_payload(endpoint: dict, payload: bytes) -> None:
    family = socket.AF_INET6 if ":" in endpoint["address"] else socket.AF_INET
    kind = socket.SOCK_STREAM if endpoint["transport"] == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as connection:
        connection.settimeout(2)
        target = (endpoint["address"], endpoint["port"])
        if kind == socket.SOCK_STREAM:
            connection.connect(target)
            connection.sendall(payload)
        else:
            connection.sendto(payload, target)


def main() -> None:
    with DeliveryReceiver("127.0.0.1", "tcp") as receiver:
        print(receiver.endpoint["port"], flush=True)
        try:
            receiver.thread.join()
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    main()
