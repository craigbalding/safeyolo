"""The Python handoff uses the existing platform stream and readiness signal."""

import io
import socket
import sys
import threading

from safeyolo import provider_stream


def _stdio(monkeypatch, input_bytes: bytes) -> io.BytesIO:
    output = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(input_bytes)))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(output, write_through=True))
    monkeypatch.setattr(sys, "argv", ["safeyolo.provider_stream", "proofspot", "8088"])
    return output


def test_stopped_provider_reports_unavailable_before_opening_port(monkeypatch):
    output = _stdio(monkeypatch, b"request")

    class Stopped:
        def is_sandbox_running(self, name):
            assert name == "proofspot"
            return False

        def popen_port_forward(self, name, port):
            raise AssertionError("port forwarding started for stopped sandbox")

    monkeypatch.setattr(provider_stream, "get_platform", Stopped)
    assert provider_stream.main() == 1
    assert output.getvalue() == b"\x00"


def test_closed_guest_port_reports_unavailable(monkeypatch):
    output = _stdio(monkeypatch, b"request")

    class ClosedPort:
        def is_sandbox_running(self, name):
            assert name == "proofspot"
            return True

        def popen_port_forward(self, name, port):
            assert (name, port) == ("proofspot", 8088)
            raise OSError("guest port refused")

    monkeypatch.setattr(provider_stream, "get_platform", ClosedPort)
    assert provider_stream.main() == 1
    assert output.getvalue() == b"\x00"


def test_ready_provider_streams_bytes_through_platform_port_forward(monkeypatch):
    output = _stdio(monkeypatch, b"request")
    platform_side, guest_side = socket.socketpair()
    received = []

    def guest() -> None:
        try:
            received.append(guest_side.recv(7))
            guest_side.sendall(b"response")
        finally:
            guest_side.close()

    worker = threading.Thread(target=guest)
    worker.start()

    class Relay:
        stdin = platform_side.makefile("wb", buffering=0)
        stdout = platform_side.makefile("rb", buffering=0)

        def wait(self, timeout=None):
            assert timeout == 1
            self.stdin.close()
            self.stdout.close()
            platform_side.close()
            return 0

    class Platform:
        def is_sandbox_running(self, name):
            assert name == "proofspot"
            return True

        def popen_port_forward(self, name, port):
            assert (name, port) == ("proofspot", 8088)
            return Relay()

    monkeypatch.setattr(provider_stream, "get_platform", Platform)
    assert provider_stream.main() == 0
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert received == [b"request"]
    assert output.getvalue() == b"\x01response"
