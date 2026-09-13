"""Shell diagnostics use the actual socket and require a complete SSH banner."""

import socket
import threading
import time
from contextlib import contextmanager

import pytest

from safeyolo.vm_diagnostics import probe_shell_socket


@contextmanager
def _server(path, chunks, *, delay=0.0):
    accepted = threading.Event()
    stop = threading.Event()
    errors = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(2)

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    accepted.set()
                    for chunk in chunks:
                        if stop.wait(delay):
                            break
                        conn.sendall(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # A bounded diagnostic deliberately stops reading.
            except Exception as exc:  # Report worker failures in the test thread.
                errors.append(exc)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield accepted
        finally:
            stop.set()
            worker.join(3)
            assert not worker.is_alive()
            assert not errors


def test_fragmented_banner_with_preidentification_lines(tmp_path):
    path = tmp_path / "shell.sock"
    with _server(path, [b"notice\r\nSS", b"H-2.0-OpenSSH_test\r", b"\n"]):
        result = probe_shell_socket(path)
    assert result.connected and result.error is None
    assert result.banner == "SSH-2.0-OpenSSH_test"


@pytest.mark.parametrize("chunks,error", [
    ([], "closed"),
    ([b"SSH-2.0-unfinished"], "closed"),
    ([b"SSH-9.0-wrong\r\n"], "invalid"),
    ([b"SSH-2.0-\x1b[31m\r\n"], "invalid"),
    ([b"SSH-2.0-" + b"a" * 255 + b"\r\n"], "invalid"),
    ([b"x" * 8192], "8192"),
])
def test_connection_is_not_a_successful_shell_probe(tmp_path, chunks, error):
    path = tmp_path / "shell.sock"
    with _server(path, chunks) as accepted:
        result = probe_shell_socket(path)
        assert accepted.is_set()
    assert result.connected
    assert result.banner is None
    assert error in result.error


def test_slow_trickle_uses_one_deadline(tmp_path):
    path = tmp_path / "shell.sock"
    start = time.monotonic()
    with _server(path, [b"S", b"S", b"H", b"-", b"2"], delay=0.04) as accepted:
        result = probe_shell_socket(path, timeout=0.11)
        assert accepted.is_set()
    assert result.connected and result.banner is None
    assert "timed out" in result.error
    assert time.monotonic() - start < 0.5


def test_missing_and_refused_socket_are_connect_failures(tmp_path):
    path = tmp_path / "shell.sock"
    assert not probe_shell_socket(path).connected
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(str(path))
        result = probe_shell_socket(path)
    assert not result.connected and result.banner is None and result.error
