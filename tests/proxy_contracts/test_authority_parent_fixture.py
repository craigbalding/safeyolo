"""Exercise the authority parent fixture's real TCP close and error paths."""

import socket
import struct
import threading
import traceback
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace

import pytest

from tests.proxy_contracts.test_authority_consistency import ALLOWED, Parent, ParentRequest, _server


class CompletedParentRequest(ParentRequest):
    def finish(self):
        self.server.request_done.set()


@contextmanager
def _parent():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        origin = SimpleNamespace(name="idle-origin", server_address=listener.getsockname())
        parent = Parent(None, None, origin, None)
        parent.request_done = threading.Event()
        parent.RequestHandlerClass = CompletedParentRequest
        with _server(parent):
            yield parent, listener


def _connect(client, listener):
    client.sendall(f"CONNECT {ALLOWED}:443 HTTP/1.1\r\nHost: {ALLOWED}:443\r\n\r\n".encode())
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        chunk = client.recv(1)
        assert chunk, response
        response.extend(chunk)
    assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    upstream, _ = listener.accept()
    upstream.settimeout(5)
    return upstream


def _abort(stream):
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    stream.close()


def _teardown_error(stack):
    with pytest.raises(AssertionError) as failure:
        stack.close()
    return str(failure.value)


@pytest.mark.parametrize("abortive", [False, True], ids=["orderly", "abortive"])
def test_established_connect_client_close_is_clean(abortive):
    with _parent() as (parent, listener):
        with socket.create_connection(parent.server_address, timeout=5) as client:
            with _connect(client, listener) as upstream:
                if abortive:
                    _abort(client)
                else:
                    client.shutdown(socket.SHUT_WR)
                assert upstream.recv(1) == b""
                assert parent.request_done.wait(5), "parent did not finish after client close"
                assert parent.errors == [], "".join(
                    "".join(traceback.format_exception(error)) for error in parent.errors)


def test_established_connect_upstream_reset_is_still_an_error():
    with ExitStack() as stack:
        parent, listener = stack.enter_context(_parent())
        parent.test_stage = "upstream reset control"
        with socket.create_connection(parent.server_address, timeout=5) as client:
            with _connect(client, listener) as upstream:
                _abort(upstream)
                assert parent.request_done.wait(5)
                assert len(parent.errors) == 1
                assert isinstance(parent.errors[0], ConnectionResetError)
        failure = _teardown_error(stack)
    assert "ConnectionResetError" in failure
    assert "source.recv(65536)" in failure
    assert "direction=upstream->client; operation=recv" in failure
    assert "stage=established CONNECT; test stage=upstream reset control" in failure


@pytest.mark.parametrize("abortive", [False, True], ids=["malformed", "pre-connect-reset"])
def test_request_errors_remain_visible(abortive):
    with ExitStack() as stack:
        parent, _ = stack.enter_context(_parent())
        with socket.create_connection(parent.server_address, timeout=5) as client:
            if abortive:
                _abort(client)
            else:
                client.sendall(b"malformed\r\n\r\n")
                client.shutdown(socket.SHUT_WR)
            assert parent.request_done.wait(5)
            assert len(parent.errors) == 1
            assert isinstance(parent.errors[0], ConnectionResetError if abortive else ValueError)
        failure = _teardown_error(stack)
    assert ("ConnectionResetError" if abortive else "ValueError") in failure
    assert "parent fixture stage=reading request" in failure


def test_unexpected_relay_error_remains_visible(monkeypatch):
    error = RuntimeError("unexpected relay failure")

    def fail_select(*args):
        raise error

    monkeypatch.setattr("tests.proxy_contracts.test_authority_consistency.select.select", fail_select)
    with ExitStack() as stack:
        parent, listener = stack.enter_context(_parent())
        with socket.create_connection(parent.server_address, timeout=5) as client:
            with _connect(client, listener):
                assert parent.request_done.wait(5)
                assert parent.errors == [error]
        failure = _teardown_error(stack)
    assert "RuntimeError: unexpected relay failure" in failure
    assert "fail_select" in failure
    assert "direction=both; operation=select" in failure
    assert "parent fixture stage=established CONNECT" in failure


def test_client_reset_preserves_existing_errors():
    error = ValueError("earlier fixture error")
    with ExitStack() as stack:
        parent, listener = stack.enter_context(_parent())
        parent.errors.append(error)
        with socket.create_connection(parent.server_address, timeout=5) as client:
            with _connect(client, listener) as upstream:
                _abort(client)
                assert upstream.recv(1) == b""
                assert parent.request_done.wait(5)
                assert parent.errors == [error]
        failure = _teardown_error(stack)
    assert "ValueError: earlier fixture error" in failure
