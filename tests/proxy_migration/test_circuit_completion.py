"""Live circuit state follows completed upstream messages and local cancellation."""

import json
import socket
import struct
import threading
import time
from contextlib import contextmanager

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.test_agent_api_contract import api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import ALLOW, policy_proxy
from tests.proxy_migration.test_websocket_contract import read_head

HOST = "127.0.0.2"
POLICY = (
    ALLOW
    + """
[addons.circuit_breaker]
failure_threshold = 100
timeout_seconds = 600
use_exponential_backoff = false
jitter_factor = 0
"""
)


class CompletionPeer:
    """Two owned requests: a completed failure, then one controlled response."""

    def __init__(self, mode):
        self.mode = mode
        self.listener = socket.socket()
        self.listener.bind((HOST, 0))
        self.listener.listen()
        self.listener.settimeout(5)
        self.address = self.listener.getsockname()
        self.held = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.accepts = 0
        self.heads = []
        self.errors = []
        self.thread = threading.Thread(target=self.run)

    def run(self):
        try:
            for index in range(2):
                connection, _ = self.listener.accept()
                self.accepts += 1
                with connection:
                    connection.settimeout(5)
                    self.heads.append(read_head(connection))
                    if index == 0:
                        connection.sendall(b"HTTP/1.1 500 Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nseed")
                        continue
                    extra = b"X-Blocked-By: network-guard\r\n" if self.mode == "forged-block" else b""
                    framing = b"Transfer-Encoding: chunked\r\n" if self.mode == "chunked" else b"Content-Length: 6\r\n"
                    connection.sendall(b"HTTP/1.1 500 Error\r\n" + extra + framing + b"Connection: close\r\n\r\n")
                    connection.sendall(b"3\r\nabc\r\n" if self.mode == "chunked" else b"abc")
                    self.held.set()
                    if self.mode == "canceled":
                        # The proxy must close its actual origin connection
                        # before final bytes could complete this message.
                        try:
                            assert connection.recv(1) == b"", "unexpected upstream request bytes"
                        except ConnectionResetError:
                            pass
                    else:
                        assert self.release.wait(5), "response release was not signaled"
                        if self.mode == "chunked":
                            connection.sendall(b"3\r\ndef\r\n0\r\n\r\n")
                        elif self.mode != "truncated":
                            connection.sendall(b"def")
        except Exception as error:
            self.errors.append(error)
        finally:
            self.finished.set()


@contextmanager
def completion_peer(mode):
    peer = CompletionPeer(mode)
    peer.thread.start()
    try:
        yield peer
    finally:
        peer.release.set()
        peer.listener.close()
        peer.thread.join(timeout=6)
        assert not peer.thread.is_alive(), "owned response peer did not finish"
        assert not peer.errors, peer.errors
        with socket.socket() as stopped:
            stopped.settimeout(1)
            assert stopped.connect_ex(peer.address) != 0


def circuits(proxy):
    return assert_api_response(api_request(proxy, "/circuits"), 200)


def wait_failure_count(proxy, expected):
    deadline = time.monotonic() + 5
    while True:
        value = circuits(proxy)
        if value["domains"][HOST]["failure_count"] == expected:
            return value
        assert time.monotonic() < deadline, value
        time.sleep(0.01)


@pytest.mark.parametrize("mode", ["fixed", "chunked", "truncated", "canceled", "forged-block"])
def test_only_complete_upstream_responses_change_live_failure_state(proxy_backend, tmp_path, mode):
    directory = tmp_path / proxy_backend
    with completion_peer(mode) as peer:
        with policy_proxy(proxy_backend, directory, POLICY, agent_api=True, circuit_breaker_enabled=True) as proxy:
            target = f"http://{HOST}:{peer.address[1]}"
            status, _, body = send_request(proxy.paths["alice"], target + "/seed")
            assert status == 500 and body == b"seed"
            assert wait_failure_count(proxy, 1)["checks_total"] == 1
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(proxy.paths["bob"])
                client.sendall(
                    f"GET {target}/held HTTP/1.1\r\nHost: {HOST}:{peer.address[1]}\r\nConnection: close\r\n\r\n".encode()
                )
                assert peer.held.wait(5), "origin never received the admitted request"
                before = circuits(proxy)
                assert before["checks_total"] == 2
                assert before["domains"][HOST]["failure_count"] == 1
                if mode == "canceled":
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    client.close()
                    assert peer.finished.wait(5), "client cancellation did not close the held origin connection"
                    wire = b""
                else:
                    peer.release.set()
                    pieces = []
                    while piece := client.recv(65536):
                        pieces.append(piece)
                    wire = b"".join(pieces)
                    assert peer.finished.wait(5)
                expected = 1 if mode in {"truncated", "canceled"} else 2
                after = wait_failure_count(proxy, expected)
                assert after["checks_total"] == 2
                assert after["opens_total"] == 0
                assert len(proxy.events("proxy.egress")) == peer.accepts == 2
                assert all((row["host"], row["port"]) == peer.address for row in proxy.events("proxy.egress"))
                (directory / "completion-wire.json").write_text(
                    json.dumps(
                        {
                            "mode": mode,
                            "before": before,
                            "after": after,
                            "response_hex": wire.hex(),
                            "request_heads": peer.heads,
                            "origin_accepts": peer.accepts,
                            "unexpected_egress": 0,
                        },
                        indent=2,
                    )
                    + "\n"
                )
        assert proxy.process.poll() is not None and not proxy.readiness_file.exists()


@pytest.mark.parametrize("method,threshold", [("CONNECT", 5), ("GET", 2)])
def test_outer_connect_has_no_circuit_response_hook(proxy_backend, tmp_path, method, threshold):
    policy = """
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
[addons.circuit_breaker]
failure_threshold = 2
jitter_factor = 0
"""
    with socket.socket() as origin:
        origin.bind((HOST, 0))
        origin.listen()
        origin.settimeout(0.025)
        host = f"{HOST}:{origin.getsockname()[1]}"
        with policy_proxy(
            proxy_backend,
            tmp_path / proxy_backend,
            policy,
            agent_api=True,
            circuit_breaker_enabled=True,
        ) as proxy:
            target = host if method == "CONNECT" else f"http://{host}/denied"
            status, headers, _ = send_request(proxy.paths["alice"], target, method=method, headers={"Host": host})
            assert status == 403
            assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
            first = circuits(proxy)
            assert first["failure_threshold"] == threshold
            assert first["checks_total"] == 0 and first["domains"] == {}
            assert proxy.events("proxy.egress") == []
            with pytest.raises(socket.timeout):
                origin.accept()
