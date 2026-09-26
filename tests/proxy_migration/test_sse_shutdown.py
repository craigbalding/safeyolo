"""Real SSE socket ownership during cancellation and graceful shutdown."""

from __future__ import annotations

import json
import os
import select
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.proxy_migration.harness import (
    RunningProxy,
    child_process,
    connection,
    launch_proxy,
    python_proxy_environment,
    request,
    wait_ready,
)
from tests.proxy_migration.scenarios import POLICY

FIRST = b"data: first\n\n"
LAST = b"data: last\n\n"


class EventOrigin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.first_sent = threading.Event()
        self.release = threading.Event()
        self.peer_closed = threading.Event()
        self.finished = threading.Event()
        self.requests = 0
        super().__init__(("127.0.0.1", 0), EventHandler)


class EventHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.server.requests += 1
        assert self.path == "/events"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(FIRST)
            self.wfile.flush()
            self.server.first_sent.set()
            deadline = time.monotonic() + 12
            while not self.server.release.is_set() and time.monotonic() < deadline:
                readable, _, _ = select.select([self.connection], [], [], 0.02)
                if readable and not self.connection.recv(1, socket.MSG_PEEK):
                    self.server.peer_closed.set()
                    return
            if self.server.release.is_set():
                self.wfile.write(LAST)
                self.wfile.flush()
        except (ConnectionResetError, BrokenPipeError):
            self.server.peer_closed.set()
        finally:
            self.server.finished.set()


@contextmanager
def event_origin():
    origin = EventOrigin()
    worker = threading.Thread(target=origin.serve_forever)
    worker.start()
    try:
        yield origin
    finally:
        origin.release.set()
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive()


def wait_until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(0.02)


def event_url(origin):
    return f"http://127.0.0.1:{origin.server_address[1]}/events"


def test_early_sse_disconnect_exits_and_restarts(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with launch_proxy(proxy_backend, directory, POLICY, native_policy=True) as proxy:
        config = (directory / "proxy.json").read_bytes()
        policy = (directory / "policy.toml").read_bytes()
        with event_origin() as origin:
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(proxy.paths["alice"])
                url = event_url(origin)
                client.sendall(f"GET {url} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
                received = bytearray()
                while FIRST not in received:
                    part = client.recv(4096)
                    assert part, received
                    received.extend(part)
                assert b"200" in received.split(b"\r\n", 1)[0]
                assert origin.first_sent.is_set()
            # The raw client socket is now actually gone. Observe the origin
            # close before SIGTERM, so shutdown cannot cause the cancellation.
            assert origin.peer_closed.wait(2), "upstream stayed open after client disconnect"
            assert origin.finished.wait(2)
            assert origin.requests == 1

        first_pid = proxy.process.pid
        start = time.monotonic()
        proxy.process.terminate()
        wait_until(lambda: not proxy.readiness_file.exists())
        assert proxy.process.wait(timeout=3) == 0
        assert time.monotonic() - start < 3
        for path in proxy.paths.values():
            with socket.socket(socket.AF_UNIX) as client:
                assert client.connect_ex(path) != 0

        restart_dir = directory / "restart"
        restart_dir.mkdir()
        environment = python_proxy_environment(
            python_source=os.environ.get("SAFEYOLO_PYTHON_SOURCE")
        )
        environment["SAFEYOLO_LOG_PATH"] = str(directory / "audit.jsonl")
        with child_process(proxy.process.args, restart_dir, environment) as process:
            wait_ready(
                process, [proxy.readiness_file, *proxy.paths.values()],
                restart_dir / "process.log", readiness_file=proxy.readiness_file,
                expected_backend="python" if proxy_backend == "python" else "rust-m2",
            )
            restarted = RunningProxy(proxy.paths, proxy.event_log, process, proxy.readiness_file)
            assert process.pid != first_pid
            assert json.loads(proxy.readiness_file.read_text())["pid"] == process.pid
            assert (directory / "proxy.json").read_bytes() == config
            assert (directory / "policy.toml").read_bytes() == policy
            with event_origin() as origin:
                origin.release.set()
                assert request(restarted.paths["alice"], event_url(origin))[0] == 200
                status, headers, _ = request(restarted.paths["bob"], event_url(origin))
                headers = {name.lower(): value for name, value in headers.items()}
                assert status == 403 and headers.get("x-blocked-by") == "network-guard"
                assert origin.requests == 1
        assert not proxy.readiness_file.exists()


def test_live_sse_response_shutdown_behavior(proxy_backend, tmp_path):
    with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY, native_policy=True) as proxy:
        with event_origin() as origin:
            client = connection(proxy.paths["alice"])
            response = None
            try:
                client.request("GET", event_url(origin), headers={"Connection": "close"})
                response = client.getresponse()
                assert response.status == 200
                assert response.read(len(FIRST)) == FIRST
                # HTTPConnection detaches a close-delimited HTTPResponse. Its
                # close() does not close the still-open response socket.
                client.close()
                assert not origin.peer_closed.is_set()
                start = time.monotonic()
                proxy.process.terminate()
                wait_until(lambda: not proxy.readiness_file.exists())
                if proxy_backend == "rust":
                    assert proxy.process.poll() is None
                    assert not origin.peer_closed.is_set()
                    origin.release.set()
                    assert response.read() == LAST
                else:
                    assert origin.peer_closed.wait(2)
                    origin.release.set()
                    assert response.read() == b""
                assert origin.finished.wait(2)
                assert proxy.process.wait(timeout=3) == 0
                assert time.monotonic() - start < 3
            finally:
                origin.release.set()
                if response is not None:
                    response.close()
                client.close()
