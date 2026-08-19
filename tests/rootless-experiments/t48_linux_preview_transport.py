#!/usr/bin/env python3
"""Bounded Linux preview-transport experiment against an existing agent.

Compares the current per-connection ``runsc exec -> socat`` path with
gVisor's native ``runsc port-forward --stream`` UDS donation. This file is
experimental: it does not mutate SafeYolo configuration or product code.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import select
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from safeyolo.platform.linux import (
    LinuxPlatform,
    _container_id,
    _find_runsc,
    _get_userns_pid,
    _nsenter_cmd,
    _runsc_root,
)
from safeyolo.preview import build_guest_relay_command

TIMEOUT_SECONDS = 8.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ProbeError(RuntimeError):
    """One transport probe failed."""


@dataclass
class Relay:
    reader_fd: int
    write_bytes: Callable[[bytes], None]
    close_write: Callable[[], None]
    close_relay: Callable[[], None]

    def write(self, data: bytes) -> None:
        self.write_bytes(data)

    def shutdown_write(self) -> None:
        self.close_write()

    def close(self) -> None:
        self.close_relay()


@dataclass
class ProcessTracker:
    processes: list[subprocess.Popen] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, process: subprocess.Popen) -> None:
        with self.lock:
            self.processes.append(process)

    def unreaped(self) -> list[int]:
        with self.lock:
            return [process.pid for process in self.processes if process.poll() is None]

    def terminate_all(self) -> None:
        with self.lock:
            processes = list(self.processes)
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


def terminate_process(process: subprocess.Popen) -> None:
    """Bounded cleanup for an experiment child process."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


class ExecSocatFactory:
    def __init__(self, agent: str, tracker: ProcessTracker):
        self.agent = agent
        self.tracker = tracker
        self.platform = LinuxPlatform()

    def open(self) -> Relay:
        process = self.platform.popen_binary_in_sandbox(
            self.agent,
            build_guest_relay_command(6080),
            user="agent",
        )
        self.tracker.add(process)
        if process.stdin is None or process.stdout is None:
            terminate_process(process)
            raise ProbeError("runsc exec relay has no stdin/stdout")

        def write_bytes(data: bytes) -> None:
            process.stdin.write(data)
            process.stdin.flush()

        def close_write() -> None:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()

        def close_relay() -> None:
            close_write()
            terminate_process(process)

        return Relay(process.stdout.fileno(), write_bytes, close_write, close_relay)


class PortForwardStreamFactory:
    def __init__(self, agent: str, tracker: ProcessTracker, socket_dir: Path):
        self.agent = agent
        self.tracker = tracker
        self.socket_dir = socket_dir
        self.counter = 0
        self.lock = threading.Lock()

    def _next_path(self) -> Path:
        with self.lock:
            self.counter += 1
            return self.socket_dir / f"stream-{self.counter}.sock"

    def open(self) -> Relay:
        stream_path = self._next_path()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(TIMEOUT_SECONDS)
        listener.bind(str(stream_path))
        listener.listen(1)

        userns_pid = _get_userns_pid(self.agent)
        prefix = _nsenter_cmd(userns_pid) if userns_pid else []
        command = prefix + [
            _find_runsc(),
            "--root",
            _runsc_root(),
            "port-forward",
            "--stream",
            str(stream_path),
            _container_id(self.agent),
            "6080",
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.tracker.add(process)
        connection: socket.socket | None = None
        try:
            connection, _ = listener.accept()
            connection.setblocking(True)
            stdout, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
            if process.returncode != 0:
                detail = (stderr or stdout).decode(errors="replace").strip()
                raise ProbeError(f"runsc port-forward exited {process.returncode}: {detail or '<no output>'}")
        except Exception:
            if connection is not None:
                connection.close()
            terminate_process(process)
            raise
        finally:
            listener.close()
            stream_path.unlink(missing_ok=True)

        if connection is None:  # Defensive; listener.accept() either returns or raises.
            raise ProbeError("runsc port-forward did not connect to the stream socket")

        def write_bytes(data: bytes) -> None:
            connection.sendall(data)

        def close_write() -> None:
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        return Relay(connection.fileno(), write_bytes, close_write, connection.close)


def read_until(relay: Relay, marker: bytes | None) -> bytes:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    output = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("timed out waiting for relay response")
        readable, _, _ = select.select([relay.reader_fd], [], [], remaining)
        if not readable:
            raise ProbeError("timed out waiting for relay response")
        chunk = os.read(relay.reader_fd, 65536)
        if not chunk:
            if marker is not None and marker not in output:
                raise ProbeError("relay closed before complete response headers")
            return bytes(output)
        output.extend(chunk)
        if len(output) > MAX_RESPONSE_BYTES:
            raise ProbeError("response exceeded experiment limit")
        if marker is not None and marker in output:
            return bytes(output)


def http_probe(factory, request_number: int, *, half_close_write: bool) -> None:
    relay = factory.open()
    try:
        relay.write(
            (
                f"GET /vnc.html?probe={request_number} HTTP/1.1\r\nHost: 127.0.0.1:6080\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        if half_close_write:
            relay.shutdown_write()
        response = read_until(relay, None)
        first_line = response.split(b"\r\n", 1)[0]
        if b" 200 " not in first_line:
            raise ProbeError(f"unexpected HTTP response: {first_line!r}")
        if b"<html" not in response.lower() and b"<!doctype" not in response.lower():
            raise ProbeError("HTTP 200 response did not contain the noVNC page")
    finally:
        relay.close()


def open_websocket(factory) -> Relay:
    relay = factory.open()
    try:
        relay.write(
            b"GET /websockify HTTP/1.1\r\n"
            b"Host: 127.0.0.1:6080\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Origin: http://127.0.0.1:6080\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"Sec-WebSocket-Protocol: binary\r\n\r\n"
        )
        response = read_until(relay, b"\r\n\r\n")
        first_line = response.split(b"\r\n", 1)[0]
        if b" 101 " not in first_line:
            raise ProbeError(f"unexpected WebSocket response: {first_line!r}")
    except Exception:
        relay.close()
        raise
    return relay


def verify_preconditions(agent: str) -> None:
    result = subprocess.run(
        ["safeyolo", "agent", "shell", agent, "-c", "/safeyolo/guest-desktop status"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ProbeError(f"agent desktop is not ready: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("transport", choices=("exec-socat", "port-forward-stream"))
    parser.add_argument("agent")
    parser.add_argument("--requests", type=int, default=48)
    parser.add_argument("--concurrency", type=int, default=12)
    parser.add_argument(
        "--http-write",
        choices=("half-close", "keep-open"),
        default="half-close",
        help="whether HTTP probes close their write side before reading",
    )
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1:
        parser.error("--requests and --concurrency must be positive")

    verify_preconditions(args.agent)
    tracker = ProcessTracker()
    failures: list[str] = []
    websocket: Relay | None = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="safeyolo-preview-t48-") as temporary:
            if args.transport == "exec-socat":
                factory = ExecSocatFactory(args.agent, tracker)
            else:
                factory = PortForwardStreamFactory(args.agent, tracker, Path(temporary))

            try:
                websocket = open_websocket(factory)
            except Exception as exc:  # noqa: BLE001 - experiment records the transport failure
                failures.append(f"websocket: {type(exc).__name__}: {exc}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                futures = [
                    pool.submit(
                        http_probe,
                        factory,
                        number,
                        half_close_write=args.http_write == "half-close",
                    )
                    for number in range(args.requests)
                ]
                for number, future in enumerate(futures):
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001 - report every failed connection
                        failures.append(f"http[{number}]: {type(exc).__name__}: {exc}")
    finally:
        if websocket is not None:
            websocket.close()
        tracker.terminate_all()

    elapsed = time.monotonic() - started
    print(f"transport: {args.transport}")
    print(f"agent: {args.agent}")
    print(f"workload: 1 websocket + {args.requests} HTTP requests at concurrency {args.concurrency}")
    print(f"HTTP write side: {args.http_write}")
    print(f"elapsed: {elapsed:.2f}s")
    print(f"passed: {args.requests + 1 - len(failures)}/{args.requests + 1}")
    print(f"unreaped child processes: {tracker.unreaped()}")
    if failures:
        print(f"failures: {len(failures)}")
        for failure in failures[:12]:
            print(f"  {failure}")
        if len(failures) > 12:
            print(f"  ... {len(failures) - 12} more")
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
