"""Bounded host-side probes for a VM with no network interface."""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

_SSH_IDENTIFICATION = re.compile(rb"SSH-(?:2\.0|1\.99)-[!-~]+(?: [ -~]*)?\r?\n")


@dataclass(frozen=True)
class SSHBannerProbe:
    connected: bool
    banner: str | None
    error: str | None
    elapsed_ms: int


def _read_banner(sock: socket.socket, deadline: float) -> str:
    pending = b""
    received = 0
    while received < 8192:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SSH identification deadline expired")
        sock.settimeout(remaining)
        chunk = sock.recv(min(1024, 8192 - received))
        if not chunk:
            raise ValueError("peer closed before SSH identification")
        pending += chunk
        received += len(chunk)
        while b"\n" in pending:
            line, _, pending = pending.partition(b"\n")
            line += b"\n"
            if line.startswith(b"SSH-"):
                if len(line) > 255 or _SSH_IDENTIFICATION.fullmatch(line) is None:
                    raise ValueError("peer sent invalid SSH identification")
                return line.decode("ascii").rstrip("\r\n")
    raise ValueError("no SSH identification within 8192 diagnostic bytes")


def probe_shell_socket(path: Path, *, timeout: float = 3.0) -> SSHBannerProbe:
    """Observe UDS connect and an SSH identification separately, without authentication.

    A single monotonic deadline includes connect, pre-banner lines and fragmented
    input. The byte limit bounds this diagnostic's work; it does not limit relays.
    """
    start = time.monotonic()
    connected = False
    banner = None
    error = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            connected = True
            banner = _read_banner(sock, start + timeout)
    except TimeoutError:
        error = "timed out waiting for SSH identification" if connected else "UDS connect timed out"
    except (OSError, ValueError) as exc:
        error = str(exc)
    return SSHBannerProbe(connected, banner, error, int((time.monotonic() - start) * 1000))
