#!/usr/bin/env python3
"""Fixed, unprivileged guest health probe for the PID-1 recovery recipe."""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
import time
from pathlib import Path


def deadline_expired(*_args: object) -> None:
    raise TimeoutError("guest probe exceeded eight seconds")


def ssh_banner() -> dict:
    deadline = time.monotonic() + 1.0
    try:
        with socket.create_connection(("127.0.0.1", 22), timeout=1.0) as sock:
            raw = bytearray()
            while not raw.endswith(b"\n") and len(raw) < 256:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("SSH banner deadline expired")
                sock.settimeout(remaining)
                part = sock.recv(1)
                if not part:
                    break
                raw.extend(part)
        return {"received": raw.startswith(b"SSH-2.0-") and raw.endswith(b"\n"),
                "banner": raw.decode("ascii", errors="replace").rstrip()}
    except OSError as error:
        return {"received": False, "error": str(error)[:256]}


def processes() -> dict:
    # Linux comm is limited to 15 visible bytes. Do not collect argv or env.
    names = {"sshd", "socat", "guest-shell-bri", "guest-proxy-bri", "vsock-term", "tmux: server"}
    found = []
    inspected = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            inspected += 1
            if inspected > 4096 or len(found) == 64:
                return {"matches": found, "truncated": True}
            try:
                comm = (Path(entry.path) / "comm").read_text().strip()[:64]
            except OSError:
                continue  # A process can exit between directory and comm reads.
            if comm in names:
                found.append({"pid": int(entry.name), "comm": comm})
    return {"matches": found, "truncated": False}


def main() -> int:
    result = {"probe_id": sys.argv[1], "uid": os.getuid(), "pid": os.getpid()}
    stop = Path(os.environ.get("SAFEYOLO_COMMAND_SUPERVISOR_STOP",
                               "/home/agent/.safeyolo-command-supervisor.stop"))
    signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(8)
    try:
        result["processes"] = processes()
        result["sshd_loopback"] = ssh_banner()
    except (OSError, TimeoutError) as error:
        result["error"] = str(error)[:256]
    finally:
        signal.alarm(0)
        # The supervisor retains a bounded stderr tail. Fence before exit so
        # its normal restart policy does not rerun this one-shot probe.
        print(json.dumps(result, sort_keys=True), file=sys.stderr, flush=True)
        stop.write_text(json.dumps({"probe_id": result["probe_id"]}) + "\n")
    return 1 if "error" in result else 0


if __name__ == "__main__":
    raise SystemExit(main())
