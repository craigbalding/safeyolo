#!/usr/bin/env python3
"""Guest-side shell bridge: vsock:2220 -> 127.0.0.1:22 (sshd).

Mirrors guest-proxy-forwarder.py in reverse direction. Accepts vsock
connections from the host-side VSockShellBridge (in safeyolo-vm) and
pumps each one to the in-VM sshd on loopback TCP. This is how
`safeyolo agent shell` reaches an agent VM that has no network
interface (macOS vsock mode).

socat would be a one-liner but isn't in the base rootfs. Python is,
and the pump is a dozen lines of stdlib code — same code path as the
proxy forwarder.

Started by guest-init-per-run.sh; runs as a daemon until shutdown.
"""
from __future__ import annotations

import itertools
import logging
import os
import socket
import sys
import threading
import time

LISTEN_PORT = 2220
SSHD_HOST = "127.0.0.1"
SSHD_PORT = 22
VMADDR_CID_ANY = 0xFFFFFFFF  # accept from any remote CID (i.e. the host)

log = logging.getLogger("safeyolo.guest-shell-bridge")

_DEBUG_ENABLED = os.environ.get("SAFEYOLO_VM_DEBUG", "").lower() in ("1", "true")
_flow_counter = itertools.count(1)
try:
    _AGENT = open("/safeyolo/agent-name").read().strip() or "unknown"
except OSError:
    _AGENT = "unknown"


def _forward(src: socket.socket, dst: socket.socket, counter: list[int]) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            counter[0] += len(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(vsock_conn: socket.socket) -> None:
    flow = next(_flow_counter)
    started = time.monotonic()

    if _DEBUG_ENABLED:
        log.info("accept flow=%d agent=%s upstream=%s:%d",
                 flow, _AGENT, SSHD_HOST, SSHD_PORT)

    try:
        tcp = socket.create_connection((SSHD_HOST, SSHD_PORT), timeout=5)
        tcp.settimeout(None)
    except OSError as exc:
        log.warning("flow=%d agent=%s sshd connect failed: %s: %s",
                    flow, _AGENT, type(exc).__name__, exc)
        vsock_conn.close()
        return

    bytes_in: list[int] = [0]
    bytes_out: list[int] = [0]
    t1 = threading.Thread(target=_forward, args=(vsock_conn, tcp, bytes_in), daemon=True)
    t2 = threading.Thread(target=_forward, args=(tcp, vsock_conn, bytes_out), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    vsock_conn.close()
    tcp.close()

    duration_ms = int((time.monotonic() - started) * 1000)
    log.info("done flow=%d agent=%s bytes_in=%d bytes_out=%d duration_ms=%d",
             flow, _AGENT, bytes_in[0], bytes_out[0], duration_ms)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    if not hasattr(socket, "AF_VSOCK"):
        log.error("AF_VSOCK unsupported on this kernel")
        return 1

    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        server.bind((VMADDR_CID_ANY, LISTEN_PORT))
    except OSError as exc:
        log.error("vsock bind port %d failed: %s: %s",
                  LISTEN_PORT, type(exc).__name__, exc)
        return 1
    server.listen(32)
    log.info("forwarding vsock:%d -> %s:%d",
             LISTEN_PORT, SSHD_HOST, SSHD_PORT)

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(
                target=handle_client, args=(conn,), daemon=True,
            ).start()
    except KeyboardInterrupt:
        log.info("shutting down")
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
