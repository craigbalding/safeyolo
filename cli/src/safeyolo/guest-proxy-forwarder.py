#!/usr/bin/env python3
"""SafeYolo guest-side proxy forwarder.

Listens on localhost:PORT (agent HTTP_PROXY target) and forwards each
connection to the host-side SafeYolo proxy via:

  - Unix domain socket (Linux/gVisor): connect to /safeyolo/proxy.sock
    (bind-mounted from host; gVisor --host-uds=open relays the connect).
  - vsock (macOS/VZ framework): connect to (VMADDR_CID_HOST, 1080) which
    the SafeYolo VM helper accepts and relays to mitmproxy on the host.

Auto-detects transport by probing for the UDS path first, falling back
to vsock. The agent inside the VM never knows which is active — it just
uses HTTP_PROXY=http://127.0.0.1:<PORT>.

Started by guest-init; runs as a daemon until the VM shuts down.

Usage:
    guest-proxy-forwarder.py [port] [uds_path]

Defaults: port=8080, uds_path=/safeyolo/proxy.sock, vsock_port=1080
"""
import itertools
import logging
import os
import socket
import sys
import threading
import time

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
UDS_PATH = sys.argv[2] if len(sys.argv) > 2 else "/safeyolo/proxy.sock"
VSOCK_HOST_PORT = 1080
VMADDR_CID_HOST = 2  # standard vsock host CID

log = logging.getLogger("safeyolo.guest-proxy-forwarder")

# SAFEYOLO_VM_DEBUG gates the per-flow accept log. done/warn are
# always on — low volume, load-bearing for post-mortem.
_DEBUG_ENABLED = os.environ.get("SAFEYOLO_VM_DEBUG", "").lower() in ("1", "true")
_flow_counter = itertools.count(1)

# Agent name for log correlation. guest-init-static writes it to
# /safeyolo/agent-name from the config share. Fallback "unknown" keeps
# the format stable if the file is absent.
try:
    _AGENT = open("/safeyolo/agent-name").read().strip() or "unknown"
except OSError:
    _AGENT = "unknown"


def detect_transport() -> str:
    """Pick UDS (preferred) or vsock based on what's reachable."""
    if os.path.exists(UDS_PATH):
        return "uds"
    if hasattr(socket, "AF_VSOCK"):
        return "vsock"
    raise RuntimeError(
        f"No transport available: UDS {UDS_PATH} missing and AF_VSOCK unsupported"
    )


def connect_upstream(transport: str) -> socket.socket:
    """Open a fresh connection to the host-side proxy."""
    if transport == "uds":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(UDS_PATH)
        return s
    # vsock
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((VMADDR_CID_HOST, VSOCK_HOST_PORT))
    return s


def _forward(src: socket.socket, dst: socket.socket, counter: list[int]) -> None:
    """Copy src->dst until EOF, then half-close dst's write side.

    `counter` is a single-element list used as an out-param for the
    byte count — threading makes returning a value awkward.
    """
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            counter[0] += len(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        # Peer hung up or transport died — normal mid-flow termination.
        # Let finally half-close so the opposite-direction thread sees EOF.
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            # Socket already closed; half-close is a best-effort wake-up
            # for the reverse pump thread.
            pass


def handle_client(client: socket.socket, transport: str) -> None:
    flow = next(_flow_counter)
    started = time.monotonic()
    target = UDS_PATH if transport == "uds" else f"vsock:{VMADDR_CID_HOST}:{VSOCK_HOST_PORT}"

    if _DEBUG_ENABLED:
        log.info("accept flow=%d agent=%s upstream=%s", flow, _AGENT, target)

    try:
        upstream = connect_upstream(transport)
    except OSError as exc:
        log.warning("flow=%d agent=%s upstream=%s connect failed: %s: %s",
                    flow, _AGENT, target, type(exc).__name__, exc)
        client.close()
        return

    bytes_in: list[int] = [0]
    bytes_out: list[int] = [0]
    t1 = threading.Thread(target=_forward, args=(client, upstream, bytes_in), daemon=True)
    t2 = threading.Thread(target=_forward, args=(upstream, client, bytes_out), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()

    duration_ms = int((time.monotonic() - started) * 1000)
    log.info("done flow=%d agent=%s bytes_in=%d bytes_out=%d duration_ms=%d",
             flow, _AGENT, bytes_in[0], bytes_out[0], duration_ms)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    try:
        transport = detect_transport()
    except RuntimeError as exc:
        log.error("%s", exc)
        return 1

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as exc:
        log.error("bind %s:%d failed: %s: %s",
                  LISTEN_HOST, LISTEN_PORT, type(exc).__name__, exc)
        return 1
    server.listen(32)

    target = UDS_PATH if transport == "uds" else f"vsock:{VMADDR_CID_HOST}:{VSOCK_HOST_PORT}"
    log.info("forwarding %s:%d -> %s", LISTEN_HOST, LISTEN_PORT, target)

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(
                target=handle_client, args=(conn, transport), daemon=True
            ).start()
    except KeyboardInterrupt:
        log.info("shutting down")
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
