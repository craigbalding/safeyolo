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
import logging
import os
import socket
import sys
import threading

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
UDS_PATH = sys.argv[2] if len(sys.argv) > 2 else "/safeyolo/proxy.sock"
VSOCK_HOST_PORT = 1080
VMADDR_CID_HOST = 2  # standard vsock host CID

log = logging.getLogger("safeyolo.guest-proxy-forwarder")


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


def _forward(src: socket.socket, dst: socket.socket) -> None:
    """Copy src->dst until EOF, then half-close dst's write side."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
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
    try:
        upstream = connect_upstream(transport)
    except OSError as exc:
        log.warning("upstream connect failed: %s: %s", type(exc).__name__, exc)
        client.close()
        return

    t1 = threading.Thread(target=_forward, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=_forward, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


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
