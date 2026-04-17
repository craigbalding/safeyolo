#!/usr/bin/env python3
"""Guest-side proxy forwarder: localhost:PORT -> UDS or vsock.

Listens on localhost:PORT (the HTTP_PROXY target). Each connection is
forwarded to the host-side proxy via either:
  - Unix domain socket (Linux/gVisor with --host-uds=open)
  - vsock (macOS/VZ framework)

Auto-detects transport: if the UDS path exists, uses UDS. Otherwise
falls back to vsock.

Usage:
    python3 guest_proxy_forwarder.py [port] [uds_path]

Defaults: port=8080, uds_path=/safeyolo/proxy.sock, vsock_port=1080
"""
import os
import socket
import sys
import threading

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
UDS_PATH = sys.argv[2] if len(sys.argv) > 2 else "/safeyolo/proxy.sock"
VSOCK_PORT = 1080
VSOCK_CID_HOST = 2  # VMADDR_CID_HOST


def detect_transport():
    """Detect whether to use UDS or vsock."""
    if os.path.exists(UDS_PATH):
        return "uds"
    # Check if AF_VSOCK is available (Linux 4.8+, gVisor doesn't support it)
    if hasattr(socket, "AF_VSOCK"):
        return "vsock"
    return None


def connect_upstream():
    """Connect to the host proxy via the detected transport."""
    transport = detect_transport()
    if transport == "uds":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(UDS_PATH)
        return s
    elif transport == "vsock":
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((VSOCK_CID_HOST, VSOCK_PORT))
        return s
    else:
        raise RuntimeError("No transport available: no UDS at {UDS_PATH} and no AF_VSOCK")


def forward(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(tcp_conn):
    try:
        upstream = connect_upstream()
    except OSError as exc:
        print(f"  upstream connect failed: {exc}", flush=True)
        tcp_conn.close()
        return

    t1 = threading.Thread(target=forward, args=(tcp_conn, upstream), daemon=True)
    t2 = threading.Thread(target=forward, args=(upstream, tcp_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    tcp_conn.close()
    upstream.close()


def main():
    transport = detect_transport()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", LISTEN_PORT))
    server.listen(16)

    # Write readiness marker
    with open(f"/tmp/forwarder-{LISTEN_PORT}.ready", "w") as f:
        f.write(str(os.getpid()))

    print(f"Proxy forwarder on 127.0.0.1:{LISTEN_PORT} -> {transport}",
          flush=True)

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    main()
