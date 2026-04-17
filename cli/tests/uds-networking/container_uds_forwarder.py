#!/usr/bin/env python3
"""Container-side forwarder: listen on localhost:PORT, forward to a UDS.

Usage:
    python3 container_uds_forwarder.py 8080 /safeyolo/proxy.sock

Runs as a daemon inside the container. guest-init would start this
before the agent process. All HTTP_PROXY traffic goes through this.
"""
import os
import socket
import sys
import threading


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


def handle_client(tcp_conn, uds_path):
    try:
        uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        uds.connect(uds_path)
    except OSError as exc:
        print(f"  UDS connect to {uds_path} failed: {exc}", flush=True)
        tcp_conn.close()
        return

    t1 = threading.Thread(target=forward, args=(tcp_conn, uds), daemon=True)
    t2 = threading.Thread(target=forward, args=(uds, tcp_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    tcp_conn.close()
    uds.close()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <uds_path>")
        sys.exit(1)

    port = int(sys.argv[1])
    uds_path = sys.argv[2]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(16)
    print(f"Forwarder listening on 127.0.0.1:{port} -> {uds_path}", flush=True)

    # Write a marker file so the test can detect readiness
    marker = f"/tmp/forwarder-{port}.ready"
    with open(marker, "w") as f:
        f.write(str(os.getpid()))

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(
                target=handle_client, args=(conn, uds_path), daemon=True
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    main()
