#!/usr/bin/env python3
"""Host-side bridge: accept connections on a UDS, forward to a TCP endpoint.

Usage:
    python3 host_uds_bridge.py /path/to/proxy.sock 127.0.0.1 8080

Each UDS connection is forwarded bidirectionally to the TCP endpoint.
Runs until killed. Cleans up the socket file on exit.
"""
import os
import socket
import sys
import threading


def forward(src, dst, label):
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


def handle_client(uds_conn, tcp_host, tcp_port):
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.connect((tcp_host, tcp_port))
    except OSError as exc:
        print(f"  TCP connect to {tcp_host}:{tcp_port} failed: {exc}", flush=True)
        uds_conn.close()
        return

    t1 = threading.Thread(target=forward, args=(uds_conn, tcp, "uds→tcp"), daemon=True)
    t2 = threading.Thread(target=forward, args=(tcp, uds_conn, "tcp→uds"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    uds_conn.close()
    tcp.close()


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <socket_path> <tcp_host> <tcp_port>")
        sys.exit(1)

    sock_path = sys.argv[1]
    tcp_host = sys.argv[2]
    tcp_port = int(sys.argv[3])

    # Clean up stale socket
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, 0o666)  # container needs access
    server.listen(16)
    print(f"UDS bridge listening on {sock_path} -> {tcp_host}:{tcp_port}", flush=True)

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(
                target=handle_client, args=(conn, tcp_host, tcp_port), daemon=True
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
