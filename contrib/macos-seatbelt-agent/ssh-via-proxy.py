#!/usr/bin/env python3
"""OpenSSH ProxyCommand using only the configured SafeYolo HTTP proxy."""

import argparse
import os
import re
import socket
import ssl
import sys
import threading
from urllib.parse import urlsplit


def destination(host, port):
    """Validate an SSH destination before putting it in CONNECT authority form."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host) or host.startswith("-"):
        raise ValueError("Host must be a DNS name or an unbracketed IP address")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def connect(host, port):
    authority = destination(host, port)
    proxy = urlsplit(os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "")
    if proxy.scheme not in {"http", "https"} or not proxy.hostname:
        raise ValueError("Set HTTPS_PROXY or HTTP_PROXY to the approved proxy URL; no direct fallback")
    if proxy.username or proxy.password or proxy.path not in {"", "/"} or proxy.query or proxy.fragment:
        raise ValueError("Expected a proxy URL without credentials, path, query or fragment")
    stream = socket.create_connection((proxy.hostname, proxy.port or (443 if proxy.scheme == "https" else 80)), timeout=15)
    try:
        if proxy.scheme == "https":
            stream = ssl.create_default_context().wrap_socket(stream, server_hostname=proxy.hostname)
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        # Avoid reading past the headers: an SSH server can send its banner
        # immediately, and every byte must reach the SSH client unchanged.
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            chunk = stream.recv(1)
            if not chunk or len(header) >= 32768:
                raise OSError("Proxy closed the connection or sent oversized CONNECT headers")
            header.extend(chunk)
        lines = header.decode("iso-8859-1").split("\r\n")
        fields = lines[0].split(" ", 2)
        if len(fields) < 2 or fields[1] != "200":
            details = [line for line in lines[1:] if line.lower().startswith(("x-blocked-by:", "x-safeyolo-request-id:"))]
            if len(fields) >= 2 and fields[1] == "428":
                details.append("Operator approval required: run safeyolo watch on the host, then retry once approved.")
            raise OSError(f"CONNECT rejected: {lines[0]!r}; {'; '.join(details)}")
        stream.settimeout(None)
        return stream
    except (OSError, ValueError):
        stream.close()
        raise


def relay(stream):
    def send_input():
        try:
            while chunk := os.read(sys.stdin.fileno(), 65536):
                stream.sendall(chunk)
            stream.shutdown(socket.SHUT_WR)
        except OSError:
            # A peer close can race stdin EOF or an outstanding SSH write.
            # The receiving loop observes the peer's close/error and terminates.
            return

    threading.Thread(target=send_input, daemon=True).start()
    while chunk := stream.recv(65536):
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    try:
        with connect(args.host, args.port) as stream:
            relay(stream)
    except (OSError, ValueError) as exc:
        print(f"ssh-via-proxy: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
