#!/usr/bin/env python3
"""Route blackbox fixture hosts to the owned sinkhole through an HTTP parent.

The selected SafeYolo proxy still owns policy, credentials, and the Agent API.
This process supplies only an upstream test route. Other destinations use the
configured parent when one exists, or the host's ordinary network route.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from sinkhole_router import (
    SINKHOLE_HOST,
    SINKHOLE_HOST_HTTPS_PORTS,
    SINKHOLE_HOSTS,
    SINKHOLE_HTTP_PORT,
    SINKHOLE_HTTPS_PORT,
)


def _open_peer(
    host: str, port: int, *, tls: bool = False, ca_file: Path | None = None
) -> socket.socket:
    peer = socket.create_connection((host, port), timeout=10)
    peer.settimeout(30)
    if tls:
        try:
            context = ssl.create_default_context()
            if ca_file is not None:
                context.load_verify_locations(cafile=str(ca_file))
            wrapped = context.wrap_socket(peer, server_hostname=host)
            wrapped.settimeout(None)
            return wrapped
        except Exception:
            peer.close()
            raise
    peer.settimeout(None)
    return peer


def _copy_tunnel(source: socket.socket, destination: socket.socket) -> None:
    try:
        while data := source.recv(65_536):
            destination.sendall(data)
    except (OSError, ssl.SSLError):
        pass
    try:
        destination.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _copy_exact(source, destination: socket.socket, length: int) -> None:
    while length:
        data = source.read(min(length, 65_536))
        if not data:
            raise ConnectionError("request body ended early")
        destination.sendall(data)
        length -= len(data)


class Parent(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self, upstream_parent: str | None, ca_file: Path | None,
        p2_ssh_port_file: Path | None = None,
    ):
        self.upstream_parent = urlsplit(upstream_parent) if upstream_parent else None
        self.ca_file = ca_file
        self.p2_ssh_port_file = p2_ssh_port_file
        if (
            self.upstream_parent
            and self.upstream_parent.scheme == "https"
            and ca_file is not None
            and not ca_file.is_file()
        ):
            raise ValueError(f"configured upstream CA is unavailable: {ca_file}")
        if self.upstream_parent and (
            self.upstream_parent.scheme not in {"http", "https"}
            or not self.upstream_parent.hostname
            or self.upstream_parent.username
            or self.upstream_parent.password
            or self.upstream_parent.path not in {"", "/"}
            or self.upstream_parent.query
            or self.upstream_parent.fragment
        ):
            raise ValueError("configured test-instance parent must be an unauthenticated HTTP(S) URL")
        if self.upstream_parent is not None and self.upstream_parent.port == 0:
            raise ValueError("configured test-instance parent has an invalid port")
        super().__init__(("127.0.0.1", 0), Request)


class Request(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: Parent

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _peer(self, host: str, port: int, *, tls_origin: bool) -> tuple[socket.socket, bool]:
        fixture_host = host.rstrip(".").lower()
        if (tls_origin and fixture_host == "failing.test" and port == 22
                and self.server.p2_ssh_port_file):
            ssh_port = int(self.server.p2_ssh_port_file.read_text().strip())
            if not 1 <= ssh_port <= 65535:
                raise ValueError("invalid P2 SSH port")
            return _open_peer(SINKHOLE_HOST, ssh_port), False
        if fixture_host in SINKHOLE_HOSTS:
            sinkhole_port = (
                SINKHOLE_HOST_HTTPS_PORTS.get(fixture_host, SINKHOLE_HTTPS_PORT)
                if tls_origin
                else SINKHOLE_HTTP_PORT
            )
            return _open_peer(SINKHOLE_HOST, sinkhole_port), False
        parent = self.server.upstream_parent
        if parent is not None:
            return _open_peer(
                parent.hostname,
                parent.port or (443 if parent.scheme == "https" else 80),
                tls=parent.scheme == "https",
                ca_file=self.server.ca_file,
            ), True
        return _open_peer(host, port), False

    def _forward_http(self) -> None:
        target = urlsplit(self.path)
        if target.scheme != "http" or not target.hostname:
            self.send_error(400, "parent requires an absolute HTTP target")
            return
        try:
            port = target.port or 80
            body_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid HTTP authority or content length")
            return
        if body_length < 0:
            self.send_error(400, "invalid fixture request body length")
            return
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if transfer_encoding not in {"", "chunked"} or (transfer_encoding and "Content-Length" in self.headers):
            self.send_error(400, "invalid fixture request framing")
            return
        chunked = transfer_encoding == "chunked"
        upgrade = self.headers.get("Upgrade") is not None
        try:
            peer, via_parent = self._peer(target.hostname, port, tls_origin=False)
            with peer:
                path = self.path if via_parent else (target.path or "/") + (f"?{target.query}" if target.query else "")
                peer.sendall(f"{self.command} {path} HTTP/1.1\r\n".encode("ascii"))
                for name, value in self.headers.items():
                    if name.lower() not in {"proxy-connection", "proxy-authorization"} and (
                        upgrade or name.lower() != "connection"
                    ):
                        peer.sendall(f"{name}: {value}\r\n".encode("latin-1"))
                peer.sendall(b"\r\n" if upgrade else b"Connection: close\r\n\r\n")
                if chunked:
                    while True:
                        size_line = self.rfile.readline(65_536)
                        if not size_line:
                            raise ConnectionError("chunked request ended early")
                        peer.sendall(size_line)
                        size = int(size_line.split(b";", 1)[0], 16)
                        if size:
                            _copy_exact(self.rfile, peer, size + 2)
                        else:
                            while trailer := self.rfile.readline(65_536):
                                peer.sendall(trailer)
                                if trailer == b"\r\n":
                                    break
                            break
                else:
                    _copy_exact(self.rfile, peer, body_length)
                if upgrade:
                    head = bytearray()
                    while not head.endswith(b"\r\n\r\n") and len(head) < 65_536:
                        part = peer.recv(1)
                        if not part:
                            break
                        head.extend(part)
                    self.connection.sendall(head)
                    if head.startswith((b"HTTP/1.1 101 ", b"HTTP/1.0 101 ")):
                        peer.settimeout(None)
                        from_peer = threading.Thread(
                            target=_copy_tunnel, args=(peer, self.connection), daemon=True
                        )
                        from_peer.start()
                        _copy_tunnel(self.connection, peer)
                        from_peer.join(timeout=30)
                        self.close_connection = True
                        return
                while response := peer.recv(65_536):
                    self.connection.sendall(response)
        except (OSError, ssl.SSLError, ConnectionError, ValueError):
            self.close_connection = True
            return
        self.close_connection = True

    do_GET = _forward_http
    do_HEAD = _forward_http
    do_POST = _forward_http
    do_PUT = _forward_http
    do_PATCH = _forward_http
    do_DELETE = _forward_http

    def do_CONNECT(self) -> None:
        try:
            target = urlsplit("//" + self.path)
            if not target.hostname or not target.port:
                raise ValueError("missing CONNECT authority")
            peer, via_parent = self._peer(target.hostname, target.port, tls_origin=True)
        except ValueError:
            self.send_error(400, "invalid CONNECT authority")
            return
        except (OSError, ssl.SSLError):
            self.send_error(502, "upstream connection failed")
            return
        with peer:
            if via_parent:
                try:
                    peer.sendall(
                        f"CONNECT {self.path} HTTP/1.1\r\nHost: {self.path}\r\n\r\n".encode("ascii")
                    )
                    head = bytearray()
                    while not head.endswith(b"\r\n\r\n") and len(head) < 65_536:
                        part = peer.recv(1)
                        if not part:
                            break
                        head.extend(part)
                    if not head.startswith(b"HTTP/1.1 200 ") and not head.startswith(b"HTTP/1.0 200 "):
                        self.connection.sendall(head)
                        self.close_connection = True
                        return
                except OSError:
                    self.send_error(502, "upstream CONNECT failed")
                    return
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            peer.settimeout(None)
            from_peer = threading.Thread(target=_copy_tunnel, args=(peer, self.connection), daemon=True)
            from_peer.start()
            _copy_tunnel(self.connection, peer)
            from_peer.join(timeout=30)
        self.close_connection = True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--parent")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--p2-ssh-port-file", type=Path)
    args = parser.parse_args()
    with Parent(args.parent, args.ca_file, args.p2_ssh_port_file) as server:
        args.port_file.write_text(f"{server.server_address[1]}\n")
        server.serve_forever()


if __name__ == "__main__":
    main()
