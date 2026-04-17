#!/usr/bin/env python3
"""Minimal HTTP CONNECT proxy for testing. Not for production.

Handles:
  - CONNECT tunneling (for HTTPS through proxy)
  - Plain HTTP forwarding (for HTTP through proxy)

Usage: python3 mini_proxy.py [port]
"""
import http.server
import os
import socket
import sys
import threading


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port) if port else 443
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError as exc:
            self.send_error(502, f"Cannot connect to {self.path}: {exc}")
            return

        self.send_response(200, "Connection established")
        self.end_headers()

        # Bidirectional tunnel
        client = self.connection

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        t = threading.Thread(target=forward, args=(upstream, client), daemon=True)
        t.start()
        forward(client, upstream)
        t.join(timeout=2)
        upstream.close()

    def do_GET(self):
        self._forward_request("GET")

    def do_POST(self):
        self._forward_request("POST")

    def _forward_request(self, method):
        # For plain HTTP proxy requests, the path is a full URL
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, f"Cannot connect to {host}:{port}: {exc}")
            return

        # Forward the request
        req = f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n"
        for key, val in self.headers.items():
            if key.lower() not in ("host", "proxy-connection"):
                req += f"{key}: {val}\r\n"
        req += "\r\n"
        upstream.sendall(req.encode())

        # Read and forward body if present
        length = int(self.headers.get("Content-Length", 0))
        if length:
            upstream.sendall(self.rfile.read(length))

        # Forward response back to client
        response = b""
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            response += chunk
        upstream.close()

        self.wfile.write(response)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[proxy] {fmt % args}\n")
        sys.stderr.flush()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), ProxyHandler)
    with open("/tmp/mini-proxy.pid", "w") as f:
        f.write(str(os.getpid()))
    print(f"Mini proxy on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
