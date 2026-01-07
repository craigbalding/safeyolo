"""
Multi-host HTTP server that acts as a sinkhole for all test traffic.

Routes requests based on Host header to appropriate handlers.
Records all requests for later inspection via control API.

Supports both HTTP (port 8080) and HTTPS (port 443) for testing
HTTPS requests through the proxy.
"""

import json
import logging
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from handlers import DEFAULT_HANDLER, HANDLERS, Response
from models import CapturedRequest

log = logging.getLogger("sinkhole")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


class SSLSafeThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with graceful SSL error handling.

    SSL handshake errors (connection resets, protocol mismatches) are common
    and should not crash the server. This class catches these errors and logs
    them at debug level, keeping the server running.
    """

    def handle_error(self, request, client_address):
        """Handle errors without crashing on SSL exceptions."""
        import sys
        exc_type, exc_value, _ = sys.exc_info()

        # SSL errors are common and expected (client disconnects, protocol issues)
        if exc_type and issubclass(exc_type, (ssl.SSLError, ConnectionResetError, BrokenPipeError)):
            log.debug(f"SSL/connection error from {client_address}: {exc_type.__name__}: {exc_value}")
            return

        # Log other errors but don't crash
        log.warning(f"Request handler error from {client_address}: {exc_type.__name__}: {exc_value}")

# Thread-safe request storage
_lock = threading.Lock()
_captured_requests: list[CapturedRequest] = []


def capture_request(req: CapturedRequest):
    """Store a captured request."""
    with _lock:
        _captured_requests.append(req)


def get_requests(
    host: Optional[str] = None,
    since: Optional[float] = None,
    method: Optional[str] = None,
) -> list[CapturedRequest]:
    """Query captured requests with optional filters."""
    with _lock:
        results = list(_captured_requests)

    if host:
        results = [r for r in results if r.host == host]
    if since:
        results = [r for r in results if r.timestamp >= since]
    if method:
        results = [r for r in results if r.method == method]

    return results


def clear_requests():
    """Clear all captured requests."""
    with _lock:
        _captured_requests.clear()


class SinkholeHandler(BaseHTTPRequestHandler):
    """HTTP handler that routes to per-host handlers and captures requests."""

    def log_message(self, format, *args):
        log.debug(f"{self.client_address[0]} - {format % args}")

    def _get_host(self) -> str:
        """Extract host from Host header."""
        host = self.headers.get("Host", "unknown")
        # Strip port if present
        if ":" in host:
            host = host.split(":")[0]
        return host

    def _read_body(self) -> bytes:
        """Read request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            return self.rfile.read(content_length)
        return b""

    def _capture_and_route(self, method: str):
        """Capture request and route to handler."""
        host = self._get_host()
        body = self._read_body()
        parsed = urlparse(self.path)

        # Capture the request
        captured = CapturedRequest(
            timestamp=time.time(),
            host=host,
            method=method,
            path=parsed.path,
            headers=dict(self.headers),
            body=body,
            client_ip=self.client_address[0],
            query_params=parse_qs(parsed.query),
        )
        capture_request(captured)
        log.info(f"Captured: {method} {host}{self.path}")

        # Route to handler
        handler = HANDLERS.get(host, DEFAULT_HANDLER)
        response: Response = handler.handle(captured)

        # Send response
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.wfile.write(response.body)

    def do_GET(self):
        self._capture_and_route("GET")

    def do_POST(self):
        self._capture_and_route("POST")

    def do_PUT(self):
        self._capture_and_route("PUT")

    def do_DELETE(self):
        self._capture_and_route("DELETE")

    def do_PATCH(self):
        self._capture_and_route("PATCH")

    def do_HEAD(self):
        self._capture_and_route("HEAD")

    def do_OPTIONS(self):
        self._capture_and_route("OPTIONS")


class ControlAPIHandler(BaseHTTPRequestHandler):
    """Control API for test assertions."""

    def log_message(self, format, *args):
        log.debug(f"Control API: {format % args}")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._send_json({"status": "ok"})
        elif parsed.path == "/requests":
            host = query.get("host", [None])[0]
            since = query.get("since", [None])[0]
            since_float = float(since) if since else None

            requests = get_requests(host=host, since=since_float)
            self._send_json({"count": len(requests), "requests": [r.to_dict() for r in requests]})
        elif parsed.path == "/requests/count":
            host = query.get("host", [None])[0]
            requests = get_requests(host=host)
            self._send_json({"count": len(requests)})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/requests/clear":
            clear_requests()
            self._send_json({"status": "cleared"})
        else:
            self._send_json({"error": "not found"}, 404)


def load_tls_cert(cert_path: Path, key_path: Path) -> ssl.SSLContext | None:
    """Load TLS certificate for HTTPS server.

    The certificate should be pre-generated and signed by the test CA.
    This mirrors production where upstreams have CA-signed certificates.
    No self-signed cert generation - ground truth testing requires real TLS.

    Returns:
        SSLContext if cert exists, None otherwise (falls back to HTTP-only)
    """
    if not cert_path.exists() or not key_path.exists():
        log.warning(f"TLS cert not found at {cert_path} - HTTPS disabled")
        log.warning("Run: ./certs/generate-certs.sh to create test certificates")
        return None

    log.info(f"Loading TLS certificate from {cert_path}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def run_servers(
    http_port: int = 8080,
    https_port: int = 443,
    control_port: int = 9999,
    cert_path: str = "/certs/sinkhole.crt",
    key_path: str = "/certs/sinkhole.key",
):
    """Run sinkhole (HTTP + HTTPS) and control API servers.

    HTTPS requires a certificate signed by the test CA. This mirrors production
    where SafeYolo verifies upstream certificates against trusted CAs.

    Uses ThreadingHTTPServer for concurrent request handling (important for
    tests that make multiple parallel requests through the proxy).
    """
    # HTTP sinkhole (for non-TLS tests or fallback)
    http_server = SSLSafeThreadingHTTPServer(("0.0.0.0", http_port), SinkholeHandler)
    log.info(f"Sinkhole HTTP server listening on port {http_port}")

    # HTTPS sinkhole (for proxied HTTPS requests - ground truth testing)
    https_server = None
    ssl_context = load_tls_cert(Path(cert_path), Path(key_path))
    if ssl_context:
        https_server = SSLSafeThreadingHTTPServer(("0.0.0.0", https_port), SinkholeHandler)
        https_server.socket = ssl_context.wrap_socket(https_server.socket, server_side=True)
        log.info(f"Sinkhole HTTPS server listening on port {https_port}")

    # Control API (threading for concurrent health checks during tests)
    control = ThreadingHTTPServer(("0.0.0.0", control_port), ControlAPIHandler)
    log.info(f"Control API listening on port {control_port}")

    # Run servers in background threads
    threads = [
        threading.Thread(target=http_server.serve_forever, daemon=True, name="http"),
        threading.Thread(target=control.serve_forever, daemon=True, name="control"),
    ]
    if https_server:
        threads.append(threading.Thread(target=https_server.serve_forever, daemon=True, name="https"))

    for thread in threads:
        thread.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down...")
        http_server.shutdown()
        if https_server:
            https_server.shutdown()
        control.shutdown()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sinkhole server for blackbox tests")
    parser.add_argument("--http-port", type=int, default=8080, help="Port for HTTP server")
    parser.add_argument("--https-port", type=int, default=443, help="Port for HTTPS server")
    parser.add_argument("--control-port", type=int, default=9999, help="Port for control API")
    parser.add_argument("--cert", type=str, default="/certs/sinkhole.crt", help="TLS certificate path")
    parser.add_argument("--key", type=str, default="/certs/sinkhole.key", help="TLS key path")
    args = parser.parse_args()

    run_servers(
        http_port=args.http_port,
        https_port=args.https_port,
        control_port=args.control_port,
        cert_path=args.cert,
        key_path=args.key,
    )
