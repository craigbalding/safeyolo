"""
Multi-host HTTP server that acts as a sinkhole for all test traffic.

Routes requests based on Host header to appropriate handlers.
Records all requests for later inspection via control API.
"""

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from handlers import DEFAULT_HANDLER, HANDLERS, Response
from models import CapturedRequest

log = logging.getLogger("sinkhole")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

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


def run_servers(sinkhole_port: int = 8080, control_port: int = 9999):
    """Run both sinkhole and control API servers."""
    sinkhole = HTTPServer(("0.0.0.0", sinkhole_port), SinkholeHandler)
    control = HTTPServer(("0.0.0.0", control_port), ControlAPIHandler)

    log.info(f"Sinkhole server listening on port {sinkhole_port}")
    log.info(f"Control API listening on port {control_port}")

    # Run control API in background thread
    control_thread = threading.Thread(target=control.serve_forever, daemon=True)
    control_thread.start()

    # Run sinkhole in main thread
    try:
        sinkhole.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sinkhole.shutdown()
        control.shutdown()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sinkhole server for blackbox tests")
    parser.add_argument("--sinkhole-port", type=int, default=8080, help="Port for sinkhole HTTP server")
    parser.add_argument("--control-port", type=int, default=9999, help="Port for control API")
    args = parser.parse_args()

    run_servers(sinkhole_port=args.sinkhole_port, control_port=args.control_port)
