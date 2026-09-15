"""Temporary network-policy adapter for the issue #620 HTTP migration fixture.

Run this only in an isolated development instance. It evaluates the existing
Python PDP; it does not run credential, service, or content inspection. Remove
the adapter when Rust owns network policy. The socket must stay on the host,
outside every agent mount. Only metadata crosses this socket, never header
values or request bodies.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from pdp.core import PDPCore
from pdp.schemas import Effect, IdentitySource, create_http_event

MAX_METADATA_BYTES = 1024 * 1024


class NetworkRequest(BaseModel):
    """Metadata supplied by the trusted Rust listener, not an agent request."""

    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    connection_id: str = Field(min_length=1)
    method: str = Field(min_length=1)
    scheme: Literal["http"]
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    path: str
    header_names: list[str] = Field(default_factory=list)
    body_present: bool = False


def decide(pdp: PDPCore, request: NetworkRequest) -> dict:
    """Evaluate the same network event as NetworkGuard in blocking mode."""
    path, separator, query = request.path.partition("?")
    event = create_http_event(
        event_id=f"evt_{request.request_id}",
        sensor_id="rust-http-migration",
        principal_id=f"agent:{request.agent_id}",
        identity_source=IdentitySource.MANUAL,
        agent=request.agent_id,
        method=request.method,
        scheme=request.scheme,
        host=request.host,
        port=request.port,
        path=path,
        query_string=query if separator else None,
        headers_present=request.header_names,
        body_present=request.body_present,
    )
    decision = pdp.evaluate(event)
    result = {"allow": decision.effect is Effect.ALLOW, "decision": decision.effect.value}
    if decision.effect is Effect.ALLOW:
        return result
    # PDP supplies its existing error representation. NetworkGuard's user-facing
    # reflection text and approval audit workflow remain separate parity work.
    response = decision.immediate_response
    result.update(
        status=response.status_code if response else 500,
        headers=[["content-type", "application/json"], ["x-blocked-by", "network-guard"]],
        body=json.dumps(response.body_json if response else {"error": "Policy evaluation failed"}),
    )
    return result


class PolicyServer(socketserver.UnixStreamServer):
    """Serialize evaluations so existing policy and budget state has one owner."""

    def __init__(self, socket_path: Path, pdp: PDPCore):
        self.pdp = pdp
        super().__init__(str(socket_path), PolicyRequestHandler)
        self.timeout = 0.2

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def handle_error(self, request, client_address):
        if isinstance(sys.exception(), ConnectionError):
            # The Rust request owner cancels its adapter socket when a client
            # disconnects. A closed peer ends this exchange, not the process.
            return
        # An unexpected worker error is fatal and visible. Do not print request
        # metadata through socketserver's default traceback logging.
        raise RuntimeError("Temporary policy adapter request failed")


class PolicyRequestHandler(BaseHTTPRequestHandler):
    """One private HTTP operation, with bounded metadata and no request logging."""

    def log_message(self, format, *args):
        # Request paths and parser diagnostics can contain supplied text. The
        # fixture observes status and process exit rather than access logs.
        return

    def _reply(self, status: int, value: dict) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/decision":
            self._reply(404, {"error": "Unknown adapter operation"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
            self._reply(400, {"error": "Expected one metadata Content-Length"})
            return
        length = int(lengths[0])
        if not 0 < length <= MAX_METADATA_BYTES:
            self._reply(413, {"error": "Metadata size outside adapter limit"})
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._reply(400, {"error": "Incomplete metadata"})
            return
        try:
            request = NetworkRequest.model_validate_json(raw)
        except ValidationError:
            self._reply(400, {"error": "Invalid network metadata"})
            return
        try:
            result = decide(self.server.pdp, request)
        except ConnectionError as error:
            # Only this handler's socket errors are expected cancellations.
            # A policy failure must still reach the server's fatal error path.
            raise RuntimeError("Temporary policy evaluation failed") from error
        self._reply(200, result)


def serve(socket_path: Path, policy_path: Path) -> None:
    """Bind a private socket, retaining current production policy reload rules."""
    if not policy_path.is_file():
        raise ValueError("The temporary adapter requires an existing policy file")
    pdp = PDPCore(baseline_path=policy_path)
    # The temporary bridge deliberately reaches into the existing loader for
    # lifecycle only. It must not leave a failed initial load looking ready.
    loader = pdp._engine._loader
    if not loader.reload():
        loader.stop_watcher()
        raise ValueError("The temporary adapter could not load its policy")
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    server = None
    owned_socket = None
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        # A live or stale existing pathname is not ours to remove. Binding fails
        # visibly instead of taking another process's socket or a regular file.
        old_mask = os.umask(0o077)
        try:
            server = PolicyServer(socket_path, pdp)
        finally:
            os.umask(old_mask)
        owned_socket = socket_path.stat()
        socket_path.chmod(0o600)
        while not stopping:
            server.handle_request()
    finally:
        if server is not None:
            server.server_close()
        if owned_socket is not None:
            try:
                current = socket_path.lstat()
            except FileNotFoundError:
                # An operator can remove the fixture socket during shutdown.
                current = None
            if current and (current.st_dev, current.st_ino) == (owned_socket.st_dev, owned_socket.st_ino):
                socket_path.unlink()
        loader.stop_watcher()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    serve(args.socket, args.policy)


if __name__ == "__main__":
    main()
