#!/usr/bin/env python3
"""Serve the VZ blackbox parent, sinkhole, and control API on two TCP ports.

The physical Mac test account permits one HTTP origin port and one HTTPS
origin port. The HTTP listener also acts as the native proxy's test parent;
TLS certificate variants share the HTTPS listener through SNI.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sinkhole"))

from server import (  # noqa: E402
    ControlAPIHandler,
    SinkholeHandler,
    SSLSafeThreadingHTTPServer,
    accept_connection,
    close_connection,
    load_tls_cert,
)
from sinkhole_parent import Parent, Request, _open_peer  # noqa: E402
from sinkhole_router import SINKHOLE_HOST, SINKHOLE_HOSTS  # noqa: E402

log = logging.getLogger("vz_fixture")


class VZRequest(Request):
    """Dispatch parent requests and direct fixture/control requests."""

    _get_host = SinkholeHandler._get_host
    _read_body = SinkholeHandler._read_body
    _raw_request_target = SinkholeHandler._raw_request_target
    _capture_and_route = SinkholeHandler._capture_and_route
    _send_json = ControlAPIHandler._send_json

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            connection_id = getattr(self, "connection_id", None)
            if connection_id is not None:
                close_connection(connection_id)

    def _peer(self, host: str, port: int, *, tls_origin: bool):
        if tls_origin and host.rstrip(".").lower() in SINKHOLE_HOSTS:
            return _open_peer(SINKHOLE_HOST, self.server.https_port), False
        return super()._peer(host, port, tls_origin=tls_origin)

    def _dispatch(self) -> None:
        try:
            target = urlsplit(self.path)
            target_host = target.hostname
            target_port = target.port
        except ValueError:
            self.send_error(400, "invalid fixture target")
            return
        if target.scheme == "http" and target_host:
            if target_host in {"127.0.0.1", "localhost"} and \
               (target_port or 80) == self.server.server_port:
                self.send_error(502, "fixture parent cannot route to itself")
                return
            if target_host.rstrip(".").lower() not in SINKHOLE_HOSTS:
                self._forward_http()
                return
            # A normal HTTP origin receives origin-form targets from its
            # parent. Preserve that view in the sinkhole's raw capture too.
            path = (target.path or "/") + (f"?{target.query}" if target.query else "")
            self.path = path
            self.raw_requestline = (
                f"{self.command} {path} {self.request_version}\r\n".encode("latin-1")
            )
            for hop_header in ("Proxy-Authorization", "Proxy-Connection"):
                if hop_header in self.headers:
                    del self.headers[hop_header]
            fixture = True
        elif self.path.startswith("/"):
            host = self.headers.get("Host", "").split(":", 1)[0].rstrip(".").lower()
            fixture = host in SINKHOLE_HOSTS
            if not fixture and host not in {"127.0.0.1", "localhost"}:
                self.send_error(400, "unknown fixture host")
                return
        else:
            self.send_error(400, "invalid fixture target")
            return

        if fixture:
            self.connection_id = accept_connection(self.client_address[0])
            method = getattr(SinkholeHandler, f"do_{self.command}", None)
        else:
            method = getattr(ControlAPIHandler, f"do_{self.command}", None)
        if method is None:
            self.send_error(405, "unsupported fixture method")
            return
        method(self)

    do_GET = _dispatch
    do_HEAD = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--parent")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--extra-cert", action="append", default=[], metavar="HOST:CERT:KEY")
    args = parser.parse_args()

    if args.http_port == args.https_port:
        parser.error("HTTP and HTTPS ports must differ")
    default_context = load_tls_cert(args.cert, args.key)
    if default_context is None:
        parser.error("the HTTPS fixture certificate and key are required")

    cert_contexts = {}
    for spec in args.extra_cert:
        try:
            host, cert, key = spec.split(":", 2)
        except ValueError:
            parser.error(f"invalid --extra-cert: {spec}")
        if host not in SINKHOLE_HOSTS or host in cert_contexts:
            parser.error(f"unknown or duplicate certificate host: {host}")
        context = load_tls_cert(Path(cert), Path(key))
        if context is None:
            parser.error(f"certificate unavailable for {host}")
        cert_contexts[host] = context

    def select_cert(connection, server_name, _context):
        if server_name:
            connection.context = cert_contexts.get(server_name.rstrip(".").lower(), default_context)

    default_context.set_servername_callback(select_cert)

    with Parent(
        args.parent, args.ca_file, host="0.0.0.0", port=args.http_port,
        request_handler=VZRequest,
    ) as http_server, SSLSafeThreadingHTTPServer(
        ("0.0.0.0", args.https_port), SinkholeHandler
    ) as https_server:
        http_server.https_port = args.https_port
        https_server.socket = default_context.wrap_socket(https_server.socket, server_side=True)
        thread = threading.Thread(target=https_server.serve_forever, daemon=True)
        thread.start()
        log.info("VZ fixture listening on HTTP %d and HTTPS %d", args.http_port, args.https_port)
        try:
            http_server.serve_forever()
        finally:
            https_server.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
