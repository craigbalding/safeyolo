"""httpx transport that proxies HTTP(S) requests through a UDS.

Replaces the TCP-proxy client blackbox tests used in the pre-UDS
architecture. Mitmproxy's `HttpProxy` top layer (attached to every
`UnixInstance`) expects proxy-form requests on plain HTTP and a
`CONNECT` tunnel for HTTPS — the same wire format a normal forward
HTTP proxy accepts. This transport opens an AF_UNIX connection to the
socket file backing the listener and speaks that protocol, so tests
can keep using an `httpx.Client` fixture.

Usage (from `conftest.py`):

    transport = UDSProxyTransport(uds_path, ca_cert=ca_path)
    client = httpx.Client(transport=transport, verify=str(ca_path))

No TLS is done on the socket itself (UDS is local, the agent-side
analogue in production is a VSOCK tunnel, also plaintext to
mitmproxy). TLS is initiated only *after* the CONNECT tunnel, against
the upstream target, using the supplied CA bundle.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from pathlib import Path

import httpx


class _UDSHTTPConnection(http.client.HTTPConnection):
    """`http.client.HTTPConnection` that connects over AF_UNIX.

    Everything else — framing, keep-alive, chunked encoding — stays in
    the stdlib implementation. We only override `connect()` to swap the
    socket for a Unix domain one.
    """

    def __init__(self, uds_path: str, host: str, port: int | None = None,
                 timeout: float | None = None) -> None:
        super().__init__(host, port=port, timeout=timeout or socket._GLOBAL_DEFAULT_TIMEOUT)
        self._uds_path = uds_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None and self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(self.timeout)
        sock.connect(self._uds_path)
        self.sock = sock


class _UDSHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS-over-UDS-via-CONNECT.

    Opens an AF_UNIX connection, issues the CONNECT tunnel set by
    `set_tunnel()`, then TLS-wraps the socket against the tunnel
    target. Same semantics as `http.client.HTTPSConnection` used
    through a regular TCP proxy.
    """

    def __init__(self, uds_path: str, host: str, port: int = 443,
                 context: ssl.SSLContext | None = None,
                 timeout: float | None = None) -> None:
        super().__init__(host, port=port, context=context,
                         timeout=timeout or socket._GLOBAL_DEFAULT_TIMEOUT)
        self._uds_path = uds_path

    def connect(self) -> None:
        # Base socket: UDS, not TCP.
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None and self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(self.timeout)
        sock.connect(self._uds_path)
        self.sock = sock

        # If set_tunnel() was called, `_tunnel_host` is the upstream to
        # CONNECT to. http.client's `_tunnel()` sends CONNECT over
        # self.sock, reads the 200 response, and leaves self.sock ready
        # for TLS wrap.
        if self._tunnel_host:
            self._tunnel()

        # TLS against the tunnel target (not the proxy).
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class UDSProxyTransport(httpx.BaseTransport):
    """httpx transport: `httpx.Client(transport=UDSProxyTransport(...))`.

    Each request opens a fresh AF_UNIX connection — simpler than
    pooling, and adequate for blackbox throughput. Mitmproxy's
    `HttpProxy` top layer handles `Connection: close` cleanly.
    """

    def __init__(self, uds_path: str | Path, ca_cert: str | Path | None = None) -> None:
        self._uds_path = str(uds_path)
        self._ca_cert = str(ca_cert) if ca_cert else None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        scheme = url.scheme
        if scheme == "http":
            return self._handle_http(request)
        elif scheme == "https":
            return self._handle_https(request)
        else:
            raise ValueError(f"unsupported scheme for UDS proxy: {scheme!r}")

    # ------- HTTP: proxy-form request, no TLS --------------------------------
    def _handle_http(self, request: httpx.Request) -> httpx.Response:
        conn = _UDSHTTPConnection(self._uds_path, host="uds-proxy",
                                  timeout=request.extensions.get("timeout", {}).get("connect", 30))
        try:
            conn.connect()
            body = request.read()
            headers = dict(request.headers)
            headers.setdefault("Host", _host_header(request))
            # http.client's request() sends the URL as-is for the
            # request line — full absolute form → proxy-form.
            conn.request(request.method, str(request.url), body=body, headers=headers)
            resp = conn.getresponse()
            return _response_from_httpresponse(resp, request)
        finally:
            conn.close()

    # ------- HTTPS: CONNECT tunnel + TLS + origin-form request ---------------
    def _handle_https(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or 443
        ctx = ssl.create_default_context(cafile=self._ca_cert) if self._ca_cert \
            else ssl.create_default_context()
        conn = _UDSHTTPSConnection(
            self._uds_path, host=host, port=port, context=ctx,
            timeout=request.extensions.get("timeout", {}).get("connect", 30),
        )
        # Trigger CONNECT + TLS wrap on connect().
        conn.set_tunnel(host, port)
        try:
            conn.connect()
            body = request.read()
            headers = dict(request.headers)
            headers.setdefault("Host", _host_header(request))
            # Origin-form path (everything after the authority).
            path = request.url.raw_path.decode() or "/"
            conn.request(request.method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return _response_from_httpresponse(resp, request)
        finally:
            conn.close()


def _host_header(request: httpx.Request) -> str:
    host = request.url.host
    port = request.url.port
    default = 443 if request.url.scheme == "https" else 80
    if port and port != default:
        return f"{host}:{port}"
    return host


def _response_from_httpresponse(resp: http.client.HTTPResponse,
                                request: httpx.Request) -> httpx.Response:
    body = resp.read()
    return httpx.Response(
        status_code=resp.status,
        headers=list(resp.getheaders()),
        content=body,
        request=request,
    )
