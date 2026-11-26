"""HTTP and TLS stay in Unikraft; the host exposes only delegated proxy bytes.

Use open_url() as a context manager. This client does not follow redirects or
retry requests. Raw guest socket and DNS facilities remain disabled.
"""

import base64
import http.client
import io
import ssl
from contextlib import contextmanager
from urllib.parse import urlsplit, urlunsplit

CHUNK = 16 * 1024


def call(request):
    import hyperlight

    reply = hyperlight.call("sy.call", request)
    if reply["ok"] is not True:
        raise OSError(reply.get("error", "delegated proxy call failed"))
    return reply["value"]


class ProxySocket:
    """A stream to the proxy selected by the invocation's host authority."""

    def __init__(self):
        self.id = call({"kind": "proxy_open"})["id"]

    def sendall(self, data):
        while data:
            part = data[:CHUNK]
            written = call({"kind": "proxy_write", "id": self.id,
                            "data_base64": base64.b64encode(part).decode()})["written"]
            if not 0 < written <= len(part):
                raise OSError("invalid delegated proxy write count")
            data = data[written:]

    def recv(self, length):
        if not length:
            return b""
        reply = call({"kind": "proxy_read", "id": self.id, "length": min(length, CHUNK)})
        data = base64.b64decode(reply["data_base64"], validate=True)
        if len(data) > min(length, CHUNK):
            raise OSError("delegated proxy read exceeds its limit")
        return data

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError("the HTTP client needs a binary response reader")
        return io.BufferedReader(SocketReader(self))

    def close(self):
        if self.id is not None:
            stream_id, self.id = self.id, None
            call({"kind": "proxy_close", "id": stream_id})


class SocketReader(io.RawIOBase):
    def __init__(self, stream):
        self.stream = stream

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.stream.recv(len(buffer))
        buffer[:len(data)] = data
        return len(data)


class TlsSocket:
    """OpenSSL's maintained TLS implementation over the selected byte stream."""

    def __init__(self, stream, context, hostname):
        self.stream = stream
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname=hostname)
        self.perform(self.tls.do_handshake)

    def flush(self):
        while self.outgoing.pending:
            self.stream.sendall(self.outgoing.read(CHUNK))

    def perform(self, operation, *args):
        while True:
            try:
                return operation(*args)
            except ssl.SSLWantReadError:
                self.flush()
                data = self.stream.recv(CHUNK)
                if data:
                    self.incoming.write(data)
                else:
                    self.incoming.write_eof()
            except ssl.SSLWantWriteError:
                self.flush()
            finally:
                self.flush()

    def sendall(self, data):
        while data:
            written = self.perform(self.tls.write, data[:CHUNK])
            data = data[written:]

    def recv(self, length):
        return self.perform(self.tls.read, length)

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError("the HTTP client needs a binary response reader")
        return io.BufferedReader(SocketReader(self))

    def close(self):
        self.stream.close()


class ProxyConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = ProxySocket()
        if self._tunnel_host:
            # Reuse the standard HTTP client's CONNECT framing and parser.
            self._tunnel()


@contextmanager
def open_url(url, method="GET", *, headers=None, body=None, service=None):
    """Issue one request; Gateway authority remains separate from network access."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("an HTTP(S) URL is required")
    config = call({"kind": "proxy_config"})
    request_headers = dict(headers or {})
    request_headers.setdefault("Host", parsed.netloc)
    if service is not None:
        header = call({"kind": "gateway_header", "service": service})
        request_headers[header["name"]] = header["value"]
    connection = ProxyConnection("delegated-proxy")
    response = None
    try:
        if parsed.scheme == "https":
            connection.set_tunnel(parsed.hostname, parsed.port or 443)
            connection.connect()
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=config["ca_pem"])
            connection.sock = TlsSocket(connection.sock, context, parsed.hostname)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            path = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        yield response
    finally:
        if response is not None:
            response.close()
        connection.close()
