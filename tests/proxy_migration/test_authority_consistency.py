"""Authority and credential destination through both real proxy processes.

The parent is an intentionally Host-routed peer: a forwarded conflicting Host
would reach the other physical origin. CONNECT routes by its request target.
The origins record application bytes independently of the parent's accepts.
"""

import http.client
import select
import socket
import socketserver
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy, read_events
from tests.proxy_migration.test_http2_contract import h2_requests, headers

ALLOWED = "allowed.invalid"
FORBIDDEN = "forbidden.invalid"
SECRET = b"key-authority-owned"
BODY = b"part=one%2Ftwo&part=three\x00signed"
TARGET = "/signed/%2F?part=one&part=two%2Fthree&empty="

POLICY = f'''budget = 12000
[[permissions]]
action = "network:request"
resource = "{ALLOWED}/*"
effect = "allow"
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
[[permissions]]
action = "credential:use"
resource = "{ALLOWED}/*"
effect = "allow"
[[permissions]]
action = "credential:use"
resource = "*"
effect = "prompt"
[[credential_rules]]
name = "synthetic-authority"
patterns = ["key-authority-owned"]
allowed_hosts = ["{ALLOWED}"]
header_names = ["authorization"]
[addons.credential_guard]
enabled = true
[addons.credential_guard.settings]
use_default_credential_rules = false
'''


def _read_request(stream):
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        part = stream.recv(1)
        if not part:
            if not head:
                return None
            raise AssertionError("request ended before its headers completed")
        head.extend(part)
        assert len(head) < 65536, "request head exceeded fixture limit"
    head = bytes(head)
    length = next((int(line.split(b":", 1)[1].strip()) for line in head.split(b"\r\n")[1:]
                   if line.lower().startswith(b"content-length:")), 0)
    body = bytearray()
    while len(body) < length:
        part = stream.recv(length - len(body))
        assert part, "request ended before its declared body"
        body.extend(part)
    return head, bytes(body)


def _host(head):
    values = [line.split(b":", 1)[1].strip().decode("ascii")
              for line in head.split(b"\r\n")[1:] if line.lower().startswith(b"host:")]
    assert len(values) == 1, head
    return values[0]


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, name, *, tls_context=None):
        self.name = name
        self.tls_context = tls_context
        self.accepts = 0
        self.requests = []
        self.sni = []
        self.errors = []
        self.lock = threading.Lock()
        if tls_context:
            tls_context.set_servername_callback(self._record_sni)
        super().__init__(("127.0.0.1", 0), OriginRequest)

    def _record_sni(self, _stream, name, _context):
        with self.lock:
            self.sni.append(name)

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.accepts += 1
        return result


class OriginRequest(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            if self.server.tls_context:
                with self.server.tls_context.wrap_socket(self.request, server_side=True) as stream:
                    self._reply(stream)
            else:
                self._reply(self.request)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            # A rejected upstream certificate can close after ClientHello.
            return
        except Exception as error:
            self.server.errors.append(error)

    def _reply(self, stream):
        request = _read_request(stream)
        if request is None:
            return
        head, body = request
        with self.server.lock:
            self.server.requests.append({"head": head, "body": body})
        payload = self.server.name.encode()
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode()
                       + b"\r\nConnection: close\r\n\r\n" + payload)


class Parent(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, allowed_http, forbidden_http, allowed_tls, forbidden_tls):
        self.http = {ALLOWED: allowed_http, FORBIDDEN: forbidden_http}
        self.tls = {ALLOWED: allowed_tls, FORBIDDEN: forbidden_tls}
        self.connect_override = None
        self.accepts = 0
        self.requests = []
        self.errors = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), ParentRequest)

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.accepts += 1
        return result


class ParentRequest(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            request = _read_request(self.request)
            assert request is not None, "parent connection closed before a request"
            head, body = request
            method, target, _ = head.split(b"\r\n", 1)[0].split(b" ", 2)
            if method == b"CONNECT":
                host, port = target.decode("ascii").rsplit(":", 1)
                assert port == "443"
                origin = self.server.connect_override or self.server.tls[host.lower()]
                route = origin.name
                with self.server.lock:
                    self.server.requests.append({"kind": "connect", "target": target,
                                                 "head": head, "route": route})
                with socket.create_connection(origin.server_address, timeout=5) as upstream:
                    upstream.settimeout(5)
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self._relay(upstream)
            else:
                host = _host(head).split(":", 1)[0].lower()
                origin = self.server.http[host]
                parsed = urlsplit(target.decode("ascii"))
                path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                first = method + b" " + path.encode("ascii") + b" HTTP/1.1\r\n"
                forwarded = first + head.split(b"\r\n", 1)[1] + body
                with self.server.lock:
                    self.server.requests.append({"kind": "http", "target": target,
                                                 "head": head, "body": body, "route": origin.name})
                with socket.create_connection(origin.server_address, timeout=5) as upstream:
                    upstream.settimeout(5)
                    upstream.sendall(forwarded)
                    while chunk := upstream.recv(65536):
                        self.request.sendall(chunk)
        except Exception as error:
            self.server.errors.append(error)

    def _relay(self, upstream):
        peers = (self.request, upstream)
        while True:
            ready, _, _ = select.select(peers, [], [], 5)
            assert ready, "CONNECT relay stalled"
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (upstream if source is self.request else self.request).sendall(data)


@contextmanager
def _server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert server.errors == [], server.errors


def _certificate(directory, host):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
                   .sign(key, hashes.SHA256()))
    pem = directory / f"{host}.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
                    + certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem)
    context.set_alpn_protocols(["http/1.1"])
    return context, certificate.public_bytes(serialization.Encoding.PEM)


@contextmanager
def _peers(directory):
    directory.mkdir(parents=True)
    allowed_context, allowed_cert = _certificate(directory, ALLOWED)
    forbidden_context, forbidden_cert = _certificate(directory, FORBIDDEN)
    trust = directory / "origin-roots.pem"
    trust.write_bytes(allowed_cert + forbidden_cert)
    with _server(Origin("allowed-http")) as allowed_http, \
         _server(Origin("forbidden-http")) as forbidden_http, \
         _server(Origin("allowed-tls", tls_context=allowed_context)) as allowed_tls, \
         _server(Origin("forbidden-tls", tls_context=forbidden_context)) as forbidden_tls, \
         _server(Parent(allowed_http, forbidden_http, allowed_tls, forbidden_tls)) as parent:
        yield parent, (allowed_http, forbidden_http, allowed_tls, forbidden_tls), trust


def _raw_http(path, target, host, *, method=b"GET", body=b"", secret=False):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(path)
        head = (method + b" " + target + b" HTTP/1.1\r\nHost: " + host
                + b"\r\nConnection: close\r\n")
        if secret:
            head += b"Authorization: Bearer " + SECRET + b"\r\n"
        if body:
            head += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        stream.sendall(head + b"\r\n" + body)
        response = http.client.HTTPResponse(stream)
        response.begin()
        return response.status, dict(response.getheaders()), response.read()


def _connect(path, authority, sni, ca, *, outer_host=None, verify_client_name=True,
             offers=("http/1.1",)):
    raw = socket.socket(socket.AF_UNIX)
    raw.settimeout(5)
    try:
        raw.connect(path)
        raw.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: "
                    + (outer_host or authority) + b"\r\n\r\n")
        response = http.client.HTTPResponse(raw)
        response.begin()
        status = response.status
        if status != 200:
            response.read()
            raw.close()
            return status, None
        response.close()
        context = ssl.create_default_context(cafile=ca)
        context.set_alpn_protocols(list(offers))
        context.check_hostname = verify_client_name
        return status, context.wrap_socket(raw, server_hostname=sni)
    except Exception:
        raw.close()
        raise


def test_absolute_authority_and_host_keep_credential_on_one_route(proxy_backend, tmp_path):
    """A Host-routing parent exposes any forwarded authority confusion."""
    directory = tmp_path / proxy_backend
    with _peers(directory / "peers") as (parent, peers, _):
        allowed, forbidden, _, _ = peers
        with launch_proxy(proxy_backend, directory / "proxy", POLICY,
                          native_policy=True, credential_head_decision=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            path = proxy.paths["alice"]
            canonical = _raw_http(path, b"http://allowed.invalid:80" + TARGET.encode(),
                                  b"ALLOWED.INVALID", method=b"POST", body=BODY, secret=True)
            assert canonical[0] == 200 and canonical[2] == b"allowed-http", canonical
            assert parent.requests[-1]["route"] == "allowed-http"
            assert parent.requests[-1]["body"] == BODY
            assert parent.requests[-1]["target"] == b"http://allowed.invalid:80" + TARGET.encode()
            assert allowed.requests[-1]["head"].split(b"\r\n", 1)[0] == b"POST " + TARGET.encode() + b" HTTP/1.1"
            assert allowed.requests[-1]["body"] == BODY
            assert SECRET in allowed.requests[-1]["head"]
            if proxy_backend == "python":
                assert _host(parent.requests[-1]["head"]) == "ALLOWED.INVALID"
            else:
                assert _host(parent.requests[-1]["head"]) == "allowed.invalid:80"

            before = (parent.accepts, forbidden.accepts)
            denied = _raw_http(path, b"http://forbidden.invalid/denied", b"allowed.invalid", secret=True)
            assert denied[0] == 403, denied
            assert (parent.accepts, forbidden.accepts) == before

            conflict = _raw_http(path, b"http://allowed.invalid/conflict", b"forbidden.invalid",
                                 secret=True)
            assert conflict[0] == 200 and conflict[2] == b"allowed-http", conflict
            assert parent.requests[-1]["route"] == "allowed-http"
            assert _host(parent.requests[-1]["head"]).lower() in (ALLOWED, f"{ALLOWED}:80")
            assert SECRET in allowed.requests[-1]["head"]
            assert forbidden.accepts == 0 and forbidden.requests == []
            audit = read_events(directory / "proxy/audit.jsonl")
            assert any(row["event"] == "security.network_guard" and row["host"] == FORBIDDEN
                       and row["decision"] == "deny" for row in audit)
            assert any(row["event"] == "security.credential_guard" and row["host"] == ALLOWED
                       and row["decision"] == "allow" for row in audit)
            if proxy_backend == "rust":
                egress = proxy.events("proxy.egress")
                assert egress
                assert all(row["host"] == ALLOWED and row["port"] == 80 and row["route"] == "parent"
                           for row in egress)
        # The peer itself must route an authored conflicting Host to the other
        # physical origin. This checks the observer without proxy behavior.
        with socket.create_connection(parent.server_address, timeout=5) as direct:
            direct.sendall(b"GET http://allowed.invalid/observer-control HTTP/1.1\r\n"
                           b"Host: forbidden.invalid\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(direct)
            response.begin()
            assert response.status == 200 and response.read() == b"forbidden-http"
        assert parent.requests[-1]["route"] == "forbidden-http"
        assert b"/observer-control" in forbidden.requests[-1]["head"]
        assert SECRET not in forbidden.requests[-1]["head"]


def test_connect_inner_authority_sni_and_verification_stay_scoped(proxy_backend, tmp_path):
    """CONNECT, decrypted Host/:authority and SNI cannot redirect a credential."""
    directory = tmp_path / proxy_backend
    with _peers(directory / "peers") as (parent, peers, trust):
        _, _, allowed, forbidden = peers
        CertStore.from_store(directory / "proxy/ca", "mitmproxy", 2048)
        with launch_proxy(proxy_backend, directory / "proxy", POLICY, native_policy=True,
                          credential_head_decision=True, tls=True, upstream_ca=trust,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            ca = directory / "proxy/ca/mitmproxy-ca-cert.pem"
            path = proxy.paths["alice"]
            allowed_authority = f"{ALLOWED}:443".encode()
            forbidden_authority = f"{FORBIDDEN}:443".encode()

            denied, no_stream = _connect(path, forbidden_authority, FORBIDDEN, ca,
                                         outer_host=allowed_authority)
            assert denied == 403 and no_stream is None
            assert parent.accepts == allowed.accepts == forbidden.accepts == 0

            status, stream = _connect(path, allowed_authority, ALLOWED, ca)
            assert status == 200
            with stream:
                stream.sendall(b"POST " + TARGET.encode() + b" HTTP/1.1\r\nHost: "
                               + allowed_authority + b"\r\nAuthorization: Bearer " + SECRET
                               + b"\r\nContent-Length: " + str(len(BODY)).encode()
                               + b"\r\nConnection: close\r\n\r\n" + BODY)
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200 and response.read() == b"allowed-tls"
            assert allowed.requests[-1]["body"] == BODY
            assert allowed.requests[-1]["head"].split(b"\r\n", 1)[0] == b"POST " + TARGET.encode() + b" HTTP/1.1"
            assert SECRET in allowed.requests[-1]["head"]
            assert allowed.sni[-1] == ALLOWED
            assert forbidden.requests == []

            status, stream = _connect(path, allowed_authority, ALLOWED, ca)
            assert status == 200
            with stream:
                stream.sendall(b"POST " + TARGET.encode() + b" HTTP/1.1\r\n"
                               b"Host: ALLOWED.INVALID:443\r\nAuthorization: Bearer " + SECRET
                               + b"\r\nContent-Length: " + str(len(BODY)).encode()
                               + b"\r\nConnection: close\r\n\r\n" + BODY)
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200 and response.read() == b"allowed-tls"
            assert b"POST " + TARGET.encode() + b" HTTP/1.1" in allowed.requests[-1]["head"]
            assert _host(allowed.requests[-1]["head"]) == "ALLOWED.INVALID:443"
            assert allowed.requests[-1]["body"] == BODY
            assert SECRET in allowed.requests[-1]["head"]
            assert forbidden.requests == []

            # A different client SNI cannot replace the admitted CONNECT name
            # for origin TLS verification or create a forbidden-origin route.
            before_allowed = len(allowed.requests)
            try:
                status, stream = _connect(path, allowed_authority, FORBIDDEN, ca,
                                          verify_client_name=False)
            except ssl.SSLError:
                sni_status = None  # A proxy may reject SNI during client TLS.
            else:
                assert status == 200
                with stream:
                    stream.sendall(b"GET /sni-conflict HTTP/1.1\r\nHost: " + allowed_authority
                                   + b"\r\nConnection: close\r\n\r\n")
                    response = http.client.HTTPResponse(stream)
                    try:
                        response.begin()
                        sni_status = response.status
                        response.read()
                    except (OSError, http.client.HTTPException, ssl.SSLError):
                        sni_status = None  # The source may close after upstream TLS failure.
            assert sni_status in (None, 200, 400, 403, 502), sni_status
            assert forbidden.accepts == 0 and forbidden.requests == []
            if sni_status == 200:
                assert len(allowed.requests) == before_allowed + 1
                assert allowed.sni[-1] == ALLOWED
            else:
                assert len(allowed.requests) == before_allowed

            status, stream = _connect(path, allowed_authority, ALLOWED, ca)
            assert status == 200
            before_h1 = len(allowed.requests)
            with stream:
                stream.sendall(b"GET /inner-conflict HTTP/1.1\r\nHost: " + forbidden_authority
                               + b"\r\nAuthorization: Bearer " + SECRET
                               + b"\r\nConnection: close\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                h1_status = response.status
                response.read()
            assert h1_status == 400
            assert len(allowed.requests) == before_h1
            assert forbidden.requests == []

            # A request head with an announced streaming body must receive a
            # local response before the client uploads that body.
            status, stream = _connect(path, allowed_authority, ALLOWED, ca)
            assert status == 200
            before_stream = len(allowed.requests)
            with stream:
                stream.sendall(b"POST /stream-conflict HTTP/1.1\r\nHost: " + forbidden_authority
                               + b"\r\nAuthorization: Bearer " + SECRET
                               + b"\r\nContent-Length: 12000000\r\nExpect: 100-continue\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 400
                response.read()
            assert len(allowed.requests) == before_stream
            assert forbidden.accepts == 0

            status, stream = _connect(path, allowed_authority, ALLOWED, ca, offers=("h2",))
            assert status == 200
            with stream:
                assert stream.selected_alpn_protocol() == "h2"
                before_h2 = len(allowed.requests)
                result = h2_requests(stream, [headers(f"{FORBIDDEN}:443", "/h2-conflict", [
                    ("authorization", "Bearer " + SECRET.decode()),
                ])], allow_rejection=True)[0]
            assert len(allowed.requests) == before_h2
            assert forbidden.requests == []
            assert result["headers"][":status"] == "400", result

            status, stream = _connect(path, allowed_authority, ALLOWED, ca, offers=("h2",))
            assert status == 200
            with stream:
                assert stream.selected_alpn_protocol() == "h2"
                before_host = len(allowed.requests)
                host_result = h2_requests(stream, [headers(f"{ALLOWED}:443", "/h2-host-conflict", [
                    ("host", f"{FORBIDDEN}:443"),
                    ("authorization", "Bearer " + SECRET.decode()),
                ])], allow_rejection=True)[0]
            assert len(allowed.requests) == before_host and forbidden.requests == []
            if proxy_backend == "rust":
                assert host_result["headers"][":status"] == "400", host_result
            else:
                assert host_result.get("goaway") == 1 or host_result.get("reset") == 1, host_result

            # The parent deliberately sends this CONNECT to a wrong-name TLS
            # endpoint. The permitted policy name must still be the verifier.
            before = len(forbidden.requests)
            parent.connect_override = forbidden
            status, stream = _connect(path, allowed_authority, ALLOWED, ca)
            assert status == 200
            with stream:
                stream.sendall(b"GET /wrong-certificate HTTP/1.1\r\nHost: " + allowed_authority
                               + b"\r\nAuthorization: Bearer " + SECRET
                               + b"\r\nConnection: close\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 502, response.status
                response.read()
            assert len(forbidden.requests) == before
            assert forbidden.sni[-1] == ALLOWED
            assert all(SECRET not in item["head"] for item in forbidden.requests)
            assert all(row["target"] == allowed_authority for row in parent.requests
                       if row["kind"] == "connect")
            audit = read_events(directory / "proxy/audit.jsonl")
            assert any(row["event"] == "security.network_guard" and row["host"] == FORBIDDEN
                       and row["decision"] == "deny" and row["details"]["method"] == "CONNECT"
                       for row in audit)
            assert any(row["event"] == "security.network_guard" and row["host"] == ALLOWED
                       and row["decision"] == "allow" and row["details"]["method"] == "CONNECT"
                       for row in audit)
            assert any(row["event"] == "security.credential_guard" and row["host"] == ALLOWED
                       and row["decision"] == "allow" for row in audit)
            if proxy_backend == "rust":
                egress = proxy.events("proxy.egress")
                assert egress
                assert all(row["host"] == ALLOWED and row["port"] == 443 and row["route"] == "parent"
                           for row in egress)
        # The wrong-name certificate is trusted and valid for its own name.
        # This direct control distinguishes name verification from CA failure.
        context = ssl.create_default_context(cafile=trust)
        with socket.create_connection(forbidden.server_address, timeout=5) as direct:
            with context.wrap_socket(direct, server_hostname=FORBIDDEN) as stream:
                stream.sendall(b"GET /direct-cert-control HTTP/1.1\r\nHost: forbidden.invalid\r\n"
                               b"Connection: close\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200 and response.read() == b"forbidden-tls"
        assert b"/direct-cert-control" in forbidden.requests[-1]["head"]
        assert SECRET not in forbidden.requests[-1]["head"]
        assert all(SECRET not in item["head"] for item in forbidden.requests)
