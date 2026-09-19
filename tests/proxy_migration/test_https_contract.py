"""HTTPS forwarding through real policy with verification enabled at both peers."""

import hashlib
import http.client
import json
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.scenarios import POLICY, Origin
from tests.proxy_migration.test_http2_contract import origin_certificate


@pytest.mark.parametrize("effect,default_effect,status", [("deny", "allow", 200), ("allow", "deny", 403)])
def test_connect_has_no_http_path(proxy_backend, tmp_path, effect, default_effect, status):
    """An authority-form CONNECT must not match an HTTP slash-path condition."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    policy = f'''[[permissions]]
action = "network:request"
resource = "*"
effect = "{default_effect}"
[[permissions]]
action = "network:request"
resource = "localhost/*"
effect = "{effect}"
condition = {{ method = "CONNECT", path_prefix = "/" }}
'''
    # Restore the production eager CONNECT behavior. Admission authorizes this
    # TCP contact; a denied CONNECT still opens no destination connection.
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.2)
        authority = f"localhost:{origin.getsockname()[1]}"
        with launch_proxy(proxy_backend, directory, policy, tls=True, eager_connect=True) as proxy:
            with socket.socket(socket.AF_UNIX) as raw:
                raw.settimeout(5)
                raw.connect(proxy.paths["alice"])
                raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                response = http.client.HTTPResponse(raw)
                response.begin()
                assert response.status == status
                response.close()
            if status == 200:
                accepted, _ = origin.accept()
                with accepted:
                    accepted.settimeout(2)
                    assert accepted.recv(1) == b""
                assert len(proxy.events("proxy.egress")) == 1
            else:
                with pytest.raises(TimeoutError):
                    origin.accept()
                assert proxy.events("proxy.egress") == []


@pytest.mark.parametrize("certificate_host,trusted,status", [
    ("localhost", True, 200),
    ("wrong.invalid", True, 502),
    ("localhost", False, 502),
])
def test_https_origin_verification(proxy_backend, tmp_path, certificate_host, trusted, status):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, certificate_host)])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(certificate_host)]), critical=False)
                   .sign(key, hashes.SHA256()))
    server_pem = directory / "origin.pem"
    server_pem.touch(mode=0o600)
    server_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()) + certificate.public_bytes(serialization.Encoding.PEM))
    origin_ca = directory / "origin-ca.pem"
    origin_ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_pem)
    origin = Origin()
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        port = origin.server_address[1]
        authority = f"localhost:{port}"
        with launch_proxy(proxy_backend, directory, POLICY, tls=True, upstream_ca=origin_ca if trusted else None) as proxy:
            denied, _, _ = request(proxy.paths["bob"], authority, method="CONNECT",
                                    headers={"Host": authority, "X-SafeYolo-Agent": "alice"})
            assert denied == 403
            raw = socket.socket(socket.AF_UNIX)
            raw.settimeout(5)
            try:
                raw.connect(proxy.paths["alice"])
                raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                head = b""
                while not head.endswith(b"\r\n\r\n"):
                    byte = raw.recv(1)
                    assert byte, head
                    head += byte
                assert head.startswith(b"HTTP/1.1 200"), head
                client_context = ssl.create_default_context(cafile=directory / "ca/mitmproxy-ca-cert.pem")
                tls = client_context.wrap_socket(raw, server_hostname="localhost")
                client = http.client.HTTPConnection("localhost", port, timeout=5)
                client.sock = tls
                try:
                    client.request("GET", "/signed?x=one&x=two%2Fthree")
                    response = client.getresponse()
                    body = response.read()
                    assert response.status == status, body
                    if status == 200:
                        assert body == b"hello"
                        assert origin.requests == [{"method": "GET", "target": "/signed?x=one&x=two%2Fthree"}]
                    else:
                        assert origin.requests == []
                finally:
                    client.close()
            finally:
                raw.close()
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)


def test_https_not_yet_valid_origin_certificate_is_rejected(proxy_backend, tmp_path):
    """A trusted-but-not-yet-valid origin certificate cannot reach HTTP."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    not_valid_before = now + timedelta(days=1)
    not_valid_after = now + timedelta(days=2)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(not_valid_before)
                   .not_valid_after(not_valid_after)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                   .sign(key, hashes.SHA256()))
    server_pem = directory / "not-yet-valid-origin.pem"
    server_pem.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
        + certificate.public_bytes(serialization.Encoding.PEM)
    )
    origin_ca = directory / "not-yet-valid-origin-ca.pem"
    origin_ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    origin_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    origin_context.load_cert_chain(server_pem)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    authority = f"localhost:{listener.getsockname()[1]}"
    observation = {
        "accepted": False,
        "peer": None,
        "handshake": None,
        "application_bytes": b"",
        "error": None,
    }

    def serve_origin():
        try:
            raw, peer = listener.accept()
            observation["accepted"] = True
            observation["peer"] = list(peer)
            try:
                with origin_context.wrap_socket(raw, server_side=True) as stream:
                    observation["handshake"] = "succeeded"
                    stream.settimeout(2)
                    observation["application_bytes"] = stream.recv(4096)
            except ssl.SSLError as error:
                observation["handshake"] = "failed"
                observation["error"] = f"{type(error).__name__}: {error}"
            finally:
                raw.close()
        except BaseException as error:  # report listener failures in the test thread
            observation["error"] = f"{type(error).__name__}: {error}"

    thread = threading.Thread(target=serve_origin)
    thread.start()
    certificate_sha256 = hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    try:
        with launch_proxy(
            proxy_backend,
            directory,
            POLICY,
            tls=True,
            upstream_ca=origin_ca,
            native_policy=proxy_backend == "rust",
        ) as proxy:
            raw = socket.socket(socket.AF_UNIX)
            raw.settimeout(5)
            try:
                raw.connect(proxy.paths["alice"])
                raw.sendall(
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
                )
                tunnel_response = http.client.HTTPResponse(raw)
                tunnel_response.begin()
                assert tunnel_response.status == 200
                tunnel_response.close()
                client_context = ssl.create_default_context(
                    cafile=directory / "ca/mitmproxy-ca-cert.pem"
                )
                tls = client_context.wrap_socket(raw, server_hostname="localhost")
                client = http.client.HTTPConnection("localhost", listener.getsockname()[1], timeout=5)
                client.sock = tls
                try:
                    client.request("GET", "/not-yet-valid")
                    response = client.getresponse()
                    body = response.read()
                    assert response.status == 502, body
                finally:
                    client.close()
            finally:
                raw.close()
            assert proxy.process.poll() is None
            thread.join(timeout=5)
            assert not thread.is_alive()
            provenance = None
            if proxy_backend == "rust":
                provenance = json.loads(
                    (directory / "native-policy-provenance.json").read_text()
                )
                assert provenance == {
                    "backend": "rust",
                    "policy_mode": "native",
                    "policy_file": str(directory / "policy.toml"),
                    "temporary_policy_socket": None,
                    "temporary_policy_adapter": False,
                }
            (directory / "not-yet-valid-certificate.json").write_text(
                json.dumps(
                    {
                        "backend": proxy_backend,
                        "authority": authority,
                        "certificate_sha256": certificate_sha256,
                        "not_valid_before": not_valid_before.isoformat(),
                        "not_valid_after": not_valid_after.isoformat(),
                        "client_tunnel_status": 200,
                        "client_http_status": 502,
                        "origin_observed": {
                            "accepted": observation["accepted"],
                            "peer": observation["peer"],
                            "handshake": observation["handshake"],
                            "application_bytes_hex": observation["application_bytes"].hex(),
                            "error": observation["error"],
                        },
                        "proxy_egress_events": proxy.events("proxy.egress"),
                        "native_policy_provenance": provenance,
                        "limits": [
                            "This proves one trusted-by-file but not-yet-valid origin certificate rejection.",
                            "It does not establish mTLS/client-certificate, OCSP/CRL, TLS version, cipher or renegotiation behavior.",
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
    finally:
        listener.close()
        thread.join(timeout=6)
    assert not thread.is_alive()
    assert observation["accepted"] is True
    assert observation["handshake"] == "failed", observation
    assert observation["application_bytes"] == b""


def _write_mtls_material(directory):
    """Create disposable CA, server and client certificates for one fixture."""
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned-mtls-ca")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(common_name, usage):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(common_name)]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return key, certificate

    server_key, server_certificate = leaf("localhost", ExtendedKeyUsageOID.SERVER_AUTH)
    client_key, client_certificate = leaf("owned-client", ExtendedKeyUsageOID.CLIENT_AUTH)

    def private_key_pem(key):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    ca_file = directory / "mtls-ca.pem"
    server_file = directory / "mtls-server.pem"
    client_file = directory / "mtls-client.pem"
    ca_file.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    server_file.write_bytes(
        private_key_pem(server_key)
        + server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    client_file.write_bytes(
        private_key_pem(client_key)
        + client_certificate.public_bytes(serialization.Encoding.PEM)
    )
    return ca_file, server_file, client_file


class MtlsOrigin(Origin):
    """Origin that records TLS handshakes before handing HTTP to OriginHandler."""

    def __init__(self, context):
        self.mtls_context = context
        self.tls_successes = 0
        self.tls_failures = []
        super().__init__()

    def get_request(self):
        raw, address = super().get_request()
        try:
            stream = self.mtls_context.wrap_socket(raw, server_side=True)
        except ssl.SSLError as error:
            self.tls_failures.append(type(error).__name__)
            raw.close()
            raise
        self.tls_successes += 1
        return stream, address


class TlsNegotiationOrigin(Origin):
    """Origin that records the negotiated upstream TLS version and cipher."""

    def __init__(self, context):
        self.tls_context = context
        self.negotiations = []
        super().__init__()

    def get_request(self):
        raw, address = super().get_request()
        try:
            stream = self.tls_context.wrap_socket(raw, server_side=True)
        except BaseException:
            raw.close()
            raise
        self.negotiations.append({
            "version": stream.version(),
            "cipher": list(stream.cipher()),
        })
        return stream, address


def test_https_origin_requires_client_certificate_before_http(proxy_backend, tmp_path):
    """A mutual-TLS origin rejects the proxy before it can send HTTP bytes."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    ca_file, server_file, client_file = _write_mtls_material(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_file)
    context.load_verify_locations(cafile=ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    origin = MtlsOrigin(context)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        port = origin.server_address[1]

        # This direct control proves that the origin really requires and accepts
        # a valid client certificate. The proxy path below receives no client
        # certificate configuration.
        direct_context = ssl.create_default_context(cafile=ca_file)
        direct_context.load_cert_chain(client_file)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with direct_context.wrap_socket(raw, server_hostname="localhost") as tls:
                direct = http.client.HTTPConnection("localhost", port, timeout=5)
                direct.sock = tls
                direct.request("GET", "/direct-mtls")
                direct_response = direct.getresponse()
                assert direct_response.status == 200
                assert direct_response.read() == b"hello"
                direct.close()

        with launch_proxy(
            proxy_backend,
            directory,
            POLICY,
            tls=True,
            upstream_ca=ca_file,
            eager_connect=True,
            native_policy=True,
        ) as proxy:
            raw = socket.socket(socket.AF_UNIX)
            raw.settimeout(5)
            try:
                raw.connect(proxy.paths["alice"])
                raw.sendall(
                    f"CONNECT localhost:{port} HTTP/1.1\r\n"
                    f"Host: localhost:{port}\r\n\r\n".encode()
                )
                head = bytearray()
                while not head.endswith(b"\r\n\r\n"):
                    data = raw.recv(1)
                    assert data, bytes(head)
                    head.extend(data)
                assert head.startswith(b"HTTP/1.1 200"), bytes(head)
                client_context = ssl.create_default_context(
                    cafile=directory / "ca/mitmproxy-ca-cert.pem"
                )
                with client_context.wrap_socket(raw, server_hostname="localhost") as tls:
                    client = http.client.HTTPConnection("localhost", port, timeout=5)
                    client.sock = tls
                    client.request("GET", "/missing-client-certificate")
                    response = client.getresponse()
                    body = response.read()
                    assert response.status == 502, body
                    client.close()
            finally:
                raw.close()

            assert origin.tls_successes == 1
            # A backend may make more than one failed TLS attempt while
            # completing the one CONNECT request. Every attempt must fail before
            # HTTP application data reaches the origin.
            assert len(origin.tls_failures) >= 1
            assert origin.accepts == 1 + len(origin.tls_failures)
            assert origin.requests == [{"method": "GET", "target": "/direct-mtls"}]
            events = proxy.events("proxy.request")
            if proxy_backend == "rust":
                provenance = json.loads(
                    (directory / "native-policy-provenance.json").read_text()
                )
                assert provenance == {
                    "backend": "rust",
                    "policy_mode": "native",
                    "policy_file": str(directory / "policy.toml"),
                    "temporary_policy_socket": None,
                    "temporary_policy_adapter": False,
                }
                error_events = [event for event in events if event["status"] == 502]
                assert len(error_events) == 1
                assert error_events[0]["agent"] == "alice"
                assert error_events[0]["decision"] == "error"
            (directory / "mtls-negative-observation.json").write_text(
                json.dumps(
                    {
                        "backend": proxy_backend,
                        "authority": f"localhost:{port}",
                        "direct_positive_control": {
                            "client_certificate_sha256": hashlib.sha256(
                                client_file.read_bytes()
                            ).hexdigest(),
                            "status": direct_response.status,
                            "body": "hello",
                        },
                        "proxied_without_client_certificate": {
                            "status": response.status,
                            "body_sha256": hashlib.sha256(body).hexdigest(),
                        },
                        "origin": {
                            "tcp_accepts": origin.accepts,
                            "tls_successes": origin.tls_successes,
                            "tls_failures": origin.tls_failures,
                            "http_requests": origin.requests,
                        },
                        "proxy_request_events": events if proxy_backend == "rust" else [],
                        "native_policy_provenance": (
                            provenance if proxy_backend == "rust" else None
                        ),
                        "limits": [
                            "One direct client-certificate success and one proxy connection without a client certificate.",
                            "This proves the current proxy path fails closed at the origin TLS handshake; it does not implement or test proxy client-certificate configuration.",
                            "TLS version, cipher, OCSP/CRL and renegotiation matrices remain outside this control.",
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_https_tls12_origin_records_version_and_cipher(proxy_backend, tmp_path):
    """An allowed request reaches an origin restricted to TLS 1.2 and one cipher."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    server_pem, origin_ca = origin_certificate(directory)
    cipher_name = "ECDHE-RSA-AES128-GCM-SHA256"
    origin_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    origin_context.minimum_version = ssl.TLSVersion.TLSv1_2
    origin_context.maximum_version = ssl.TLSVersion.TLSv1_2
    origin_context.set_ciphers(cipher_name)
    origin_context.load_cert_chain(server_pem)
    origin = TlsNegotiationOrigin(origin_context)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        port = origin.server_address[1]
        authority = f"localhost:{port}"

        # A direct TLS 1.2 client control proves the origin restriction and
        # certificate trust independently of either proxy implementation.
        direct_context = ssl.create_default_context(cafile=origin_ca)
        direct_context.minimum_version = ssl.TLSVersion.TLSv1_2
        direct_context.maximum_version = ssl.TLSVersion.TLSv1_2
        direct_context.set_ciphers(cipher_name)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with direct_context.wrap_socket(raw, server_hostname="localhost") as tls:
                direct = http.client.HTTPConnection("localhost", port, timeout=5)
                direct.sock = tls
                direct.request("GET", "/direct-tls12")
                response = direct.getresponse()
                assert response.status == 200
                assert response.read() == b"hello"
                direct.close()

        with launch_proxy(
            proxy_backend,
            directory,
            POLICY,
            tls=True,
            upstream_ca=origin_ca,
            eager_connect=True,
            native_policy=proxy_backend == "rust",
        ) as proxy:
            raw = socket.socket(socket.AF_UNIX)
            raw.settimeout(5)
            try:
                raw.connect(proxy.paths["alice"])
                raw.sendall(
                    f"CONNECT {authority} HTTP/1.1\r\n"
                    f"Host: {authority}\r\n\r\n".encode()
                )
                head = bytearray()
                while not head.endswith(b"\r\n\r\n"):
                    data = raw.recv(1)
                    assert data, bytes(head)
                    head.extend(data)
                assert head.startswith(b"HTTP/1.1 200"), bytes(head)
                client_context = ssl.create_default_context(
                    cafile=directory / "ca/mitmproxy-ca-cert.pem"
                )
                with client_context.wrap_socket(raw, server_hostname="localhost") as tls:
                    client = http.client.HTTPConnection("localhost", port, timeout=5)
                    client.sock = tls
                    client.request("GET", "/proxied-tls12")
                    response = client.getresponse()
                    assert response.status == 200
                    assert response.read() == b"hello"
                    client.close()
            finally:
                raw.close()

            provenance = None
            if proxy_backend == "rust":
                provenance = json.loads(
                    (directory / "native-policy-provenance.json").read_text()
                )
                assert provenance == {
                    "backend": "rust",
                    "policy_mode": "native",
                    "policy_file": str(directory / "policy.toml"),
                    "temporary_policy_socket": None,
                    "temporary_policy_adapter": False,
                }
            (directory / "tls12-negotiation-observation.json").write_text(
                json.dumps(
                    {
                        "backend": proxy_backend,
                        "authority": authority,
                        "certificate_sha256": hashlib.sha256(
                            origin_ca.read_bytes()
                        ).hexdigest(),
                        "required_tls_version": "TLSv1.2",
                        "required_cipher": cipher_name,
                        "direct_request": {"target": "/direct-tls12", "status": 200},
                        "proxied_request": {"target": "/proxied-tls12", "status": 200},
                        "origin": {
                            "tcp_accepts": origin.accepts,
                            "negotiations": origin.negotiations,
                            "http_requests": origin.requests,
                        },
                        "proxy_request_events": (
                            proxy.events("proxy.request") if proxy_backend == "rust" else []
                        ),
                        "native_policy_provenance": provenance,
                        "limits": [
                            "One direct control and one proxied request against a TLS 1.2-only origin.",
                            "The origin records the negotiated TLS version and cipher; this does not configure a proxy TLS policy.",
                            "It does not establish TLS 1.3, cipher matrices, OCSP/CRL, renegotiation, or long-duration behavior.",
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert origin.accepts == 2
    assert origin.negotiations == [
        {"version": "TLSv1.2", "cipher": [cipher_name, "TLSv1.2", 128]},
        {"version": "TLSv1.2", "cipher": [cipher_name, "TLSv1.2", 128]},
    ]
    assert origin.requests == [
        {"method": "GET", "target": "/direct-tls12"},
        {"method": "GET", "target": "/proxied-tls12"},
    ]
