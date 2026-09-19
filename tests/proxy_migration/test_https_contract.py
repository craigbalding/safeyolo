"""HTTPS forwarding through real policy with verification enabled at both peers."""

import http.client
import hashlib
import json
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.scenarios import POLICY, Origin


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
