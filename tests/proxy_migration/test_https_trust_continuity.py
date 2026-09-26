"""Upstream TLS trust and interception CA continuity through real proxies."""

import http.client
import socket
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy
from tests.proxy_migration.test_authority_consistency import (
    ALLOWED,
    FORBIDDEN,
    POLICY,
    SECRET,
    Origin,
    Parent,
    _connect,
    _peers,
    _server,
)

AUTHORITY = f"{ALLOWED}:443".encode()
CA_FILES = (
    "mitmproxy-ca.pem", "mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer",
    "mitmproxy-ca.p12", "mitmproxy-ca-cert.p12", "mitmproxy-dhparam.pem",
)


def _get(stream, path):
    stream.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: " + AUTHORITY
                   + b"\r\nAuthorization: Bearer " + SECRET
                   + b"\r\nConnection: close\r\n\r\n")
    response = http.client.HTTPResponse(stream)
    response.begin()
    return response.status, response.read()


def _proxied_get(proxy, parent, origin, ca, path, expected_status):
    """Require client trust and independent parent, handshake, and HTTP observations."""
    before = (parent.accepts, origin.accepts, len(origin.sni),
              len(origin.tls_handshakes), len(origin.requests), len(origin.application_bytes))
    connect_status, stream = _connect(proxy.paths["alice"], AUTHORITY, ALLOWED, ca)
    assert connect_status == 200
    with stream:
        peer = x509.load_der_x509_certificate(stream.getpeercert(binary_form=True))
        interception_ca = x509.load_pem_x509_certificate(ca.read_bytes())
        assert peer.issuer == interception_ca.subject
        status, body = _get(stream, path)
    assert status == expected_status, (status, body)
    assert parent.accepts > before[0]
    assert parent.requests[-1]["kind"] == "connect"
    assert parent.requests[-1]["target"] == AUTHORITY
    assert parent.requests[-1]["route"] == origin.name
    assert SECRET not in parent.requests[-1]["head"]
    assert origin.server_address[0] == parent.server_address[0] == "127.0.0.1"
    assert origin.accepts > before[1], "upstream rejection needs a live TCP origin"
    assert origin.sni[before[2]:] and set(origin.sni[before[2]:]) == {ALLOWED}
    with origin.handshake_ready:
        assert origin.handshake_ready.wait_for(
            lambda: len(origin.tls_handshakes) > before[3], timeout=5
        ), "origin did not observe a TLS handshake outcome"
    completed = origin.tls_handshakes[before[3]:].count("complete")
    if completed:
        with origin.application_ready:
            assert origin.application_ready.wait_for(
                lambda: len(origin.application_bytes) >= before[5] + completed, timeout=5
            ), "origin did not finish reading application bytes"
    if expected_status == 200:
        assert "complete" in origin.tls_handshakes[before[3]:]
        assert len(origin.requests) == before[4] + 1
        assert body == origin.name.encode()
        assert path in origin.requests[-1]["head"]
        assert b"Authorization: Bearer " + SECRET in origin.requests[-1]["head"]
    else:
        assert len(origin.requests) == before[4], "invalid upstream certificate reached HTTP"
        assert all(not data for data in origin.application_bytes[before[5]:]), (
            "invalid upstream certificate delivered application bytes"
        )


def _direct_get(origin, name, context, path, *, certificate=None):
    """Prove the selected physical origin serves HTTP with the named certificate."""
    with socket.create_connection(origin.server_address, timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=name) as stream:
            if certificate is not None:
                peer = x509.load_der_x509_certificate(stream.getpeercert(binary_form=True))
                assert peer.fingerprint(hashes.SHA256()) == certificate.fingerprint(hashes.SHA256())
            stream.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: " + name.encode()
                           + b"\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(stream)
            response.begin()
            assert response.status == 200
            assert response.read() == origin.name.encode()


def _ca_chain(directory, label, now):
    """Make a private root and intermediate; only the root is configured as trusted."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{label} root")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .sign(root_key, hashes.SHA256()))
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{label} intermediate")])
    intermediate = (x509.CertificateBuilder().subject_name(intermediate_name).issuer_name(root_name)
                    .public_key(intermediate_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=10))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .sign(root_key, hashes.SHA256()))
    root_file = directory / f"{label}-root.pem"
    root_file.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    return root_file, intermediate_key, intermediate


def _chain_leaf(directory, label, host, intermediate_key, intermediate, now, *, future=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(intermediate.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=2) if future else now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(intermediate_key, hashes.SHA256()))
    pem = directory / f"{label}.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
                    + certificate.public_bytes(serialization.Encoding.PEM)
                    + intermediate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem)
    context.set_alpn_protocols(["http/1.1"])
    return context, certificate


def test_upstream_tls_uses_logical_name_sni_and_additional_ca(proxy_backend, tmp_path):
    """A loopback parent cannot change the logical name used to verify a full chain."""
    directory = tmp_path / proxy_backend
    directory.mkdir(parents=True)
    now = datetime.now(UTC)
    trust, signing_key, intermediate = _ca_chain(directory, "trusted", now)
    untrusted_root, other_key, other_intermediate = _ca_chain(directory, "untrusted", now)
    allowed_context, allowed_cert = _chain_leaf(directory, "allowed", ALLOWED, signing_key,
                                                intermediate, now)
    wrong_context, wrong_cert = _chain_leaf(directory, "wrong-name", FORBIDDEN, signing_key,
                                            intermediate, now)
    untrusted_context, untrusted_cert = _chain_leaf(directory, "untrusted", ALLOWED, other_key,
                                                    other_intermediate, now)
    future_context, future_cert = _chain_leaf(directory, "future", ALLOWED, signing_key,
                                              intermediate, now, future=True)
    for certificate, host in ((allowed_cert, ALLOWED), (wrong_cert, FORBIDDEN),
                              (untrusted_cert, ALLOWED), (future_cert, ALLOWED)):
        assert certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName) == [host]
    with (
        _server(Origin("allowed-chain", tls_context=allowed_context)) as allowed,
        _server(Origin("wrong-name-chain", tls_context=wrong_context)) as wrong_name,
        _server(Origin("untrusted-chain", tls_context=untrusted_context)) as untrusted,
        _server(Origin("future-leaf", tls_context=future_context)) as future,
        _server(Parent(allowed, wrong_name, allowed, wrong_name)) as parent,
    ):
        CertStore.from_store(directory / "proxy/ca", "mitmproxy", 2048)
        client_ca = directory / "proxy/ca/mitmproxy-ca-cert.pem"
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        with launch_proxy(proxy_backend, directory / "proxy", POLICY, native_policy=True,
                          credential_head_decision=True, tls=True, upstream_ca=trust,
                          parent_proxy=parent_url) as proxy:
            _proxied_get(proxy, parent, allowed, client_ca, b"/trusted", 200)

            parent.connect_override = wrong_name
            _proxied_get(proxy, parent, wrong_name, client_ca, b"/wrong-name", 502)

            parent.connect_override = untrusted
            _proxied_get(proxy, parent, untrusted, client_ca, b"/untrusted", 502)

            parent.connect_override = future
            _proxied_get(proxy, parent, future, client_ca, b"/future", 502)

        # Strict direct clients distinguish name, chain trust, and validity
        # failures from dead origins or a broken parent route.
        _direct_get(wrong_name, FORBIDDEN, ssl.create_default_context(cafile=trust),
                    b"/wrong-name-control", certificate=wrong_cert)
        with pytest.raises(ssl.SSLCertVerificationError):
            _direct_get(wrong_name, ALLOWED, ssl.create_default_context(cafile=trust),
                        b"/wrong-name-rejected-control")
        _direct_get(untrusted, ALLOWED, ssl.create_default_context(cafile=untrusted_root),
                    b"/untrusted-control", certificate=untrusted_cert)
        with pytest.raises(ssl.SSLCertVerificationError):
            _direct_get(untrusted, ALLOWED, ssl.create_default_context(cafile=trust),
                        b"/untrusted-rejected-control")
        with pytest.raises(ssl.SSLCertVerificationError):
            _direct_get(future, ALLOWED, ssl.create_default_context(cafile=trust),
                        b"/future-rejected-control")
        # No strict client can accept a leaf before its validity window.
        direct_liveness = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        direct_liveness.check_hostname = False
        direct_liveness.verify_mode = ssl.CERT_NONE
        _direct_get(future, ALLOWED, direct_liveness, b"/future-live-control",
                    certificate=future_cert)

        # The same complete chain fails when the additional root is absent.
        parent.connect_override = allowed
        CertStore.from_store(directory / "without-extra-ca/ca", "mitmproxy", 2048)
        without_extra_ca = directory / "without-extra-ca/ca/mitmproxy-ca-cert.pem"
        with launch_proxy(proxy_backend, directory / "without-extra-ca", POLICY,
                          native_policy=True, credential_head_decision=True,
                          tls=True, parent_proxy=parent_url) as proxy:
            _proxied_get(proxy, parent, allowed, without_extra_ca,
                         b"/missing-extra-ca", 502)
        _direct_get(allowed, ALLOWED, ssl.create_default_context(cafile=trust),
                    b"/additional-ca-control", certificate=allowed_cert)
        with pytest.raises(ssl.SSLCertVerificationError):
            _direct_get(allowed, "127.0.0.1", ssl.create_default_context(cafile=trust),
                        b"/physical-address-rejected-control")


def _ca_files(directory):
    return {name: (directory / name).read_bytes() for name in CA_FILES}


def test_python_ca_is_reused_by_rust_after_restart(proxy_backend, tmp_path):
    """A Python-generated CA remains the client trust anchor across Rust starts."""
    if proxy_backend == "python":
        pytest.skip("The cross-backend transition runs in the Rust leg")
    directory = tmp_path / "ca-transition"
    with _peers(directory / "peers") as (parent, peers, trust):
        _, _, allowed, _ = peers
        proxy_dir = directory / "proxy"
        ca_dir = proxy_dir / "ca"
        ca_dir.mkdir(parents=True)
        CertStore.from_store(ca_dir, "mitmproxy", 2048)
        original = _ca_files(ca_dir)
        key = serialization.load_pem_private_key(original["mitmproxy-ca.pem"], password=None)
        certificate = x509.load_pem_x509_certificate(original["mitmproxy-ca-cert.pem"])
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.public_key().public_numbers() == certificate.public_key().public_numbers()
        client_ca = ca_dir / "mitmproxy-ca-cert.pem"
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        for backend, path in (("python", b"/python-original"),
                              ("rust", b"/rust-import"),
                              ("rust", b"/rust-restart")):
            with launch_proxy(backend, proxy_dir, POLICY, native_policy=True,
                              tls=True, upstream_ca=trust, parent_proxy=parent_url) as proxy:
                _proxied_get(proxy, parent, allowed, client_ca, path, 200)
                if path == b"/rust-import":
                    with pytest.raises(ssl.SSLCertVerificationError):
                        _connect(proxy.paths["alice"], AUTHORITY, ALLOWED, trust)
            assert _ca_files(ca_dir) == original, f"{backend} replaced Python CA material"
