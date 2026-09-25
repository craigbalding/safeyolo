"""Upstream TLS trust and interception CA continuity through real proxies."""

import http.client
import socket
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy
from tests.proxy_migration.test_authority_consistency import (
    ALLOWED,
    FORBIDDEN,
    POLICY,
    Origin,
    _certificate,
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
                   + b"\r\nConnection: close\r\n\r\n")
    response = http.client.HTTPResponse(stream)
    response.begin()
    return response.status, response.read()


def _proxied_get(proxy, parent, origin, ca, path, expected_status):
    """Require a trusted client response and independent parent/origin contact."""
    before = (parent.accepts, origin.accepts, len(origin.sni), len(origin.requests))
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
    assert origin.server_address[0] == parent.server_address[0] == "127.0.0.1"
    assert origin.accepts > before[1], "upstream rejection needs a live TCP origin"
    assert origin.sni[before[2]:] and set(origin.sni[before[2]:]) == {ALLOWED}
    if expected_status == 200:
        assert len(origin.requests) == before[3] + 1
        assert body == origin.name.encode()
        assert path in origin.requests[-1]["head"]
    else:
        assert len(origin.requests) == before[3], "invalid upstream certificate reached HTTP"


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


def test_upstream_tls_uses_logical_name_sni_and_additional_ca(proxy_backend, tmp_path):
    """The parent dials loopback while upstream verification keeps the logical name."""
    directory = tmp_path / proxy_backend
    with _peers(directory / "peers") as (parent, peers, trust):
        _, _, allowed, wrong_name = peers
        allowed_cert = x509.load_pem_x509_certificate(trust.read_bytes())
        assert allowed_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName) == [ALLOWED]
        now = datetime.now(UTC)
        untrusted_context, untrusted_pem = _certificate(
            directory / "peers", ALLOWED, filename="untrusted-origin",
        )
        future_context, future_pem = _certificate(
            directory / "peers", ALLOWED, filename="future-origin",
            not_before=now + timedelta(days=1), not_after=now + timedelta(days=2),
        )
        future_cert = x509.load_pem_x509_certificate(future_pem)
        assert future_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName) == [ALLOWED]
        trust.write_bytes(trust.read_bytes() + future_pem)
        untrusted_root = directory / "peers/untrusted-root.pem"
        untrusted_root.write_bytes(untrusted_pem)
        with _server(Origin("untrusted-tls", tls_context=untrusted_context)) as untrusted, \
             _server(Origin("future-tls", tls_context=future_context)) as future:
            CertStore.from_store(directory / "proxy/ca", "mitmproxy", 2048)
            client_ca = directory / "proxy/ca/mitmproxy-ca-cert.pem"
            parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
            with launch_proxy(proxy_backend, directory / "proxy", POLICY, native_policy=True,
                              tls=True, upstream_ca=trust, parent_proxy=parent_url) as proxy:
                _proxied_get(proxy, parent, allowed, client_ca, b"/trusted", 200)

                parent.connect_override = wrong_name
                _proxied_get(proxy, parent, wrong_name, client_ca, b"/wrong-name", 502)

                parent.connect_override = untrusted
                _proxied_get(proxy, parent, untrusted, client_ca, b"/untrusted", 502)

                parent.connect_override = future
                _proxied_get(proxy, parent, future, client_ca, b"/future", 502)

            # Strict direct clients show the wrong-name leaf is trusted for its
            # own name and the unlisted root works only when explicitly loaded.
            _direct_get(wrong_name, FORBIDDEN, ssl.create_default_context(cafile=trust),
                        b"/wrong-name-control")
            _direct_get(untrusted, ALLOWED, ssl.create_default_context(cafile=untrusted_root),
                        b"/untrusted-control")
            with pytest.raises(ssl.SSLCertVerificationError):
                _direct_get(untrusted, ALLOWED, ssl.create_default_context(cafile=trust),
                            b"/untrusted-rejected-control")
            with pytest.raises(ssl.SSLCertVerificationError):
                _direct_get(future, ALLOWED, ssl.create_default_context(cafile=trust),
                            b"/future-rejected-control")
            # This unverified direct call is only a liveness control for a leaf
            # that no strict client can accept before its validity window.
            direct_liveness = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            direct_liveness.check_hostname = False
            direct_liveness.verify_mode = ssl.CERT_NONE
            _direct_get(future, ALLOWED, direct_liveness, b"/future-live-control",
                        certificate=future_cert)

            # The same private root is unavailable without upstream_ca_file.
            parent.connect_override = allowed
            CertStore.from_store(directory / "without-extra-ca/ca", "mitmproxy", 2048)
            without_extra_ca = directory / "without-extra-ca/ca/mitmproxy-ca-cert.pem"
            with launch_proxy(proxy_backend, directory / "without-extra-ca", POLICY,
                              native_policy=True, tls=True, parent_proxy=parent_url) as proxy:
                _proxied_get(proxy, parent, allowed, without_extra_ca,
                             b"/missing-extra-ca", 502)
            _direct_get(allowed, ALLOWED, ssl.create_default_context(cafile=trust),
                        b"/additional-ca-control")


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
