"""Run with the frozen acceptance-tools Python, separately from the CLI suite."""

import asyncio
import base64
import hmac
import ipaddress
import json
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


@contextmanager
def http_responses(responses, tls_context=None):
    """Serve finite HTTP responses on a disposable loopback port."""
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            status, headers, body = responses.get(self.path, responses["/"])
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            if "Transfer-Encoding" not in headers:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass  # Fixture traffic is checked by the caller, not written to stderr.

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        if tls_context is not None:
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        scheme = "https" if tls_context is not None else "http"
        try:
            yield f"{scheme}://127.0.0.1:{server.server_port}", paths
        finally:
            server.shutdown()
            thread.join(timeout=5)


def hmac_token(key):
    """Create the attacker's token without PyJWT's signing-key guard."""

    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    message = segment({"alg": "HS256"}) + b"." + segment({"sub": "forged"})
    signature = base64.urlsafe_b64encode(hmac.digest(key, message, "sha256")).rstrip(b"=")
    return (message + b"." + signature).decode()


class JWTDependencies(unittest.TestCase):
    def test_asymmetric_keys_cannot_verify_hmac_forgeries(self):
        for key in (ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 2048)):
            algorithm = "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) else "RS256"
            public = key.public_key()
            pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            forms = (
                pem,
                pem.replace(b"-----END", b"\t-----END"),
                pem.replace(b"\n", b"\r"),
                b" ".join(pem.splitlines()),
            )
            for value in forms:
                with self.subTest(algorithm=algorithm, form=value[:40]):
                    serialization.load_pem_public_key(value)
                    with self.assertRaises(jwt.InvalidKeyError):
                        jwt.decode(hmac_token(value), value, algorithms=[algorithm, "HS256"])
                    with self.assertRaises(jwt.InvalidAlgorithmError):
                        jwt.decode(hmac_token(value), value, algorithms=[algorithm])
            der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            with self.subTest(algorithm=algorithm, form="DER"), self.assertRaises(jwt.InvalidKeyError):
                jwt.decode(hmac_token(der), der, algorithms=[algorithm, "HS256"])
            legitimate = jwt.encode({"sub": "valid"}, key, algorithm=algorithm)
            self.assertEqual(jwt.decode(legitimate, public, algorithms=[algorithm])["sub"], "valid")

    def test_reused_options_preserve_claim_checks(self):
        secret = "dependency-regression-secret-32-bytes"
        valid = {"exp": 4102444800, "nbf": 0, "iat": 0, "aud": "aud", "iss": "iss", "sub": "sub", "jti": "jti"}
        invalid = {
            "exp": 0,
            "nbf": 4102444800,
            "iat": 4102444800,
            "aud": "wrong",
            "iss": "wrong",
            "sub": "wrong",
            "jti": 1,
        }
        for decode in (jwt.decode, jwt.decode_complete):
            for claim, value in invalid.items():
                with self.subTest(decode=decode.__name__, claim=claim):
                    options = {"verify_signature": False}
                    token = jwt.encode({**valid, claim: value}, secret, algorithm="HS256")
                    decode(token, options=options)
                    self.assertEqual(options, {"verify_signature": False})
                    options["verify_signature"] = True
                    with self.assertRaises(jwt.InvalidTokenError):
                        decode(
                            token,
                            secret,
                            algorithms=["HS256"],
                            options=options,
                            audience="aud",
                            issuer="iss",
                            subject="sub",
                        )
                    decode(
                        jwt.encode(valid, secret, algorithm="HS256"),
                        secret,
                        algorithms=["HS256"],
                        options=options,
                        audience="aud",
                        issuer="iss",
                        subject="sub",
                    )
                    self.assertEqual(options, {"verify_signature": True})

    def test_semgrep_mcp_verifier_and_sdk_assertions(self):
        from mcp.client.auth.extensions.client_credentials import SignedJWTParameters
        from semgrep.mcp.utilities.token_verifier import IntrospectionTokenVerifier

        key = rsa.generate_private_key(65537, 2048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        public_jwk.update(kid="fixture", alg="RS256", use="sig")
        responses = {
            "/": (200, {}, json.dumps({"keys": [public_jwk]}).encode()),
            "/redirect": (302, {"Location": "/"}, b""),
        }
        with http_responses(responses) as (url, paths):
            verifier = IntrospectionTokenVerifier(url, url, url)
            token = jwt.encode(
                {"client_id": "fixture", "scope": "scan", "exp": 4102444800},
                key,
                algorithm="RS256",
                headers={"kid": "fixture"},
            )
            accepted = asyncio.run(verifier.verify_token(token))
            self.assertEqual(accepted.client_id, "fixture")
            expired = jwt.encode({"exp": 0}, key, algorithm="RS256", headers={"kid": "fixture"})
            self.assertIsNone(asyncio.run(verifier.verify_token(expired)))
            paths.clear()
            with self.assertRaises(jwt.PyJWKClientError):
                jwt.PyJWKClient(url + "/redirect").get_jwk_set()
            self.assertEqual(paths, ["/redirect"])

        private_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        provider = SignedJWTParameters(
            issuer="client", subject="client", signing_key=private_pem
        ).create_assertion_provider()
        assertion = asyncio.run(provider("authorization-server"))
        claims = jwt.decode(
            assertion,
            key.public_key(),
            algorithms=["RS256"],
            audience="authorization-server",
            issuer="client",
            subject="client",
        )
        self.assertIn("jti", claims)


class NetworkDependencies(unittest.TestCase):
    def test_chunk_lines_are_bounded_in_streaming_apis(self):
        responses = {
            "/": (200, {"Transfer-Encoding": "chunked"}, b"2\r\nok\r\n0\r\n\r\n"),
            "/long": (200, {"Transfer-Encoding": "chunked"}, b"2;" + b"x" * 65536 + b"\r\nok\r\n0\r\n\r\n"),
        }
        with http_responses(responses) as (url, _paths), urllib3.PoolManager() as pool:
            for method in ("stream", "read_chunked"):
                with self.subTest(method=method):
                    with pool.request("GET", url, preload_content=False) as response:
                        self.assertEqual(b"".join(getattr(response, method)()), b"ok")
                    with pool.request("GET", url + "/long", preload_content=False) as response:
                        with self.assertRaises(urllib3.exceptions.ProtocolError) as caught:
                            list(getattr(response, method)())
                        self.assertIn("chunk size line exceeded", str(caught.exception))
            with requests.get(url + "/long", stream=True, timeout=5) as response:
                with self.assertRaises(requests.exceptions.ChunkedEncodingError) as caught:
                    list(response.iter_content())
                self.assertIn("chunk size line exceeded", str(caught.exception))

    def test_https_proxy_keeps_its_own_certificate_policy(self):
        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        with tempfile.TemporaryDirectory() as temporary:
            cert_path, key_path = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            with http_responses({"/": (200, {}, b"ok")}, server_context) as (proxy_url, _paths):
                for forwarding in (False, True):
                    with self.subTest(forwarding=forwarding):
                        proxy_context = ssl.create_default_context()
                        with urllib3.ProxyManager(
                            proxy_url,
                            proxy_ssl_context=proxy_context,
                            use_forwarding_for_https=forwarding,
                            cert_reqs=ssl.CERT_NONE,
                        ) as pool:
                            with self.assertRaises(urllib3.exceptions.ProxyError) as caught:
                                pool.request("GET", "https://target.invalid/", retries=False, timeout=2)
                            self.assertIn("CERTIFICATE_VERIFY_FAILED", str(caught.exception))
                        self.assertEqual(proxy_context.verify_mode, ssl.CERT_REQUIRED)
                        self.assertTrue(proxy_context.check_hostname)
                trusted_proxy_context = ssl.create_default_context(cadata=cert_path.read_text())
                with urllib3.ProxyManager(
                    proxy_url,
                    proxy_ssl_context=trusted_proxy_context,
                    ssl_context=ssl.create_default_context(),
                    assert_hostname="target.invalid",
                    use_forwarding_for_https=True,
                ) as pool:
                    self.assertEqual(
                        pool.request("GET", "https://target.invalid/", retries=False, timeout=2).data, b"ok"
                    )


if __name__ == "__main__":
    unittest.main()
