"""Run with the frozen acceptance-tools Python, separately from the CLI suite."""

import asyncio
import base64
import hmac
import ipaddress
import json
import os
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import certifi
import jwt
import msgpack
import requests
import urllib3
from cachecontrol import CacheControl
from cachecontrol.caches import FileCache
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from filelock import FileLock, Timeout


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

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.do_GET()

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


class BundledRootCertificates(unittest.TestCase):
    def test_certifi_removes_compromised_emsign_root(self):
        certificates = ssl.create_default_context(cafile=certifi.where()).get_ca_certs()
        common_names = {
            value
            for certificate in certificates
            for name_parts in certificate["subject"]
            for name, value in name_parts
            if name == "commonName"
        }
        # PYSEC-2026-4320: compromised intermediate keys chain to this root.
        self.assertNotIn("emSign ECC Root CA - G3", common_names)
        self.assertIn("DigiCert Global Root G2", common_names)


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


class OpenTelemetryDependencies(unittest.TestCase):
    def test_propagation_preserves_valid_context_and_bounds_combined_headers(self):
        from opentelemetry import propagate, trace

        parent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

        def extract(state):
            return trace.get_current_span(propagate.extract({"traceparent": parent, "tracestate": state})).get_span_context()

        valid = extract(["vendor=value, other=second"])
        self.assertTrue(valid.is_remote)
        self.assertEqual(valid.trace_id, int(parent.split("-")[1], 16))
        self.assertEqual(valid.span_id, int(parent.split("-")[2], 16))
        self.assertEqual(dict(valid.trace_state), {"vendor": "value", "other": "second"})
        for state in (["vendor=first", "vendor=second"], ["bad key=value"]):
            with self.subTest(state=state):
                self.assertEqual(len(extract(state).trace_state), 0)

        # The upstream fix counts comma separators between header fields.
        headers = [f"k{index}=" + "v" * 250 for index in range(32)]
        headers[-1] += " " * (8192 - sum(map(len, headers)) - len(headers) + 1)
        self.assertEqual(len(extract(headers).trace_state), 32)
        headers[-1] += " "
        self.assertEqual(len(extract(headers).trace_state), 0)

    def test_whitespace_attack_finishes_without_quadratic_parsing(self):
        # A subprocess deadline also bounds a regression to the vulnerable parser.
        probe = """
import logging
from opentelemetry import propagate, trace
from opentelemetry.trace import TraceState

logging.disable(logging.CRITICAL)
parent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
for whitespace in (" ", "\\t"):
    state = "vendor=value" + whitespace * 200_000 + "x"
    assert len(TraceState.from_header([state])) == 0
    context = propagate.extract({"traceparent": parent, "tracestate": state})
    span = trace.get_current_span(context).get_span_context()
    assert span.is_valid and len(span.trace_state) == 0
"""
        run = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_semgrep_tracing_exports_and_preserves_parent_across_threads(self):
        # Semgrep configures global providers and instrumentation. Isolate them.
        probe = """
import logging
import os
import sys
import threading
import requests
from opentelemetry import trace
from opentelemetry._logs import get_logger_provider
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.threading import ThreadingInstrumentor
from semgrep.telemetry import Telemetry, TRACER

parent = "0af7651916cd43dd8448eb211c80319c"
os.environ["SEMGREP_TRACE_PARENT_TRACE_ID"] = parent
os.environ["SEMGREP_TRACE_PARENT_SPAN_ID"] = "b7ad6b7169203331"
Telemetry().configure(True, sys.argv[1])
assert RequestsInstrumentor().is_instrumented_by_opentelemetry
assert ThreadingInstrumentor().is_instrumented_by_opentelemetry
observed = []
with TRACER.start_as_current_span("dependency-control"):
    thread = threading.Thread(target=lambda: observed.append(trace.get_current_span().get_span_context().trace_id))
    thread.start()
    thread.join(timeout=2)
    assert observed == [int(parent, 16)]
    response = requests.get(sys.argv[1] + "/input", timeout=2)
    assert response.status_code == 200
    logging.getLogger("semgrep.telemetry").warning("dependency-control")
assert trace.get_tracer_provider().force_flush(timeout_millis=2000)
assert get_logger_provider().force_flush(timeout_millis=2000)
trace.get_tracer_provider().shutdown()
get_logger_provider().shutdown()
"""
        with http_responses({"/": (200, {}, b"")}) as (url, paths):
            run = subprocess.run([sys.executable, "-I", "-c", probe, url], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue({"/input", "/v1/traces", "/v1/logs"} <= set(paths), paths)


class CacheDependencies(unittest.TestCase):
    def test_pip_audit_cache_round_trip_survives_new_session(self):
        from pip_audit._service import PyPIService

        body = b'{"vulnerabilities": []}'
        responses = {"/": (200, {"Cache-Control": "public, max-age=3600"}, body)}
        with tempfile.TemporaryDirectory() as temporary, http_responses(responses) as (url, paths):
            # pip-audit overrides FileCache writes to avoid lock files.
            for expected_cached in (False, True):
                with PyPIService(cache_dir=Path(temporary)).session as session:
                    session.trust_env = False
                    with session.get(url + "/", timeout=5) as response:
                        self.assertEqual(response.content, body)
                        self.assertEqual(response.from_cache, expected_cached)
            self.assertEqual(paths, ["/"])

    @unittest.skipUnless(os.name == "posix", "Unix lock replacement control")
    def test_file_cache_preserves_renamed_and_hard_linked_lock_targets(self):
        # GHSA-69hj-f68j-2879: a regular file at the lock path is not a symlink.
        for replacement in ("rename", "hardlink"):
            for mode in (None, 0o666):
                with self.subTest(replacement=replacement, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    cache = FileCache(root / "cache")
                    if mode is not None:
                        cache.lock_class = partial(FileLock, mode=mode)
                    key = "https://cache.invalid/dependency"
                    cache.set(key, b"before")
                    lock_path = Path(cache._fn(key) + ".lock")
                    lock_path.unlink(missing_ok=True)
                    victim = root / "private-journal"
                    victim.write_bytes(b"keep private contents")
                    victim.chmod(0o600)
                    with victim.open("rb") as retained:
                        before = os.fstat(retained.fileno())
                        if replacement == "rename":
                            victim.rename(lock_path)
                        else:
                            os.link(victim, lock_path)
                        cache.set(key, b"after")
                        after = os.fstat(retained.fileno())
                        self.assertEqual(retained.read(), b"keep private contents")
                        self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
                        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
                    self.assertEqual(cache.get(key), b"after")
                    self.assertEqual(stat.S_IMODE(Path(cache._fn(key)).stat().st_mode), 0o600)

    def test_file_cache_lock_contention_preserves_cached_value_and_recovers(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = FileCache(temporary, lock_class=partial(FileLock, timeout=0))
            key = "https://cache.invalid/dependency"
            cache.set(key, b"before")
            with FileLock(cache._fn(key) + ".lock", timeout=0):
                with self.assertRaises(Timeout):
                    cache.set(key, b"blocked")
                self.assertEqual(cache.get(key), b"before")
            cache.set(key, b"after")
            self.assertEqual(cache.get(key), b"after")

    @unittest.skipUnless(os.name == "posix", "Unix lock mode control")
    def test_new_lock_honors_explicit_private_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private.lock"
            with FileLock(path, mode=0o600):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_uid, os.getuid())

    def test_strict_map_key_failure_releases_decoded_value(self):
        self.assertEqual(msgpack.unpackb.__module__, "msgpack._cmsgpack")
        value = object()
        payload = msgpack.packb({42: {"nested": "value"}}, use_bin_type=True)
        references = sys.getrefcount(value)
        for _ in range(100):
            with self.assertRaises(ValueError):
                msgpack.unpackb(payload, raw=False, object_hook=lambda _mapping: value)
        # The rejected outer key must release the already decoded nested value.
        self.assertEqual(sys.getrefcount(value), references)

    def test_file_cache_round_trip_and_malformed_entries_refetch(self):
        body = msgpack.packb({42: b"network body"}, use_bin_type=True)
        responses = {"/": (200, {"Cache-Control": "public, max-age=3600"}, body)}
        with tempfile.TemporaryDirectory() as temporary, http_responses(responses) as (url, paths):
            cache = FileCache(temporary)
            with CacheControl(requests.Session(), cache=cache) as session:
                session.trust_env = False
                url += "/"
                for expected_cached in (False, True):
                    with session.get(url, timeout=5) as response:
                        self.assertEqual(response.content, body)
                        self.assertEqual(response.from_cache, expected_cached)
                self.assertEqual(paths, ["/"])
                saved = cache.get(url)
                self.assertTrue(saved.startswith(b"cc=4,"))
                self.assertEqual(msgpack.loads(saved[5:], raw=False)["response"]["body"], body)
                for damaged in (
                    b"cc=4," + body,  # The same map is invalid as a serialized cache entry.
                    saved[:-1],
                    b"cc=4,\xc1",
                    saved + b"\0",
                ):
                    with self.subTest(damaged=damaged[:24]):
                        cache.set(url, damaged)
                        with session.get(url, timeout=5) as response:
                            self.assertEqual(response.content, body)
                            self.assertFalse(response.from_cache)
                        refreshed = msgpack.loads(cache.get(url)[5:], raw=False)
                        self.assertEqual(refreshed["response"]["body"], body)
                self.assertEqual(paths, ["/"] * 5)


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
