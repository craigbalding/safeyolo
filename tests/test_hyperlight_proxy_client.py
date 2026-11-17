"""Real HTTP/TLS over fragmented proxy bytes; CPU proof, not hypervisor proof."""

import base64
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[1]


def certificates(directory, *, host="example.test", expired=False):
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable test root")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=30)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=-1 if expired else 2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    certificate, private = directory / "leaf.pem", directory / "leaf.key"
    certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    with private.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(leaf_key.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private)
    return ca.public_bytes(serialization.Encoding.PEM).decode(), context


def head(stream):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        part = stream.recv(1)
        if not part:
            raise EOFError("request headers incomplete")
        data.extend(part)
        if len(data) > 65536:
            raise ValueError("test request headers exceed limit")
    return bytes(data)


class ProxyBytes:
    def __init__(self, ca, context, *, https, deny=False):
        self.ca, self.context, self.https, self.deny = ca, context, https, deny
        self.streams, self.threads, self.calls, self.requests, self.errors = {}, [], [], [], []
        self.next_id = 0

    def origin(self, stream):
        with stream:
            try:
                if self.https:
                    connect = head(stream)
                    assert connect.startswith(b"CONNECT example.test:443 HTTP/1.1\r\n")
                    if self.deny:
                        stream.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                        return
                    stream.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    with self.context.wrap_socket(stream, server_side=True) as tls:
                        self.respond(tls)
                else:
                    self.respond(stream)
            except (OSError, EOFError, ssl.SSLError) as error:
                self.errors.append(str(error))

    def respond(self, stream):
        self.requests.append(head(stream))
        status = b"403 Forbidden" if self.deny else b"200 OK"
        stream.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 2\r\n\r\nOK")

    def call(self, value):
        self.calls.append(value["kind"])
        kind = value["kind"]
        if kind == "proxy_config":
            return {"ca_pem": self.ca}
        if kind == "gateway_token":
            assert value["service"] == "example"
            return {"token": "sgw_test_scoped"}
        if kind == "time":
            return {"unix_seconds": int(datetime.now(UTC).timestamp())}
        if kind == "proxy_open":
            self.next_id += 1
            stream, peer = socket.socketpair()
            stream.settimeout(5)
            peer.settimeout(5)
            self.streams[self.next_id] = stream
            thread = threading.Thread(target=self.origin, args=(peer,))
            self.threads.append(thread)
            thread.start()
            return {"id": self.next_id}
        if kind == "proxy_close":
            self.streams.pop(value["id"]).close()
            return {}
        stream = self.streams[value["id"]]
        if kind == "proxy_write":
            data = base64.b64decode(value["data_base64"], validate=True)
            assert 0 < len(data) <= 16384
            return {"written": stream.send(data[:173])}
        if kind == "proxy_read":
            assert 0 < value["length"] <= 16384
            return {"data_base64": base64.b64encode(stream.recv(min(337, value["length"]))).decode()}
        raise AssertionError(value)

    def reply(self, value):
        try:
            return {"ok": True, "value": self.call(value)}
        except OSError as error:
            return {"ok": False, "error": str(error)}

    def close(self):
        for stream in self.streams.values():
            stream.close()
        self.streams.clear()
        for thread in self.threads:
            thread.join(6)
            assert not thread.is_alive()


def run_client(client, bridge, directory, monkeypatch, *, https, service, expected="200"):
    url = ("https" if https else "http") + "://example.test/value?x=1"
    inputs = {"expected_status": expected}
    if service:
        inputs["service"] = "example"
    request_value = {"subject": {"kind": "value", "value": url}, "inputs": inputs}
    if client == "python":
        spec = importlib.util.spec_from_file_location("safeyolo_proxy_test", REPO / "jobs/proxy_client.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert bridge.calls == []
        monkeypatch.setitem(sys.modules, "hyperlight", SimpleNamespace(call=lambda name, value: bridge.reply(value)))
        monkeypatch.setitem(sys.modules, "safeyolo_proxy", module)
        checker_spec = importlib.util.spec_from_file_location("network_checker_test", REPO / "jobs/network_checker.py")
        checker = importlib.util.module_from_spec(checker_spec)
        checker_spec.loader.exec_module(checker)
        try:
            return {"Ok": checker.check(request_value)}
        except (OSError, ValueError) as error:
            return {"Err": str(error)}
    executable = os.environ.get("SAFEYOLO_CORE_PROXY_CLIENT")
    if not executable:
        pytest.skip("set SAFEYOLO_CORE_PROXY_CLIENT to the built CPU client example")
    request = directory / "request.json"
    request.write_text(json.dumps(request_value))
    with subprocess.Popen([executable, str(request)], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
        result = None
        try:
            for line in child.stdout:
                message = json.loads(line)
                if "result" in message:
                    result = message["result"]
                    break
                child.stdin.write(json.dumps(bridge.reply(message["call"])) + "\n")
                child.stdin.flush()
            child.wait(timeout=10)
            assert child.returncode == 0, child.stderr.read()
            assert result is not None
            return result
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


@pytest.mark.parametrize("client", ["python", "core"])
@pytest.mark.parametrize("https", [False, True])
@pytest.mark.parametrize("service", [False, True])
def test_maintained_clients_use_fragmented_proxy_streams(tmp_path, monkeypatch, client, https, service):
    ca, context = certificates(tmp_path)
    bridge = ProxyBytes(ca, context, https=https)
    try:
        result = run_client(client, bridge, tmp_path, monkeypatch, https=https, service=service)
        assert result["Ok"]["finding"]["positive"] is True, result
        assert bridge.streams == {}
        assert len(bridge.requests) == 1
        request = bridge.requests[0]
        target = b"/value?x=1" if https else b"http://example.test/value?x=1"
        assert request.startswith(b"GET " + target + b" HTTP/1.1\r\n")
        assert (b"Authorization: Bearer sgw_test_scoped" in request) == service
    finally:
        bridge.close()


@pytest.mark.parametrize("client", ["python", "core"])
@pytest.mark.parametrize("failure", ["expired", "hostname", "untrusted", "connect_denied"])
def test_tls_refusal_precedes_application_request(tmp_path, monkeypatch, client, failure):
    ca, context = certificates(tmp_path, host="other.test" if failure == "hostname" else "example.test",
                               expired=failure == "expired")
    if failure == "untrusted":
        other = tmp_path / "other"
        other.mkdir()
        ca, _ = certificates(other)
    bridge = ProxyBytes(ca, context, https=True, deny=failure == "connect_denied")
    try:
        result = run_client(client, bridge, tmp_path, monkeypatch, https=True, service=False)
        assert "Err" in result, result
        assert bridge.requests == []
        assert bridge.streams == {}
    finally:
        bridge.close()


@pytest.mark.parametrize("client", ["python", "core"])
@pytest.mark.parametrize("expected", ["201", "not-a-status"])
def test_adopted_status_input_controls_finding_and_invalid_input_never_contacts_origin(tmp_path, monkeypatch, client, expected):
    ca, context = certificates(tmp_path)
    bridge = ProxyBytes(ca, context, https=False)
    try:
        result = run_client(client, bridge, tmp_path, monkeypatch, https=False, service=False, expected=expected)
        if expected == "201":
            assert result["Ok"]["finding"]["positive"] is False, result
            assert len(bridge.requests) == 1
        else:
            assert "Err" in result
            assert not bridge.requests
            assert not bridge.calls
    finally:
        bridge.close()
