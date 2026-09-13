"""Client handoff and CONNECT transport, using disposable local test listeners."""

import importlib.util
import os
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tests.test_connect_live import proxy

SOURCE = Path(__file__).resolve().parents[1] / "contrib/macos-seatbelt-agent"
spec = importlib.util.spec_from_file_location("ssh_via_proxy", SOURCE / "ssh-via-proxy.py")
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


@pytest.mark.parametrize("value", ["", "socks5://localhost:1080", "http://user:secret@localhost:8080"])
def test_requires_configured_http_proxy(monkeypatch, value):
    monkeypatch.setenv("HTTPS_PROXY", value)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    with pytest.raises(ValueError):
        transport.connect("mac.example", 22)


@pytest.mark.parametrize("effect,status", [("deny", "403"), ("prompt", "428")])
def test_policy_rejection_preserves_status_and_does_not_connect(tmp_path, monkeypatch, effect, status):
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(0.2)
        with proxy(tmp_path, effect) as port:
            monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
            with pytest.raises(OSError, match=status) as error:
                transport.connect("127.0.0.1", server.getsockname()[1])
            assert "network-guard" in str(error.value)
            if effect == "prompt":
                assert "safeyolo watch" in str(error.value)
            with pytest.raises(TimeoutError):
                server.accept()


def test_ssh_bytes_through_real_policy_proxy_without_tcp_override(tmp_path, monkeypatch):
    payload = b"SSH-2.0-test-client\r\n" + bytes(range(256)) * 1024
    reply = b"SSH-2.0-test-server\r\n" + payload
    received = bytearray()
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(10)

        def serve():
            with server.accept()[0] as stream:
                stream.settimeout(10)
                stream.sendall(reply[:21])
                while len(received) < len(payload):
                    chunk = stream.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                stream.sendall(reply[21:])

        thread = threading.Thread(target=serve)
        thread.start()
        with proxy(tmp_path, "allow", allowed_port=server.getsockname()[1]) as port:
            monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
            with transport.connect("127.0.0.1", server.getsockname()[1]) as stream:
                stream.settimeout(10)
                stream.sendall(payload)
                actual = bytearray()
                while chunk := stream.recv(65536):
                    actual.extend(chunk)
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert actual == reply
    assert received == payload


def test_client_config_pins_operator_key_and_preserves_global_config(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    identity = ssh_dir / "id_ed25519_sy_agent"
    host = tmp_path / "host-key"
    for path in (identity, host):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
    (ssh_dir / "config").write_text("Host personal\n    HostName untouched.example\n")
    original_key = identity.read_bytes()
    host_key = host.with_suffix(".pub").read_text().strip()
    result = subprocess.run(
        [sys.executable, str(SOURCE / "configure-client")],
        input=f"mac.example\n2222\n{host_key}\n", text=True, capture_output=True,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    config = ssh_dir / "seatbelt-agent/config"
    effective = subprocess.check_output(["ssh", "-G", "-F", str(config), "seatbelt-mac"], text=True)
    assert "hostname mac.example\n" in effective
    assert "port 2222\n" in effective
    assert "stricthostkeychecking true\n" in effective
    assert "hostkeyalias seatbelt-mac\n" in effective
    assert "ssh-via-proxy.py" in effective
    assert (config.parent / "known_hosts").read_text() == f"seatbelt-mac {host_key}\n"
    assert config.stat().st_mode & 0o777 == 0o600
    assert identity.read_bytes() == original_key
    assert (ssh_dir / "config").read_text() == "Host personal\n    HostName untouched.example\n"


@pytest.mark.parametrize("trusted,obsolete", [(True, False), (False, False), (True, True)])
@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1_1 is deprecated:DeprecationWarning")
def test_https_proxy_verifies_trust_and_rejects_obsolete_tls(tmp_path, monkeypatch, trusted, obsolete):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if obsolete:
        # Deliberately weak test peer: the client must refuse its handshake.
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("ALL:@SECLEVEL=0")
    received = bytearray()
    errors = []
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(5)

        def serve():
            try:
                with server.accept()[0] as raw:
                    raw.settimeout(5)
                    with context.wrap_socket(raw, server_side=True) as stream:
                        while not received.endswith(b"\r\n\r\n"):
                            chunk = stream.recv(1)
                            if not chunk:
                                raise OSError("Client closed before completing CONNECT")
                            received.extend(chunk)
                        stream.sendall(b"HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-fixture\r\n")
            except OSError as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        monkeypatch.setenv("HTTPS_PROXY", f"https://localhost:{server.getsockname()[1]}")
        if trusted:
            monkeypatch.setenv("SSL_CERT_FILE", str(cert))
        if trusted and not obsolete:
            with transport.connect("mac.example", 22) as stream:
                assert stream.recv(100) == b"SSH-2.0-fixture\r\n"
        else:
            with pytest.raises(ssl.SSLError):
                transport.connect("mac.example", 22)
        thread.join(timeout=6)
        assert not thread.is_alive()
    if trusted and not obsolete:
        assert received.startswith(b"CONNECT mac.example:22 HTTP/1.1\r\n")
        assert not errors
    else:
        assert not received and errors
