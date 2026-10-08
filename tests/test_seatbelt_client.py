"""Client handoff and CONNECT transport, using disposable local test listeners."""

import hashlib
import os
import select
import socket
import socketserver
import ssl
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "contrib/macos-seatbelt-agent"
@pytest.fixture
def native_cli():
    selected = os.environ.get("SAFEYOLO_TEST_NATIVE_CLI") or os.environ.get("SAFEYOLO_NATIVE_CLI")
    if not selected:
        selected = str(Path(__file__).resolve().parents[1] / "proxy/target/debug/safeyolo")
    cli = Path(selected)
    if not cli.is_file():
        pytest.skip("requires a built native CLI, selected with SAFEYOLO_TEST_NATIVE_CLI")
    return cli


def _relay(cli, host, port, **overrides):
    return subprocess.run(
        [str(cli), "ssh-proxy", host, str(port)],
        input=overrides.pop("input", b""), capture_output=True, timeout=15,
        env={**os.environ, **overrides},
    )


class _ConnectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ConnectHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        source = self.request.makefile("rb")
        request = source.readline(4096)
        while source.readline(4096) not in (b"\r\n", b""):
            pass
        assert request.startswith(b"CONNECT 127.0.0.1:")
        if self.server.effect != "allow":
            status = b"403 Forbidden" if self.server.effect == "deny" else b"428 Precondition Required"
            self.request.sendall(
                b"HTTP/1.1 " + status + b"\r\nX-Blocked-By: network-guard\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            return

        target = request.split()[1].decode("ascii")
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=10) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            peers = [self.request, upstream]
            while peers:
                readable, _, _ = select.select(peers, (), (), 10)
                if not readable:
                    return
                for peer in readable:
                    data = peer.recv(65536)
                    if not data:
                        if peer is upstream:
                            return
                        upstream.shutdown(socket.SHUT_WR)
                        peers.remove(peer)
                        continue
                    (upstream if peer is self.request else self.request).sendall(data)


@contextmanager
def _connect_proxy(effect):
    server = _ConnectServer(("127.0.0.1", 0), _ConnectHandler)
    server.effect = effect
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("value", ["", "socks5://localhost:1080", "http://user:secret@localhost:8080"])
def test_requires_configured_http_proxy(monkeypatch, value, native_cli):
    monkeypatch.setenv("HTTPS_PROXY", value)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    result = _relay(native_cli, "mac.example", 22)
    assert result.returncode != 0 and result.stdout == b""


@pytest.mark.parametrize("effect,status", [("deny", "403"), ("prompt", "428")])
def test_connect_rejection_preserves_status_and_does_not_connect(monkeypatch, effect, status, native_cli):
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(0.2)
        with _connect_proxy(effect) as port:
            monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
            result = _relay(native_cli, "127.0.0.1", server.getsockname()[1])
            assert result.returncode != 0 and status.encode() in result.stderr
            assert b"network-guard" in result.stderr and result.stdout == b""
            if effect == "prompt":
                assert b"safeyolo approvals list" in result.stderr
            with pytest.raises(TimeoutError):
                server.accept()


def test_ssh_bytes_through_connect_proxy_without_tcp_override(monkeypatch, native_cli):
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
        with _connect_proxy("allow") as port:
            monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
            result = _relay(native_cli, "127.0.0.1", server.getsockname()[1], input=payload)
            assert result.returncode == 0, result.stderr
            actual = result.stdout
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert actual == reply
    assert received == payload


def test_client_config_pins_operator_key_and_preserves_global_config(tmp_path, native_cli):
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
        [str(SOURCE / "configure-client")],
        input=f"mac.example\n2222\n{host_key}\n", text=True, capture_output=True,
        env={**os.environ, "HOME": str(tmp_path), "SAFEYOLO_CLI": str(native_cli)},
    )
    assert result.returncode == 0, result.stderr
    config = ssh_dir / "seatbelt-agent/config"
    effective = subprocess.check_output(["ssh", "-G", "-F", str(config), "seatbelt-mac"], text=True)
    assert "hostname mac.example\n" in effective
    assert "port 2222\n" in effective
    assert "stricthostkeychecking true\n" in effective
    assert "hostkeyalias seatbelt-mac\n" in effective
    assert "ssh-proxy %h %p" in effective
    assert str(native_cli) in effective
    assert "python" not in effective
    assert (config.parent / "known_hosts").read_text() == f"seatbelt-mac {host_key}\n"
    assert config.stat().st_mode & 0o777 == 0o600
    assert identity.read_bytes() == original_key
    assert (ssh_dir / "config").read_text() == "Host personal\n    HostName untouched.example\n"


@pytest.mark.parametrize("trusted,obsolete", [(True, False), (False, False), (True, True)])
@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1_1 is deprecated:DeprecationWarning")
def test_https_proxy_verifies_trust_and_rejects_obsolete_tls(tmp_path, monkeypatch, trusted, obsolete, native_cli):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE"],
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
        result = _relay(native_cli, "mac.example", 22)
        if trusted and not obsolete:
            assert result.returncode == 0, result.stderr
            assert result.stdout == b"SSH-2.0-fixture\r\n"
        else:
            assert result.returncode != 0 and result.stdout == b""
        thread.join(timeout=6)
        assert not thread.is_alive()
    if trusted and not obsolete:
        assert received.startswith(b"CONNECT mac.example:22 HTTP/1.1\r\n")
        assert not errors
    else:
        assert not received and errors


@pytest.mark.parametrize("entry", ["host", "staged-guest"])
@pytest.mark.parametrize("effect", ["allow", "deny"])
def test_generated_proxycommand_executes_the_native_route(tmp_path, monkeypatch, native_cli, entry, effect):
    """Observe OpenSSH calling the configured native helper, including guest staging."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    identity = ssh_dir / "id_ed25519_sy_agent"
    host_key = tmp_path / "host-key"
    for path in (identity, host_key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
    selected = native_cli
    if entry == "staged-guest":
        coord = native_cli.with_name("safeyolo-coord")
        if not coord.is_file():
            pytest.skip("requires the matching native safeyolo-coord artifact")
        artifact = tmp_path / "safeyolo-coord"
        os.link(coord, artifact)
        artifact.with_suffix(".version").write_bytes(subprocess.check_output([str(coord), "--version"]))
        with artifact.open("rb") as stream:
            artifact.with_suffix(".sha256").write_text(hashlib.file_digest(stream, "sha256").hexdigest())
        subprocess.run([str(coord), "stage-runtime", str(home), str(artifact)], check=True, capture_output=True)
        selected = home / ".safeyolo/safeyolo-coord"
    # A hidden Python transport/configuration fallback records its use and fails.
    shims = tmp_path / "shims"
    shims.mkdir()
    marker = tmp_path / "python-fallback"
    for name in ("python", "python3", "uv"):
        shim = shims / name
        shim.write_text(f"#!/bin/sh\nprintf fallback > '{marker}'\nexit 97\n")
        shim.chmod(0o755)
    env = {**os.environ, "HOME": str(home), "PATH": f"{shims}:{os.environ['PATH']}"}
    env.pop("SAFEYOLO_CLI", None)
    # Select the same guest-staged entry explicitly: ambient host installs must
    # not take precedence in a test of that guest's actual owned artifact.
    env["SAFEYOLO_SSH_PROXY_EXECUTABLE"] = str(selected)
    seen = bytearray()
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.3 if effect == "deny" else 5)
        result = subprocess.run([str(SOURCE / "configure-client")],
                                input=f"127.0.0.1\n{origin.getsockname()[1]}\n{host_key.with_suffix('.pub').read_text()}",
                                text=True, capture_output=True, env=env)
        assert result.returncode == 0, result.stderr
        worker = None
        if effect == "allow":
            def serve():
                with origin.accept()[0] as peer:
                    peer.settimeout(5)
                    peer.sendall(b"SSH-2.0-owned-fixture\r\n")
                    seen.extend(peer.recv(4096))
            worker = threading.Thread(target=serve)
            worker.start()
        with _connect_proxy(effect) as port:
            result = subprocess.run(["ssh", "-v", "-F", str(ssh_dir / "seatbelt-agent/config"),
                                     "-o", "ConnectTimeout=5", "seatbelt-mac", "id"],
                                    capture_output=True, timeout=10,
                                    env={**env, "HTTPS_PROXY": f"http://127.0.0.1:{port}"})
        # The fixture stops before key exchange; this is a transport witness,
        # not authentication or physical-host acceptance.
        assert result.returncode != 0
        if effect == "allow":
            worker.join(timeout=6)
            assert not worker.is_alive()
            assert seen.startswith(b"SSH-2.0-")
            assert b"Remote protocol version 2.0" in result.stderr
        else:
            assert b"403" in result.stderr and b"network-guard" in result.stderr
            with pytest.raises(TimeoutError):
                origin.accept()
        assert not marker.exists()
    if entry == "staged-guest":
        selected.unlink()  # Its owned invocation completed; avoid retaining test copies.
