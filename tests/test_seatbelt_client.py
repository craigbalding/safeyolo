"""Client handoff and CONNECT transport, using disposable local test listeners."""

import importlib.util
import os
import socket
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
