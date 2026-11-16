"""Real socket controls for output that begins after the client's stdin EOF."""

import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.blackbox.installed_docker_preflight import gateway_management


def provider_relay_command(root, monkeypatch):
    """Capture the maintained provider command before any Docker operation."""
    (root / "docker-caller").mkdir()
    provider = root / "provider"
    provider.mkdir()
    (provider / "docker-gateway-client").touch()
    (root / "services").mkdir()
    (root / "services/notes.yaml").write_text("retained service\n")
    (root / "policy.toml").write_text('[hosts."notes.safeyolo.internal"]\nservice = "notes"\n'
                                      + f'[agents.notes]\nfolder = "{provider}"\n')
    output = root / "output"
    output.mkdir()
    monkeypatch.setattr("tests.blackbox.installed_docker_preflight.running_guest", lambda *_: {})
    commands = []

    def background(_agent, command, label):
        if label == "gateway-port":
            commands.append(command)
            raise RuntimeError("provider command captured")
        return (SimpleNamespace(poll=lambda: None),)

    with pytest.raises(RuntimeError, match="provider command captured"):
        gateway_management(SimpleNamespace(docker_data="retained-data"), root, output,
                           lambda *_: '{"runtime_state":"stopped"}', lambda *_args, **_kwargs: "",
                           background, {})
    return commands[0]


@pytest.mark.skipif(shutil.which("socat") is None, reason="requires the installed socat transport")
@pytest.mark.parametrize("relay", ["caller", "provider"])
@pytest.mark.parametrize("payload", [b"exec-half-close\n", b""])
def test_proxy_relays_keep_delayed_output_after_stdin_eof(tmp_path, monkeypatch, relay, payload):
    """Use the actual shell commands; adapt only privileged paths and identity."""
    tools = tmp_path / "tools"
    tools.mkdir()
    socat = tools / "socat"
    socat.write_text(f"#!{sys.executable}\nimport os,sys\n"
                     "args=[arg.replace(',su=agent', '') for arg in sys.argv[1:]]\n"
                     f"os.execv({shutil.which('socat')!r}, ['socat', *args])\n")
    socat.chmod(0o700)
    sudo = tools / "sudo"
    sudo.write_text('#!/bin/sh\n[ "$1" = -n ] || exit 1\nshift\nexec "$@"\n')
    sudo.chmod(0o700)
    environment = os.environ | {"PATH": str(tools) + ":" + os.environ["PATH"], "BASH_ENV": ""}
    with socket.socket() as port_reservation:
        port_reservation.bind(("127.0.0.1", 0))
        port = port_reservation.getsockname()[1]
    # The temporary listener chooses a free port; retry only connection setup.
    # No data or uncertain operation is replayed.
    response_path = tmp_path / "response.sock"
    if relay == "caller":
        source = Path(__file__).resolve().parents[1] / "cli/src/safeyolo/guest-proxy-forwarder.sh"
        script = tmp_path / "forwarder.sh"
        script.write_text(source.read_text().replace("/run/sy-proxy-relay", str(tmp_path / "sy-proxy-relay")))
        command = ["sh", str(script), str(port), str(response_path)]
    else:
        provider = provider_relay_command(tmp_path, monkeypatch)
        provider = provider.replace("/home/agent/docker-gateway", str(tmp_path))
        provider = provider.replace("TCP4-LISTEN:2375,", f"TCP4-LISTEN:{port},")
        provider = provider.replace("/run/safeyolo-nested-docker/docker.sock", str(response_path))
        command = ["bash", "-c", provider]
    engine = socket.socket(socket.AF_UNIX)
    engine.bind(str(response_path))
    engine.listen()
    engine.settimeout(5)
    received = []
    errors = []
    output = b"output after stdin EOF\n"

    def respond():
        try:
            with engine.accept()[0] as peer:
                peer.settimeout(5)
                data = bytearray()
                while part := peer.recv(4096):
                    data.extend(part)
                received.append(bytes(data))
                # runc attachment can be silent after stdin EOF. This exceeds
                # socat's default 0.5-second reverse-direction idle wait.
                time.sleep(0.8)
                peer.sendall(output)
                peer.shutdown(socket.SHUT_WR)
        except Exception as error:
            errors.append(repr(error))

    server = threading.Thread(target=respond)
    server.start()
    child = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=5)
                break
            except ConnectionRefusedError:
                assert child.poll() is None, child.communicate()[1].decode()
                assert time.monotonic() < deadline, "relay never listened"
                time.sleep(0.01)
        with client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            reply = bytearray()
            while part := client.recv(4096):
                reply.extend(part)
        server.join(5)
        assert not server.is_alive() and not errors, errors
        assert received == [payload]
        assert bytes(reply) == output
    finally:
        # Each fork belongs to this test's process group, including after an
        # assertion or a relay-parent exit. Never signal unrelated relays.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass  # A failed command can exit before creating a relay child.
        child.communicate(timeout=5)
        engine.close()
        server.join(6)
