"""Exercise shipped forwarder admission with real socat and a local UDS upstream.

The test adapter replaces AF_VSOCK with AF_UNIX and omits the guest-only
privilege drop. Actual VZ allocation and guest identity need native acceptance.
"""

import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("socat") is None, reason="real socat is required")
@pytest.mark.parametrize("transport", ["vsock", "uds"])
def test_forwarder_admission_and_slot_reuse(tmp_path, transport):
    upstream_path = tmp_path / "upstream.sock"
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.bind(str(upstream_path))
    upstream.listen(256)
    upstream.settimeout(3)
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]

    # Keep production listen options. Adapt only the unavailable transport
    # and the root-at-start privilege drop; use the real socat executable.
    adapter = tmp_path / "socat"
    adapter.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "args = [arg.replace(',su=agent', '') for arg in sys.argv[1:]]\n"
        "if args[1].startswith('VSOCK-CONNECT:'):\n"
        "    args[1] = 'UNIX-CONNECT:' + os.environ['SOCAT_TEST_UPSTREAM']\n"
        f"os.execv({shutil.which('socat')!r}, ['socat', *args])\n"
    )
    adapter.chmod(0o755)
    script = Path(__file__).parents[1] / "src/safeyolo/guest-proxy-forwarder.sh"
    environment = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}", SOCAT_TEST_UPSTREAM=str(upstream_path))
    selected_path = upstream_path if transport == "uds" else tmp_path / "absent.sock"
    clients = []
    peers = []
    with (tmp_path / "forwarder.log").open("w") as log:
        process = subprocess.Popen(
            ["sh", str(script), str(port), str(selected_path)],
            env=environment, stdout=log, stderr=log, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 3
            while True:
                try:
                    first = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except ConnectionRefusedError:
                    assert process.poll() is None, "forwarder exited before readiness"
                    assert time.monotonic() < deadline, "forwarder did not become ready"
                    time.sleep(0.01)
            clients.append(first)
            peers.append(upstream.accept()[0])
            for _ in range(231):
                clients.append(socket.create_connection(("127.0.0.1", port), timeout=3))
                peers.append(upstream.accept()[0])
            extra = socket.create_connection(("127.0.0.1", port), timeout=3)
            clients.append(extra)
            extra.sendall(b"queued")
            if transport == "vsock":
                assert not select.select([upstream], [], [], 0.2)[0], "excess connection reached upstream"
                peers[1].sendall(b"alive")
                assert clients[1].recv(5) == b"alive", "existing flow stopped progressing"
                clients[0].close()
                peers[0].close()
            # UDS admits connection 233 immediately; VZ admits it after release.
            admitted = upstream.accept()[0]
            admitted.settimeout(3)
            peers.append(admitted)
            assert admitted.recv(6) == b"queued"
            assert process.poll() is None
        finally:
            for peer in clients + peers:
                peer.close()
            upstream.close()
            # This process group belongs exclusively to this test invocation.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                # All members already exited, so no child needs termination.
                pass
            process.wait(timeout=3)
