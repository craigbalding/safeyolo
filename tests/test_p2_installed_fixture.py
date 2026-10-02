"""Focused controls for the finite installed guest P2 fixture."""

from __future__ import annotations

import hashlib
import http.client
import queue
import shlex
import shutil
import ssl
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import pytest

BLACKBOX_DIR = Path(__file__).parent / "blackbox"
SINKHOLE_DIR = BLACKBOX_DIR / "sinkhole"
HARNESS_DIR = BLACKBOX_DIR / "harness"
sys.path.insert(0, str(BLACKBOX_DIR))
sys.path.insert(0, str(SINKHOLE_DIR))
sys.path.insert(0, str(HARNESS_DIR))

import sinkhole_parent  # noqa: E402
from p2_fixture import P2Fixture  # noqa: E402
from server import SinkholeHandler, SSLSafeThreadingHTTPServer, clear_requests, get_requests  # noqa: E402
from sinkhole_parent import Parent  # noqa: E402

from tests.blackbox import installed_workloads  # noqa: E402
from tests.blackbox.installed_workloads import owned_ssh, prepare_package, prepare_repository  # noqa: E402
from tests.blackbox.isolation import installed_workloads as guest  # noqa: E402


@pytest.fixture
def p2_origin(tmp_path, monkeypatch):
    fixture = P2Fixture(tmp_path)
    server = SSLSafeThreadingHTTPServer(("127.0.0.1", 0), SinkholeHandler)
    server.p2_fixture = fixture
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    clear_requests()
    monkeypatch.setattr(sinkhole_parent, "SINKHOLE_HTTP_PORT", server.server_address[1])
    try:
        with Parent(None, None) as parent:
            parent_thread = threading.Thread(target=parent.serve_forever)
            parent_thread.start()
            monkeypatch.setattr(guest, "PROXY", ("127.0.0.1", parent.server_address[1]))
            try:
                yield fixture, tmp_path
            finally:
                parent.shutdown()
                parent_thread.join(timeout=3)
                assert not parent_thread.is_alive()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        clear_requests()


def test_owned_package_repository_and_websocket_reach_the_origin(p2_origin, tmp_path):
    fixture, directory = p2_origin
    marker = "p2-" + uuid.uuid4().hex
    package_sha = prepare_package(directory, marker)
    commit = prepare_repository(directory, marker)

    connection = http.client.HTTPConnection(*guest.PROXY, timeout=5)
    try:
        connection.request("GET", f"http://{guest.HOST}/p2/package/{guest.PACKAGE}.deb",
                           headers={"Host": guest.HOST})
        response = connection.getresponse()
        package = response.read()
        assert response.status == 200
    finally:
        connection.close()
    assert hashlib.sha256(package).hexdigest() == package_sha
    checkout = tmp_path / "clone"
    cloned = subprocess.run([
        "git", "-c", f"http.proxy=http://127.0.0.1:{guest.PROXY[1]}",
        "-c", "protocol.version=0", "clone", f"http://{guest.HOST}/p2/repo.git", str(checkout),
    ], capture_output=True, text=True, timeout=20, check=False)
    assert cloned.returncode == 0, cloned.stderr
    assert subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                                   text=True).strip() == commit
    assert (checkout / "P2-MARKER.txt").read_text() == f"repository:{marker}\n"
    head = (directory / "repo.git/HEAD").read_bytes()
    connection = http.client.HTTPConnection(*guest.PROXY, timeout=5)
    try:
        connection.request("PUT", f"http://{guest.HOST}/p2/repo.git/HEAD", body=b"different\n",
                           headers={"Host": guest.HOST})
        response = connection.getresponse()
        response.read()
        assert response.status == 405
    finally:
        connection.close()
    assert (directory / "repo.git/HEAD").read_bytes() == head

    result = guest.websocket(marker, "bbtest", tls=False)
    assert result == {"scheme": "ws", "client": f"client:{marker}", "server": f"server:{marker}"}
    assert fixture.state(marker)["websockets"] == [
        {"marker": marker, "tls": False, "client": f"client:{marker}", "status": "complete"}
    ]
    paths = [request.path for request in get_requests() if request.host == guest.HOST]
    assert f"/p2/package/{guest.PACKAGE}.deb" in paths
    assert "/p2/repo.git/info/refs" in paths
    assert any(path.startswith("/p2/repo.git/objects/") for path in paths)
    assert paths.count(f"/p2/ws/{marker}") == 1


def test_guest_receives_first_sse_event_before_release(p2_origin, monkeypatch):
    fixture, _ = p2_origin
    marker = "p2-" + uuid.uuid4().hex
    printed = queue.Queue()
    results = queue.Queue()
    monkeypatch.setattr(guest, "print", lambda text, **_options: printed.put(text), raising=False)

    def receive():
        try:
            results.put(guest.sse(marker, "bbtest"))
        except Exception as error:
            results.put(error)

    thread = threading.Thread(target=receive)
    thread.start()
    try:
        first = printed.get(timeout=5)
        assert first.startswith("P2_SSE_FIRST=")
        assert fixture.state(marker) == {"first_sent": True, "released": False,
                                         "finished": False, "websockets": []}
        assert fixture.release(marker)
        result = results.get(timeout=5)
        if isinstance(result, Exception):
            raise result
        assert result == {"first": f"data: first:{marker}\n\n",
                          "last": f"data: last:{marker}\n\n"}
        assert fixture.state(marker)["finished"]
    finally:
        fixture.release(marker)
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_wss_reaches_the_owned_tls_peer_through_connect(tmp_path, monkeypatch):
    marker = "p2-" + uuid.uuid4().hex
    certificate = tmp_path / "origin.crt"
    key = tmp_path / "origin.key"
    created = subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(key), "-out", str(certificate), "-subj", f"/CN={guest.HOST}",
        "-addext", f"subjectAltName=DNS:{guest.HOST}",
    ], capture_output=True, text=True, timeout=10, check=False)
    assert created.returncode == 0, created.stderr
    fixture = P2Fixture(tmp_path)
    origin = SSLSafeThreadingHTTPServer(("127.0.0.1", 0), SinkholeHandler)
    origin.p2_fixture = fixture
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(certificate), str(key))
    origin.socket = tls.wrap_socket(origin.socket, server_side=True)
    monkeypatch.setattr(sinkhole_parent, "SINKHOLE_HTTPS_PORT", origin.server_address[1])
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    origin_thread = threading.Thread(target=origin.serve_forever)
    origin_thread.start()
    try:
        with Parent(None, None) as parent:
            parent_thread = threading.Thread(target=parent.serve_forever)
            parent_thread.start()
            try:
                monkeypatch.setattr(guest, "PROXY", ("127.0.0.1", parent.server_address[1]))
                assert guest.websocket(marker, "bbtest", tls=True) == {
                    "scheme": "wss", "client": f"client:{marker}", "server": f"server:{marker}",
                }
                assert fixture.state(marker)["websockets"] == [
                    {"marker": marker, "tls": True, "client": f"client:{marker}",
                     "status": "complete"},
                ]
            finally:
                parent.shutdown()
                parent_thread.join(timeout=3)
                assert not parent_thread.is_alive()
    finally:
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=3)
        assert not origin_thread.is_alive()


@pytest.mark.skipif(not (shutil.which("sshd") or Path("/usr/sbin/sshd").is_file()),
                    reason="owned SSH fixture requires openssh-server")
def test_disposable_ssh_command_uses_the_selected_connect_peer(tmp_path):
    marker = "p2-" + uuid.uuid4().hex
    share = tmp_path / "config/agents/bbtest/config-share"
    share.mkdir(parents=True)
    with owned_ssh(tmp_path, tmp_path / "config", "bbtest", marker) as (username, observed):
        with Parent(None, None, tmp_path / "ssh.port") as parent:
            thread = threading.Thread(target=parent.serve_forever)
            thread.start()
            try:
                bridge = shlex.join([
                    sys.executable, "-m", "tests.proxy_contracts.ssh_bridge",
                    str(parent.server_address[1]), f"{guest.HOST}:22", "--tcp-proxy",
                ])
                ssh_args = [
                    "ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
                    "-o", "IdentitiesOnly=yes", "-o", f"UserKnownHostsFile={share / 'p2-known-hosts'}",
                    "-o", "StrictHostKeyChecking=yes", "-o", f"ProxyCommand={bridge}",
                    "-i", str(tmp_path / "ssh/client"), f"{username}@{guest.HOST}",
                ]
                result = subprocess.run([*ssh_args, f"p2-marker {marker}"], capture_output=True,
                                        text=True, timeout=15, check=False)
                assert result.returncode == 0, result.stderr
                assert result.stdout == f"ssh-server:{marker}"
                assert observed.read_text() == marker
                refused = subprocess.run([*ssh_args, "id"], capture_output=True, text=True,
                                         timeout=15, check=False)
                assert refused.returncode != 0
                assert refused.stdout == ""
                assert observed.read_text() == marker
            finally:
                parent.shutdown()
                thread.join(timeout=3)
                assert not thread.is_alive()
    assert not (share / "p2-client-key").exists()
    assert not (share / "p2-known-hosts").exists()
    assert not (tmp_path / "ssh/host").exists()
    assert not (tmp_path / "ssh/host.pub").exists()
    assert not (tmp_path / "ssh/client").exists()
    assert not (tmp_path / "ssh/client.pub").exists()
    assert not (tmp_path / "ssh/marker-command").exists()


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="fixture requires ssh-keygen")
def test_ssh_start_failure_removes_disposable_private_keys(tmp_path, monkeypatch):
    marker = "p2-" + uuid.uuid4().hex
    share = tmp_path / "config/agents/bbtest/config-share"
    share.mkdir(parents=True)
    fake = tmp_path / "failed-sshd"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    original_which = shutil.which
    monkeypatch.setattr(installed_workloads.shutil, "which",
                        lambda name: str(fake) if name == "sshd" else original_which(name))
    with pytest.raises(AssertionError):
        with owned_ssh(tmp_path, tmp_path / "config", "bbtest", marker):
            pytest.fail("failed SSH daemon cannot yield a ready fixture")
    assert not (share / "p2-client-key").exists()
    assert not (share / "p2-known-hosts").exists()
    assert not (tmp_path / "ssh/host").exists()
    assert not (tmp_path / "ssh/host.pub").exists()
    assert not (tmp_path / "ssh/client").exists()
    assert not (tmp_path / "ssh/client.pub").exists()
    assert not (tmp_path / "ssh/marker-command").exists()
