"""Focused controls for the finite installed guest P2 fixture."""

from __future__ import annotations

import hashlib
import http.client
import io
import queue
import shlex
import shutil
import ssl
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec

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


@pytest.mark.parametrize("kind", ["sse", "http"])
def test_state_observation_waits_for_first_delivery_flush(p2_origin, monkeypatch, kind):
    """Pause after real delivery to expose the former flush-to-state gap."""
    fixture, _ = p2_origin
    marker = ("p2-" if kind == "sse" else "p4-") + uuid.uuid4().hex
    path = f"/p2/sse/{marker}" if kind == "sse" else f"/p4/hold/{marker}"
    state = fixture.state if kind == "sse" else fixture.p4_state
    release = fixture.release if kind == "sse" else fixture.release_p4
    flushed = threading.Event()
    resume = threading.Event()
    completed = threading.Event()
    attempts = queue.Queue()
    observations = queue.Queue()
    lock = fixture.lock

    class ObservedLock:
        def __enter__(self):
            if threading.current_thread() is observer:
                acquired = lock.acquire(blocking=False)
                attempts.put(acquired)
                if acquired:
                    return self
            lock.acquire()
            return self

        def __exit__(self, *_args):
            lock.release()

    def observe():
        observations.put(state(marker))

    observer = threading.Thread(target=observe)
    fixture.lock = ObservedLock()
    end_headers = SinkholeHandler.end_headers

    def pause_flush(handler):
        end_headers(handler)
        flush = handler.wfile.flush

        def first_flush():
            flush()
            handler.wfile.flush = flush
            flushed.set()
            assert resume.wait(5), "first-delivery flush was not resumed"

        handler.wfile.flush = first_flush

    handle = fixture.handle

    def finish(handler):
        try:
            return handle(handler)
        finally:
            completed.set()

    monkeypatch.setattr(SinkholeHandler, "end_headers", pause_flush)
    monkeypatch.setattr(fixture, "handle", finish)
    connection = http.client.HTTPConnection(*guest.PROXY, timeout=5)
    try:
        connection.request("GET", f"http://{guest.HOST}{path}", headers={"Host": guest.HOST})
        response = connection.getresponse()
        assert response.status == 200
        first = f"data: first:{marker}\n\n".encode() if kind == "sse" else f"first:{marker}\n".encode()
        assert response.read(len(first)) == first
        assert flushed.wait(5)
        observer.start()
        assert attempts.get(timeout=5) is False, "state read entered the post-flush publication gap"
        resume.set()
        before = observations.get(timeout=5)
        assert before["first_sent"] and not before["released"] and not before["finished"], before
        assert not completed.is_set()
        assert release(marker)
        last = f"data: last:{marker}\n\n".encode() if kind == "sse" else f"last:{marker}\n".encode()
        assert response.read() == last
        assert completed.wait(5)
        after = state(marker)
        assert after["first_sent"] and after["released"] and after["finished"], after
    finally:
        resume.set()
        release(marker)
        connection.close()
        if observer.ident is not None:
            observer.join(timeout=5)
            assert not observer.is_alive()


def _held_response_handler(path):
    handler = SinkholeHandler.__new__(SinkholeHandler)
    handler.path = path
    handler.wfile = io.BytesIO()
    control = create_autospec(handler, spec_set=True)
    control.path = path
    return control


@pytest.mark.parametrize("kind", ["sse", "http"])
@pytest.mark.parametrize("failed_operation", ["write", "flush"])
def test_failed_first_delivery_is_not_reported_as_sent(tmp_path, kind, failed_operation):
    fixture = P2Fixture(tmp_path)
    marker = ("p2-" if kind == "sse" else "p4-") + uuid.uuid4().hex
    path = f"/p2/sse/{marker}" if kind == "sse" else f"/p4/hold/{marker}"
    state = fixture.state if kind == "sse" else fixture.p4_state
    handler = _held_response_handler(path)
    getattr(handler.wfile, failed_operation).side_effect = BrokenPipeError("first delivery failed")

    with pytest.raises(BrokenPipeError, match="first delivery failed"):
        fixture.handle(handler)
    observed = state(marker)
    assert not observed["first_sent"] and not observed["released"] and observed["finished"], observed
    assert handler.wfile.write.call_count == 1
    assert handler.wfile.flush.call_count == (failed_operation == "flush")

    duplicate = _held_response_handler(path)
    assert fixture.handle(duplicate)
    duplicate.send_error.assert_called_once_with(409, "P2 stream marker already used" if kind == "sse"
                                                 else "P4 HTTP marker already used")
    duplicate.wfile.write.assert_not_called()
    assert state(marker) == observed


@pytest.mark.parametrize("kind", ["sse", "http"])
def test_held_fixture_refuses_invalid_marker_and_unknown_release(tmp_path, kind):
    fixture = P2Fixture(tmp_path)
    prefix = "/p2/sse/" if kind == "sse" else "/p4/hold/"
    release = fixture.release if kind == "sse" else fixture.release_p4
    handler = _held_response_handler(prefix + "invalid")
    assert fixture.handle(handler)
    handler.send_error.assert_called_once_with(400, "Invalid P2 marker" if kind == "sse" else "Invalid P4 marker")
    handler.wfile.write.assert_not_called()
    assert not fixture.streams and not fixture.held_http
    assert not release("invalid")
    assert not release(("p2-" if kind == "sse" else "p4-") + uuid.uuid4().hex)


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


@pytest.mark.parametrize("corruption", [None, "plain-ws", "unfinished", "extra-delivery", "blocked-origin"])
def test_workload_report_requires_one_completed_tls_exchange_and_no_denied_delivery(
    tmp_path, monkeypatch, corruption,
):
    marker = "p2-" + uuid.uuid4().hex
    paths = [f"/p2/package/{guest.PACKAGE}.deb", "/p2/repo.git/info/refs",
             "/p2/repo.git/objects/fixture", f"/p2/sse/{marker}", f"/p2/ws/{marker}"]
    states = [{"tls": True, "status": "complete", "client": f"client:{marker}"}]
    if corruption == "plain-ws":
        states[0]["tls"] = False
    elif corruption == "unfinished":
        states[0]["status"] = "open"
    elif corruption == "extra-delivery":
        paths.append(f"/p2/ws/{marker}")
    elif corruption == "blocked-origin":
        paths.append(f"/p2/ws/{marker}-blocked")
    requests = [SimpleNamespace(host=guest.HOST, path=path, method="GET") for path in paths]
    sinkhole = SimpleNamespace(get_requests=lambda: requests)
    monkeypatch.setattr(installed_workloads, "control", lambda *_args: {"websockets": states})
    observed = tmp_path / "ssh-observed"
    observed.write_text(marker)
    package = {"package_sha256": "fixture-sha", "repository_commit": "fixture-commit",
               "trace_agent": "bbtest", "package_request_id": "req-fixture"}
    stream = {"first": f"data: first:{marker}\n\n", "last": f"data: last:{marker}\n\n"}
    websocket = {"wss": {"server": f"server:{marker}"},
                 "blocked_canary": {"status": 403, "blocked_by": "network-guard"},
                 "ssh": {"server": f"ssh-server:{marker}", "pinned_host_key": True, "port": 22}}
    if corruption:
        with pytest.raises(AssertionError):
            installed_workloads.check_origin(sinkhole, marker, "fixture-sha", "fixture-commit",
                                             package, stream, websocket, observed)
    else:
        report = installed_workloads.check_origin(sinkhole, marker, "fixture-sha", "fixture-commit",
                                                  package, stream, websocket, observed)
        assert report["wss_requests"] == 1
        assert report["websocket_peers"] == states
        assert report["blocked_canary_origin_deliveries"] == 0


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
