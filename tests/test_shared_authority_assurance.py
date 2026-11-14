"""Check selector identities and failure accounting for authority assurance."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

from tests.blackbox import catalogue, guest_exec, installed_tailnet, native_authority
from tests.blackbox.selections import NATIVE_AUTHORITY


@pytest.mark.parametrize("unexpected", [None, b"", b"CONNECT private-observer-canary\r\n"])
def test_tailnet_observer_requires_live_paired_probes_and_counts_silent_connections(tmp_path, unexpected):
    output = tmp_path / "observer"
    output.mkdir()
    errors = []

    def observe():
        try:
            installed_tailnet.observe("127.0.0.1", "127.0.0.1", 1, output)
        except AssertionError as error:
            errors.append(error)

    thread = threading.Thread(target=observe)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not (output / "ready.json").exists():
            assert thread.is_alive() and time.monotonic() < deadline
            time.sleep(.01)
        ready = json.loads((output / "ready.json").read_text())
        installed_tailnet.probe("127.0.0.1", ready["port"], "127.0.0.1", ready["nonce"])
        if unexpected is not None:
            with socket.create_connection(("127.0.0.1", ready["port"]), timeout=5) as connection:
                assert connection.recv(4096).startswith(b"INFO ")
                connection.sendall(unexpected)
        installed_tailnet.probe("127.0.0.1", ready["port"], "127.0.0.1", ready["nonce"])
    finally:
        thread.join(timeout=5)
        assert not thread.is_alive()
    text = (output / "result.json").read_text()
    report = json.loads(text)
    assert report["closed"] is True
    assert report["status"] == ("passed" if unexpected is None else "failed")
    assert len(report["connections"]) == (2 if unexpected is None else 3)
    assert bool(errors) is (unexpected is not None)
    assert "private-observer-canary" not in text


def test_curated_native_cases_resolve_to_ignored_native_coord_tests():
    _controls, witnesses, _outside = catalogue.load()
    found = {node["node"] for witness in witnesses if witness.get("target") == "native_coord"
             for _reference, nodes in witness["resolved"] for node in nodes if node["ignored"]}
    selected = [case for cases in NATIVE_AUTHORITY.values() for case in cases]
    assert len(selected) == len(set(selected)) and set(selected) <= found


@pytest.mark.parametrize("payload", ["", "  body\nwith a newline\n"])
def test_guest_http_transport_retains_body_and_native_response_references(tmp_path, monkeypatch, payload):
    curl = shutil.which("curl")
    if curl is None:
        pytest.skip("curl is required for the real guest transport control")
    seen = []

    class Reply(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-SafeYolo-Approval-ID", "apr-fixture")
            self.send_header("X-SafeYolo-Request-ID", "req-fixture")
            self.end_headers()
            self.wfile.write(payload.encode())

        def log_message(self, *_arguments):
            pass  # The fixture records its own request body, without headers.

    socket = tmp_path / "origin.sock"
    server = socketserver.UnixStreamServer(str(socket), Reply)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
    thread.start()
    wrappers = tmp_path / "bin"
    wrappers.mkdir()
    executable = wrappers / "curl"
    executable.write_text("#!/bin/sh\nexec " + shlex.join([curl, "--unix-socket", str(socket)]) + ' "$@"\n')
    executable.chmod(0o755)
    monkeypatch.setattr(guest_exec, "guest_command_args", lambda _cli, _agent, command, **_options: ["bash", "-c", command])
    try:
        body = {"literal": "$(never executed)\nquoted ' value"}
        observed = guest_exec.guest_http_request("fixture", "owned", "POST", "http://127.0.0.1/fixture", body,
            env=os.environ | {"PATH": str(wrappers) + os.pathsep + os.environ["PATH"]})
        assert observed == {"status": 200, "body": payload, "approval_id": "apr-fixture", "request_id": "req-fixture"}
        assert seen == [body]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_access_preparation_carries_desktop_and_offline_inputs_through_guest_sudo(monkeypatch):
    calls = []
    monkeypatch.setattr(guest_exec.subprocess, "run", lambda command, **_options: calls.append(command))
    guest_exec.prepare_guest_tests("native", "owned", env={"SAFEYOLO_CONFIG_DIR": "/selected",
        "SAFEYOLO_GUEST_TEST_INPUTS": "/workspace/offline inputs", "SAFEYOLO_BLACKBOX_DESKTOP": "1"})
    assert calls[0][:7] == ["native", "--root", "/selected", "agent", "shell", "owned", "-c"]
    sudo = shlex.split(calls[0][-1])
    assert sudo[:5] == ["exec", "sudo", "-n", "/bin/bash", "-lc"]
    assert shlex.split(sudo[-1]) == ["bash", "/workspace/tests/blackbox/prepare-guest-tests.sh", "/workspace/offline inputs", "--desktop"]


@pytest.mark.parametrize("defect", [None, "absent", "zero-tests", "failed"])
def test_native_receipts_require_an_executed_exact_case_and_keep_other_controls(tmp_path, monkeypatch, defect):
    executable = tmp_path / "native-coord-fixture"
    executable.write_text(f'''#!{sys.executable}
import sys
case = sys.argv[1]
if '--list' in sys.argv:
    if not (case == 'bad' and {defect!r} == 'absent'):
        print(case + ': test')
elif case == 'bad' and {defect!r} == 'zero-tests':
    print('test result: ok. 0 passed')
elif case == 'bad' and {defect!r} == 'failed':
    print('test bad ... FAILED')
    sys.exit(1)
else:
    print('test ' + case + ' ... ok')
''')
    executable.chmod(0o755)
    broker = tmp_path / "nats-fixture"
    broker.write_text("not executed by this observer control")
    monkeypatch.setenv("SAFEYOLO_COORD_NATS_BINARY", str(broker))
    monkeypatch.setattr(native_authority, "NATIVE_AUTHORITY", {"BB-24": ("bad",), "BB-25": ("good",)})
    output = tmp_path / "receipts"
    if defect:
        with pytest.raises(AssertionError, match="native authority failures"):
            native_authority.run(executable, output)
    else:
        native_authority.run(executable, output)
    failed = json.loads((output / "BB-24/result.json").read_text())
    healthy = json.loads((output / "BB-25/result.json").read_text())
    assert failed["complete"] is (defect is None)
    assert failed["executed"][0]["passed"] is (defect is None)
    assert healthy["complete"] is True and healthy["executed"][0]["case"] == "good"
    assert json.loads((output / "BB-24/procedure.json").read_text())["finished"] is (defect is None)
    assert json.loads((output / "BB-25/procedure.json").read_text())["finished"] is True
