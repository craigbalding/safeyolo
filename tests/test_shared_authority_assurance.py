"""Check selector identities and failure accounting for authority assurance."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import pytest

from tests.blackbox import catalogue, guest_exec, installed_tailnet, native_authority
from tests.blackbox.selections import NATIVE_AUTHORITY


@pytest.mark.parametrize("defect", [None, "refused-bytes", "no-active-connection", "delayed-refused-marker"])
def test_tailnet_forwarding_observer_counts_real_frames_and_forces_reconnect(tmp_path, defect):
    received, errors = [], []

    class Broker(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(installed_tailnet.INFO)
            reader = self.request.makefile("rb")
            first = reader.readline()
            if first:
                received.append(first)
                self.request.sendall(b"+OK\r\n")
                while reader.readline():
                    self.request.sendall(b"PONG\r\n")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Broker)
    server.daemon_threads = True
    broker_thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
    broker_thread.start()
    output = tmp_path / "observer"
    output.mkdir()

    def observe():
        try:
            installed_tailnet.observe_federation("127.0.0.1", "127.0.0.1", server.server_address[1], 10, output)
        except AssertionError as error:
            errors.append(error)

    observer_thread = threading.Thread(target=observe)
    observer_thread.start()
    clients = []
    try:
        deadline = time.monotonic() + 5
        while not (output / "ready.json").exists():
            assert observer_thread.is_alive() and time.monotonic() < deadline
            time.sleep(.01)
        ready = json.loads((output / "ready.json").read_text())

        def mark(phase):
            installed_tailnet.probe("127.0.0.1", ready["port"], "127.0.0.1", ready["nonce"], phase)

        def authenticate(phase):
            client = socket.create_connection(("127.0.0.1", ready["port"]), timeout=2)
            clients.append(client)
            assert installed_tailnet.protocol_line(client).startswith(b"INFO ")
            authentication = b'CONNECT {"user":"peer","pass":"private-credential-sentinel"}\r\n'
            client.sendall(authentication)
            assert installed_tailnet.protocol_line(client) == b"+OK\r\n"
            marker = f"bb26-{ready['nonce']}-{phase}".encode()
            head = f"PUB request {len(marker)}\r\n".encode()
            split = len(marker) // 2
            client.sendall(head + marker[:split])
            assert installed_tailnet.protocol_line(client) == b"PONG\r\n"
            while True:
                report = json.loads((output / "result.json").read_text())
                if report["connections"][-1]["received_bytes"] >= len(authentication) + len(head) + split:
                    break
                assert time.monotonic() < deadline
                time.sleep(.01)
            client.sendall(marker[split:] + b"\r\n")
            assert installed_tailnet.protocol_line(client) == b"PONG\r\n"
            return client

        mark("initial")
        initial = authenticate("initial")
        if defect == "no-active-connection":
            initial.shutdown(socket.SHUT_RDWR)
            initial.close()
            while True:
                report = json.loads((output / "result.json").read_text())
                if any(row.get("connect") and row.get("closed") for row in report["connections"]):
                    break
                assert time.monotonic() < deadline
                time.sleep(.01)
        mark("wrong-node")
        mark("wrong-route")
        if defect == "refused-bytes":
            authenticate("wrong-route")
        mark("missing-interface")
        # A reconnect may reach TCP but must withhold its authentication bytes.
        with socket.create_connection(("127.0.0.1", ready["port"]), timeout=2) as silent:
            assert installed_tailnet.protocol_line(silent).startswith(b"INFO ")
        mark("lost-interface")
        if defect != "no-active-connection":
            assert initial.recv(1) == b""
        mark("restored")
        restored = authenticate("restored")
        if defect == "delayed-refused-marker":
            restored.sendall(f"PUB request 1\r\nbb26-{ready['nonce']}-lost-interface\r\n".encode())
            assert installed_tailnet.protocol_line(restored) == b"PONG\r\n"
            assert installed_tailnet.protocol_line(restored) == b"PONG\r\n"
        mark("finished")
        observer_thread.join(timeout=5)
        assert not observer_thread.is_alive()
        text = (output / "result.json").read_text()
        report = json.loads(text)
        assert report["closed"] is True and report["status"] == ("failed" if defect else "passed")
        assert bool(errors) is bool(defect)
        assert "private-credential-sentinel" not in text
        assert all(line.startswith(b"CONNECT ") for line in received)
        assert len(received) == (3 if defect == "refused-bytes" else 2)
    finally:
        for client in clients:
            client.close()
        observer_thread.join(timeout=12)
        server.shutdown()
        server.server_close()
        broker_thread.join(timeout=5)
        assert not observer_thread.is_alive() and not broker_thread.is_alive()


@pytest.fixture
def tailnet_phase(tmp_path, monkeypatch):
    root, installation = tmp_path / "source", tmp_path / "installed"
    (root / "data").mkdir(parents=True)
    (root / ".safeyolo-platform-smoke").touch()
    (root / "data/instance_id").write_text("sy-source")
    (root / "agents/owned/config-share").mkdir(parents=True)
    (root / "agents/owned/config-share/safeyolo-guest").write_text("selected guest")
    (installation / "bin").mkdir(parents=True)
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        (installation / "bin" / name).write_text(name)
    args = SimpleNamespace(cli=str(installation / "bin/safeyolo"), root=root, agent="owned",
        source_node="node-source", destination_node="node-destination", source="100.64.0.1",
        address="100.64.0.2", port=12345, nonce="one-observer", home="destination", room="bb26",
        phase="initial", initial=None)
    guest = {"name": "owned", "agent_id": "ag-source", "run_id": "run-1", "backend_pid": 123,
             "backend_token": "guest-birth"}
    runtime = {"pid": 456, "receipt": {"token": "proxy-birth"}}
    calls = []
    diagnosis = {"instance_id": "sy-source", "expected_owner": "sy-destination",
        "configured": {"mode": "tailscale", "url": f"nats://{args.address}:{args.port}",
                       "tailscale_node": args.destination_node}, "protection": {"verified": True},
        "broker_authentication": "authenticated", "owner": {"reachable": True, "identity_verified": True}}

    def checked(command, **_options):
        if command[0] == "tailscale":
            return json.dumps({"BackendState": "Running", "TUN": True,
                "Self": {"ID": args.source_node, "TailscaleIPs": [args.source]},
                "Peer": {"destination": {"ID": args.destination_node, "TailscaleIPs": [args.address]}}})
        if command[-1] == "--version":
            return "commit=" + "a" * 40
        if "status" in command:
            return "{}"
        assert command[-4:] == ["coord", "federation", "check", args.home]
        return json.dumps(diagnosis)

    def submit(*_command, **_options):
        calls.append(_command[4])
        return {"status": 503 if args.phase == "lost-interface" else 200}

    monkeypatch.setattr(installed_tailnet, "_cli_identity", lambda _cli: {"source_revision": "a" * 40})
    monkeypatch.setattr(installed_tailnet, "_native_config", lambda *_arguments: {})
    monkeypatch.setattr(installed_tailnet, "_runtime_observation", lambda *_arguments, **_options: runtime)
    monkeypatch.setattr(installed_tailnet, "running_guest", lambda *_arguments: dict(guest))
    monkeypatch.setattr(installed_tailnet, "checked", checked)
    monkeypatch.setattr(installed_tailnet, "guest_http_request", submit)
    return args, guest, runtime, diagnosis, calls


def test_tailnet_phases_keep_one_live_source_and_submit_each_marker_once(tailnet_phase, tmp_path):
    args, _guest, _runtime, diagnosis, calls = tailnet_phase
    for name in ("initial", "lost-interface", "restored"):
        args.phase = name
        output = tmp_path / name
        output.mkdir()
        diagnosis.update(protection={"verified": name != "lost-interface"},
                         broker_authentication="not_checked" if name == "lost-interface" else "authenticated")
        if name == "lost-interface":
            diagnosis["protection"]["reason"] = installed_tailnet.REASONS["missing-interface"]
        installed_tailnet.phase(args, output)
        report = json.loads((output / "result.json").read_text())
        assert report["status"] == "passed" and report["proxy"]["start_token"] == "proxy-birth"
        assert report["guest"]["run_id"] == "run-1"
        args.initial = tmp_path / "initial/result.json"
    assert [body["body"] for body in calls] == [f"bb26-one-observer-{name}" for name in ("initial", "lost-interface", "restored")]


@pytest.mark.parametrize("defect", ["guest-restarted", "proxy-restarted", "wrong-endpoint", "wrong-protection", "lost-reply"])
def test_tailnet_phase_rejects_changed_context_and_retains_uncertain_submission(tailnet_phase, tmp_path, monkeypatch, defect):
    args, guest, runtime, diagnosis, calls = tailnet_phase
    output = tmp_path / "initial"
    output.mkdir()
    installed_tailnet.phase(args, output)
    args.initial = output / "result.json"
    args.phase = "restored"
    if defect == "guest-restarted":
        guest["backend_token"] = "another-birth"
    elif defect == "proxy-restarted":
        runtime["receipt"]["token"] = "another-birth"
    elif defect == "wrong-endpoint":
        diagnosis["configured"]["url"] = "nats://100.64.0.2:5555"
    elif defect == "wrong-protection":
        diagnosis["configured"]["mode"] = "loopback"
    else:
        def lose_reply(*_arguments, **_options):
            calls.append({"body": "uncertain-restored"})
            raise TimeoutError("lost reply")
        monkeypatch.setattr(installed_tailnet, "guest_http_request", lose_reply)
    failed = tmp_path / "failed"
    failed.mkdir()
    with pytest.raises((AssertionError, TimeoutError)):
        installed_tailnet.phase(args, failed)
    report = json.loads((failed / "result.json").read_text())
    assert report["status"] == "incomplete" and report["finished_at"]
    assert len(calls) == (2 if defect == "lost-reply" else 1)


@pytest.mark.parametrize("defect", [None, "refused-effect", "wrong-principal", "source-restarted",
    "wrong-refusal", "missing-case", "unrelated-observer", "source-cleanup", "destination-cleanup", "false-lost-pass", "outside-window", "different-binary"])
def test_tailnet_verifier_pairs_full_producer_receipts_with_independent_destination(tailnet_phase, tmp_path, monkeypatch, defect):
    args, _guest, _runtime, diagnosis, _calls = tailnet_phase
    phases, checks = [], []

    def retain(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return path

    for name in ("initial", "lost-interface", "restored"):
        args.phase = name
        output = tmp_path / name
        output.mkdir()
        diagnosis.update(protection={"verified": name != "lost-interface"},
                         broker_authentication="not_checked" if name == "lost-interface" else "authenticated")
        if name == "lost-interface":
            diagnosis["protection"]["reason"] = installed_tailnet.REASONS["missing-interface"]
        installed_tailnet.phase(args, output)
        phases.append(output / "result.json")
        args.initial = phases[0]
    initial = json.loads(phases[0].read_text())
    for case, reason in installed_tailnet.REASONS.items():
        checks.append(retain(case + ".json", {**initial, "case": case, "destination_address": args.address,
            "refusal": {"exit": 1, "reason": reason}, "cleanup": "stopped", "cleanup_failures": [],
            "coord": {"sha256": initial["binaries"]["safeyolo-coord"]}}))
    # Place producer records in explicit source-clock windows for this reader
    # control. The real TCP control above exercises the probe clock exchange.
    for path in (*phases, *checks):
        value = json.loads(path.read_text())
        index = installed_tailnet.PHASES.index(value.get("case", value["phase"]))
        value.update(started_ns=1000 + index * 100 + 2, finished_ns=1000 + index * 100 + 3)
        path.write_text(json.dumps(value))
    observer = {"nonce": args.nonce, "port": args.port, "address": args.address, "source": args.source,
        "closed": True, "status": "passed", "phase_marks": [{"phase": phase, "disconnected": int(phase == "lost-interface"),
            "source_sent_ns": 1000 + index * 100, "source_received_ns": 1000 + index * 100 + 1}
            for index, phase in enumerate(installed_tailnet.PHASES)], "connections": [
            {"source": args.source, "control": False, "phase": phase, "received_bytes": 1,
             "connect": True, "markers": [phase]} for phase in ("initial", "restored")]}
    cleanup = {"root": initial["root"], "cli": initial["cli"], "cleanup": "stopped", "cleanup_failures": []}
    # Same length-prefixed principal contract as the native destination producer.
    principal = "ag-fed-" + hashlib.sha256(b"9:sy-sourceag-source").hexdigest()
    rows = [{"body": f"bb26-{args.nonce}-{name}", "sender_kind": "agent",
             "sender_agent_id": principal, "origin_instance_id": "sy-destination"} for name in ("initial", "restored")]
    if defect == "refused-effect":
        rows.append(rows[0] | {"body": f"bb26-{args.nonce}-lost-interface"})
    elif defect == "wrong-principal":
        rows[1]["sender_agent_id"] = "ag-other"
    elif defect in {"source-restarted", "false-lost-pass"}:
        path = phases[2 if defect == "source-restarted" else 1]
        value = json.loads(path.read_text())
        if defect == "source-restarted":
            value["guest"]["backend_token"] = "new-birth"
        else:
            value["response_status"] = 200
        path.write_text(json.dumps(value))
    elif defect == "wrong-refusal":
        value = json.loads(checks[0].read_text())
        value["refusal"]["reason"] = "unrelated error"
        checks[0].write_text(json.dumps(value))
    elif defect == "outside-window":
        value = json.loads(checks[1].read_text())
        value["started_ns"] = 1
        checks[1].write_text(json.dumps(value))
    elif defect == "different-binary":
        value = json.loads(checks[0].read_text())
        value["coord"]["sha256"] = "other-bytes"
        checks[0].write_text(json.dumps(value))
    elif defect == "missing-case":
        checks.pop()
    elif defect == "unrelated-observer":
        observer["nonce"] = "another-run"
    elif defect == "source-cleanup":
        cleanup["cleanup_failures"] = ["owned guest still running"]
    destination = tmp_path / "destination"
    (destination / "data").mkdir(parents=True)
    (destination / "data/instance_id").write_text("sy-destination")
    (destination / ".safeyolo-platform-smoke").touch()
    stopped = []

    def stop(_cli, root):
        stopped.append(root)
        return ["owned listener survived"] if defect == "destination-cleanup" else []

    monkeypatch.setattr(installed_tailnet, "cleanup_instance", stop)
    monkeypatch.setattr(installed_tailnet, "checked", lambda command, **_options: "\n".join(map(json.dumps, rows)))
    args = SimpleNamespace(root=destination, cli=args.cli, phase_report=phases, check_report=checks,
        observer=retain("observer.json", observer), source_cleanup=retain("source-stop.json", cleanup))
    output = tmp_path / "verification"
    output.mkdir()
    if defect:
        with pytest.raises(AssertionError):
            installed_tailnet.verify(args, output)
    else:
        installed_tailnet.verify(args, output)
    report = json.loads((output / "result.json").read_text())
    assert report["status"] == ("failed" if defect == "destination-cleanup" else "incomplete" if defect else "passed")
    assert stopped == [destination]
    assert report["cleanup"] == ("failed" if defect == "destination-cleanup" else "stopped")


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


def test_native_timeout_retains_diagnostics_and_stops_later_cases(tmp_path, monkeypatch):
    executable = tmp_path / "native-coord-fixture"
    executable.write_text(f'''#!{sys.executable}
import sys
import time
case = sys.argv[1]
if '--list' in sys.argv:
    print(case + ': test')
else:
    print('owned-fixture-stdout-before-timeout', flush=True)
    print('owned-fixture-stderr-before-timeout', file=sys.stderr, flush=True)
    time.sleep(30)
''')
    executable.chmod(0o755)
    broker = tmp_path / "nats-fixture"
    broker.write_text("not executed by this observer control")
    monkeypatch.setenv("SAFEYOLO_COORD_NATS_BINARY", str(broker))
    monkeypatch.setattr(native_authority, "NATIVE_AUTHORITY", {
        "BB-24": ("slow", "must-not-run"), "BB-25": ("also-must-not-run",)})
    run = subprocess.run

    def bounded_run(command, **options):
        if "--list" not in command:
            options["timeout"] = .5
        return run(command, **options)

    monkeypatch.setattr(native_authority.subprocess, "run", bounded_run)
    output = tmp_path / "receipts"
    with pytest.raises(RuntimeError, match="native test timed out"):
        native_authority.run(executable, output)
    report = json.loads((output / "BB-24/result.json").read_text())
    assert report["complete"] is False
    assert len(report["executed"]) == 1
    row = report["executed"][0]
    assert row["case"] == "slow" and row["passed"] is False and row["exit"] is None
    assert row["error"].startswith("TimeoutExpired:")
    assert row["cleanup"] == "unverified after test timeout; remaining cases did not run"
    assert json.loads((output / "BB-24/procedure.json").read_text())["finished"] is False
    assert not (output / "BB-24/must-not-run.log").exists()
    assert not (output / "BB-25").exists()
    diagnostics = (output / "BB-24/slow.log").read_text()
    assert "owned-fixture-stdout-before-timeout" in diagnostics
    assert "owned-fixture-stderr-before-timeout" in diagnostics
