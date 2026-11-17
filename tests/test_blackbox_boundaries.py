"""Exercise boundary observers against real owned TCP and Unix receivers."""

from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.blackbox import execution_receipt as receipts
from tests.blackbox import installed_boundaries as boundaries
from tests.blackbox import installed_docker_preflight as docker
from tests.blackbox.harness.process_identity import process_start_token
from tests.blackbox.host import job_network, job_sandbox
from tests.blackbox.selections import BOUNDARY_SECTIONS, PROCEDURES, SECTIONS

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("grant,valid", [
    ({"capability": "reader", "token": "job-secret"}, True),
    ({"capability": "reader", "token": "job-secret", "account": "agent"}, True),
    ({"capability": "reader", "token": "job-secret", "account": "foreign"}, False),
    ({"capability": "reader", "token": "job-secret", "account": ""}, False),
    ({"capability": "writer", "token": "job-secret", "account": "agent"}, False),
    ({"capability": "reader", "token": "other", "account": "agent"}, False),
    ({"capability": "reader", "account": "agent"}, False),
    ({"token": "job-secret", "account": "agent"}, False),
    ({"capability": "reader", "token": "job-secret", "account": "agent", "host": "foreign"}, False),
])
def test_restored_job_grant_preserves_effective_account_capability_and_credential(tmp_path, grant, valid):
    # The explicit default is the native-authorized grant retained in execution 18382.
    (tmp_path / "policy.toml").write_text(tomlkit.dumps({"agents": {"gate:proof": {"services": {"simple": grant}}}}))
    if valid:
        job_network.assert_restored_gate_grant(tmp_path)
    else:
        with pytest.raises(AssertionError, match="saved gate authority changed"):
            job_network.assert_restored_gate_grant(tmp_path)

@pytest.fixture
def job_observer_cli(tmp_path):
    """Publish the job producer's records around a real owned backend process."""
    if sys.platform != "linux":
        pytest.skip("the controlled backend uses Linux runsc arguments and process births")
    root = tmp_path / "instance"
    root.mkdir()
    (root / "config.toml").touch()
    (root / "data").mkdir()
    backend = tmp_path / "runsc-sandbox"
    backend.symlink_to(sys.executable)

    def prepare(mode="starting-live"):
        cli = tmp_path / "cli"
        output = ("a" * 64 + "\nHTTPS gateway, route/Agent API/egress refusal\n").encode()
        payload = {"retained_base64": base64.b64encode(output).decode(),
                   "bytes": len(output), "sha256": hashlib.sha256(output).hexdigest()}
        cli.write_text(f'''#!{sys.executable}
import json, pathlib, shutil, signal, subprocess, sys, time
sys.path.insert(0, {str(ROOT)!r})
from tests.blackbox.harness.process_identity import process_start_token
root = pathlib.Path(sys.argv[sys.argv.index("--root") + 1])
directory = root / "data/job-observer"
directory.mkdir()
(directory / "config.toml").symlink_to(root / "config.toml")
record = directory / "agents/job-observer/runtime.json"
record.parent.mkdir(parents=True)
run = {{"name": "job-observer", "agent_id": "job-observer", "run_id": "1" * 32, "state": "starting"}}
mode = {mode!r}
backend = None
def publish():
    temporary = record.with_suffix(".new")
    temporary.write_text(json.dumps(run))
    temporary.replace(record)
def interrupted(number, _frame):
    print(f"caller signal {{number}}", file=sys.stderr, flush=True)
    raise SystemExit(128 + number)
signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)
try:
    if mode != "live":
        publish()
        print("published starting", file=sys.stderr, flush=True)
        time.sleep(0.3 if mode != "pending" else 30)
        if mode == "failed-start":
            raise SystemExit(17)
    bundle = "/another/job" if mode == "foreign-bundle" else str(record.parent)
    backend = subprocess.Popen([{str(backend)!r}, "-c", "import time; time.sleep(30)",
                                "--bundle=" + bundle, "--platform=systrap"])
    run.update(backend_pid=backend.pid, backend_token=process_start_token(backend.pid))
    if mode == "stale-birth":
        run["backend_token"] = "another-process-birth"
    publish()
    print("published live", file=sys.stderr, flush=True)
    # Keep the live identity observable until the caller is signalled or exits.
    time.sleep(0.3)
finally:
    if backend is not None:
        backend.terminate()
        backend.wait(timeout=5)
    shutil.rmtree(directory)
    print("owned cleanup", file=sys.stderr, flush=True)
print(json.dumps({{"outcome": {{"kind": "exit", "code": 0}}, "observation_error": None,
                  "gate_principal": "gate:proof", "authorization_principal": "gate:proof",
                  "stdout": {payload!r}}}))
''')
        cli.chmod(0o755)
        return cli, root

    return prepare


@pytest.mark.parametrize("mode", ["starting-live", "failed-start"])
def test_job_network_caller_keeps_backend_readiness_and_failure_evidence(job_observer_cli, tmp_path, monkeypatch, mode):
    cli, root = job_observer_cli(mode)
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_LANE", "systrap")
    if mode == "failed-start":
        with pytest.raises(AssertionError, match="verified live backend"):
            job_network.job(cli, root, tmp_path, port=0, index=1)
        assert (tmp_path / "job-1.exit").read_text() == "17"
        assert json.loads((tmp_path / "job-1.backend.json").read_text()) == []
    else:
        result, fingerprint = job_network.job(cli, root, tmp_path, port=0, index=1)
        assert fingerprint == "a" * 64
        assert result["observed_backends"][0]["platform"] == "systrap"
        assert (tmp_path / "job-1.exit").read_text() == "0"
    assert b"published starting\n" in (tmp_path / "job-1.stderr").read_bytes()
    assert b"owned cleanup\n" in (tmp_path / "job-1.stderr").read_bytes()
    assert job_sandbox.job_directories(root) == set()


@pytest.mark.parametrize("mode", ["live", "starting-live"])
@pytest.mark.parametrize("interrupt", [None, signal.SIGINT, signal.SIGTERM])
def test_job_observer_waits_for_verified_live_backend(job_observer_cli, monkeypatch, mode, interrupt):
    cli, root = job_observer_cli(mode)
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_LANE", "systrap")
    result, records, observed = job_sandbox.interrupt_request([str(cli), "--root", str(root)], root, interrupt)
    assert result.returncode == (0 if interrupt is None else 128 + interrupt), result.stderr
    assert len(records) == len(observed) == 1
    backend = observed[0]
    assert backend["platform"] == "systrap" and backend["agent"] == "job-observer"
    assert backend["start_token"] and process_start_token(backend["pid"]) is None
    assert b"published live\n" in result.stderr and b"owned cleanup\n" in result.stderr
    if mode == "starting-live":
        assert b"published starting\n" in result.stderr
    if interrupt is not None:
        assert result.stderr.index(b"published live\n") < result.stderr.index(b"caller signal")
    assert job_sandbox.job_directories(root) == set()


@pytest.mark.parametrize("mode,error", [
    ("stale-birth", "native sandbox receipt does not own a live backend"),
    ("foreign-bundle", "runsc backend belongs to another bundle"),
    ("wrong-lane", "job used another backend"),
])
def test_job_observer_rejects_invalid_live_identity_after_starting(job_observer_cli, monkeypatch, mode, error):
    cli, root = job_observer_cli(mode)
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_LANE", "kvm" if mode == "wrong-lane" else "systrap")
    result, records, observed = job_sandbox.interrupt_request([str(cli), "--root", str(root)], root, None)
    assert result.returncode == 128 + signal.SIGTERM
    assert len(records) == 1 and observed == [{"error": error}]
    assert b"published live\n" in result.stderr and b"owned cleanup\n" in result.stderr
    assert job_sandbox.job_directories(root) == set()


def test_job_observer_keeps_starting_within_existing_deadline(job_observer_cli, monkeypatch):
    cli, root = job_observer_cli("pending")
    record = root / "data/job-observer/agents/job-observer/runtime.json"
    monotonic = job_sandbox.time.monotonic
    monkeypatch.setattr(job_sandbox.time, "monotonic", lambda: monotonic() + (181 if record.exists() else 0))
    with pytest.raises(subprocess.TimeoutExpired) as timeout:
        job_sandbox.interrupt_request([str(cli), "--root", str(root)], root, signal.SIGINT)
    assert b"published starting\n" in timeout.value.stderr and b"owned cleanup\n" in timeout.value.stderr
    assert b"published live\n" not in timeout.value.stderr and b"caller signal 2\n" not in timeout.value.stderr
    assert job_sandbox.job_directories(root) == set()


@pytest.mark.parametrize("leak", [None, "http", "tcp"])
def test_network_off_observer_rejects_actual_receiver_delivery(tmp_path, leak):
    receipt = receipts.ProcedureReceipt("job-sandbox", tmp_path / "result.json")
    privileges = []

    def job(program, *, privilege):
        privileges.append(privilege)
        if leak:
            port = int(re.search(r"/dev/tcp/127\.0\.0\.1/(\d+)", program)[1])
            if leak == "tcp":
                with socket.create_connection(("127.0.0.1", port), timeout=3):
                    pass
                return 0, {"outcome": {"kind": "exit", "code": 0}}
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                connection.request("GET", "/forbidden-job-delivery")
                response = connection.getresponse()
                assert response.status == 200
                response.read()
            finally:
                connection.close()
        return 0, {"outcome": {"kind": "exit", "code": 0}}

    if leak:
        with pytest.raises(AssertionError):
            job_sandbox.network_off(job, receipt)
    else:
        job_sandbox.network_off(job, receipt)
        assert privileges == ["unprivileged", "guest-root"]
        assert receipt.document["observations"]["network-off"]["receiver_hits"] == ["/host-positive", "/host-positive-after"]


@pytest.mark.parametrize("live_path,live_connection", [(False, False), (True, False), (False, True)])
def test_terminated_delegation_checks_both_endpoint_and_existing_connection(tmp_path, live_path, live_connection):
    path = tmp_path / "job.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        client = socket.socket(socket.AF_UNIX)
        client.connect(str(path))
        server, _ = listener.accept()
        connection = http.client.HTTPConnection("unused", timeout=2)
        connection.sock = client
        connection.auto_open = 0
        if not live_path:
            path.unlink()
        thread = None
        if live_connection:
            def respond():
                with server:
                    assert server.recv(4096).startswith(b"GET /value")
                    server.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            thread = threading.Thread(target=respond)
            thread.start()
        else:
            server.close()
        try:
            if live_path or live_connection:
                with pytest.raises(AssertionError, match="retained"):
                    job_network.ended_delegation(path, connection, "synthetic-scope", [], 0)
            else:
                job_network.ended_delegation(path, connection, "synthetic-scope", [], 0)
        finally:
            connection.close()
            if thread:
                thread.join(timeout=3)
                assert not thread.is_alive()


def test_missing_delegation_never_reconnects_directly_to_origin(tmp_path):
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.1)
        port = origin.getsockname()[1]
        # Use a normal trusted context. No TLS peer should be reached at all.
        connection = job_network.DelegatedHTTPSConnection(tmp_path / "missing-job.sock", port, ssl.get_default_verify_paths().cafile)
        try:
            with pytest.raises(FileNotFoundError):
                job_network.scoped_request(connection, "synthetic-scope")
            with pytest.raises(TimeoutError):
                origin.accept()
        finally:
            connection.close()


def test_failed_backend_observation_retains_native_output_and_reaps_caller(tmp_path, monkeypatch):
    root = tmp_path / "instance"
    root.mkdir()
    (root / "config.toml").write_text("")
    (root / "data").mkdir()
    code = '''import pathlib, sys, time
root = pathlib.Path(sys.argv[1])
directory = root / "data/job-failed"
directory.mkdir()
(directory / "config.toml").symlink_to(root / "config.toml")
record = directory / "agents/job-failed/runtime.json"
record.parent.mkdir(parents=True)
print("native output before observer failure", flush=True)
record.write_text("{}")
time.sleep(30)
'''

    def unavailable(_record):
        raise ValueError("wrong backend lifetime")

    monkeypatch.setattr(job_sandbox, "observe_backend", unavailable)
    result, records, observed = job_sandbox.interrupt_request([sys.executable, "-c", code, str(root)], root, None)
    assert result.returncode < 0 and b"native output before observer failure" in result.stdout
    assert len(records) == 1 and observed == [{"error": "wrong backend lifetime"}]


@pytest.mark.parametrize("section", BOUNDARY_SECTIONS)
@pytest.mark.parametrize("defect", [None, "case", "run", "lane", "unfinished", "identities", "dirty-controller"])
def test_boundary_receipt_recomputes_required_cases_and_selected_context(tmp_path, monkeypatch, section, defect):
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_RUN_ID", "current")
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_LANE", "systrap")
    receipt = receipts.ProcedureReceipt(section, tmp_path / "result.json")
    receipt.document["identities"] = {"product": {"source_revision": "product"},
                                      "controller": {"controller_revision": "controller", "controller_dirty": False},
                                      "guest_selection": {"index": "selected"}}
    for name in PROCEDURES[section][1]:
        if defect != "case" or name != PROCEDURES[section][1][2]:
            receipt.checkpoint(name)
    if defect == "run":
        receipt.document["run_id"] = "old"
    if defect == "lane":
        receipt.document["lane"] = "kvm"
    if defect == "unfinished":
        receipt.document["finished"] = False
    if defect == "identities":
        del receipt.document["identities"]["guest_selection"]
    if defect == "dirty-controller":
        receipt.document["identities"]["controller"].update(controller_dirty=True, controller_revision=None)
    receipts.save(receipt.path, receipt.document)
    observed = receipts.section_execution(tmp_path, section, "systrap", "current")
    assert observed["complete"] == (defect is None)


@pytest.mark.parametrize("defect", [None, "allowed-missing", "denied-delivered", "direct-delivered", "receiver-cleanup"])
@pytest.mark.parametrize("application_resume", [False, True])
def test_docker_origins_require_exact_independent_effects_and_cleanup(tmp_path, monkeypatch, defect, application_resume):
    base = tmp_path / "base"
    base.mkdir()
    (base / "config.toml").write_text("")
    args = SimpleNamespace(prepared_config=base, output=tmp_path / "docker",
                           application_resume=tmp_path / "prior.json" if application_resume else None)
    receipt = None if application_resume else receipts.ProcedureReceipt("docker", tmp_path / "receipt/result.json")
    servers = []
    original_server = docker.ParentObserver

    class ObservedServer(original_server):
        def __init__(self, address):
            super().__init__(address)
            self.closed = False
            servers.append(self)

        def server_close(self):
            super().server_close()
            self.closed = True
            if defect == "receiver-cleanup":
                raise OSError("receiver cleanup failed")

    monkeypatch.setattr(docker, "ParentObserver", ObservedServer)

    def journey(selected, supplied):
        assert supplied is receipt
        args.output.mkdir()
        expected = 2 if application_resume else 3
        count = expected - 1 if defect == "allowed-missing" else expected
        for destination in ([selected.owned_origins["PROBE_ALLOWED"]] * count +
                            [selected.owned_origins["PROBE_DENIED"]] * (defect == "denied-delivered") +
                            [f"http://{selected.host_address}:{selected.host_port}/direct"] * (defect == "direct-delivered")):
            from urllib.parse import urlsplit
            address = urlsplit(destination)
            connection = http.client.HTTPConnection(address.hostname, address.port, timeout=3)
            try:
                connection.request("GET", address.path)
                response = connection.getresponse()
                assert response.status == 200
                response.read()
            finally:
                connection.close()
        return {"cleanup": "stopped", "status": "application-resume-ran" if application_resume else "journey-passed"}

    monkeypatch.setattr(docker, "run", journey)
    monkeypatch.delenv("SAFEYOLO_DOCKER_ORIGIN_BIND", raising=False)
    if defect:
        with pytest.raises((AssertionError, OSError)):
            docker.recurring_journey(args, receipt)
        if receipt is not None:
            assert not receipt.document["finished"]
        else:
            assert json.loads((args.output / "result.json").read_text())["status"] == "application-resume-ran"
    else:
        result = docker.recurring_journey(args, receipt)
        assert result["owned_origins"]["allowed_accepts"] == (4 if application_resume else 5)
        assert result["owned_origins"]["denied_accepts"] == 2
        if receipt is not None:
            assert receipt.document["finished"]
        else:
            assert result["status"] == "application-resume-passed"
    assert len(servers) == 2 and all(server.closed for server in servers)


@pytest.mark.parametrize("section", BOUNDARY_SECTIONS)
def test_boundary_preparation_failure_is_incomplete_and_keeps_cleanup_result(tmp_path, monkeypatch, section):
    args = SimpleNamespace(output=tmp_path / "reports", prepared_config=tmp_path / "prepared",
                           root=tmp_path / "fresh", section=section, revision="a" * 40, lane="systrap",
                           admin_port=None, upstream_port=None, nats_client_port=None, nats_monitor_port=None)
    monkeypatch.setattr(boundaries, "_cli_identity", lambda _cli: {"source_revision": "b" * 40})
    stopped = []
    monkeypatch.setattr(boundaries, "cleanup_instance", lambda cli, root: stopped.append(root) or [])
    with pytest.raises(AssertionError, match="selected revision"):
        boundaries.run(args)
    result = json.loads((args.output / "boundary-result.json").read_text())
    assert not result["finished"] and result["cleanup_failures"] == []
    assert "selected revision" in result["error"] and stopped == [args.root]
    assert not receipts.section_execution(args.output, section, "systrap", "run")["complete"]


@pytest.mark.parametrize("lane,probe", [("systrap", None), ("vz", None), ("systrap", "absent"),
                                        ("systrap", "supplied"), ("vz", "supplied")])
@pytest.mark.parametrize("explicit_ports", [False, True])
def test_installed_mounts_select_guest_holder_before_starting_services(tmp_path, monkeypatch, lane, probe, explicit_ports):
    base = tmp_path / "prepared"
    (base / "share").mkdir(parents=True)
    (base / "share/guest-selection.json").write_text('{"guest":"selected"}')
    args = SimpleNamespace(output=tmp_path / "reports", prepared_config=base,
                           root=tmp_path / "fresh", section="mounts", revision="a" * 40, lane=lane,
                           admin_port=46374 if explicit_ports else None, upstream_port=None,
                           nats_client_port=46375 if explicit_ports else None,
                           nats_monitor_port=46378 if explicit_ports else None)
    monkeypatch.setattr(boundaries, "_cli_identity", lambda _: {"source_revision": args.revision})
    monkeypatch.setattr(boundaries, "controller_identity", lambda: {"controller_revision": "b" * 40, "controller_dirty": False})
    monkeypatch.setattr(boundaries, "free_port", lambda: 43123)
    calls, cleaned = [], []
    monkeypatch.setattr(boundaries, "prepare", lambda base, root, port: calls.append(("admin", port)))
    monkeypatch.setattr(boundaries, "copy_prepared_nats", lambda *_: calls.append("nats"))
    monkeypatch.setattr(boundaries.subprocess, "run", lambda argv, **_: calls.append(argv))
    monkeypatch.setattr(boundaries, "cleanup_instance", lambda _, root: cleaned.append(root) or [])
    supplied = tmp_path / "mount holder"
    if probe == "supplied":
        supplied.write_bytes(b"explicit guest executable")
    if probe is None:
        monkeypatch.delenv("SAFEYOLO_MOUNT_HOLDER_PROBE", raising=False)
    else:
        monkeypatch.setenv("SAFEYOLO_MOUNT_HOLDER_PROBE", str(supplied))

    def run_proof(root, output, *, candidate, receipt, holder_probe):
        expected = supplied.resolve() if probe == "supplied" else None
        assert (root, output, candidate, holder_probe) == (args.root, args.output / "mounts", args.revision, expected)
        assert receipt.path == args.output / "procedure.json"
        calls.append("mounts")

    monkeypatch.setitem(sys.modules, "tests.nested_linux_live_mount", SimpleNamespace(run_proof=run_proof))
    ready = probe == "supplied" or (lane == "systrap" and probe is None)
    if ready:
        assert boundaries.run(args) == 0
        coord = [str(base / "bin/safeyolo"), "--root", str(args.root), "coord", "start"]
        if explicit_ports:
            coord += ["--client-port", "46375", "--monitor-port", "46378"]
        elif lane == "vz":
            coord += ["--client-port", "46370", "--monitor-port", "46372"]
        assert calls[0] == ("admin", 46374 if explicit_ports else 46371 if lane == "vz" else 43123)
        assert calls[1:] == ["nats", coord, [str(base / "bin/safeyolo"), "--root", str(args.root), "start"], "mounts"]
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            boundaries.run(args)
        assert len(calls) == 1 and calls[0][0] == "admin"
    result = json.loads((args.output / "boundary-result.json").read_text())
    assert result["finished"] == ready
    assert result["cleanup_failures"] == [] and cleaned == [args.root]
    # Forwarding a supplied fixture cannot supply missing procedure checkpoints.
    assert not receipts.section_execution(args.output, "mounts", "systrap", "run")["complete"]


@pytest.mark.parametrize("lane,section", [(lane, section) for lane in ("systrap", "kvm", "vz")
                                        for section in ("job-sandbox", "job-network")] + [("systrap", "docker")])
@pytest.mark.parametrize("explicit_ports", [False, True])
def test_boundary_port_options_reach_job_and_docker_consumers(tmp_path, monkeypatch, lane, section, explicit_ports):
    base, root, output = tmp_path / "prepared", tmp_path / "fresh", tmp_path / "reports"
    (base / "share").mkdir(parents=True)
    (base / "share/guest-selection.json").write_text('{}')
    (base / "config.toml").write_text('admin_port = 9999\n')
    revision = "a" * 40
    monkeypatch.setattr(boundaries, "_cli_identity", lambda _: {"source_revision": revision})
    monkeypatch.setattr(boundaries, "controller_identity", lambda: {"controller_revision": "b" * 40, "controller_dirty": False})
    monkeypatch.setattr(boundaries, "free_port", lambda: 43123)
    monkeypatch.setenv("SAFEYOLO_JOB_OBSERVER_PROBE", str(tmp_path / "observer"))
    cleaned, observed = [], []
    monkeypatch.setattr(boundaries, "cleanup_instance", lambda cli, path: cleaned.append(path) or [])

    def initialize(base, root):
        (root / "data").mkdir(parents=True)
        (root / "config.toml").write_text('admin_port = 9999\n')

    monkeypatch.setattr(boundaries, "prepare_native_instance", initialize)
    admin = 46374 if explicit_ports else 46371 if lane == "vz" else 43123
    upstream = 46372 if explicit_ports else 46373 if lane == "vz" else 43123

    def sandbox(cli, path, scratch, **kwargs):
        assert tomlkit.parse((path / "config.toml").read_text())["admin_port"] == admin
        assert kwargs["receiver_port"] == (upstream if explicit_ports or lane == "vz" else 0)
        observed.append("sandbox")

    def network(args, receipt):
        assert (args.admin_port, args.upstream_port) == (admin, upstream)
        observed.append("network")

    def nested_docker(args, receipt):
        assert (args.admin_port, args.host_port) == (admin, upstream)
        observed.append("docker")

    monkeypatch.setattr(job_sandbox, "run", sandbox)
    monkeypatch.setattr(job_network, "run", network)
    monkeypatch.setattr(docker, "recurring_journey", nested_docker)
    arguments = ["boundary", "--section", section, "--lane", lane, "--prepared-config", str(base),
                 "--root", str(root), "--output", str(output), "--revision", revision]
    if explicit_ports:
        arguments += ["--admin-port", "46374", "--upstream-port", "46372"]
    monkeypatch.setattr(sys, "argv", arguments)
    assert boundaries.main() == 0
    assert observed == [{"job-sandbox": "sandbox", "job-network": "network", "docker": "docker"}[section]]
    assert cleaned == [root]
    assert tomlkit.parse((base / "config.toml").read_text())["admin_port"] == 9999


@pytest.mark.parametrize("busy", [False, True])
def test_explicit_boundary_receiver_binds_or_fails_without_complete_coverage(tmp_path, monkeypatch, busy):
    base, root, output = tmp_path / "prepared", tmp_path / "fresh", tmp_path / "reports"
    (base / "share").mkdir(parents=True)
    (base / "share/guest-selection.json").write_text('{}')
    revision = "a" * 40
    monkeypatch.setattr(boundaries, "_cli_identity", lambda _: {"source_revision": revision})
    monkeypatch.setattr(boundaries, "controller_identity", lambda: {"controller_revision": "b" * 40, "controller_dirty": False})
    monkeypatch.setattr(boundaries, "prepare", lambda *_: None)
    cleaned = []
    monkeypatch.setattr(boundaries, "cleanup_instance", lambda cli, path: cleaned.append(path) or [])

    def job(program, **kwargs):
        assert not busy, "busy receiver must fail before any job"
        assert f"/dev/tcp/127.0.0.1/{port}" in program
        return 0, {"outcome": {"kind": "exit", "code": 0}}

    def sandbox(cli, root, scratch, **kwargs):
        job_sandbox.network_off(job, kwargs["receipt"], kwargs["receiver_port"])

    monkeypatch.setattr(job_sandbox, "run", sandbox)
    with socket.socket() as foreign:
        foreign.bind(("127.0.0.1", 0))
        foreign.listen()
        port = foreign.getsockname()[1]
        if not busy:
            foreign.close()
        monkeypatch.setattr(sys, "argv", ["boundary", "--section", "job-sandbox", "--lane", "systrap",
                                         "--prepared-config", str(base), "--root", str(root), "--output", str(output),
                                         "--revision", revision, "--upstream-port", str(port)])
        assert boundaries.main() == (2 if busy else 0)
        if busy:
            assert foreign.getsockname()[1] == port and foreign.fileno() >= 0
        else:
            with socket.socket() as restored:
                restored.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                restored.bind(("127.0.0.1", port))
    result = json.loads((output / "boundary-result.json").read_text())
    assert result["finished"] is not busy
    if busy:
        assert "OSError" in result["error"]
    assert result["cleanup_failures"] == [] and cleaned == [root]
    assert not receipts.section_execution(output, "job-sandbox", "systrap", "run")["complete"]


def test_installed_boundary_selection_uses_current_journeys_and_preserves_hardware_scope():
    assert set(BOUNDARY_SECTIONS) <= set(SECTIONS["systrap"])
    assert {"job-sandbox", "job-network", "mounts"} <= set(SECTIONS["kvm"]) & set(SECTIONS["vz"])
    assert "docker" not in SECTIONS["kvm"] + SECTIONS["vz"]
    spec = importlib.util.spec_from_file_location("live_mount_probe", ROOT / "tests/nested-linux/live_mount_backend_proof.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.run_proof)
    result = subprocess.run([sys.executable, str(ROOT / "tests/blackbox/installed_boundaries.py"), "--help"],
                            capture_output=True, text=True, timeout=10, env=dict(os.environ, PYTHONPATH=""))
    assert result.returncode == 0 and "job-network" in result.stdout
