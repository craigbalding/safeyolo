"""Exercise boundary observers against real owned TCP and Unix receivers."""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.blackbox import execution_receipt as receipts
from tests.blackbox import installed_boundaries as boundaries
from tests.blackbox import installed_docker_preflight as docker
from tests.blackbox.host import job_network, job_sandbox
from tests.blackbox.selections import BOUNDARY_SECTIONS, PROCEDURES, SECTIONS

ROOT = Path(__file__).resolve().parents[1]


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
def test_docker_origins_require_exact_independent_effects_and_cleanup(tmp_path, monkeypatch, defect):
    base = tmp_path / "base"
    base.mkdir()
    (base / "config.toml").write_text("")
    args = SimpleNamespace(prepared_config=base, output=tmp_path / "docker")
    receipt = receipts.ProcedureReceipt("docker", tmp_path / "receipt/result.json")
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
        count = 2 if defect == "allowed-missing" else 3
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
        return {"cleanup": "stopped"}

    monkeypatch.setattr(docker, "run", journey)
    monkeypatch.delenv("SAFEYOLO_DOCKER_ORIGIN_BIND", raising=False)
    if defect:
        with pytest.raises((AssertionError, OSError)):
            docker.recurring_journey(args, receipt)
        assert not receipt.document["finished"]
    else:
        result = docker.recurring_journey(args, receipt)
        assert result["owned_origins"]["allowed_accepts"] == 5
        assert result["owned_origins"]["denied_accepts"] == 2
        assert receipt.document["finished"]
    assert len(servers) == 2 and all(server.closed for server in servers)


@pytest.mark.parametrize("section", BOUNDARY_SECTIONS)
def test_boundary_preparation_failure_is_incomplete_and_keeps_cleanup_result(tmp_path, monkeypatch, section):
    args = SimpleNamespace(output=tmp_path / "reports", prepared_config=tmp_path / "prepared",
                           root=tmp_path / "fresh", section=section, revision="a" * 40, lane="systrap")
    monkeypatch.setattr(boundaries, "_cli_identity", lambda _cli: {"source_revision": "b" * 40})
    stopped = []
    monkeypatch.setattr(boundaries, "cleanup_instance", lambda cli, root: stopped.append(root) or [])
    with pytest.raises(AssertionError, match="selected revision"):
        boundaries.run(args)
    result = json.loads((args.output / "boundary-result.json").read_text())
    assert not result["finished"] and result["cleanup_failures"] == []
    assert "selected revision" in result["error"] and stopped == [args.root]
    assert not receipts.section_execution(args.output, section, "systrap", "run")["complete"]


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
