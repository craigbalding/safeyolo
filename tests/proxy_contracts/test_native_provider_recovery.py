"""Real Linux holder-loss witness with the installed native product and runsc.

On an owned Ubuntu/systrap host, supply SAFEYOLO_NATIVE_BUNDLE (the selected
candidate), SAFEYOLO_PLATFORM_ASSETS (prepared rootfs-tree) and
SAFEYOLO_971_RUNSC (absolute verified runsc). The ordinary host needs uidmap,
subordinate IDs 100000–165535 and nsenter. The guest needs python3 for the
synthetic HTTP service. Use a short disk-backed pytest --basetemp directory.
No proxy or sandbox needs to be running. This test installs a fresh instance,
starts only its provider sandbox, kills/reaps its verified namespace holder,
then stops its owned backend and proxy. It launches no coding model.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import signal
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.blackbox.harness.process_identity import process_start_token
from tests.proxy_contracts.harness import connection, request
from tests.proxy_contracts.test_gateway_provider import SERVICE
from tests.proxy_contracts.test_native_policy_cli import native_instance

POLICY = '''[hosts."proofspot.safeyolo.internal"]
service = "proofspot"
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
agent_id = "ag-11111111111111111111111111111111"
[agents.alice.services.proofspot]
capability = "assessment"
'''
SERVICE_CODE = '''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"owned-provider-971"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 8764), Handler)
Path("/workspace/service-ready").write_text("ready")
server.serve_forever()
'''


@contextmanager
def adopt_fixture_children():
    """Reap the detached holder in this test process; restore its prior setting."""
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0  # PR_GET_CHILD_SUBREAPER
    assert libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
    try:
        yield
    finally:
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0


def kill_owned_process(pid, token):
    """Bind this fixture signal to the recorded birth, then reap that child."""
    descriptor = os.pidfd_open(pid)
    try:
        assert process_start_token(pid) == token, "fixture process identity changed"
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        reap_owned_process(pid)
    finally:
        os.close(descriptor)


def reap_owned_process(pid):
    """Wait at most five seconds for a fixture child to exit and reap it."""
    deadline = time.monotonic() + 5
    while os.waitpid(pid, os.WNOHANG)[0] == 0:
        assert time.monotonic() < deadline, "owned fixture child did not exit"
        time.sleep(0.02)


@pytest.mark.skipif(
    os.uname().sysname != "Linux" or not (
        os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
        and os.environ.get("SAFEYOLO_PLATFORM_ASSETS")
        and os.environ.get("SAFEYOLO_971_RUNSC")
    ),
    reason="requires the selected native bundle and an owned Linux runsc/rootfs host",
)
@pytest.mark.timeout(240)
def test_authorized_provider_survives_only_its_holder_loss(tmp_path):
    runsc = Path(os.environ["SAFEYOLO_971_RUNSC"])
    assert runsc.is_absolute() and runsc.is_file()
    # Seed the service before startup; native install permits directories but
    # refuses existing instance configuration, policy or credentials.
    services = tmp_path / "installed/services"
    services.mkdir(parents=True)
    (services / "proofspot.yaml").write_text(SERVICE)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "service.py").write_text(SERVICE_CODE)
    with adopt_fixture_children(), native_instance(
        tmp_path, POLICY, services=True,
        platform_assets=Path(os.environ["SAFEYOLO_PLATFORM_ASSETS"]),
    ) as instance:
        # The installed fixture filters PATH to its private bin directory.
        # Make the actual native runtime tools available there, with no shell
        # wrappers or alternate forwarding route.
        for name in ("unshare", "tail", "newuidmap", "newgidmap", "nsenter", "ip", "cp"):
            executable = shutil.which(name)
            assert executable, f"missing host prerequisite: {name}"
            (instance.root / "bin" / name).symlink_to(executable)
        for name in ("aa-exec", "systemctl", "systemd-run"):
            if executable := shutil.which(name):
                (instance.root / "bin" / name).symlink_to(executable)
        (instance.root / "bin/runsc").symlink_to(runsc)
        created = instance.cli("agent", "create", "proofspot", "--workspace", str(workspace),
                               "--launcher", "supervisor", "--memory", "512")
        assert created.returncode == 0, created.stderr
        saved = None
        held = None
        try:
            started = instance.cli("agent", "start", "proofspot", "--sandbox-only", timeout=150)
            assert started.returncode == 0, started.stderr
            agent = instance.root / "agents/proofspot"
            saved = json.loads((agent / "runtime.json").read_text())
            holder, backend = saved["holder_pid"], saved["backend_pid"]
            assert holder != backend
            assert process_start_token(holder) == saved["holder_token"]
            assert process_start_token(backend) == saved["backend_token"]
            arguments = Path(f"/proc/{backend}/cmdline").read_bytes().split(b"\0")
            run_id = "safeyolo-" + saved["run_id"]
            assert b"boot" in arguments and run_id.encode() in arguments
            root_argument = str(instance.root / "run").encode()
            assert ((b"--root=" + root_argument) in arguments or
                    any(pair == [b"--root", root_argument] for pair in
                        (arguments[index:index + 2] for index in range(len(arguments) - 1))))
            for kind in ("user", "net"):
                operator_namespace = Path(f"/proc/self/ns/{kind}").stat().st_ino
                assert Path(f"/proc/{holder}/ns/{kind}").stat().st_ino != operator_namespace
                assert Path(f"/proc/{backend}/ns/{kind}").stat().st_ino != operator_namespace
            service = instance.cli("agent", "shell", "proofspot", "-c",
                                   "cd /workspace; python3 /workspace/service.py"
                                   " </dev/null >service.log 2>&1 &")
            assert service.returncode == 0, service.stderr
            deadline = time.monotonic() + 15
            while not (workspace / "service-ready").is_file():
                assert time.monotonic() < deadline, "guest HTTP service did not start"
                time.sleep(0.05)
            tokens = instance.agent_api("alice", "/gateway/services")
            token = tokens["authorized"]["proofspot"]["token"]
            url = "http://proofspot.safeyolo.internal:8764/api/v1/ready"
            headers = {"Authorization": f"Bearer {token}"}
            held = connection(instance.paths["alice"])
            held.request("GET", url, headers=headers)
            reply = held.getresponse()
            assert reply.status == 200 and reply.read() == b"owned-provider-971"
            foreign_id = "safeyolo-0123456789abcdef0123456789abcdef"
            foreign_state = instance.root / "run" / f"{foreign_id}_sandbox:{foreign_id}.state"
            foreign_lock = foreign_state.with_suffix(".lock")
            foreign_state.write_bytes(b"foreign incarnation canary")
            foreign_lock.write_bytes(b"foreign lock canary")
            kill_owned_process(holder, saved["holder_token"])
            recovered = instance.cli("agent", "status", "proofspot")
            assert recovered.returncode == 0, recovered.stderr
            status = json.loads(recovered.stdout)
            assert (status["runtime_state"], status["control_state"]) == ("degraded", "recovered")
            assert status["run_id"] == saved["run_id"] and status["port_forward"] is True
            assert process_start_token(backend) == saved["backend_token"]
            # Keep the original authorized connection, and also require a new
            # stream through recovered namespace control in the same session.
            held.request("GET", url, headers=headers)
            reply = held.getresponse()
            assert reply.status == 200 and reply.read() == b"owned-provider-971"
            code, _, body = request(instance.paths["alice"], url, headers=headers)
            assert code == 200 and body == b"owned-provider-971"
            code, _, body = request(instance.paths["alice"], url.replace(":8764", ":8765"), headers=headers)
            assert code == 502 and json.loads(body) == {"error": "Proxy request failed"}
            held.close()
            held = None
            stopped = instance.cli("agent", "stop", "proofspot")
            assert stopped.returncode == 0, stopped.stderr
            assert json.loads(stopped.stdout)["runtime_state"] == "stopped"
            reap_owned_process(backend)
            assert process_start_token(backend) is None
            assert not list((instance.root / "run").glob(f"{run_id}_sandbox:{run_id}.*"))
            assert foreign_state.read_bytes() == b"foreign incarnation canary"
            assert foreign_lock.read_bytes() == b"foreign lock canary"
            repeated = instance.cli("agent", "stop", "proofspot")
            assert repeated.returncode == 0, repeated.stderr
            print(json.dumps({"run_id": saved["run_id"], "holder_pid": holder,
                              "backend_pid": backend, "recovered_control": status["control_state"],
                              "held_and_fresh_authorized_requests": 3, "closed_port_status": code,
                              "owned_backend_stopped": True, "foreign_state_preserved": True,
                              "repeat_stop": json.loads(repeated.stdout)["runtime_state"]}))
        finally:
            if held is not None:
                held.close()
            cleanup = instance.cli("agent", "stop", "proofspot")
            if saved is not None:
                # Preserve a failed product stop as a test failure. Reap only
                # these test-owned births so fixture teardown leaves no backend.
                for key in ("backend", "holder"):
                    pid, token = saved[f"{key}_pid"], saved[f"{key}_token"]
                    if process_start_token(pid) == token:
                        kill_owned_process(pid, token)
            assert cleanup.returncode == 0, cleanup.stderr
