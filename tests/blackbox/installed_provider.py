#!/usr/bin/env python3
"""Compose a native HTTP service through two real Linux/systrap sandboxes.

On an owned Linux host, supply Python 3.11+, tomlkit, a prepared installation
with the selected CLI/proxy/guest binaries and pinned runsc, and a free Admin
port. --root and --output must be new disk-backed directories with traversable
parents. The driver reuses immutable inputs, creates two credential-free agents,
grants only the caller's reader capability, exercises refusal and revocation,
then stops its guests, proxy and broker. It preserves the prepared installation.
No model, external service credential or Coord message is used.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import tomlkit

from tests.blackbox.guest_exec import guest_command_args
from tests.blackbox.installed_host_smoke import (
    _agent_listeners,
    _native_config,
    _require_disposable,
    _runtime_observation,
    _sha256,
)
from tests.blackbox.installed_ingress import runsc_identity
from tests.blackbox.installed_lifecycle import running_guest
from tests.blackbox.installed_sections import (
    copy_prepared_nats,
    owned_processes,
    prepare_native_instance,
    surviving_processes,
)

SERVICE = """schema_version: 1
name: proofspot
default_host: proofspot.safeyolo.internal
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /api/v1/**
"""
NAMES = ("proofspot", "caller")


def checked(command, *, env=None, timeout=90, diagnostics=None):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)
    if diagnostics is not None:
        with diagnostics.open("a") as log:
            log.write(f"{json.dumps(command)}: exit {result.returncode}\n{result.stderr}\n")
    if result.returncode:
        # Native authorization views can contain gateway tokens. Do not put
        # command output in an assertion or the returned nonsecret report.
        raise RuntimeError(f"{Path(command[0]).name} failed with exit {result.returncode}")
    return result.stdout


class ParentObserver(HTTPServer):
    """Count TCP accepts, including attempts that never form an HTTP request."""

    def __init__(self):
        self.accepts = 0
        super().__init__(("127.0.0.1", 0), ParentResponse)

    def get_request(self):
        connection, address = super().get_request()
        self.accepts += 1
        connection.settimeout(5)
        return connection, address


class ParentResponse(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b"fallback")

    def log_message(self, *_args):
        pass  # The observer retains only its accept count, never HTTP headers.


def origin_observation(workspace):
    accepts = workspace / "accepts"
    requests = workspace / "requests.tsv"
    return {
        "accepts": len(accepts.read_text().splitlines()) if accepts.exists() else 0,
        "requests": [line.split("\t") for line in requests.read_text().splitlines()]
        if requests.exists() else [],
    }


def client_observation(workspace):
    path = workspace / "results.tsv"
    if not path.exists():
        return {}
    return {label: {"status": int(status), "body_sha256": digest}
            for label, status, digest in (line.split("\t") for line in path.read_text().splitlines())}


def wait_file(path, child):
    deadline = time.monotonic() + 65
    while not path.exists():
        if child.poll() is not None:
            raise RuntimeError(f"guest command exited before {path.name}: {child.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"guest command did not reach {path.name}")
        time.sleep(0.05)


def prepare(base, root, admin_port, parent_port):
    prepare_native_instance(base, root)
    root.chmod(0o755)
    (root / "data").chmod(0o755)
    (root / ".safeyolo-platform-smoke").touch()
    copy_prepared_nats(base, root)
    config = tomlkit.parse((root / "config.toml").read_text())
    assert "linux" in config, "the prepared installation needs native Linux settings"
    config.update(admin_port=admin_port, flow_store_enabled=False,
                  parent_proxy=f"http://127.0.0.1:{parent_port}",
                  gateway_services_dir="services", gateway_builtin_services_dir="builtin-services")
    (root / "config.toml").write_text(tomlkit.dumps(config))
    (root / "services/proofspot.yaml").write_text(SERVICE)
    (root / "policy.toml").write_text('''[hosts."proofspot.safeyolo.internal"]
service = "proofspot"
egress = "deny"
[hosts."proofspot.safeyolo.internal:8088"]
egress = "allow"
[hosts."*"]
egress = "deny"
[controls.network]
enabled = true
action = "block"
''')


def inputs(base, revision):
    result = {}
    for name, path in (("cli", base / "bin/safeyolo"), ("proxy", base / "bin/safeyolo-proxy"),
                       ("guest", base / "assets/guest/safeyolo-guest")):
        version = checked([str(path), "--version"]).strip()
        assert f"commit={revision}" in version, f"{name} does not match the selected source"
        result[name] = {"path": str(path.resolve()), "sha256": _sha256(path), "version": version}
    result["rootfs"] = str((base / "share/rootfs-tree").resolve(strict=True))
    for name in ("package-info", "share/guest-selection.json"):
        if (base / name).is_file():
            result[name] = (base / name).read_text()
    return result


def run(args):
    base, root, output = args.prepared_config.resolve(), args.root.resolve(), args.output.resolve()
    assert not root.exists(), "--root must be new"
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"started_at": datetime.now(UTC).isoformat(), "revision": args.revision,
              "root": str(root), "status": "failed", "cleanup": "unverified"}
    original = {base / name: (base / name).read_bytes() for name in ("config.toml", "policy.toml")}
    cli = str(base / "bin/safeyolo")
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_NATS_TEST_INSTANCE": uuid.uuid4().hex,
                        "SAFEYOLO_RUNSC_DEBUG": "1", "SAFEYOLO_RUNSC_PLATFORM": "systrap",
                        "TMPDIR": str(root / "data/tmp")}

    def native(*arguments):
        return checked([cli, "--root", str(root), *arguments], env=env,
                       diagnostics=output / "native.log")
    producer, caller = root / "workspaces/proofspot", root / "workspaces/caller"
    children = []
    parent = ParentObserver()
    parent_thread = threading.Thread(target=parent.serve_forever)
    parent_thread.start()
    try:
        report["inputs"] = inputs(base, args.revision)
        prepare(base, root, args.admin_port, parent.server_port)
        (root / "data/tmp").mkdir(mode=0o755)
        _require_disposable(root)
        for name in NAMES:
            workspace = root / "workspaces" / name
            workspace.mkdir(parents=True, mode=0o755)
            native("agent", "create", name, "--workspace", str(workspace), "--memory", "512")
        for filename, workspace in (("provider-origin.sh", producer), ("provider-caller.sh", caller)):
            source = Path(__file__).parent / "isolation" / filename
            target = workspace / filename
            target.write_bytes(source.read_bytes())
            target.chmod(0o755)
        native("start")
        native("services", "authorize", "caller", "proofspot", "--capability", "reader")
        report["participants"] = {}
        for name in NAMES:
            native("agent", "start", name, "--sandbox-only")
            status = json.loads(native("agent", "status", name))
            listener = next(row for row in _agent_listeners(root) if row["agent_id"] == name)
            report["participants"][name] = {
                "runtime": running_guest(root, name, status),
                "ingress": runsc_identity(root, name, Path(listener["path"]), platform="systrap"),
                "interfaces": native("agent", "shell", name, "-c", "ls /sys/class/net").split(),
                "guest_sha256": _sha256(root / "agents" / name / "config-share/safeyolo-guest"),
            }
            assert report["participants"][name]["interfaces"] == ["lo"]
            assert report["participants"][name]["guest_sha256"] == report["inputs"]["guest"]["sha256"]
        native_config = _native_config(root / "config.toml", root)
        report["proxy"] = _runtime_observation(root, native_config, base / "bin/safeyolo-proxy",
            config_path=root / "config.toml", working_directory=root, require_running=True,
            require_authenticated_identity=True)
        doctor = json.loads(native("doctor"))
        runtime_path = Path(doctor["linux"]["path"])
        report["runsc"] = {**doctor["linux"], "sha256": _sha256(runtime_path)}

        def guest_process(name, command):
            log = (output / f"{name}.log").open("wb")
            try:
                child = subprocess.Popen(guest_command_args(cli, name, command, env=env),
                                         env=env, stdout=log, stderr=log)
            finally:
                log.close()
            children.append(child)
            return child

        server = guest_process("proofspot", "echo $$ > /workspace/server.pid; "
            "exec socat TCP4-LISTEN:8088,bind=127.0.0.1,reuseaddr,fork EXEC:/workspace/provider-origin.sh")
        # Inspect the listener without generating an origin accept.
        native("agent", "shell", "proofspot", "-c",
               "for ((i=0;i<200;i++)); do ss -ltnH 'sport = :8088' | "
               "grep -q . && exit 0; sleep 0.1; done; exit 1")
        worker = guest_process("caller", "exec /bin/bash /workspace/provider-caller.sh")

        def phase(name, expected, count):
            if name != "refusals":
                (caller / f"{name}.go").touch()
            wait_file(caller / f"{name}.ready", worker)
            report["clients"] = client_observation(caller)
            report["origin"] = origin_observation(producer)
            report["parent_accepts"] = parent.accepts
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            assert all(report["clients"][label]["status"] in statuses
                       for label, statuses in expected.items()), report["clients"]
            assert report["origin"]["accepts"] == count, report["origin"]
            assert parent.accepts == 0, "provider route reached the ordinary parent transport"

        phase("refusals", {name: {403} for name in ("method", "path", "destination", "port")}, 0)
        unrelated = native("agent", "shell", "proofspot", "-c",
            "curl --silent --show-error --max-time 15 --output /dev/null --write-out '%{http_code}' "
            "-H 'X-SafeYolo-Agent-ID: forged-id' "
            "http://proofspot.safeyolo.internal:8088/api/v1/value")
        report["unrelated_identity_status"] = int(unrelated)
        report["origin"] = origin_observation(producer)
        assert int(unrelated) == 403 and report["origin"]["accepts"] == 0
        phase("allowed", {"allowed": {200}}, 1)
        caller_id = report["participants"]["caller"]["runtime"]["agent_id"]
        assert report["origin"]["requests"] == [["GET /api/v1/value HTTP/1.1", caller_id, "caller",
                                                "proofspot.safeyolo.internal:8088", "0", "0", "1", "1"]]
        assert report["clients"]["allowed"]["body_sha256"] == hashlib.sha256(b"native-http-service\n").hexdigest()
        native("services", "revoke", "caller", "proofspot")
        phase("revoked", {"revoked": {403}}, 1)
        native("services", "authorize", "caller", "proofspot", "--capability", "reader")
        phase("recovered", {"recovered": {200}}, 2)
        assert report["origin"]["requests"] == [report["origin"]["requests"][0]] * 2
        assert report["clients"]["recovered"]["body_sha256"] == report["clients"]["allowed"]["body_sha256"]
        native("agent", "shell", "proofspot", "-c", 'kill -TERM "$(cat /workspace/server.pid)"')
        server.wait(timeout=20)
        phase("closed", {"closed": {502, 503}}, 2)
        native("agent", "stop", "proofspot")
        phase("stopped", {"stopped": {502, 503}}, 2)
        assert worker.wait(timeout=20) == 0
        # Prove that the parent observer was live throughout the zero-hit checks.
        control = http.client.HTTPConnection("127.0.0.1", parent.server_port, timeout=5)
        try:
            control.request("GET", "/positive-control")
            response = control.getresponse()
            assert response.status == 200 and response.read() == b"fallback"
        finally:
            control.close()
        report["parent_control_accepts"] = parent.accepts
        assert parent.accepts == 1
        report["status"] = "passed"
    finally:
        report["origin"] = origin_observation(producer)
        report["clients"] = client_observation(caller)
        failures = []
        if (root / ".safeyolo-platform-smoke").is_file():
            try:
                processes = owned_processes(root)
            except (OSError, ValueError) as error:
                # A broken receipt must not prevent stopping the owned instance.
                processes = []
                failures.append(f"cannot inspect owned processes: {error}")
            # The producer was stopped during the unavailable-provider case.
            # Its removed PID file must not hide a surviving original backend.
            processes.extend({"pid": row["runtime"]["backend_pid"],
                              "start_token": row["runtime"]["backend_token"]}
                             for row in report.get("participants", {}).values())
            try:
                native("stop")
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
            for child in children:
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    failures.append("native guest command survived owned stop")
            failures.extend(surviving_processes(processes))
            if (root / "data/ready.json").exists():
                failures.append("proxy readiness survived owned stop")
            for row in _agent_listeners(root):
                with socket.socket(socket.AF_UNIX) as listener:
                    if listener.connect_ex(row["path"]) == 0:
                        failures.append("owned agent listener survived stop")
        for path, content in original.items():
            if path.read_bytes() != content:
                failures.append(f"prepared input changed: {path.name}")
        parent.shutdown()
        parent.server_close()
        parent_thread.join(timeout=10)
        if parent_thread.is_alive():
            failures.append("parent observer thread survived stop")
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures,
                      finished_at=datetime.now(UTC).isoformat())
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        assert not failures, failures
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-config", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--admin-port", type=int, required=True)
    args = parser.parse_args()
    report = run(args)
    print(json.dumps({"status": report["status"], "cleanup": report["cleanup"],
                      "report": str(args.output / "result.json")}))


if __name__ == "__main__":
    main()
