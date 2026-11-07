#!/usr/bin/env python3
"""Probe nested Docker in one disposable installed Linux/systrap sandbox.

On an owned Linux host, supply a prepared installation, this source checkout,
Python 3.11+ with tomlkit, and a free Admin port. Root/output must be new,
disk-backed paths with traversable parents. --nested-docker selects the
candidate's guest configuration; without it the driver records the default.
The guest installs Debian Docker packages through its normal proxy, attempts
one local daemon/pull/container and stops. --journey additionally runs the
Compose lifecycle, sandbox recovery and application-bound provider controls.
--reuse-root continues this probe's stopped disposable instance without
replacing its policy, registry approvals or prepared inputs. Run only after
any retained registry refusal has been resolved; the driver does not approve
or retry a failed operation. Independent acceptance remains separate.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shlex
import shutil
import subprocess
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

import tomlkit

from tests.blackbox.guest_exec import guest_command_args
from tests.blackbox.installed_host_smoke import _agent_listeners, _native_config, _runtime_observation, _sha256
from tests.blackbox.installed_ingress import runsc_identity
from tests.blackbox.installed_lifecycle import running_guest
from tests.blackbox.installed_provider import (
    ParentObserver,
    capture_guest_command,
    checked,
    client_observation,
    wait_file,
)
from tests.blackbox.installed_sections import (
    copy_prepared_nats,
    owned_processes,
    prepare_native_instance,
    surviving_processes,
)

POLICY = '''[hosts."deb.debian.org"]
egress = "allow"
[hosts."security.debian.org"]
egress = "allow"
[hosts."auth.docker.io"]
egress = "allow"
[hosts."registry-1.docker.io"]
egress = "allow"
[hosts."production.cloudflare.docker.com"]
egress = "allow"
[hosts."production.cloudfront.docker.com"]
egress = "allow"
[hosts."example.com"]
egress = "allow"
[hosts."*"]
egress = "deny"
[controls.network]
enabled = true
action = "block"
'''
STATE = "/home/agent/docker-journey"
DOCKER = "docker --host=unix:///run/safeyolo-nested-docker/docker.sock"
COMPOSE = f"{DOCKER} compose --project-directory {STATE}/context"
SERVICE = '''schema_version: 1
name: notes
default_host: notes.safeyolo.internal
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /api/v1/notes
'''


def compose_journey(args, root, output, workspace, native, guest, background, report):
    """Run one finite application journey against the hosting guest's daemon."""
    fixture = workspace / "nested-docker"
    shutil.copytree(Path(__file__).parent / "fixtures/nested-docker", fixture)
    # Exercise freshly initialized certificate bytes and permissions without
    # altering the retained instance's CA or copying its private material.
    fresh = output / "fresh-init"
    native("init", instance=fresh)
    certificate = fresh / "certs/mitmproxy-ca-cert.pem"
    report["fresh_init_modes"] = {name: (fresh / name).stat().st_mode & 0o777 for name in (
        "certs/mitmproxy-ca-cert.pem", "certs/mitmproxy-ca.pem", "data/admin_token", "data/agent_token")}
    assert report["fresh_init_modes"] == {
        "certs/mitmproxy-ca-cert.pem": 0o644, "certs/mitmproxy-ca.pem": 0o600,
        "data/admin_token": 0o600, "data/agent_token": 0o600}
    shutil.copy2(certificate, fixture / "fresh-ca.crt")
    reader = guest("sudo -n -u _apt sha256sum /workspace/nested-docker/fresh-ca.crt", "fresh-ca-reader")
    assert reader.split()[0] == _sha256(certificate), "_apt could not read the fresh public CA"
    guest("sudo -n -u _apt cat /usr/local/share/ca-certificates/safeyolo.crt >/dev/null", "installed-ca-reader")

    def packages(label):
        guest("if ! command -v dockerd >/dev/null || ! docker compose version >/dev/null 2>&1; then "
              "sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends "
              "docker.io docker-cli docker-compose; fi", label, timeout=300)

    def start_daemon(label):
        data_root = f"env SAFEYOLO_DOCKER_DATA_ROOT={shlex.quote(args.docker_data)} " if args.docker_data else ""
        child = background("notes", f"exec sudo -n {data_root}bash /workspace/docker-preflight.sh {STATE} --daemon", label)[0]
        guest(f"for ((i=0;i<150;i++)); do version=$(sudo -n {DOCKER} info --format '{{{{.ServerVersion}}}}' "
              "2>/dev/null) || version=; [[ -n $version ]] && exit 0; sleep 0.1; done; exit 1", f"{label}-ready")
        assert child.poll() is None, "daemon exited after readiness"
        return child

    def docker(command, label, timeout=90):
        return guest(f"sudo -n env DOCKER_BUILDKIT=0 DOCKER_CONFIG={STATE}/client {command}", label, timeout=timeout)

    def notes(expected, label):
        body = guest("for ((i=0;i<100;i++)); do "
                     "if curl --silent --fail --max-time 3 http://127.0.0.1:8088/api/v1/notes; then exit 0; fi; "
                     "sleep 0.1; done; exit 1", label)
        assert json.loads(body) == expected, f"unexpected notes during {label}"

    packages("packages")
    guest(f"test ! -e {STATE}; mkdir -p {STATE}; cp -a /workspace/nested-docker {STATE}/context; "
          f"cp /usr/local/share/ca-certificates/safeyolo.crt {STATE}/context/safeyolo.crt", "context")
    daemon = start_daemon("daemon-initial")
    if not args.docker_data:
        docker(f"{DOCKER} pull debian:trixie-slim", "image-pull", timeout=180)
    report["base_image"] = json.loads(docker(f"{DOCKER} image inspect debian:trixie-slim", "image-identity"))
    report["reused_image_data"] = args.docker_data
    # Keep an unexpected 428 or transport error as a failure, not a denial pass.
    denied = guest(f"sudo -n {DOCKER} pull denied.invalid/safeyolo/never:qualification "
                   f">{STATE}/denied-image.log 2>&1 && exit 1; "
                   f"cat {STATE}/denied-image.log; grep -Eq '403|Forbidden' {STATE}/denied-image.log", "image-denied")
    assert "428" not in denied, "image refusal requires operator diagnosis"
    build = docker(f"{COMPOSE} build --no-cache store", "compose-build", timeout=240)
    docker(f"{COMPOSE} create", "compose-create")
    docker(f"{COMPOSE} start", "compose-start")
    notes([], "notes-empty")
    marker = "persist-" + uuid.uuid4().hex
    body = shlex.quote(json.dumps({"text": marker}))
    guest(f"curl --silent --show-error --fail -H 'Content-Type: application/json' --data {body} "
          "http://127.0.0.1:8088/api/v1/notes", "notes-write")
    notes([marker], "notes-written")
    report["docker_info"] = json.loads(docker(f"{DOCKER} info --format '{{{{json .}}}}'", "docker-info"))
    assert report["docker_info"]["Driver"] == "vfs"
    identifiers = docker(f"{COMPOSE} ps --quiet", "compose-ps").split()
    assert len(identifiers) == 2, "both application services must run"
    report["containers"] = json.loads(docker(f"{DOCKER} inspect " + shlex.join(identifiers), "compose-inspect"))
    assert all(row["State"]["Running"] and row["State"]["Pid"] > 1 and
               row["HostConfig"]["NetworkMode"] == "host" for row in report["containers"])
    for index, identifier in enumerate(identifiers):
        docker(f"{DOCKER} top {shlex.quote(identifier)}", f"container-processes-{index}")
    guest("ps -eo pid,ppid,uid,args; cat /proc/self/mountinfo; ip -j link; ip -j route", "outer-boundary")
    host_file = output / ("unshared-" + uuid.uuid4().hex)
    host_file.write_text("host-only qualification marker\n")
    report["unshared_host_file"] = str(host_file)
    guest("sudo -n test ! -e " + shlex.quote(str(host_file)), "guest-root-cannot-read-unshared-host-file")
    probe_environment = ["PROBE_PHASE=privileged", f"PROBE_HOST={args.host_address}",
                         f"PROBE_HOST_PORT={args.host_port}", f"PROBE_HOST_FILE={host_file}"]
    application = docker(f"{COMPOSE} exec -T " + " ".join(f"-e {shlex.quote(value)}" for value in (
        "PROBE_PHASE=application", f"PROBE_HOST={args.host_address}",
        f"PROBE_HOST_PORT={args.host_port}", f"PROBE_HOST_FILE={host_file}")) +
        " api python3 /app/network_probe.py", "application-network")
    privileged = docker(f"{DOCKER} run --rm --privileged --network=host "
                        "--env HTTP_PROXY --env HTTPS_PROXY " +
                        " ".join(f"--env {shlex.quote(value)}" for value in probe_environment) +
                        " nested-notes:qualification python3 /app/network_probe.py", "privileged-network")
    report["network_probes"] = []
    for log in (build, application, privileged):
        for line in log.splitlines():
            if '{"phase":' in line:
                report["network_probes"].append(json.loads(line[line.index('{"phase":'):]))
    assert len(report["network_probes"]) == 6, "build, application and privileged probes must each test both destinations"
    docker(f"{COMPOSE} logs --no-color", "compose-logs")
    docker(f"{COMPOSE} exec -T api python3 -c 'print(\"compose-exec-ran\")'", "compose-exec")
    docker(f"{COMPOSE} restart", "compose-restart")
    notes([marker], "after-container-restart")
    docker(f"{COMPOSE} stop", "compose-stop")
    docker(f"{COMPOSE} down", "compose-remove")
    assert not docker(f"{COMPOSE} ps --all --quiet", "removed-containers").strip()
    docker(f"{COMPOSE} up --no-build --pull never -d", "compose-recreate")
    notes([marker], "after-recreation")
    docker(f"{DOCKER} volume inspect nested-notes_notes", "volume-before-sandbox-stop")
    first = report["runtime"]
    native("agent", "stop", "notes")
    daemon.wait(timeout=20)
    assert not surviving_processes([{"pid": first["backend_pid"], "start_token": first["backend_token"]}])
    native("agent", "start", "notes", "--sandbox-only")
    second = running_guest(root, "notes", json.loads(native("agent", "status", "notes")))
    report["recovery"] = {"before": first, "after": second}
    assert second["agent_id"] == first["agent_id"] and second["run_id"] != first["run_id"]
    assert _sha256(root / "agents/notes/config-share/safeyolo-guest") == report["inputs"]["guest"]["sha256"]
    guest("test ! -S /run/safeyolo-nested-docker/docker.sock", "daemon-not-running-after-boot")
    packages("packages-after-boot")
    start_daemon("daemon-recovered")
    docker(f"{COMPOSE} up --no-build --pull never -d", "application-recovered")
    notes([marker], "after-sandbox-restart")
    docker(f"{COMPOSE} down --volumes", "explicit-data-deletion")
    assert not docker(f"{DOCKER} volume ls --quiet --filter name=nested-notes_notes", "deleted-volume").strip()
    docker(f"{COMPOSE} up --no-build --pull never -d", "recreate-empty-data")
    notes([], "after-data-deletion")
    provider_controls(root, output, native, guest, background, docker, report)


def provider_controls(root, output, native, guest, background, docker, report):
    """Use the existing provider controls at the actual nested application's binding."""
    caller = root / "docker-caller"
    caller.mkdir(mode=0o755)
    shutil.copy2(Path(__file__).parent / "isolation/provider-caller.sh", caller)
    native("agent", "create", "dockercaller", "--workspace", str(caller), "--memory", "512")
    native("agent", "start", "dockercaller", "--sandbox-only")
    caller_runtime = running_guest(root, "dockercaller", json.loads(native("agent", "status", "dockercaller")))
    report["caller"] = caller_runtime
    config_path = root / "config.toml"
    original = config_path.read_bytes()
    parent = ParentObserver()
    parent_thread = threading.Thread(target=parent.serve_forever)
    parent_thread.start()
    try:
        # Only the provider controls use the fallback observer. Real image,
        # build and application egress already used the approved parent route.
        native("stop")
        config = tomlkit.parse(original.decode())
        config["parent_proxy"] = f"http://127.0.0.1:{parent.server_port}"
        config_path.write_text(tomlkit.dumps(config))
        native("start")
        url = "http://notes.safeyolo.internal:8088/api/v1/notes"
        unapproved = guest("curl --silent --show-error --max-time 20 --output /dev/null --write-out '%{http_code}' "
                           "-H 'X-SafeYolo-Agent-ID: forged-approved' " + url, "unapproved-caller", agent="dockercaller")
        assert int(unapproved) == 403
        native("services", "authorize", "dockercaller", "notes", "--capability", "reader")
        worker = background("dockercaller", "exec bash /workspace/provider-caller.sh /workspace notes /api/v1/notes",
                            "provider-caller")[0]

        def phase(name, expected):
            if name != "refusals":
                (caller / f"{name}.go").touch()
            wait_file(caller / f"{name}.ready", worker)
            clients = report["provider_clients"] = client_observation(caller)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            assert all(clients[label]["status"] in statuses for label, statuses in expected.items())
            assert parent.accepts == 0, "provider request used ordinary-network fallback"

        phase("refusals", {name: {403} for name in ("method", "path", "destination", "port")})
        phase("allowed", {"allowed": {200}})
        native("services", "revoke", "dockercaller", "notes")
        phase("revoked", {"revoked": {403}})
        native("services", "authorize", "dockercaller", "notes", "--capability", "reader")
        phase("recovered", {"recovered": {200}})
        assert report["provider_clients"]["allowed"]["body_sha256"] == report["provider_clients"]["recovered"]["body_sha256"]
        logs = docker(f"{COMPOSE} logs --no-color --no-log-prefix api", "provider-origin")
        requests = report["provider_origin"] = [json.loads(line) for line in logs.splitlines() if line.startswith('{"role":')]
        forwarded = [row for row in requests if row["caller_ids"]]
        assert len(forwarded) == 2, "refused requests reached the application"
        assert all(row["caller_ids"] == [caller_runtime["agent_id"]] and
                   row["caller_names"] == ["dockercaller"] and row["authorization_count"] == 0 and
                   row["legacy_identity_count"] == 0 for row in forwarded), "forged headers changed authority"
        docker(f"{COMPOSE} stop api", "close-application-port")
        phase("closed", {"closed": {502, 503}})
        native("agent", "stop", "notes")
        phase("stopped", {"stopped": {502, 503}})
        assert worker.wait(timeout=20) == 0
        report["parent_fallback_accepts"] = parent.accepts
        control = http.client.HTTPConnection("127.0.0.1", parent.server_port, timeout=5)
        try:
            control.request("GET", "/positive-control")
            response = control.getresponse()
            assert response.status == 200 and response.read() == b"fallback"
        finally:
            control.close()
        report["parent_control_accepts"] = parent.accepts
        assert parent.accepts == 1, "fallback observer was not live"
    finally:
        config_path.write_bytes(original)
        parent.shutdown()
        parent.server_close()
        parent_thread.join(timeout=5)


def verify_outbound(events, report, *, reused_image):
    """Require request IDs from this journey's hosting sandbox generations."""
    agent_id = report["runtime"]["agent_id"]
    run_ids = {report["runtime"]["run_id"], report["recovery"]["after"]["run_id"]}
    outbound = []
    for event in events:
        run = event.get("details", {}).get("sandbox_run", {})
        if (event.get("event") not in {"security.network_guard", "traffic.response"} or
                event.get("agent") not in {"notes", agent_id} or run.get("agent_id") != agent_id or
                run.get("run_id") not in run_ids):
            continue
        outbound.append({**{key: event.get(key) for key in ("event", "request_id", "agent", "host", "decision")},
                         "sandbox_run": run})
    report["outbound"] = outbound
    for probe in report["network_probes"]:
        assert probe["request_id"] and any(row["request_id"] == probe["request_id"] and
            row["host"] == probe["destination"] and
            (row["event"] == "traffic.response" if probe["status"] == 200 else row["decision"] == "deny")
            for row in outbound), "probe lacks hosting-principal policy evidence"
    if not reused_image:
        assert any(row["host"] == "registry-1.docker.io" and row["decision"] == "allow" for row in outbound)
    assert any(row["host"] == "denied.invalid" and row["decision"] == "deny" for row in outbound)


def run(args):
    base, root, output = args.prepared_config.resolve(), args.root.resolve(), args.output.resolve()
    assert root.is_dir() if args.reuse_root else not root.exists(), "--reuse-root requires the retained disposable root"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli = str(base / "bin/safeyolo")
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_RUNSC_PLATFORM": "systrap",
                        "SAFEYOLO_NATS_TEST_INSTANCE": uuid.uuid4().hex, "SAFEYOLO_RUNSC_DEBUG": "1"}
    report = {"started_at": datetime.now(UTC).isoformat(), "status": "incomplete",
              "nested_docker": args.nested_docker, "revision": args.revision,
              "root": str(root), "cleanup": "unverified"}
    processes = []
    children = []
    capture_failures = []

    def native(*arguments, timeout=90, instance=root):
        return checked([cli, "--root", str(instance), *arguments], env=env, timeout=timeout,
                       diagnostics=output / "native.log")

    def guest(command, label, *, timeout=90, agent="notes"):
        report["step"] = label
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        path = output / f"{label}.log"
        child, reader, finished = background(agent, command, label)
        try:
            child.wait(timeout=timeout)
        finally:
            finished.set()
            reader.join(timeout=5)
        if reader.is_alive():
            raise RuntimeError(f"guest output capture remained live: {label}")
        if child.returncode:
            raise RuntimeError(f"guest step {label} exited {child.returncode}; inspect {path.name}")
        return path.read_text()

    def background(agent, command, label):
        child, reader, finished = capture_guest_command(
            guest_command_args(cli, agent, command, env=env), env, output / f"{label}.log", capture_failures)
        children.append((label, child, reader, finished))
        return child, reader, finished

    try:
        report["inputs"] = {}
        for name in ("package-info", "share/guest-selection.json"):
            if (base / name).is_file():
                report["inputs"][name] = (base / name).read_text()
        report["inputs"]["rootfs"] = str((base / "share/rootfs-tree").resolve(strict=True))
        for name, path, revision in (
            ("cli", base / "bin/safeyolo", args.revision),
            ("proxy", base / "bin/safeyolo-proxy", args.proxy_revision or args.revision),
            ("guest", base / "assets/guest/safeyolo-guest", args.guest_revision or args.revision),
        ):
            version = checked([str(path), "--version"]).strip()
            assert f"commit={revision}" in version, f"selected {name} revision differs"
            report["inputs"][name] = {"path": str(path), "sha256": _sha256(path), "version": version}
        if args.reuse_root:
            status = json.loads(native("agent", "status", "notes"))
            assert status["runtime_state"] == "stopped", "stop the retained fixture before continuing"
            policy = tomlkit.parse((root / "policy.toml").read_text())
            assert policy["agents"]["notes"]["nested_docker"] is True
            workspace = Path(policy["agents"]["notes"]["folder"])
        else:
            prepare_native_instance(base, root)
            root.chmod(0o755)
            (root / "data").chmod(0o755)
            copy_prepared_nats(base, root)
            config = tomlkit.parse((root / "config.toml").read_text())
            assert "linux" in config, "the prepared installation needs native Linux settings"
            config["admin_port"] = args.admin_port
            # If this approved host uses a parent proxy, preserve that route.
            prepared = tomlkit.parse((base / "config.toml").read_text())
            if "parent_proxy" in prepared:
                config["parent_proxy"] = prepared["parent_proxy"]
            (root / "config.toml").write_text(tomlkit.dumps(config))
            (root / "policy.toml").write_text(POLICY)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o755)
            native("agent", "create", "notes", "--workspace", str(workspace), "--memory", "1536",
                   "--nested-docker", str(args.nested_docker).lower())
        source = Path(__file__).parent / "isolation/docker-preflight.sh"
        shutil.copy2(source, workspace / source.name)
        if args.journey:
            # This is the existing disposable fixture's application binding.
            # Keep registry decisions and unrelated policy entries intact.
            config = tomlkit.parse((root / "config.toml").read_text())
            config["gateway_services_dir"] = "services"
            config["gateway_builtin_services_dir"] = "builtin-services"
            (root / "config.toml").write_text(tomlkit.dumps(config))
            (root / "services/notes.yaml").write_text(SERVICE)
            policy = tomlkit.parse((root / "policy.toml").read_text())
            policy.setdefault("hosts", {})["notes.safeyolo.internal"] = {"service": "notes", "egress": "deny"}
            policy["hosts"]["notes.safeyolo.internal:8088"] = {"egress": "allow"}
            (root / "policy.toml").write_text(tomlkit.dumps(policy))
        native("start")
        native("agent", "start", "notes", "--sandbox-only")
        status = json.loads(native("agent", "status", "notes"))
        report["runtime"] = running_guest(root, "notes", status)
        assert _sha256(root / "agents/notes/config-share/safeyolo-guest") == report["inputs"]["guest"]["sha256"]
        processes = owned_processes(root)
        listener = next(row for row in _agent_listeners(root) if row["agent_id"] == "notes")
        report["ingress"] = runsc_identity(root, "notes", Path(listener["path"]), platform="systrap")
        report["oci"] = json.loads((root / "agents/notes/config.json").read_text())
        report["doctor"] = json.loads(native("doctor"))
        report["proxy"] = _runtime_observation(root, _native_config(root / "config.toml", root),
            base / "bin/safeyolo-proxy", config_path=root / "config.toml", working_directory=root,
            require_running=True, require_authenticated_identity=True)
        if args.journey:
            compose_journey(args, root, output, workspace, native, guest, background, report)
            report["status"] = "journey-ran"
        else:
            command = "sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends docker.io docker-cli docker-compose && sudo -n bash /workspace/docker-preflight.sh /home/agent/docker-preflight"
            child = background("notes", command, "guest")[0]
            report["guest_exit"] = child.wait(timeout=300)
            report["status"] = "container-ran" if child.returncode == 0 else "preflight-failed"
    finally:
        failures = []
        if (root / "config.toml").is_file():
            try:
                processes.extend(owned_processes(root))
            except (OSError, ValueError, KeyError) as error:
                failures.append(f"cannot inspect owned process receipts: {error}")
        for name in ("notes", "dockercaller"):
            if (root / "agents" / name).is_dir():
                try:
                    native("agent", "stop", name)
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    failures.append(f"guest stop {name}: {error}")
        if (root / "config.toml").exists():
            try:
                native("stop")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                failures.append(f"instance stop: {error}")
        report["commands"] = []
        for label, child, reader, finished in children:
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                failures.append(f"native guest command survived owned stop: {label}")
            finally:
                finished.set()
                reader.join(timeout=5)
            if reader.is_alive():
                failures.append(f"guest output capture remained live: {label}")
            report["commands"].append({"step": label, "exit": child.returncode})
        failures.extend(capture_failures)
        observations = root / "agents/notes/home" / ("docker-journey" if args.journey else "docker-preflight")
        if observations.is_dir():
            for path in observations.iterdir():
                if path.is_file():
                    shutil.copy2(path, output / path.name)
            if not args.journey and (observations / "outcome.txt").is_file():
                report["outcome"] = (observations / "outcome.txt").read_text().strip()
        failures.extend(surviving_processes(processes))
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures,
                      finished_at=datetime.now(UTC).isoformat())
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.journey and report["status"] == "journey-ran" and report["cleanup"] == "stopped":
        # stop flushes the current audit writer. Match these real request IDs,
        # rather than treating a caller-supplied phase header as authority.
        events = [json.loads(line) for line in (root / "logs/audit.jsonl").read_text().splitlines() if line.strip()]
        try:
            verify_outbound(events, report, reused_image=bool(args.docker_data))
        finally:
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        report["status"] = "journey-passed"
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-config", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--guest-revision")
    parser.add_argument("--proxy-revision", help="source-equivalent prepared proxy revision when only the CLI changed")
    parser.add_argument("--admin-port", type=int)
    parser.add_argument("--nested-docker", action="store_true")
    parser.add_argument("--journey", action="store_true")
    parser.add_argument("--reuse-root", action="store_true")
    parser.add_argument("--docker-data", help="existing guest Docker data root; reuse its qualified image instead of pulling again")
    parser.add_argument("--host-address", help="unapproved real venue host address for the inner network negative control")
    parser.add_argument("--host-port", type=int, help="unapproved real host TCP port for the negative control")
    args = parser.parse_args()
    if args.reuse_root and not args.journey:
        parser.error("--reuse-root requires --journey")
    if not args.reuse_root and args.admin_port is None:
        parser.error("a fresh instance requires --admin-port")
    if args.reuse_root and not args.docker_data:
        parser.error("--reuse-root requires the retained --docker-data path")
    if args.journey and (not args.nested_docker or not args.host_address or not args.host_port):
        parser.error("--journey requires --nested-docker, --host-address and --host-port")
    report = run(args)
    print(json.dumps({key: report.get(key) for key in ("status", "cleanup", "outcome")}))
    return int(report["status"] not in {"container-ran", "journey-passed"} or report["cleanup"] != "stopped")


if __name__ == "__main__":
    raise SystemExit(main())
