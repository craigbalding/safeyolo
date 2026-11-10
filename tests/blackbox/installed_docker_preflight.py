#!/usr/bin/env python3
"""Probe nested Docker in one disposable installed Linux/systrap sandbox.

On an owned Linux host, supply a prepared installation, this source checkout,
and Python 3.11+ with tomlkit. Use a new output directory and a new root unless
--reuse-root is selected. A new instance also needs a free Admin port. Use
disk-backed paths with traversable parents. --nested-docker selects the
candidate's guest configuration; without it the driver records the default.
The guest installs Debian Docker packages through its normal proxy, attempts
one local daemon/pull/container and stops. --journey additionally runs the
Compose lifecycle, sandbox recovery and application-bound provider controls.
--gateway reuses the stopped qualified fixture for Docker management through
its provider route. It restores ephemeral guest tools, but does not repeat image
pulls or the application lifecycle.
--gateway-lifecycle adds the missing Compose lifecycle through that same route.
It requires a private, already approved fixed RegistryToken AuthConfig file in
the caller guest and the retained nested-notes image. It does not obtain or
approve registry credentials. Failed mutations are retained without replay.
--gateway-failures-only retains the earlier management proof and runs only the
daemon, closed-port and stopped-provider failure controls with --gateway.
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

DOCKER_SERVICE = '''schema_version: 1
name: notes
default_host: notes.safeyolo.internal
docker:
  endpoint: http://notes.safeyolo.internal:2375
  execution_boundary: sandbox
capabilities:
  engine:
    docker_access: {mode: sandbox_admin}
    routes:
      - methods: [GET, HEAD, POST, PUT, DELETE]
        path: /v1.45/**
'''


def verify_gateway_client_failure(observation):
    """Require a failed client and diagnostic text beyond Docker's prefix."""
    assert observation["exit"] != 0, "Docker client unexpectedly succeeded"
    diagnostic = observation["stderr"].strip()
    for prefix in ("docker:", "Error response from daemon:", "Error:"):
        if diagnostic.lower().startswith(prefix.lower()):
            diagnostic = diagnostic[len(prefix):].strip()
    assert diagnostic and not diagnostic.isdigit(), "Docker client returned no useful failure diagnostic"


def gateway_client_failure(client_command, label):
    """Retain the actual CLI exit, stderr and a read-only raw HTTP response."""
    directory = "/home/agent/docker-gateway-client"
    capture = f'''
import http.client, json, os
from pathlib import Path
from urllib.parse import urlsplit
directory = Path({directory!r})
label = {label!r}
endpoint = urlsplit(os.environ["HTTP_PROXY"])
connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=20)
headers = json.loads((directory / "config.json").read_text())["HttpHeaders"]
connection.request("GET", "/v1.45/version", headers=headers)
response = connection.getresponse()
raw = {{"status": response.status, "headers": response.getheaders(), "body": response.read().decode("utf-8", "replace")}}
connection.close()
(directory / (label + ".http.json")).write_text(json.dumps(raw))
print(json.dumps({{"exit": int((directory / (label + ".exit")).read_text()),
                  "stderr": (directory / (label + ".log")).read_text(), "http": raw}}))
'''
    command = (f"client_exit=0; /workspace/docker-client version >{directory}/{label}.stdout "
               f"2>{directory}/{label}.log || client_exit=$?; "
               f"printf '%s\\n' \"$client_exit\" >{directory}/{label}.exit; "
               "python3 -c " + shlex.quote(capture))
    return json.loads(client_command(command, label).strip().removeprefix("\x1b[2K"))


def gateway_compose_journey(args, caller, client_command, guest, report):
    """Run the missing multi-service lifecycle through the caller's gateway."""
    name = "sycompose" + uuid.uuid4().hex[:12]
    image = name + ":qualification"
    state = "/home/agent/" + name
    marker = "persist-" + uuid.uuid4().hex
    observation = {"project": name, "image": image, "volume": name + "_notes",
                   "state": "incomplete", "registry_auth_file": args.gateway_registry_auth}
    report["gateway_lifecycle"] = observation
    source = client_command("/workspace/docker-client image inspect nested-notes:qualification", "gateway-base-image")
    observation["base_image"] = json.loads(source.strip().removeprefix("\x1b[2K"))[0]
    image_id = observation["base_image"]["Id"]
    assert image_id.startswith("sha256:") and len(image_id) == 71 and all(c in "0123456789abcdef" for c in image_id[7:])
    # Reuse the qualified Python/application image. This build exercises the
    # gateway's build stream without reinstalling packages or changing its tag.
    fixture = caller / name
    fixture.mkdir()
    maintained = Path(__file__).parent / "fixtures/nested-docker"
    shutil.copy2(maintained / "notes.py", fixture / "notes.py")
    (fixture / "Dockerfile").write_text(f"FROM {image_id}\nCOPY notes.py /app/notes.py\n")
    (fixture / "compose.yaml").write_text((maintained / "compose.yaml").read_text().replace("nested-notes:qualification", image))
    (fixture / "transfer.txt").write_text(marker + "\n")
    guest(f"set -eu; mkdir -p {state}; cp -a /workspace/{name} {state}/context; "
          "mkdir -p /home/agent/docker-gateway-client/cli-plugins; "
          "install -m 0755 /workspace/docker-compose /home/agent/docker-gateway-client/cli-plugins/docker-compose",
          "gateway-compose-context", agent="dockercaller")
    observation["compose_version"] = client_command("/workspace/docker-client compose version", "gateway-compose-version")
    # The CLI supports registrytoken in its auths configuration. Keep the fixed
    # approved bearer separate from the ordinary scoped gateway configuration.
    prepare_pull = f'''
import json
from pathlib import Path
directory = Path({state!r}) / "pull-config"
directory.mkdir(mode=0o700)
auth = json.loads(Path({args.gateway_registry_auth!r}).read_text())
assert auth.get("registrytoken"), "supply the already approved fixed RegistryToken"
config = json.loads(Path("/home/agent/docker-gateway-client/config.json").read_text())
config["auths"] = {{"https://index.docker.io/v1/": {{"registrytoken": auth["registrytoken"]}}}}
path = directory / "config.json"
path.touch(mode=0o600, exist_ok=False)
path.write_text(json.dumps(config))
'''
    try:
        guest("python3 -c " + shlex.quote(prepare_pull), "gateway-pull-config", agent="dockercaller")
        base_image = (maintained / "Dockerfile").read_text().splitlines()[0].split()[1]
        client_command(f"DOCKER_CONFIG={state}/pull-config /workspace/docker-client pull {shlex.quote(base_image)} </dev/null",
                       "gateway-image-pull", timeout=180)
        observation["pulled_image"] = json.loads(client_command(
            f"/workspace/docker-client image inspect {shlex.quote(base_image)}", "gateway-pulled-image").strip().removeprefix("\x1b[2K"))
    finally:
        guest(f"rm -f -- {state}/pull-config/config.json; rmdir -- {state}/pull-config",
              "gateway-pull-config-remove", agent="dockercaller")
    compose = f"/workspace/docker-client compose -p {name} --project-directory {state}/context"
    client_command(f"DOCKER_BUILDKIT=0 {compose} build --no-cache store", "gateway-compose-build", timeout=180)
    guest("bash -c " + shlex.quote("if (: </dev/tcp/127.0.0.1/8088) 2>/dev/null || "
          "(: </dev/tcp/127.0.0.1/8090) 2>/dev/null; then echo 'application port already in use' >&2; exit 1; fi"),
          "gateway-application-ports")
    client_command(f"{compose} up --no-build --pull never -d", "gateway-compose-up")

    def containers(label):
        identifiers = client_command(f"{compose} ps --all --quiet", label).strip().removeprefix("\x1b[2K").split()
        assert len(identifiers) == 2, "both services must exist through the gateway"
        return identifiers

    observation["containers"] = containers("gateway-compose-containers")
    inspected = json.loads(client_command("/workspace/docker-client inspect " + shlex.join(observation["containers"]),
                                          "gateway-compose-inspect").strip().removeprefix("\x1b[2K"))
    assert all(row["State"]["Running"] and row["HostConfig"]["NetworkMode"] == "host" for row in inspected)
    api = next(row["Id"] for row in inspected if row["Config"]["Labels"]["com.docker.compose.service"] == "api")

    def notes(expected, label, write=False):
        program = f'''import http.client, json, time
for attempt in range(100):
    connection = http.client.HTTPConnection("127.0.0.1", 8088, timeout=3)
    try:
        connection.request("GET", "/api/v1/notes")
        response = connection.getresponse()
        body = response.read()
        if response.status == 200:
            break
    except OSError:
        if attempt == 99:
            raise
    finally:
        connection.close()
    time.sleep(0.1)
else:
    raise RuntimeError("application not ready")
if {write!r}:
    connection = http.client.HTTPConnection("127.0.0.1", 8088, timeout=3)
    try:
        connection.request("POST", "/api/v1/notes", json.dumps({{"text": {marker!r}}}), {{"Content-Type": "application/json"}})
        response = connection.getresponse()
        assert response.status == 200
        body = response.read()
    finally:
        connection.close()
assert json.loads(body) == {expected!r}, body
print(body.decode())
'''
        return client_command(f"{compose} exec -T api python3 -c {shlex.quote(program)}", label)

    notes([], "gateway-notes-empty")
    observation["written"] = notes([marker], "gateway-notes-write", write=True)
    echoed = client_command(f"printf 'gateway-exec\\n' | {compose} exec -T api cat", "gateway-compose-exec")
    assert "gateway-exec" in echoed
    client_command(f"/workspace/docker-client cp {state}/context/transfer.txt {api}:/tmp/gateway-transfer.txt", "gateway-copy-in")
    client_command(f"/workspace/docker-client cp {api}:/tmp/gateway-transfer.txt {state}/returned.txt; "
                   f"cmp {state}/context/transfer.txt {state}/returned.txt", "gateway-copy-out")
    logs = client_command(f"{compose} logs --no-color", "gateway-compose-logs")
    assert '"role": "api"' in logs and '"role": "store"' in logs
    observation["attach_container"] = name + "-attach"
    client_command(f"/workspace/docker-client create -i --network=host --name {name}-attach {image} "
                   "sh -c 'read line; echo attach:$line'", "gateway-lifecycle-attach-create")
    client_command(f"/workspace/docker-client start {name}-attach", "gateway-lifecycle-attach-start")
    attached = client_command(f"printf 'gateway-attach\\n' | /workspace/docker-client attach --sig-proxy=false {name}-attach",
                              "gateway-lifecycle-attach")
    assert "attach:gateway-attach" in attached
    client_command(f"/workspace/docker-client rm {name}-attach", "gateway-lifecycle-attach-remove")
    observation["volume_before"] = json.loads(client_command(
        f"/workspace/docker-client volume inspect {name}_notes", "gateway-volume-before").strip().removeprefix("\x1b[2K"))
    client_command(f"{compose} down", "gateway-compose-remove")
    assert not client_command(f"{compose} ps --all --quiet", "gateway-compose-removed").strip().removeprefix("\x1b[2K")
    client_command(f"{compose} up --no-build --pull never -d", "gateway-compose-recreate")
    observation["recreated_containers"] = containers("gateway-compose-recreated")
    assert set(observation["containers"]).isdisjoint(observation["recreated_containers"])
    observation["recovered"] = notes([marker], "gateway-notes-recovered")
    volume_after = json.loads(client_command(f"/workspace/docker-client volume inspect {name}_notes",
                                             "gateway-volume-after").strip().removeprefix("\x1b[2K"))
    assert volume_after[0]["CreatedAt"] == observation["volume_before"][0]["CreatedAt"]
    client_command(f"{compose} down --volumes", "gateway-compose-teardown")
    client_command(f"/workspace/docker-client image rm {image}", "gateway-image-remove")
    for arguments, label in ((f"ps --all --quiet --filter label=com.docker.compose.project={name}", "containers"),
                             (f"volume ls --quiet --filter name={name}_notes", "volumes"),
                             (f"image ls --quiet {image}", "images")):
        remaining = client_command("/workspace/docker-client " + arguments, "gateway-teardown-" + label)
        assert not remaining.strip().removeprefix("\x1b[2K"), f"owned {label} remain after teardown"
    observation["state"] = "passed"


def gateway_management(args, root, output, native, guest, background, report):
    """Exercise the real inner Engine over the existing sandbox-provider route."""
    caller = root / "docker-caller"
    assert caller.is_dir(), "reuse the qualified #1436 caller and workspace"
    assert json.loads(native("agent", "status", "dockercaller"))["runtime_state"] == "stopped"
    service = root / "services/notes.yaml"
    policy = root / "policy.toml"
    originals = {path: path.read_bytes() for path in (service, policy)}
    # The ordinary private output also supplies rollback inputs if the driver
    # itself is interrupted before its finally block can restore the fixture.
    for path, original in originals.items():
        backup = output / f"original-{path.name}"
        backup.write_bytes(original)
        backup.chmod(0o600)
    lifecycle = getattr(args, "gateway_lifecycle", False)
    name = "sygateway" + uuid.uuid4().hex[:12]
    if not lifecycle:
        report["gateway_container"] = name
    report["reused_image_data"] = args.docker_data
    failures_only = getattr(args, "gateway_failures_only", False)
    report["gateway_failures_only"] = failures_only
    state = "/home/agent/docker-gateway"
    try:
        native("stop")
        service.write_text(DOCKER_SERVICE)
        settings = tomlkit.parse(originals[policy].decode())
        settings["hosts"]["notes.safeyolo.internal:2375"] = {"egress": "allow"}
        policy.write_text(tomlkit.dumps(settings))
        native("start")
        native("agent", "start", "dockercaller", "--sandbox-only")
        report["caller"] = running_guest(root, "dockercaller", json.loads(native("agent", "status", "dockercaller")))
        guest("set -eu; if ! command -v dockerd >/dev/null || ! command -v socat >/dev/null "
              "|| ! docker compose version >/dev/null 2>&1; then "
              "sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends "
              "docker.io docker-cli docker-compose socat; fi; "
              f"mkdir -p {state}; cp -- \"$(command -v docker)\" /workspace/docker-gateway-client", "gateway-tools", timeout=300)
        # Use the guest's matching Debian client, without assuming that a host
        # binary can run against the guest's libc. It carries no credentials.
        shutil.copy2(Path(settings["agents"]["notes"]["folder"]) / "docker-gateway-client", caller / "docker-client")
        if lifecycle:
            guest("set -eu; plugin=$(dpkg-query -L docker-compose | sed -n '\\|/cli-plugins/docker-compose$|p'); "
                  "test -n \"$plugin\"; cp -- \"$plugin\" /workspace/docker-gateway-compose", "gateway-compose-plugin")
            shutil.copy2(Path(settings["agents"]["notes"]["folder"]) / "docker-gateway-compose", caller / "docker-compose")
            guest("if ! command -v python3 >/dev/null; then sudo -n apt-get update && "
                  "sudo -n apt-get install -y --no-install-recommends python3; fi",
                  "gateway-caller-tools", agent="dockercaller", timeout=300)
        daemon = background("notes", f"exec sudo -n env SAFEYOLO_DOCKER_DATA_ROOT={shlex.quote(args.docker_data)} "
                            f"bash /workspace/docker-preflight.sh {state} --daemon", "gateway-daemon")[0]
        guest(f"for ((i=0;i<150;i++)); do version=$(sudo -n {DOCKER} info --format '{{{{.ServerVersion}}}}' "
              "2>/dev/null) || version=; [[ -n $version ]] && exit 0; sleep 0.1; done; exit 1", "gateway-daemon-ready")
        assert daemon.poll() is None, "inner daemon exited after readiness"
        # Guest root can open the root-owned daemon socket. The listener stays
        # on guest loopback and adds no host listener or outer privilege.
        relay_command = f"echo $$ >{state}/relay.pid; exec socat " \
                        "TCP4-LISTEN:2375,bind=127.0.0.1,reuseaddr,fork " \
                        "UNIX-CONNECT:/run/safeyolo-nested-docker/docker.sock"
        relay = background("notes", "exec sudo -n bash -c " + shlex.quote(relay_command), "gateway-port")[0]
        guest("for ((i=0;i<100;i++)); do curl --silent --fail --max-time 1 "
              "http://127.0.0.1:2375/_ping && exit 0; sleep 0.1; done; exit 1", "gateway-port-ready")
        assert relay.poll() is None, "inner endpoint exited after readiness"
        url = "http://notes.safeyolo.internal:2375/v1.45/version"
        refused = guest("curl --silent --show-error --max-time 20 --output /dev/null --write-out '%{http_code}' "
                        + url, "gateway-unapproved", agent="dockercaller")
        assert refused.strip().removeprefix("\x1b[2K") == "403", "unapproved Docker caller reached the provider"
        native("services", "authorize", "dockercaller", "notes", "--capability", "engine")
        # Only the scoped gateway token enters the caller. The internal
        # endpoint has no upstream administrative credential to distribute.
        prepare = '''set -eu
umask 077
mkdir -p /home/agent/docker-gateway-client
agent_token=$(cat /app/agent_token)
printf 'Authorization: Bearer %s\\n' "$agent_token" |
  curl --silent --show-error --fail --header @- http://_safeyolo.proxy.internal/gateway/services |
  python3 -c 'import json,sys; from pathlib import Path; token=json.load(sys.stdin)["authorized"]["notes"]["token"]; Path("/home/agent/docker-gateway-client/config.json").write_text(json.dumps({"HttpHeaders":{"X-SafeYolo-Docker-Service":"notes","Authorization":"Bearer "+token}}))'
'''
        guest(prepare, "gateway-client-config", agent="dockercaller")

        def client_command(arguments, label, timeout=90):
            return guest("set -eu; unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH; "
                         "proxy_address=${HTTP_PROXY#http://}; "
                         "export DOCKER_HOST=tcp://${proxy_address%/} DOCKER_API_VERSION=1.45 "
                         "DOCKER_CONFIG=/home/agent/docker-gateway-client; "
                         + arguments, label, agent="dockercaller", timeout=timeout)

        report["gateway_versions"] = client_command("/workspace/docker-client version", "gateway-version")
        if lifecycle:
            report["gateway_shells"] = {agent: guest("printf '%s\\n' \"$BASH_VERSION\"; uname -srvmo",
                                                     "gateway-shell-" + agent, agent=agent)
                                         for agent in ("notes", "dockercaller")}
            report["gateway_route"] = {"provider": "notes", "caller": "dockercaller", "endpoint": url,
                                       "execution_boundary": "sandbox", "api_version": "1.45"}
            gateway_compose_journey(args, caller, client_command, guest, report)
            report["gateway_result"] = "multi-service gateway lifecycle passed"
            return
        # Keep the accepted single-container and negative-only paths separate
        # from the optional missing-route proof. Both use guest host networking.
        if not failures_only:
            client_command(f"/workspace/docker-client create -i --network=host --name {name} "
                           "debian:trixie-slim sh -c 'read line; echo internal:$line'", "gateway-create")
            client_command(f"/workspace/docker-client start {name}", "gateway-container-start")
            inspected = client_command(f"/workspace/docker-client inspect --format '{{{{.State.Running}}}}' {name}", "gateway-inspect")
            assert inspected.strip().removeprefix("\x1b[2K") == "true"
            echoed = client_command(f"printf 'exec-half-close\\n' | /workspace/docker-client exec -i {name} cat", "gateway-exec")
            assert "exec-half-close" in echoed
            attached = client_command(f"printf 'attach-half-close\\n' | /workspace/docker-client attach --sig-proxy=false {name}", "gateway-attach")
            assert "internal:attach-half-close" in attached
            client_command(f"/workspace/docker-client rm {name}", "gateway-remove")

        def failure(label):
            observation = gateway_client_failure(client_command, label)
            report.setdefault("gateway_failures", {})[label] = observation
            (output / f"{label}.json").write_text(json.dumps(observation, indent=2) + "\n")
            verify_gateway_client_failure(observation)

        guest("sudo -n kill -TERM $(cat /run/safeyolo-nested-docker/dockerd.pid)", "gateway-stop-daemon")
        report["gateway_daemon_exit"] = daemon.wait(timeout=20)
        failure("gateway-daemon-failed")
        guest(f"sudo -n kill -TERM $(cat {state}/relay.pid)", "gateway-close-port")
        report["gateway_port_exit"] = relay.wait(timeout=20)
        failure("gateway-closed")
        native("agent", "stop", "notes")
        failure("gateway-stopped")
        report["gateway_result"] = ("daemon failure and unavailable provider passed" if failures_only else
                                    "version, create/inspect, exec/attach half-close, removal, daemon failure and unavailable provider passed")
    finally:
        # Stop before restoring the retained application service and its
        # authorizations. Keep failure diagnostics and uncertain resources.
        try:
            native("stop")
        finally:
            for path, original in originals.items():
                path.write_bytes(original)


def compose_journey(args, root, output, workspace, native, guest, background, report):
    """Run one finite application journey against the hosting guest's daemon."""
    fixture = workspace / "nested-docker"
    shutil.copytree(Path(__file__).parent / "fixtures/nested-docker", fixture)
    base_image = shlex.quote((fixture / "Dockerfile").read_text().splitlines()[0].split()[1])
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
    # The hosting workspace can be private; let _apt read only a temporary
    # public certificate copy without changing any workspace permissions.
    reader = guest("set -eu; public_ca=$(mktemp /tmp/safeyolo-docker-ca.XXXXXX); "
                   "trap 'rm -f -- \"$public_ca\"' EXIT; "
                   "install -m 0644 -- /workspace/nested-docker/fresh-ca.crt \"$public_ca\"; "
                   "sudo -n -u _apt sha256sum \"$public_ca\"", "fresh-ca-reader")
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
        docker(f"{DOCKER} pull {base_image}", "image-pull", timeout=180)
    report["base_image"] = json.loads(docker(f"{DOCKER} image inspect {base_image}", "image-identity"))
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
        report["provider_origin"] = verify_provider_origin(logs, caller_runtime["agent_id"])
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


def verify_provider_origin(logs, caller_id):
    """Read application JSON, including Compose's observed erase-line prefix."""
    lines = (line.removeprefix("\x1b[2K") for line in logs.splitlines())
    requests = [json.loads(line) for line in lines if line.startswith('{"role":')]
    forwarded = [row for row in requests if row["caller_ids"]]
    # The recreated API has one local readiness read, then the two approved
    # gateway reads. Also catch an extra refused request stripped of identity.
    assert len(requests) == 3 and len(forwarded) == 2, "refused requests reached the application"
    assert all(row["role"] == "api" and row["method"] == "GET" and row["path"] == "/api/v1/notes" and
               row["caller_ids"] == [caller_id] and row["caller_names"] == ["dockercaller"] and
               row["authorization_count"] == 0 and row["legacy_identity_count"] == 0
               for row in forwarded), "forged headers changed authority"
    return requests


def verify_outbound(events, report, *, reused_image):
    """Join guard run authority to terminal/response records by request ID."""
    runtime = report["runtime"]
    # These probes and the image pull run before sandbox recovery. Only the
    # evaluated guard producer binds sandbox_run; traffic records do not.
    guards = {event["request_id"]: event for event in events
              if event.get("event") == "security.network_guard.evaluated" and
              event.get("details", {}).get("sandbox_run", {}).get("agent_id") == runtime["agent_id"] and
              event["details"]["sandbox_run"].get("run_id") == runtime["run_id"] and
              event["details"]["sandbox_run"].get("agent") == "notes"}
    outbound = report["outbound"] = []
    for event in events:
        guard = guards.get(event.get("request_id"))
        details = event.get("details", {})
        attribution = details.get("attribution", {})
        provenance = attribution.get("attribution_provenance", {})
        if (guard is None or (event.get("event") == "security.network_guard.evaluated" and
                details.get("sandbox_run") != guard["details"]["sandbox_run"]) or event.get("event") not in {
                "security.network_guard.evaluated", "security.network_guard",
                "traffic.response", "traffic.request_outcome"} or
                event.get("agent") != "notes" or event.get("host") != guard.get("host") or
                attribution.get("attribution_status") != "resolved" or
                attribution.get("trusted_transport_identity") != "notes" or
                provenance.get("transport_source") != "uds" or provenance.get("uds_agent") != "notes"):
            continue
        outbound.append({**{key: event.get(key) for key in ("event", "request_id", "agent", "host", "decision")},
                         "details": {key: details[key] for key in (
                             "sandbox_run", "outcome", "status", "decision", "attribution") if key in details}})

    def complete_request(request_id, host, status):
        rows = [row for row in outbound if row["request_id"] == request_id and row["host"] == host]
        decision, outcome = ("allow", "allowed") if status == 200 else ("deny", "blocked")
        return (bool(request_id) and status in {200, 403} and
                any(row["event"] == "security.network_guard.evaluated" and
                    row["details"].get("outcome") == outcome for row in rows) and
                any(row["event"] == "traffic.request_outcome" and row["decision"] == decision and
                    row["details"].get("decision") == decision and row["details"].get("status") == status
                    for row in rows) and
                any(row["event"] == "traffic.response" and row["details"].get("status") == status for row in rows) and
                (status == 200 or any(row["event"] == "security.network_guard" and row["decision"] == "deny"
                                      for row in rows)))

    for probe in report["network_probes"]:
        assert complete_request(probe["request_id"], probe["destination"], probe["status"]), \
            "probe lacks hosting-principal policy evidence"
    if not reused_image:
        assert any(row["host"] == "registry-1.docker.io" and
                   complete_request(row["request_id"], row["host"], 200) for row in outbound), \
            "image pull lacks hosting-principal policy evidence"


def run(args):
    base, root, output = args.prepared_config.resolve(), args.root.resolve(), args.output.resolve()
    assert root.is_dir() if args.reuse_root else not root.exists(), "--reuse-root requires the retained disposable root"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli = str(base / "bin/safeyolo")
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_RUNSC_PLATFORM": "systrap",
                        "SAFEYOLO_NATS_TEST_INSTANCE": uuid.uuid4().hex, "SAFEYOLO_RUNSC_DEBUG": "1"}
    report = {"started_at": datetime.now(UTC).isoformat(), "status": "incomplete",
              "nested_docker": args.nested_docker, "revision": args.revision,
              "driver": {"path": str(Path(__file__).resolve()), "sha256": _sha256(Path(__file__))},
              "root": str(root), "cleanup": "unverified"}
    processes = []
    children = []
    capture_failures = []
    original_bin = None

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
            if args.gateway:
                # Preserve either a directory or a prepared-installation link
                # on the same filesystem. Never copy through a donor link.
                saved_bin = root / ("bin-docker-gateway-" + uuid.uuid4().hex)
                (root / "bin").rename(saved_bin)
                original_bin = saved_bin
                (output / "original-bin-path.txt").write_text(str(saved_bin) + "\n")
                (root / "bin").symlink_to(base / "bin", target_is_directory=True)
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
        if args.gateway:
            gateway_management(args, root, output, native, guest, background, report)
            report["status"] = "gateway-passed"
        elif args.journey:
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
        if original_bin is not None:
            (root / "bin").unlink(missing_ok=True)
            original_bin.rename(root / "bin")
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
        observations = root / "agents/notes/home" / ("docker-gateway" if args.gateway else "docker-journey" if args.journey else "docker-preflight")
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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--journey", action="store_true")
    mode.add_argument("--gateway", action="store_true", help="only management through the retained nested provider")
    parser.add_argument("--gateway-failures-only", action="store_true",
                        help="with --gateway, retain positive proof and run only the three failure controls")
    parser.add_argument("--gateway-lifecycle", action="store_true",
                        help="with --gateway, run the missing Compose lifecycle instead of the retained single-container checks")
    parser.add_argument("--gateway-registry-auth",
                        help="private AuthConfig JSON path in dockercaller with a fixed RegistryToken already approved for registry-1.docker.io")
    parser.add_argument("--reuse-root", action="store_true")
    parser.add_argument("--docker-data", help="existing guest Docker data root; reuse its qualified image instead of pulling again")
    parser.add_argument("--host-address", help="unapproved real venue host address for the inner network negative control")
    parser.add_argument("--host-port", type=int, help="unapproved real host TCP port for the negative control")
    args = parser.parse_args()
    if args.gateway_failures_only and not args.gateway:
        parser.error("--gateway-failures-only requires --gateway")
    if args.gateway_lifecycle and (not args.gateway or args.gateway_failures_only or not args.gateway_registry_auth):
        parser.error("--gateway-lifecycle requires --gateway and --gateway-registry-auth, without --gateway-failures-only")
    if args.gateway_registry_auth and not args.gateway_lifecycle:
        parser.error("--gateway-registry-auth requires --gateway-lifecycle")
    if args.reuse_root and not (args.journey or args.gateway):
        parser.error("--reuse-root requires --journey or --gateway")
    if args.gateway and (not args.reuse_root or not args.nested_docker):
        parser.error("--gateway requires --reuse-root and --nested-docker")
    if not args.reuse_root and args.admin_port is None:
        parser.error("a fresh instance requires --admin-port")
    if args.reuse_root and not args.docker_data:
        parser.error("--reuse-root requires the retained --docker-data path")
    if args.journey and (not args.nested_docker or not args.host_address or not args.host_port):
        parser.error("--journey requires --nested-docker, --host-address and --host-port")
    report = run(args)
    print(json.dumps({key: report.get(key) for key in ("status", "cleanup", "outcome")}))
    return int(report["status"] not in {"container-ran", "journey-passed", "gateway-passed"} or report["cleanup"] != "stopped")


if __name__ == "__main__":
    raise SystemExit(main())
