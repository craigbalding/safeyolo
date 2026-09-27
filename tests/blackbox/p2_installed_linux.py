#!/usr/bin/env python3
"""Check the finite installed P2 traffic selection through one Linux guest."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pwd
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import tomllib
import uuid
from contextlib import contextmanager
from pathlib import Path

from host.sinkhole_client import SinkholeClient
from installed_host_smoke import _sha256
from isolation.p1_guest_requests import is_mounted_forwarder
from kvm_p1_ingress import FROZEN_R, installed_identity, runsc_identity

PACKAGE = "safeyolo-p2-fixture"


def checked(command: list[str], *, timeout: int = 30, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                            cwd=cwd, check=False)
    assert result.returncode == 0, f"{command[0]} exited {result.returncode}: {result.stderr[-800:]}"
    return result


def prepare_package(directory: Path, marker: str) -> str:
    source = directory / "package-source"
    control = source / "DEBIAN"
    payload = source / "usr/local/share/safeyolo-blackbox/p2-package"
    control.mkdir(parents=True)
    payload.parent.mkdir(parents=True)
    (control / "control").write_text("\n".join([
        f"Package: {PACKAGE}", "Version: 1.0", "Architecture: all",
        "Maintainer: SafeYolo blackbox", "Description: finite installed P2 package probe", "",
    ]))
    payload.write_text(f"package:{marker}\n")
    package = directory / f"{PACKAGE}.deb"
    checked(["dpkg-deb", "--build", str(source), str(package)])
    return hashlib.sha256(package.read_bytes()).hexdigest()


def prepare_repository(directory: Path, marker: str) -> str:
    source = directory / "repo-source"
    bare = directory / "repo.git"
    source.mkdir()
    checked(["git", "init", "-q", "--initial-branch=main"], cwd=source)
    (source / "P2-MARKER.txt").write_text(f"repository:{marker}\n")
    checked(["git", "add", "P2-MARKER.txt"], cwd=source)
    checked(["git", "-c", "user.name=SafeYolo fixture", "-c", "user.email=fixture@example.test",
             "commit", "-q", "-m", "Finite P2 read-only fixture"], cwd=source)
    commit = checked(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
    checked(["git", "init", "-q", "--bare", "--initial-branch=main", str(bare)])
    checked(["git", "push", "-q", str(bare), "main"], cwd=source)
    checked(["git", "--git-dir", str(bare), "update-server-info"])
    return commit


@contextmanager
def owned_ssh(directory: Path, config_dir: Path, agent: str, marker: str):
    ssh = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").is_file() else None)
    keygen = shutil.which("ssh-keygen")
    assert ssh and keygen, "P2 host requires sshd and ssh-keygen"
    private = directory / "ssh"
    private.mkdir(mode=0o700)
    forced = private / "marker-command"
    share = config_dir / "agents" / agent / "config-share"
    guest_key = share / "p2-client-key"
    guest_known = share / "p2-known-hosts"
    port_file = directory / "ssh.port"
    observed = directory / "ssh-observed"
    server = None
    try:
        assert share.is_dir(), f"guest config share is absent: {share}"
        for name in ("host", "client"):
            checked([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(private / name)])
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        username = pwd.getpwuid(os.getuid()).pw_name
        host_type, host_data, *_ = (private / "host.pub").read_text().split()
        guest_key.write_bytes((private / "client").read_bytes())
        guest_known.write_text(f"failing.test {host_type} {host_data}\n")
        guest_key.chmod(0o444)  # The guest copies this key into a private 0600 file.
        guest_known.chmod(0o444)
        forced.write_text("\n".join([
            "#!/bin/sh", "set -eu",
            f'[ "${{SSH_ORIGINAL_COMMAND:-}}" = {shlex.quote("p2-marker " + marker)} ] || exit 1',
            f"printf %s {shlex.quote(marker)} > {shlex.quote(str(observed))}",
            f"printf %s {shlex.quote('ssh-server:' + marker)}", "",
        ]))
        forced.chmod(0o700)
        configuration = private / "sshd.conf"
        configuration.write_text("\n".join([
            "ListenAddress 127.0.0.1", f"Port {port}", f"HostKey {private / 'host'}",
            f"PidFile {private / 'sshd.pid'}", f"AuthorizedKeysFile {private / 'client.pub'}",
            "UsePAM yes", "StrictModes no", "PubkeyAuthentication yes", "PasswordAuthentication no",
            "KbdInteractiveAuthentication no", "PermitRootLogin no", "PrintMotd no",
            "DisableForwarding yes", "PermitTTY no", f"ForceCommand {shlex.quote(str(forced))}",
            f"AllowUsers {username}", "",
        ]))
        with (directory / "sshd.log").open("w") as log:
            server = subprocess.Popen([ssh, "-D", "-e", "-f", str(configuration)],
                                      stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None, (directory / "sshd.log").read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "owned SSH daemon did not listen"
                    time.sleep(0.025)
            port_file.write_text(f"{port}\n")
            yield username, observed
    finally:
        port_file.unlink(missing_ok=True)
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        guest_key.unlink(missing_ok=True)
        guest_known.unlink(missing_ok=True)
        for name in ("host", "host.pub", "client", "client.pub"):
            (private / name).unlink(missing_ok=True)
        forced.unlink(missing_ok=True)


def guest_args(cli: str, agent: str, marker: str, phase: str, *extra: str) -> list[str]:
    command = shlex.join([
        "python3", "-m", "tests.blackbox.isolation.p2_guest_traffic",
        "--phase", phase, "--agent", agent, "--marker", marker, *extra,
    ])
    return [cli, "agent", "shell", agent, "--root", "-c", f"cd /workspace && {command}"]


def observation(output: str, phase: str, marker: str) -> dict:
    lines = [line.removeprefix("P2_OBSERVATION=") for line in output.splitlines()
             if line.startswith("P2_OBSERVATION=")]
    assert len(lines) == 1, f"guest {phase} did not return one observation: {output[-800:]}"
    value = json.loads(lines[0])
    assert value["phase"] == phase and value["marker"] == marker
    assert value["guest_proxy"] == "http://127.0.0.1:8080"
    assert is_mounted_forwarder(value["forwarder"]["argv"]), "guest lost its mounted UDS forwarder"
    return value["result"]


def run_guest(cli: str, agent: str, marker: str, phase: str, *extra: str) -> dict:
    result = subprocess.run(guest_args(cli, agent, marker, phase, *extra), capture_output=True,
                            text=True, timeout=120, check=False)
    assert result.returncode == 0, f"guest {phase} exited {result.returncode}: {result.stderr[-900:]}"
    return observation(result.stdout, phase, marker)


def control(method: str, path: str) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", 19999, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        body = json.loads(response.read())
        assert response.status == 200, f"fixture control {path} returned {response.status}: {body}"
        return body
    finally:
        connection.close()


def run_held_sse(cli: str, agent: str, marker: str) -> tuple[dict, dict]:
    process = subprocess.Popen(guest_args(cli, agent, marker, "sse"), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, bufsize=1)
    assert process.stdout is not None
    first = None
    lines = []
    try:
        deadline = time.monotonic() + 12
        while first is None:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "guest did not receive the first SSE event before release"
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            assert ready, "guest did not receive the first SSE event before release"
            line = process.stdout.readline()
            assert line, "guest SSE client exited before its first event"
            lines.append(line)
            if line.startswith("P2_SSE_FIRST="):
                first = json.loads(line.removeprefix("P2_SSE_FIRST="))
        assert first == {"marker": marker, "event": f"data: first:{marker}\n\n"}
        before = control("GET", f"/p2/state/{marker}")
        assert before["first_sent"] and not before["released"] and not before["finished"], before
        assert control("POST", f"/p2/release/{marker}")["status"] == "released"
        stdout, stderr = process.communicate(timeout=20)
        lines.append(stdout)
        assert process.returncode == 0, f"guest SSE exited {process.returncode}: {stderr[-900:]}"
        result = observation("".join(lines), "sse", marker)
        after = control("GET", f"/p2/state/{marker}")
        assert after["first_sent"] and after["released"] and after["finished"], after
        return result, {"before_release": before, "after_release": after}
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        # Release the owned fixture if the first-event assertion failed.
        try:
            control("POST", f"/p2/release/{marker}")
        except AssertionError:
            pass


def check_origin(sinkhole: SinkholeClient, marker: str, package_sha: str, repo_commit: str,
                 guest: dict, stream: dict, websocket: dict, observed: Path) -> dict:
    requests = sinkhole.get_requests()
    paths = [request.path for request in requests if request.host == "failing.test"]
    assert paths.count(f"/p2/package/{PACKAGE}.deb") == 1, paths
    assert "/p2/repo.git/info/refs" in paths and any(
        path.startswith("/p2/repo.git/objects/") for path in paths
    ), "repository clone never read owned Git objects"
    assert all(request.method in {"GET", "HEAD"} for request in requests
               if request.host == "failing.test" and request.path.startswith("/p2/repo.git/")), (
        "repository fixture received a non-read request"
    )
    assert paths.count(f"/p2/sse/{marker}") == 1
    assert paths.count(f"/p2/ws/{marker}") == 2
    assert not any(request.path == f"/p2/ws/{marker}-blocked" for request in requests), (
        "blocked canary reached the owned origin"
    )
    assert observed.read_text() == marker, "owned SSH command did not run"
    assert guest["package_sha256"] == package_sha and guest["repository_commit"] == repo_commit
    assert guest["trace_agent"] and guest["package_request_id"].startswith("req-")
    assert stream == {"first": f"data: first:{marker}\n\n", "last": f"data: last:{marker}\n\n"}
    assert websocket["blocked_canary"] == {"status": 403, "blocked_by": "network-guard"}
    states = control("GET", f"/p2/state/{marker}")["websockets"]
    assert len(states) == 2 and {state["tls"] for state in states} == {False, True}, states
    assert all(state["status"] == "complete" and state["client"] == f"client:{marker}"
               for state in states), states
    assert websocket["ws"]["server"] == websocket["wss"]["server"] == f"server:{marker}"
    assert websocket["ssh"] == {"server": f"ssh-server:{marker}", "pinned_host_key": True, "port": 22}
    return {"package_requests": 1, "repository_paths": sorted({path for path in paths
            if path.startswith("/p2/repo.git/")}), "sse_requests": 1,
            "ws_wss_requests": 2, "blocked_canary_origin_deliveries": 0,
            "websocket_peers": states, "ssh_command_marker": marker}


def main() -> None:
    # The runner's bounded timeout must unwind the disposable SSH fixture.
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit("P2 pilot timed out"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--platform", choices=("kvm", "systrap"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config_dir = args.config_dir.resolve()
    install_checkout = Path(os.environ["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"]).resolve()
    revision = checked(["git", "-C", str(install_checkout), "rev-parse", "HEAD"]).stdout.strip()
    assert revision == FROZEN_R, f"pilot installed {revision}, expected frozen R"
    runtime = json.loads(args.runtime.read_text())
    identity = installed_identity(runtime, install_checkout)
    assert runtime["host"]["system"] == "Linux"
    substrate = runtime["substrate"]
    assert substrate["status"] == "discovered" and substrate["kind"] == "gvisor"
    substrate["sha256"] = _sha256(Path(substrate["path"]))
    native = json.loads((config_dir / "data" / "native.json").read_text())
    policy = tomllib.loads((config_dir / "policy.toml").read_text())
    assert policy["hosts"]["evil.com"]["egress"] == "deny"
    assert policy["hosts"]["failing.test"]["egress"] == "allow"
    assert native["parent_proxy"].startswith("http://127.0.0.1:")
    assert Path(native["upstream_ca_file"]).is_file()
    listener = next(item for item in runtime["guest_ingress"]["agents"] if item["agent_id"] == args.agent)
    gvisor = runsc_identity(config_dir, args.agent, Path(listener["path"]), platform=args.platform)
    oci = json.loads((config_dir / "agents" / args.agent / "config.json").read_text())
    rootfs = Path(oci["root"]["path"]).resolve()
    assert rootfs.is_dir() and (rootfs / "etc/os-release").is_file(), (
        "running guest has no selected rootfs tree"
    )
    gvisor["rootfs"] = {"path": str(rootfs), "os_release": (rootfs / "etc/os-release").read_text()}
    directory = config_dir / "p2-fixture"
    directory.mkdir(mode=0o700, exist_ok=True)
    assert control("GET", "/p2/health")["directory"] == str(directory.resolve())
    marker = "p2-" + uuid.uuid4().hex
    package_sha = prepare_package(directory, marker)
    repo_commit = prepare_repository(directory, marker)
    sinkhole = SinkholeClient("http://127.0.0.1:19999")
    try:
        sinkhole.wait_for_receiver_ready(timeout=10)
        with owned_ssh(directory, config_dir, args.agent, marker) as (username, observed):
            guest = run_guest(identity["cli"]["path"], args.agent, marker, "package-repo",
                              "--package-sha", package_sha, "--repo-commit", repo_commit)
            assert guest["trace_agent"] == args.agent
            stream, stream_control = run_held_sse(identity["cli"]["path"], args.agent, marker)
            websocket = run_guest(identity["cli"]["path"], args.agent, marker, "ws-ssh",
                                  "--ssh-user", username)
            origin = check_origin(sinkhole, marker, package_sha, repo_commit, guest, stream,
                                  websocket, observed)
    finally:
        sinkhole.close()
    report = {
        "status": "traffic_passed", "frozen_revision": FROZEN_R, "platform": args.platform,
        "host": runtime["host"], "substrate": substrate,
        "installed": identity, "gvisor": gvisor, "guest": {"package_repo": guest, "sse": stream,
        "websocket_ssh": websocket}, "sse_control": stream_control, "origin": origin,
        "runtime_config": {"path": str(config_dir / "data/native.json"),
        "parent_proxy": native["parent_proxy"], "upstream_ca_file": native["upstream_ca_file"]},
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Linux {args.platform} P2: installed R guest package, repository, early SSE, "
          f"WS/WSS, deny and pinned SSH verified ({args.output})")


if __name__ == "__main__":
    main()
