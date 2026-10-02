#!/usr/bin/env python3
"""Check installed native ingress through one real gVisor/KVM guest.

Require the selected wheel and packaged executable, authenticated runtime and
actual KVM runsc argv/UID mapping. Bind guest localhost requests to its mounted
agent UDS. Observe an exact allowed HTTP marker at the owned origin, a denied
request with no origin delivery, and protected local API boundaries.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tomllib
import uuid
from pathlib import Path

if __package__:
    from .host.sinkhole_client import SinkholeClient
    from .installed_host_smoke import _sha256
    from .isolation.installed_ingress import is_mounted_forwarder
else:
    from host.sinkhole_client import SinkholeClient
    from installed_host_smoke import _sha256
    from isolation.installed_ingress import is_mounted_forwarder


def runsc_identity(
    config_dir: Path, agent: str, listener: Path, *, platform: str = "kvm"
) -> dict:
    agent_dir = config_dir / "agents" / agent
    pid = int((agent_dir / "container.pid").read_text())
    assert pid > 1, f"invalid gVisor PID: {pid}"
    argv = [part.decode() for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if part]
    assert argv and Path(argv[0]).name == "runsc-sandbox", f"PID {pid} is not a runsc sandbox"
    assert f"--platform={platform}" in argv, f"running gVisor PID {pid} did not select {platform}"
    assert f"--bundle={agent_dir}" in argv, f"running gVisor PID {pid} is not this guest"

    oci = json.loads((agent_dir / "config.json").read_text())
    mounts = [mount for mount in oci["mounts"] if mount["destination"] == "/safeyolo/proxy"]
    assert len(mounts) == 1, "guest has no unique /safeyolo/proxy mount"
    mount = mounts[0]
    assert Path(mount["source"]).resolve() == listener.parent.resolve(), (
        "guest bridge mount does not name the installed native agent listener"
    )
    assert "ro" in mount["options"], "guest bridge mount is not read only"
    return {"pid": pid, "platform": platform, "bundle": str(agent_dir), "proxy_mount": mount}


def installed_identity(runtime: dict, install_checkout: Path, *, expected_revision: str) -> dict:
    assert runtime["status"] == "attached_ready", "installed runtime was not attached and ready"
    cli = runtime["cli"]
    candidate = runtime["candidate"]
    running = runtime["runtime"]
    assert running["status"] == "ready"
    assert running["authenticated_runtime_identity"]["status"] == "authenticated"
    package = Path(cli["package_location"]).resolve().parent
    stamp = json.loads((package / "_build_identity.json").read_text())
    assert stamp["source_revision"] == expected_revision and stamp["state"] == "known", (
        "installed CLI wheel does not carry the selected source build identity"
    )
    packaged = (package / "bin" / "safeyolo-proxy").resolve()
    assert Path(candidate["path"]).resolve() == packaged
    assert Path(running["actual_executable"]).resolve() == packaged
    assert candidate["sha256"] == _sha256(packaged)
    built = install_checkout / "proxy" / "target" / "release" / "safeyolo-proxy"
    assert built.is_file() and _sha256(built) == candidate["sha256"], (
        "installed native binary differs from the selected source release build"
    )
    assert Path(install_checkout).resolve() != Path.cwd().resolve(), (
        "selected install checkout must be separate from the blackbox harness"
    )
    status = subprocess.run([cli["path"], "status"], capture_output=True, text=True, check=False, timeout=15)
    assert status.returncode == 0 and "running" in status.stdout and str(running["pid"]) in status.stdout, (
        "installed CLI status did not identify the running native process"
    )
    identity = {
        "cli": cli,
        "candidate": candidate,
        "build_identity": stamp,
        "runtime": running,
        "native": runtime["native"],
        "cli_status": status.stdout.strip(),
    }
    doctor = subprocess.run(
        [cli["path"], "doctor", "--json"], capture_output=True, text=True, check=False, timeout=45
    )
    checks = json.loads(doctor.stdout)["checks"]
    runtime_checks = [row for row in checks if row["name"] == "Runtime identity"]
    assert len(runtime_checks) == 1 and runtime_checks[0]["status"] == "pass", (
        "installed CLI diagnostics did not identify the native process"
    )
    check = runtime_checks[0]
    assert Path(check["message"].removeprefix("Running ")).resolve() == packaged
    assert check["detail"] == f"PID {running['pid']}"
    identity["cli_diagnostics"] = check
    return identity


def guest_observation(cli: str, agent: str, marker: str) -> dict:
    command = (
        "python3 /workspace/tests/blackbox/isolation/installed_ingress.py "
        f"--agent {shlex.quote(agent)} --marker {shlex.quote(marker)}"
    )
    result = subprocess.run(
        [cli, "agent", "shell", agent, "-c", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    assert result.returncode == 0, f"guest request probe exited {result.returncode}: {result.stderr[-1000:]}"
    lines = [
        line.removeprefix("P1_OBSERVATION=")
        for line in result.stdout.splitlines()
        if line.startswith("P1_OBSERVATION=")
    ]
    assert len(lines) == 1, "guest request probe did not return one observation"
    return json.loads(lines[0])


def check_guest_route(guest: dict) -> None:
    """Bind the guest's localhost proxy to the mounted per-agent UDS."""
    assert guest["guest_socket"] == "/safeyolo/proxy/proxy.sock"
    assert guest["guest_proxy"] == "http://127.0.0.1:8080", "guest proxy is not its localhost forwarder"
    forwarder = guest["forwarder"]
    assert type(forwarder["pid"]) is int and forwarder["pid"] > 1
    assert is_mounted_forwarder(forwarder["argv"]), (
        "guest localhost listener is not wired to the mounted SafeYolo UDS"
    )


def check_guest_and_origin(guest: dict, sinkhole: SinkholeClient, marker: str, agent: str) -> dict:
    check_guest_route(guest)
    expected = json.dumps(
        {
            "received": True,
            "host": "httpbin.org",
            "method": "GET",
            "path": f"/{marker}",
            "has_auth": False,
        }
    ).encode()
    allowed = guest["allow"]
    denied = guest["deny"]
    assert (allowed["status"], allowed["blocked_by"]) == (200, None), allowed
    assert bytes.fromhex(allowed["body_hex"]) == expected, "origin marker response bytes differ"
    assert (denied["status"], denied["blocked_by"]) == (403, "network-guard"), denied
    assert allowed["request_id"] != denied["request_id"]
    for result, host, outcome in ((allowed, "httpbin.org", "allowed"), (denied, "evil.com", "blocked")):
        assert result["trace_agent"] == agent
        assert result["guard"] == {
            "state": "evaluated",
            "outcome": outcome,
            "host": host,
            "port": 80,
            "method": "GET",
        }, result

    captured = sinkhole.get_requests()
    delivered = [request for request in captured if request.host == "httpbin.org" and request.path == f"/{marker}"]
    prohibited = [request for request in captured if request.path == f"/{marker}-denied"]
    marked = [
        request
        for request in captured
        if {key.lower(): value for key, value in request.headers.items()}.get("x-probe-marker") == marker
    ]
    assert len(delivered) == 1, f"owned origin received {len(delivered)} allowed marker requests"
    assert delivered[0].method == "GET"
    assert marked == delivered, "origin marker appeared on another delivery"
    assert not prohibited, "denied request reached the owned prohibited origin"
    return {"allowed_origin_path": delivered[0].path, "allowed_marker_header": marker, "denied_origin_deliveries": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install-commit", required=True)
    args = parser.parse_args()
    config_dir = args.config_dir.resolve()
    install_checkout = Path(os.environ["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"]).resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(install_checkout), "rev-parse", "HEAD"],
        text=True,
        timeout=10,
    ).strip()
    assert revision == args.install_commit, f"installed {revision}, expected {args.install_commit}"
    runtime = json.loads(args.runtime.read_text())
    identity = installed_identity(runtime, install_checkout, expected_revision=args.install_commit)
    doctor = json.loads((args.output.parent / "doctor.json").read_text())
    platform_checks = [check for check in doctor["checks"] if check.get("name") == "Isolation platform"]
    assert len(platform_checks) == 1 and str(platform_checks[0].get("message", "")).startswith("KVM ")
    policy = tomllib.loads((config_dir / "policy.toml").read_text())
    assert policy["hosts"]["evil.com"]["egress"] == "deny"
    native = json.loads((config_dir / "data" / "native.json").read_text())
    assert native["network_guard_block"] is True
    assert native["agent_api_enabled"] is True
    assert native.get("temporary_policy_socket") is None
    assert native["parent_proxy"].startswith("http://127.0.0.1:")
    assert Path(native["upstream_ca_file"]).is_file()
    listener = next(item for item in runtime["guest_ingress"]["agents"] if item["agent_id"] == args.agent)
    assert any(
        item["agent_id"] == args.agent and Path(item["path"]) == Path(listener["path"])
        for item in runtime["runtime"]["listeners"]
    )
    gvisor = runsc_identity(config_dir, args.agent, Path(listener["path"]))

    marker = "p1-" + uuid.uuid4().hex
    with_sinkhole = SinkholeClient("http://127.0.0.1:19999")
    try:
        with_sinkhole.wait_for_receiver_ready(timeout=10)
        guest = guest_observation(identity["cli"]["path"], args.agent, marker)
        origin = check_guest_and_origin(guest, with_sinkhole, marker, args.agent)
    finally:
        with_sinkhole.close()

    report = {
        "status": "ingress_passed",
        "source_revision": args.install_commit,
        "installed": identity,
        "runtime_config": {
            "path": str(config_dir / "data" / "native.json"),
            "parent_proxy": native["parent_proxy"],
            "upstream_ca_file": native["upstream_ca_file"],
            "network_guard_block": native["network_guard_block"],
            "agent_api_enabled": native["agent_api_enabled"],
            "policy_file": native["policy_file"],
        },
        "gvisor": gvisor,
        "guest": guest,
        "origin": origin,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"KVM ingress: selected package, authenticated native runtime, real KVM guest, "
        f"origin marker and local denial verified ({args.output})"
    )


if __name__ == "__main__":
    main()
