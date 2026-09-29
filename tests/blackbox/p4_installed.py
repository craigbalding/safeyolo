#!/usr/bin/env python3
"""Exercise installed P4 configuration and P6 recovery through real guests."""

from __future__ import annotations

import argparse
import json
import os
import select
import shlex
import socket
import subprocess
import time
import tomllib
import uuid
from pathlib import Path

import yaml
from host.sinkhole_client import SinkholeClient
from installed_host_smoke import _agent_map, _pid_alive, _probe_agent_health, _process_start_token, _sha256
from kvm_p1_ingress import installed_identity, runsc_identity
from p2_installed_linux import control

FROZEN_R = "2faba3306de7c099e2913e0eebc8907ff3eba148"
PEER = "bbpeer"
FIXTURE = "failing.test"


def checked(
    command: list[str], *, timeout: int = 35, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=env)
    assert result.returncode == 0, f"{command[0]} exited {result.returncode}: {result.stderr[-900:]}"
    return result


def guest_command(cli: str, agent: str, phase: str, marker: str) -> list[str]:
    request = [
        "python3",
        "-m",
        "tests.blackbox.isolation.p4_guest_lifecycle",
        "--phase",
        phase,
        "--agent",
        agent,
        "--marker",
        marker,
    ]
    return [cli, "agent", "shell", agent, "-c", "cd /workspace && " + shlex.join(request)]


def observation(output: str, phase: str, agent: str) -> dict:
    lines = [line.removeprefix("P4_OBSERVATION=") for line in output.splitlines() if line.startswith("P4_OBSERVATION=")]
    assert len(lines) == 1, f"guest {phase} returned no single observation: {output[-900:]}"
    value = json.loads(lines[0])
    assert value["phase"] == phase and value["agent"] == agent, value
    assert value["forwarder"]["pid"] > 1, value
    return value["result"]


def guest(cli: str, agent: str, phase: str, marker: str, *, env: dict[str, str] | None = None) -> dict:
    return observation(checked(guest_command(cli, agent, phase, marker), timeout=55, env=env).stdout, phase, agent)


def held_guest(cli: str, agent: str, phase: str, marker: str) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        guest_command(cli, agent, phase, marker), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
    )
    try:
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + 25
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"guest {phase} did not reach its admitted-work boundary: {bytes(output)[-900:]}"
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            assert ready, f"guest {phase} did not reach its admitted-work boundary: {bytes(output)[-900:]}"
            chunk = os.read(process.stdout.fileno(), 4096)
            assert chunk, f"guest {phase} exited before its admitted-work boundary: {bytes(output)[-900:]}"
            output.extend(chunk)
            if f"P4_READY={phase}".encode() in output.splitlines():
                return process, output.decode("utf-8", "replace")
    except Exception:
        stop_child(process)
        raise


def finish_guest(process: subprocess.Popen[str], first: str, phase: str, agent: str) -> dict:
    stdout, stderr = process.communicate(timeout=35)
    assert process.returncode == 0, f"guest {phase} exited {process.returncode}: {stderr[-900:]}"
    return observation(first + stdout, phase, agent)


def stop_child(process: subprocess.Popen[str] | None) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def runtime_identity(
    config_dir: Path, cli: str, binary: str, checkout: Path, output: Path, agent: str, expected_revision: str
) -> dict:
    checked(
        [
            "python3",
            str(Path(__file__).with_name("installed_host_smoke.py")),
            "--mode",
            "attached",
            "--cli",
            cli,
            "--rust-bin",
            binary,
            "--rust-config",
            str(config_dir / "data/native.json"),
            "--config-dir",
            str(config_dir),
            "--working-directory",
            str(Path(__file__).parent),
            "--agent",
            agent,
            "--output",
            str(output),
        ],
        timeout=40,
    )
    return installed_identity(json.loads(output.read_text()), checkout, expected_revision=expected_revision)


def wait_stopped(config_dir: Path) -> None:
    readiness = config_dir / "data/proxy-readiness.json"
    deadline = time.monotonic() + 12
    while readiness.exists():
        assert time.monotonic() < deadline, "native stop did not withdraw readiness"
        time.sleep(0.05)


def assert_proxy_stopped(config_dir: Path, listener: Path, runtime: dict) -> None:
    wait_stopped(config_dir)
    assert not (config_dir / "data/proxy-rust.json").exists(), "native lifetime receipt remains"
    pid = runtime["pid"]
    assert not (_pid_alive(pid) and _process_start_token(pid) == runtime["receipt"]["start_token"]), (
        f"native process {pid} remains live after stop"
    )
    with socket.socket(socket.AF_UNIX) as closed:
        assert closed.connect_ex(str(listener)) != 0, "native agent listener still accepts"
    assert not listener.exists(), f"native agent listener remains after stop: {listener}"


def stop_guest(cli: str, config_dir: Path, agent: str) -> None:
    pid_file = config_dir / "agents" / agent / "container.pid"
    pid = int(pid_file.read_text()) if pid_file.exists() else None
    start_token = _process_start_token(pid) if pid is not None else None
    checked([cli, "agent", "stop", agent], timeout=60)
    assert not pid_file.exists(), f"guest PID file remains after stop: {pid_file}"
    if start_token is not None:
        assert not (_pid_alive(pid) and _process_start_token(pid) == start_token), (
            f"guest process {pid} remains live after stop"
        )


def start_guest(cli: str, config_dir: Path, agent: str) -> Path:
    checked([cli, "agent", "run", agent, "--sandbox-only"], timeout=120)
    listener = next(row for row in _agent_map(config_dir) if row["agent_id"] == agent)
    path = Path(listener["path"])
    assert path.is_socket(), f"restarted guest has no native listener: {path}"
    return path


def prepare_owner(
    cli: str, config_dir: Path, source_dir: Path, native: dict, binary: str, output: Path
) -> tuple[dict, dict[str, str], Path]:
    """Keep one separate installed proxy and guest live across P4's stops."""
    env = os.environ.copy()
    env["SAFEYOLO_CONFIG_DIR"] = str(config_dir)
    env["SAFEYOLO_LOGS_DIR"] = str(config_dir / "logs")
    env["SAFEYOLO_LOG_PATH"] = str(config_dir / "logs/safeyolo.jsonl")
    env["SAFEYOLO_SUBNET_BASE"] = "76"
    env["SAFEYOLO_COORD_DATA_DIR"] = str(config_dir / "data/coord")
    env["SAFEYOLO_NATS_TEST_INSTANCE"] = uuid.uuid4().hex
    checked([cli, "init", "--no-interactive"], env=env)
    for name in ("share", "bin"):
        source = source_dir / name
        target = config_dir / name
        assert source.is_dir(), f"owner instance needs bootstrapped {source}"
        target.rmdir()
        target.symlink_to(source, target_is_directory=True)
    config_path = config_dir / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["proxy"]["backend"] = "rust"
    config["proxy"]["admin_port"] = int(os.environ.get("SAFEYOLO_P4_OWNER_ADMIN_PORT", "0"))
    config["proxy"]["upstream_proxy"] = native["parent_proxy"]
    config["proxy"]["upstream_ca_cert"] = native["upstream_ca_file"]
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    checked([cli, "policy", "host", "add", FIXTURE], env=env)
    checked([cli, "policy", "host", "deny", "evil.com"], env=env)
    checked(
        [cli, "agent", "add", "bbowner", str(Path(__file__).resolve().parents[2]), "--no-run"], timeout=120, env=env
    )
    checked([cli, "start", "--no-wait"], env=env)
    checked([cli, "agent", "run", "bbowner", "--sandbox-only"], timeout=120, env=env)
    checked(
        [
            "python3",
            str(Path(__file__).with_name("installed_host_smoke.py")),
            "--mode",
            "attached",
            "--cli",
            cli,
            "--rust-bin",
            binary,
            "--rust-config",
            str(config_dir / "data/native.json"),
            "--config-dir",
            str(config_dir),
            "--working-directory",
            str(Path(__file__).parent),
            "--agent",
            "bbowner",
            "--output",
            str(output),
        ],
        timeout=40,
        env=env,
    )
    report = json.loads(output.read_text())
    assert report["status"] == "attached_ready" and report["runtime"]["status"] == "ready", report
    assert report["candidate"]["sha256"] == _sha256(Path(binary))
    assert Path(report["runtime"]["actual_executable"]).resolve() == Path(binary).resolve()
    owner_native = json.loads((config_dir / "data/native.json").read_text())
    assert owner_native["parent_proxy"] == native["parent_proxy"]
    assert owner_native["upstream_ca_file"] == native["upstream_ca_file"]
    report["config_sha256"] = _sha256(config_path)
    report["policy_sha256"] = _sha256(config_dir / "policy.toml")
    listener = next(row for row in _agent_map(config_dir) if row["agent_id"] == "bbowner")
    assert _probe_agent_health(listener, config_dir)["status"] == 200
    return report, env, Path(listener["path"])


def owner_controls(
    cli: str, config_dir: Path, listener: Path, owner: dict, env: dict[str, str], marker: str, sinkhole: SinkholeClient
) -> dict:
    """Check the untouched owner process and fresh allowed/denied traffic."""
    runtime = owner["runtime"]
    readiness = json.loads((config_dir / "data/proxy-readiness.json").read_text())
    assert _pid_alive(runtime["pid"])
    assert _process_start_token(runtime["pid"]) == runtime["receipt"]["start_token"]
    assert readiness["pid"] == runtime["pid"]
    assert readiness["instance_id"] == runtime["readiness"]["instance_id"]
    assert _sha256(config_dir / "config.yaml") == owner["config_sha256"]
    assert _sha256(config_dir / "policy.toml") == owner["policy_sha256"]
    agent = {"agent_id": "bbowner", "path": str(listener)}
    assert _probe_agent_health(agent, config_dir)["status"] == 200
    allowed = guest(cli, "bbowner", "echo", marker, env=env)
    denied = guest(cli, "bbowner", "canary", marker, env=env)
    assert allowed["status"] == 200 and denied["status"] == 403
    assert len([row for row in sinkhole.get_requests(host=FIXTURE) if row.path == f"/p4/echo/{marker}"]) == 1
    assert not any(row.path == f"/p4/canary/{marker}" for row in sinkhole.get_requests(host="evil.com"))
    return {"pid": runtime["pid"], "instance_id": readiness["instance_id"], "allowed": 200, "denied": 403}


def recovery_controls(cli: str, agent: str, sinkhole: SinkholeClient) -> dict:
    marker = "p4-" + uuid.uuid4().hex
    allowed = guest(cli, agent, "echo", marker)
    denied = guest(cli, agent, "canary", marker)
    assert allowed["status"] == 200 and denied["status"] == 403
    assert len([row for row in sinkhole.get_requests(host=FIXTURE) if row.path == f"/p4/echo/{marker}"]) == 1
    assert not any(row.path == f"/p4/canary/{marker}" for row in sinkhole.get_requests(host="evil.com"))
    return {"marker": marker, "allowed": allowed, "denied": denied}


def event_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def policy_reload_count(path: Path) -> int:
    return sum(row.get("event") == "ops.policy_reload" for row in event_rows(path))


def wait_policy_reload(path: Path, previous: int) -> int:
    deadline = time.monotonic() + 10
    while True:
        current = policy_reload_count(path)
        if current > previous:
            return current
        assert time.monotonic() < deadline, "native policy watcher did not publish the changed policy"
        time.sleep(0.05)


def wait_passthrough_audit(path: Path, agent: str) -> list[dict]:
    deadline = time.monotonic() + 10
    while True:
        rows = [
            row
            for row in event_rows(path)
            if row.get("event") in {"traffic.passthrough_start", "traffic.passthrough_end"}
            and row.get("agent") == agent
            and row.get("host") == "self-signed.test"
            and row.get("details", {}).get("port") == 443
        ]
        if [row["event"] for row in rows] == ["traffic.passthrough_start", "traffic.passthrough_end"]:
            return rows
        assert time.monotonic() < deadline, f"one owned passthrough session did not finish: {rows}"
        time.sleep(0.05)


def assert_shutdown_ownership(config_dir: Path, agent: str, marker: str) -> dict:
    native = json.loads((config_dir / "data/native.json").read_text())
    events = event_rows(Path(native["event_log"]))
    audit = event_rows(Path(native["audit_log_path"]))
    p2_marker = "p2-" + marker[3:]
    ended = [
        row
        for row in events
        if row.get("event") == "proxy.websocket.end" and row.get("agent") == agent and row.get("outcome") == "shutdown"
    ]
    assert len(ended) == 1 and ended[0].get("drained") is True, ended
    closed = [
        row
        for row in audit
        if row.get("event") in {"ops.memory.ws_closed", "ops.memory.conn_closed"} and row.get("host") == FIXTURE
    ]
    assert any(row["event"] == "ops.memory.ws_closed" for row in closed), closed
    responses = [row for row in audit if row.get("event") == "traffic.response" and row.get("agent") == agent]
    # The held HTTP and SSE legs are distinct completed traffic flows.
    assert any(row.get("details", {}).get("path") == f"/p4/hold/{marker}" for row in responses), responses[-8:]
    assert any(row.get("details", {}).get("path") == f"/p2/sse/{p2_marker}" for row in responses), responses[-8:]
    return {"websocket_end": ended[0], "memory_close_events": len(closed), "owned_response_events": len(responses)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--platform", choices=("systrap", "vz"), required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install-commit", default=FROZEN_R)
    args = parser.parse_args()
    config_dir = args.config_dir.resolve()
    checkout = Path(os.environ["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"]).resolve()
    assert checked(["git", "-C", str(checkout), "rev-parse", "HEAD"]).stdout.strip() == args.install_commit
    first_runtime = json.loads(args.runtime.read_text())
    first_identity = installed_identity(first_runtime, checkout, expected_revision=args.install_commit)
    native = json.loads((config_dir / "data/native.json").read_text())
    assert native["parent_proxy"].startswith("http://127.0.0.1:")
    assert Path(native["upstream_ca_file"]).is_file()
    assert Path(native["tls_ca_file"]).is_file()
    test_ca = Path(os.environ["SAFEYOLO_TEST_CERT_DIR"]) / "ca.crt"
    assert test_ca.read_bytes().strip() in Path(native["upstream_ca_file"]).read_bytes()
    assert tomllib.loads((config_dir / "policy.toml").read_text())["hosts"]["failing.test"]["egress"] == "allow"
    substrate = first_runtime["substrate"]
    assert substrate["status"] == "discovered"
    assert substrate["kind"] == ("virtualization.framework" if args.platform == "vz" else "gvisor")
    substrate["sha256"] = _sha256(Path(substrate["path"]))
    first_listener = next(row for row in first_runtime["guest_ingress"]["agents"] if row["agent_id"] == args.agent)
    bridge = (
        runsc_identity(config_dir, args.agent, Path(first_listener["path"]), platform=args.platform)
        if args.platform == "systrap"
        else {"platform": "vz", "host_listener": first_listener["path"], "guest_forwarder": "vsock:2:1080"}
    )
    cli = first_identity["cli"]["path"]
    binary = first_identity["candidate"]["path"]
    marker = "p4-" + uuid.uuid4().hex
    sinkhole = SinkholeClient(os.environ.get("SINKHOLE_API", "http://127.0.0.1:19999"))
    owner_dir = Path(os.environ["SAFEYOLO_P4_OWNER_CONFIG_DIR"]).resolve()
    source_dir = Path(os.environ["SAFEYOLO_P4_SOURCE_CONFIG_DIR"]).resolve()
    peer_added = False
    active: subprocess.Popen[str] | None = None
    owner_env: dict[str, str] | None = None
    owner_listener: Path | None = None
    release = config_dir / "agents" / args.agent / "config-share" / "p4-passthrough-go"
    try:
        sinkhole.wait_for_receiver_ready(timeout=10)
        sinkhole.clear_requests()
        owner, owner_env, owner_listener = prepare_owner(
            cli, owner_dir, source_dir, native, binary, args.output.with_name("p4-owner-runtime.json")
        )
        owner_checks = [owner_controls(cli, owner_dir, owner_listener, owner, owner_env, marker, sinkhole)]
        checked([cli, "agent", "add", PEER, str(Path(__file__).resolve().parents[2]), "--no-run"])
        peer_added = True
        checked([cli, "agent", "run", PEER, "--sandbox-only"], timeout=120)
        peer_listener = next(row for row in _agent_map(config_dir) if row["agent_id"] == PEER)
        peer_socket = Path(peer_listener["path"])
        assert peer_socket.is_socket() and peer_socket != Path(first_listener["path"])
        peer_bridge = (
            runsc_identity(config_dir, PEER, peer_socket, platform=args.platform)
            if args.platform == "systrap"
            else {"platform": "vz", "host_listener": str(peer_socket), "guest_forwarder": "vsock:2:1080"}
        )
        assert guest(cli, PEER, "echo", marker)["status"] == 200
        assert guest(cli, args.agent, "echo", marker)["status"] == 200
        checked([cli, "agent", "remove", PEER], timeout=60)
        peer_added = False
        with socket.socket(socket.AF_UNIX) as closed:
            assert closed.connect_ex(str(peer_socket)) != 0, "removed agent listener still accepts new use"
        assert guest(cli, args.agent, "echo", marker)["status"] == 200

        active, first = held_guest(cli, args.agent, "sse", marker)
        sse_marker = "p2-" + marker[3:]
        before = control("GET", f"/p2/state/{sse_marker}")
        assert before["first_sent"] and not before["released"] and not before["finished"], before
        audit_path = Path(native["audit_log_path"])
        reload_before = policy_reload_count(audit_path)
        checked([cli, "policy", "host", "deny", "failing.test"])
        denied_reload = wait_policy_reload(audit_path, reload_before)
        origin_before_denial = len(
            [row for row in sinkhole.get_requests(host=FIXTURE) if row.path == f"/p4/echo/{marker}"]
        )
        denied = guest(cli, args.agent, "echo", marker)
        assert denied["status"] == 403, denied
        assert (
            len([row for row in sinkhole.get_requests(host=FIXTURE) if row.path == f"/p4/echo/{marker}"])
            == origin_before_denial
        )
        assert control("POST", f"/p2/release/{sse_marker}")["status"] == "released"
        sse = finish_guest(active, first, "sse", args.agent)
        active = None
        assert control("GET", f"/p2/state/{sse_marker}")["finished"]
        checked([cli, "policy", "host", "add", "failing.test"])
        allowed_reload = wait_policy_reload(audit_path, denied_reload)
        allowed = guest(cli, args.agent, "echo", marker)
        assert allowed["status"] == 200, allowed

        passthrough_before = sum(
            row.get("event") == "traffic.passthrough_start" for row in event_rows(Path(native["audit_log_path"]))
        )
        tls = guest(cli, args.agent, "tls", marker)
        for host in ("wrong-san.test", "self-signed.test", "future-leaf.test", "expired-leaf.test"):
            assert not any(row.path == f"/p4/tls/{marker}" for row in sinkhole.get_requests(host=host)), host
        assert (
            len(
                [
                    row
                    for row in sinkhole.get_requests(host="example-chain-test.test")
                    if row.path == f"/p4/tls/{marker}"
                ]
            )
            == 1
        )
        assert (
            sum(row.get("event") == "traffic.passthrough_start" for row in event_rows(Path(native["audit_log_path"])))
            == passthrough_before
        )

        checked([cli, "proxy", "ignore-host", "add", "self-signed.test:443"])
        active, first = held_guest(cli, args.agent, "passthrough", marker)
        checked([cli, "proxy", "ignore-host", "remove", "self-signed.test:443"])
        release.write_text("go\n")
        retained = finish_guest(active, first, "passthrough", args.agent)
        active = None
        release.unlink()
        passthrough_events = wait_passthrough_audit(audit_path, args.agent)
        assert (
            len([row for row in sinkhole.get_requests(host="self-signed.test") if row.path == f"/p4/tls/{marker}"]) == 1
        )
        removed = guest(cli, args.agent, "self-signed", marker)
        assert removed["status"] == 502
        assert (
            len([row for row in sinkhole.get_requests(host="self-signed.test") if row.path == f"/p4/tls/{marker}"]) == 1
        )

        ca_before = _sha256(Path(native["tls_ca_file"]))
        trust_before = _sha256(Path(native["upstream_ca_file"]))
        policy_before = _sha256(config_dir / "policy.toml")
        checked([cli, "stop"], timeout=40)
        assert_proxy_stopped(config_dir, Path(first_listener["path"]), first_identity["runtime"])
        stop_guest(cli, config_dir, args.agent)
        owner_checks.append(
            owner_controls(cli, owner_dir, owner_listener, owner, owner_env, "p4-" + uuid.uuid4().hex, sinkhole)
        )
        checked([cli, "start", "--no-wait"], timeout=40)
        second_listener = start_guest(cli, config_dir, args.agent)
        second_runtime_path = args.output.with_name("p4-restarted-runtime.json")
        second_identity = runtime_identity(
            config_dir, cli, binary, checkout, second_runtime_path, args.agent, args.install_commit
        )
        assert (
            second_identity["runtime"]["receipt"]["start_token"] != first_identity["runtime"]["receipt"]["start_token"]
        )
        assert _sha256(Path(native["tls_ca_file"])) == ca_before
        assert _sha256(Path(native["upstream_ca_file"])) == trust_before
        assert _sha256(config_dir / "policy.toml") == policy_before
        first_recovery = recovery_controls(cli, args.agent, sinkhole)
        assert guest(cli, args.agent, "self-signed", marker)["status"] == 502
        assert (
            len([row for row in sinkhole.get_requests(host="self-signed.test") if row.path == f"/p4/tls/{marker}"]) == 1
        )

        drain_marker = "p4-" + uuid.uuid4().hex
        drain_sse_marker = "p2-" + drain_marker[3:]
        active, first = held_guest(cli, args.agent, "drain", drain_marker)
        assert control("GET", f"/p4/state/{drain_marker}")["first_sent"]
        assert control("GET", f"/p2/state/{drain_sse_marker}")["first_sent"]
        stopping = subprocess.Popen([cli, "stop"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait_stopped(config_dir)
            assert stopping.poll() is None, "stop returned before admitted HTTP and SSE completed"
            assert control("POST", f"/p4/release/{drain_marker}")["status"] == "released"
            assert control("POST", f"/p2/release/{drain_sse_marker}")["status"] == "released"
            drained = finish_guest(active, first, "drain", args.agent)
            active = None
            stdout, stderr = stopping.communicate(timeout=40)
            assert stopping.returncode == 0, f"installed stop failed: {stderr[-900:]} {stdout[-300:]}"
        finally:
            stop_child(stopping)
        assert control("GET", f"/p4/state/{drain_marker}")["finished"]
        assert control("GET", f"/p2/state/{drain_sse_marker}")["finished"]
        assert_proxy_stopped(config_dir, second_listener, second_identity["runtime"])
        ownership = assert_shutdown_ownership(config_dir, args.agent, drain_marker)
        stop_guest(cli, config_dir, args.agent)
        owner_checks.append(
            owner_controls(cli, owner_dir, owner_listener, owner, owner_env, "p4-" + uuid.uuid4().hex, sinkhole)
        )

        checked([cli, "start", "--no-wait"], timeout=40)
        third_listener = start_guest(cli, config_dir, args.agent)
        third_runtime_path = args.output.with_name("p4-recovery-runtime.json")
        third_identity = runtime_identity(
            config_dir, cli, binary, checkout, third_runtime_path, args.agent, args.install_commit
        )
        assert third_identity["runtime"]["receipt"]["start_token"] not in {
            first_identity["runtime"]["receipt"]["start_token"],
            second_identity["runtime"]["receipt"]["start_token"],
        }
        second_recovery = recovery_controls(cli, args.agent, sinkhole)
        checked([cli, "stop"], timeout=40)
        assert_proxy_stopped(config_dir, third_listener, third_identity["runtime"])
        stop_guest(cli, config_dir, args.agent)
        owner_checks.append(
            owner_controls(cli, owner_dir, owner_listener, owner, owner_env, "p4-" + uuid.uuid4().hex, sinkhole)
        )
        checked([cli, "agent", "stop", "bbowner"], timeout=60, env=owner_env)
        checked([cli, "stop"], timeout=40, env=owner_env)
        assert_proxy_stopped(owner_dir, owner_listener, owner["runtime"])
        assert not (owner_dir / "agents/bbowner/container.pid").exists()
        report = {
            "status": "selected_checks_passed",
            "source_revision": args.install_commit,
            "platform": args.platform,
            "host": first_runtime["host"],
            "substrate": substrate,
            "installed": first_identity,
            "bridge": bridge,
            "peer_bridge": peer_bridge,
            "runtime_config": {"parent_proxy": native["parent_proxy"], "upstream_ca_file": native["upstream_ca_file"]},
            "listener": {"peer_socket": str(peer_socket), "added_used_removed": True, "primary_still_usable": True},
            "policy": {
                "admitted_sse": sse,
                "denied_reload": denied_reload,
                "new_denied": denied,
                "allowed_reload": allowed_reload,
                "new_allowed": allowed,
            },
            "tls": {
                "cases": tls,
                "retained_passthrough": retained,
                "passthrough_events": passthrough_events,
                "new_after_removal": removed,
                "invalid_origin_deliveries": 0,
            },
            "restart": {
                "same_ca_sha256": ca_before,
                "same_upstream_trust_sha256": trust_before,
                "same_policy_sha256": policy_before,
                "runtime": second_identity,
                "controls": first_recovery,
            },
            "drain": {"guest": drained, "ownership": ownership},
            "owner": {
                "runtime": owner["runtime"],
                "config_sha256": owner["config_sha256"],
                "policy_sha256": owner["policy_sha256"],
                "checks": owner_checks,
                "stopped": True,
            },
            "recovery": {"runtime": third_identity, "controls": second_recovery},
            "start_stop_cycles": [
                {"pid": first_identity["runtime"]["pid"], "stopped": True, "guest_stopped": True},
                {
                    "pid": second_identity["runtime"]["pid"],
                    "stopped": True,
                    "guest_stopped": True,
                    "active_drain": True,
                },
                {"pid": third_identity["runtime"]["pid"], "stopped": True, "guest_stopped": True},
            ],
        }
        if args.install_commit == FROZEN_R:
            report["frozen_revision"] = FROZEN_R
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(
            f"{args.platform} P4/P6: installed guest configuration, TLS, drain and three-cycle recovery verified ({args.output})"
        )
    finally:
        release.unlink(missing_ok=True)
        stop_child(active)
        sinkhole.close()
        if peer_added:
            checked([cli, "agent", "remove", PEER], timeout=60)


if __name__ == "__main__":
    main()
