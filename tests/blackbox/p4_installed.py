#!/usr/bin/env python3
"""Exercise finite P4 configuration, TLS and shutdown through installed guests."""

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

from host.sinkhole_client import SinkholeClient
from installed_host_smoke import _agent_map, _sha256
from kvm_p1_ingress import FROZEN_R, installed_identity, runsc_identity
from p2_installed_linux import control

PEER = "bbpeer"
FIXTURE = "failing.test"


def checked(command: list[str], *, timeout: int = 35) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
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


def guest(cli: str, agent: str, phase: str, marker: str) -> dict:
    return observation(checked(guest_command(cli, agent, phase, marker), timeout=55).stdout, phase, agent)


def held_guest(cli: str, agent: str, phase: str, marker: str) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        guest_command(cli, agent, phase, marker), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
    )
    try:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 25)
        assert ready, f"guest {phase} did not reach its admitted-work boundary"
        line = process.stdout.readline()
        assert line.strip() == f"P4_READY={phase}", (phase, line)
        return process, line
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


def runtime_identity(config_dir: Path, cli: str, binary: str, checkout: Path, output: Path, agent: str) -> dict:
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
    return installed_identity(json.loads(output.read_text()), checkout)


def wait_stopped(config_dir: Path) -> None:
    readiness = config_dir / "data/proxy-readiness.json"
    deadline = time.monotonic() + 12
    while readiness.exists():
        assert time.monotonic() < deadline, "native stop did not withdraw readiness"
        time.sleep(0.05)


def assert_proxy_stopped(config_dir: Path, listener: Path) -> None:
    wait_stopped(config_dir)
    assert not (config_dir / "data/proxy-rust.json").exists(), "native lifetime receipt remains"
    with socket.socket(socket.AF_UNIX) as closed:
        assert closed.connect_ex(str(listener)) != 0, "native agent listener still accepts"


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
    args = parser.parse_args()
    config_dir = args.config_dir.resolve()
    checkout = Path(os.environ["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"]).resolve()
    assert checked(["git", "-C", str(checkout), "rev-parse", "HEAD"]).stdout.strip() == FROZEN_R
    first_runtime = json.loads(args.runtime.read_text())
    first_identity = installed_identity(first_runtime, checkout)
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
    sinkhole = SinkholeClient("http://127.0.0.1:19999")
    peer_added = False
    active: subprocess.Popen[str] | None = None
    release = config_dir / "agents" / args.agent / "config-share" / "p4-passthrough-go"
    try:
        sinkhole.wait_for_receiver_ready(timeout=10)
        sinkhole.clear_requests()
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
        assert_proxy_stopped(config_dir, Path(first_listener["path"]))
        checked([cli, "start", "--no-wait"], timeout=40)
        second_runtime_path = args.output.with_name("p4-restarted-runtime.json")
        second_identity = runtime_identity(config_dir, cli, binary, checkout, second_runtime_path, args.agent)
        assert second_identity["runtime"]["pid"] != first_identity["runtime"]["pid"]
        assert _sha256(Path(native["tls_ca_file"])) == ca_before
        assert _sha256(Path(native["upstream_ca_file"])) == trust_before
        assert _sha256(config_dir / "policy.toml") == policy_before
        assert guest(cli, args.agent, "echo", marker)["status"] == 200
        assert guest(cli, args.agent, "canary", marker)["status"] == 403
        assert not any(row.path == f"/p4/canary/{marker}" for row in sinkhole.get_requests(host="evil.com"))

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
        assert_proxy_stopped(config_dir, Path(first_listener["path"]))
        ownership = assert_shutdown_ownership(config_dir, args.agent, drain_marker)
        report = {
            "status": "selected_checks_passed",
            "frozen_revision": FROZEN_R,
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
            },
            "drain": {"guest": drained, "ownership": ownership},
            "start_stop_cycles": [
                {"pid": first_identity["runtime"]["pid"], "stopped": True},
                {"pid": second_identity["runtime"]["pid"], "stopped": True},
            ],
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{args.platform} P4: installed guest configuration, TLS and drain verified ({args.output})")
    finally:
        release.unlink(missing_ok=True)
        stop_child(active)
        sinkhole.close()
        if peer_added:
            checked([cli, "agent", "remove", PEER], timeout=60)


if __name__ == "__main__":
    main()
