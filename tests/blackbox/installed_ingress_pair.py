#!/usr/bin/env python3
"""Qualify two installed systrap guests on a dedicated Linux instance.

Prepare running bbtest and bbpeer agents with this checkout mounted at /workspace.
Supply their dedicated instance, attached runtime report and installed package
revision. Reuse installed inputs; this probe installs nothing. It sends forged
identity claims, checks both private mounts as ordinary guest and guest root,
and replaces the proxy while retaining the guests. Finally it stops this
instance's two guests and proxy. The section runner owns the origin and Coord.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import time
import uuid
from pathlib import Path

if __package__:
    from .guest_exec import guest_command_args
    from .host.sinkhole_client import SinkholeClient
    from .installed_host_smoke import _agent_listeners, _native_config, _process_start_token
    from .installed_ingress import (
        check_guest_and_origin,
        check_ingress_policy,
        installed_identity,
        read_native_policy,
        runsc_identity,
    )
    from .installed_lifecycle import (
        assert_proxy_stopped,
        checked,
        event_rows,
        running_guest,
        runtime_identity,
        stop_guest,
    )
    from .installed_sections import surviving_processes
else:
    from guest_exec import guest_command_args
    from host.sinkhole_client import SinkholeClient
    from installed_host_smoke import _agent_listeners, _native_config, _process_start_token
    from installed_ingress import (
        check_guest_and_origin,
        check_ingress_policy,
        installed_identity,
        read_native_policy,
        runsc_identity,
    )
    from installed_lifecycle import (
        assert_proxy_stopped,
        checked,
        event_rows,
        running_guest,
        runtime_identity,
        stop_guest,
    )
    from installed_sections import surviving_processes

AGENTS = ("bbtest", "bbpeer")


def live_guest(cli: str, config_dir: Path, agent: str) -> dict:
    """Read the current run, rejecting dead or reused backend and holder PIDs."""
    run = json.loads((config_dir / "agents" / agent / "runtime.json").read_text())
    status = json.loads(checked([cli, "--root", str(config_dir), "agent", "status", agent]).stdout)
    value = running_guest(config_dir, agent, status)
    holder, token = run["holder_pid"], run["holder_token"]
    assert token and _process_start_token(holder) == token, "namespace holder birth no longer matches"
    return {**value, "holder_pid": holder, "holder_token": token}


def guest_probe(cli: str, agent: str, marker: str, *arguments: str, guest_root: bool = False) -> dict:
    command = shlex.join(["python3", "/workspace/tests/blackbox/isolation/installed_ingress.py",
                          "--agent", agent, "--marker", marker, *arguments])
    result = checked(guest_command_args(cli, agent, command, guest_root=guest_root), timeout=90)
    lines = [line.removeprefix("P1_OBSERVATION=") for line in result.stdout.splitlines()
             if line.startswith("P1_OBSERVATION=")]
    assert len(lines) == 1, "guest did not return one ingress observation"
    return json.loads(lines[0])


def request_attribution(audit: Path, guest: dict, listener: dict) -> list[dict]:
    """Join request IDs to canonical traffic events and listener-owned source."""
    identifiers = {guest["allow"]["request_id"], guest["deny"]["request_id"]}
    deadline = time.monotonic() + 5
    while True:
        rows = event_rows(audit)
        selected = [row for row in rows if row.get("event") == "traffic.request"
                    and row.get("request_id") in identifiers]
        if len(selected) == 2:
            break
        assert time.monotonic() < deadline, "canonical ingress traffic events missing or duplicated"
        time.sleep(0.05)
    assert {row["request_id"] for row in selected} == identifiers
    assert listener["ip"], "listener has no source identity"
    for row in selected:
        assert row["agent"] == listener["agent_id"], row
        assert row["details"]["client"] == listener["ip"], row
        attribution = row["details"]["attribution"]
        assert attribution["trusted_transport_identity"] == listener["agent_id"], row
        assert attribution["attribution_provenance"]["transport_source"] == "uds", row
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--install-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    config_dir = args.config_dir.resolve()
    os.environ["SAFEYOLO_CONFIG_DIR"] = str(config_dir)
    os.environ["SAFEYOLO_BLACKBOX_PLATFORM"] = "systrap"
    raw = json.loads(args.runtime.read_text())
    assert Path(raw["instance"]["config_dir"]).resolve() == config_dir
    identity = installed_identity(raw, None, expected_revision=args.install_commit)
    cli = identity["cli"]["path"]
    active_runtime = identity["runtime"]
    native = _native_config(config_dir / "config.toml", config_dir)["raw"]
    listeners = {row["agent_id"]: row for row in _agent_listeners(config_dir)}
    # Ownership is supplied by the dedicated fixture, never inferred from a
    # process name. Refuse to restart or clean an instance with another agent.
    assert set(listeners) == set(AGENTS), "probe requires only bbtest and bbpeer"
    assert listeners[AGENTS[0]]["ip"] != listeners[AGENTS[1]]["ip"]
    assert {path.name for path in (config_dir / "agents").iterdir() if path.is_dir()} == set(AGENTS)
    before = {agent: live_guest(cli, config_dir, agent) for agent in AGENTS}
    bridges = {agent: runsc_identity(config_dir, agent, Path(listeners[agent]["path"]), platform="systrap")
               for agent in AGENTS}
    policy = read_native_policy(cli, config_dir)
    check_ingress_policy(policy)
    report = {"status": "ingress_pair_incomplete", "installed": identity, "host": raw["host"],
              "substrate": raw["substrate"], "listeners": listeners, "guests_before": before,
              "bridges": bridges, "policy": policy, "boundaries": {}}

    def save() -> None:
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    save()
    state_files = []
    sinkhole = SinkholeClient(os.environ.get("SINKHOLE_API", "http://127.0.0.1:19999"))

    def observe(phase: str) -> None:
        report[phase] = {}
        for agent, peer in (AGENTS, AGENTS[::-1]):
            marker = "p1-" + uuid.uuid4().hex
            claims = {"agent": peer, "source": listeners[peer]["ip"]}
            value = guest_probe(cli, agent, marker, "--claimed-agent", claims["agent"],
                                "--claimed-source", claims["source"])
            item = {"claims": claims, "guest": value}
            report[phase][agent] = item
            save()
            item["origin"] = check_guest_and_origin(value, sinkhole, marker, agent)
            item["attribution"] = request_attribution(Path(native["audit_log_path"]), value, listeners[agent])
            save()

    try:
        sinkhole.wait_for_receiver_ready(timeout=10)
        observe("initial")
        marker = "p1-" + uuid.uuid4().hex
        filename = ".ingress-" + marker
        states = {agent: config_dir / "agents" / agent / "home" / filename for agent in AGENTS}
        for agent in AGENTS:
            with states[agent].open("x") as state:
                state_files.append(states[agent])
                state.write(agent + marker)
        for agent, peer in (AGENTS, AGENTS[::-1]):
            peer_socket = Path(listeners[peer]["path"])
            assert peer_socket.is_socket() and states[peer].read_text() == peer + marker
            report["boundaries"][agent] = []
            for root in (False, True):
                value = guest_probe(cli, agent, marker, "--phase", "boundary", "--peer-socket", str(peer_socket),
                                    "--peer-state", str(states[peer]), "--own-state", "/home/agent/" + filename,
                                    "--state-value", agent + marker, guest_root=root)
                report["boundaries"][agent].append(value)
                save()
                assert value["uid"] == (0 if root else 1000), "boundary probe ran as the wrong guest user"
        checked([cli, "--root", str(config_dir), "stop"], timeout=45)
        report["stopped"] = {"guests": {agent: live_guest(cli, config_dir, agent) for agent in AGENTS}, "refusals": {}}
        save()
        assert report["stopped"]["guests"] == before, "proxy stop replaced a guest generation"
        for agent in AGENTS:
            path = Path(listeners[agent]["path"])
            assert_proxy_stopped(config_dir, path, identity["runtime"])
            with socket.socket(socket.AF_UNIX) as control:
                refused = control.connect_ex(str(path))
            value = guest_probe(cli, agent, marker, "--phase", "refused")
            report["stopped"]["refusals"][agent] = {"host_connect_errno": refused, "guest": value}
            save()
            assert refused != 0, "stopped private listener still accepts"
        checked([cli, "--root", str(config_dir), "start"], timeout=45)
        restarted = runtime_identity(config_dir, cli, identity["candidate"]["path"], None,
                                     args.output.with_name("ingress-pair-restarted-runtime.json"),
                                     AGENTS[0], args.install_commit)
        active_runtime = restarted["runtime"]
        report["restarted"] = {"runtime": restarted, "guests": {agent: live_guest(cli, config_dir, agent) for agent in AGENTS}}
        save()
        assert restarted["runtime"]["receipt"]["start_token"] != identity["runtime"]["receipt"]["start_token"]
        assert report["restarted"]["guests"] == before, "proxy restart replaced a guest generation"
        assert {row["agent_id"]: row for row in _agent_listeners(config_dir)} == listeners
        observe("recovery")
        report["status"] = "ingress_pair_checks_passed"
        save()
    finally:
        sinkhole.close()
        for agent in AGENTS:
            stop_guest(cli, config_dir, agent)
        checked([cli, "--root", str(config_dir), "stop"], timeout=45)
        for row in listeners.values():
            assert_proxy_stopped(config_dir, Path(row["path"]), active_runtime)
        births = [{"pid": row[pid], "start_token": row[token]} for row in before.values()
                  for pid, token in (("backend_pid", "backend_token"), ("holder_pid", "holder_token"))]
        report["cleanup_failures"] = surviving_processes(births)
        report["cleanup_processes"] = births
        if report["cleanup_failures"]:
            report["status"] = "ingress_pair_cleanup_failed"
        for path in state_files:
            path.unlink(missing_ok=True)
        save()
        assert not report["cleanup_failures"], report["cleanup_failures"]
    report["status"] = "ingress_pair_passed"
    save()
    print(f"Two-agent systrap ingress, forged claims, refusal/recovery and cleanup verified ({args.output})")


if __name__ == "__main__":
    main()
