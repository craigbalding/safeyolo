#!/usr/bin/env python3
"""Produce real selected events in an owned installed Linux/gVisor or Mac/VZ fixture.

Use the prepared native CLI/proxy, Linux guest helper and MCP binary from the
candidate, an already running proxy and the existing NATS owner. Both named
agents must be stopped. The target must have a supervisor launcher and its
saved long-running, credential-free command. Supply an empty disk-backed
--scratch. Run only in the operator-selected slot. No model is launched.

The driver starts the support sandbox, applies an observation-only event grant,
causes an actual host launcher failure, restores the saved launcher and starts
the target. It then kills only the verified target child and its command owner,
observes surviving-owner restart events, stops the target and resolves ordinary
attention from the support guest. Finally it revokes its grant and stops both
owned agents. It does not exercise the separate #1448 probe-to-harness defect.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from pathlib import Path


def run(args):
    cli = [str(args.cli.resolve()), "--root", str(args.root.resolve())]
    args.scratch.mkdir(mode=0o700)
    revision = None
    grant_name = "installed-operational-events"
    original_launcher = "supervisor"
    reached = {}

    def save(name, value):
        (args.scratch / (name + ".json")).write_text(json.dumps(value, indent=2))

    def host(*words, check=True, timeout=180):
        result = subprocess.run([*cli, *words], capture_output=True, text=True, timeout=timeout)
        if not check:
            return result
        if result.returncode != 0:
            raise RuntimeError(f"Native command {words} failed: {result.stderr[-2000:]}")
        return json.loads(result.stdout)

    def shell(name, command):
        result = host("agent", "shell", name, "-c", command, check=False, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"Guest command failed for {name}: {result.stderr[-1000:]}")
        return result.stdout

    def attention(since):
        # The token remains inside the support guest and reaches curl on
        # stdin. Neither the command string nor returned evidence contains it.
        command = (
            "agent_token=$(cat /app/agent_token) || exit; "
            "printf 'Authorization: Bearer %s\\n' \"$agent_token\" | "
            "curl -sS --max-time 15 --header @- "
            + shlex.quote(f"http://_safeyolo.proxy.internal/api/coord/attention/wait?since={since}&limit=200&timeout=5")
        )
        return json.loads(shell(args.support, command))

    def resolve(edge):
        command = (
            "agent_token=$(cat /app/agent_token) || exit; "
            "printf 'Authorization: Bearer %s\\n' \"$agent_token\" | "
            "curl -sS --max-time 15 --header @- "
            + shlex.quote(f"http://_safeyolo.proxy.internal/api/coord/attention/{edge['attention_id']}/object")
        )
        return json.loads(shell(args.support, command))

    state_path = args.root / "agents" / args.target / "home/.safeyolo-command-supervisor.json"

    def source():
        value = json.loads(state_path.read_text())
        # Keep the actual identities and exit facts, excluding commands,
        # stderr, credentials and other guest activity.
        return {key: value.get(key) for key in (
            "generation", "supervision_id", "state", "supervisor_pid", "supervisor_start_token",
            "command_pid", "command_start_token", "restart_count", "last_exit_code", "last_exit_signal",
            "last_exit_reason", "operational_events")}

    def wait_source(predicate):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if state_path.exists():
                value = source()
                if predicate(value):
                    return value
            time.sleep(0.1)
        raise RuntimeError("Native command source did not reach the expected state")

    support = host("agent", "status", args.support)
    target = host("agent", "status", args.target)
    save("before", {"support": support, "target": target})
    if support["runtime_state"] != "stopped" or target["runtime_state"] != "stopped":
        raise RuntimeError("Prepared agents must be stopped; existing work was left intact")
    if target["launcher"]["kind"] != original_launcher:
        raise RuntimeError("Prepared target needs its saved supervisor launcher")
    versions = {name: subprocess.check_output([str(args.root / "bin" / name), "--version"], text=True).strip()
                for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord")}
    save("versions", versions)
    if not all(f"commit={args.commit} profile=" in version for version in versions.values()):
        raise RuntimeError("Installed native source differs from the selected candidate")
    instance = host("support", "grants", "--json")["instance_id"]
    grant = {"instance_id": instance,
             "support": {"name": args.support, "agent_id": support["agent_id"]},
             "targets": [{"name": args.target, "agent_id": target["agent_id"]}],
             "guest_admin": False, "guest_logs": [], "lifecycle": [], "signal_rooms": [],
             "notifications": ["launch_failed", "sandbox_availability", "control_availability", "sandbox_recovered",
                               "command_exit", "command_restart", "command_failed", "supervisor_exit", "supervisor_restart"],
             "expires_at": None, "acknowledgment": None}
    proposal = {"expected_revision": None, "grant": grant}
    proposal_file = args.scratch / "proposal.json"
    failure_launcher = args.scratch / "fail-launch.sh"
    failure_launcher.write_text("#!/bin/sh\n# Owned launch failure; no target command was started.\nexit 37\n")
    failure_launcher.chmod(0o700)
    try:
        host("agent", "start", args.support, "--sandbox-only")
        guest_version = shell(args.support, "/safeyolo/safeyolo-guest --version").strip()
        save("guest-version", guest_version)
        if f"commit={args.commit} profile=" not in guest_version:
            raise RuntimeError("Installed guest helper differs from the selected candidate")
        proposal_file.write_text(json.dumps(proposal))
        preview = host("support", "preview", grant_name, "--file", str(proposal_file), "--json")
        save("preview", preview)
        grant["acknowledgment"] = preview["acknowledgment"]
        proposal["authority"] = preview["authority"]
        proposal_file.write_text(json.dumps(proposal))
        applied = host("support", "apply", grant_name, "--file", str(proposal_file), "--json")
        revision = applied["revision"]
        host("agent", "configure", args.target, "--launcher", str(failure_launcher))
        failed = host("agent", "start", args.target, check=False)
        save("launch-failure", {"status": failed.returncode, "stdout": failed.stdout, "stderr": failed.stderr})
        if failed.returncode == 0:
            raise RuntimeError("Controlled host launcher unexpectedly succeeded")
        host("agent", "configure", args.target, "--launcher", original_launcher)
        host("agent", "start", args.target)
        first = wait_source(lambda value: value["state"] == "running" and value["command_pid"])
        save("before-child-kill", first)
        current = host("agent", "status", args.target)
        if first["generation"] != current["run_id"] or first["supervision_id"] != current["launch_id"]:
            raise RuntimeError("Target source changed before fault injection")
        shell(args.target, f"kill -KILL {int(first['command_pid'])}")
        restarted = wait_source(lambda value: value["state"] == "running" and value["restart_count"] > first["restart_count"])
        save("after-child-kill", restarted)
        if not any(event["kind"] == "command_exit" and event["exit_signal"] == 9 for event in restarted["operational_events"]):
            raise RuntimeError("Surviving command owner did not retain the abrupt child exit")
        shell(args.target, f"kill -KILL {int(restarted['supervisor_pid'])}")
        resumed = wait_source(lambda value: value["state"] == "running" and value["supervisor_pid"] != restarted["supervisor_pid"])
        save("after-supervisor-kill", resumed)
        if not any(event["kind"] == "supervisor_exit" and event["source"] == "guest_pid1" for event in resumed["operational_events"]):
            raise RuntimeError("Surviving PID 1 did not retain its reaped command owner")
        host("agent", "stop", args.target)
        expected = {"launch_failed", "sandbox_recovered", "command_exit", "command_restart", "supervisor_exit", "supervisor_restart"}
        cursor, objects = 0, []
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and expected:
            page = attention(cursor)
            save("last-attention-page", page)
            if "edges" not in page:
                raise RuntimeError(f"Ordinary attention unavailable: {page}")
            for edge in page["edges"]:
                if edge["kind"] == "operational_event":
                    item = resolve(edge)
                    objects.append(item)
                    save("resolved-events", objects)
                    reference = item["object"]["reference"]
                    if reference["instance_id"] != instance or reference["target"]["agent_id"] != target["agent_id"]:
                        raise RuntimeError("Operational notice identifies another instance or target")
                    expected.discard(reference["kind"])
            cursor = page["next_cursor"]
        if expected:
            raise RuntimeError(f"Selected installed events missing: {sorted(expected)}")
        reached = {"commit": args.commit, "versions": versions, "guest": guest_version,
                   "target_run": first["generation"], "target_launch": first["supervision_id"],
                   "objects": objects, "support_grant": "observation only", "room_setup": "none",
                   "limits": "No paid model, remote instance, or probe-to-harness acceptance is inferred."}
        save("result", reached)
    finally:
        # Cleanup keeps reached operands and failures. It never deletes the
        # prepared package/runtime/cache or the original 1448 evidence.
        host("agent", "configure", args.target, "--launcher", original_launcher, check=False)
        if revision is not None:
            revoke = args.scratch / "revoke.json"
            revoke.write_text(json.dumps({"expected_revision": revision}))
            host("support", "revoke", grant_name, "--file", str(revoke), "--json", check=False)
        cleanup = {name: host("agent", "stop", name, check=False).returncode for name in (args.target, args.support)}
        save("cleanup", cleanup)
    if any(cleanup.values()):
        raise RuntimeError("Product observations are retained, but owned-agent cleanup was not verified")
    print(json.dumps(reached))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--support", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--commit", required=True)
    run(parser.parse_args())
