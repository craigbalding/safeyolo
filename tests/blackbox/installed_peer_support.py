#!/usr/bin/env python3
"""Exercise delegated support on an owned disposable installed instance.

On the selected Linux/gVisor or physical macOS/VZ host, prepare an isolated
instance with the candidate native CLI/proxy, Linux guest helper and MCP binary.
Start its proxy and configure two disposable workers with an owned workspace,
the supervisor launcher and a long-running command such as ``exec sleep 300``.
Both workers must be stopped. Supply their names as --support and --target.

Run with host Python 3.10+ and --cli, --root and an empty disk-backed --scratch.
This starts and stops those two workers, changes only the named test grant,
and retains proposals in scratch and canonical receipts in the instance.
It does not launch a model or establish the separate unexplained-fault journey.
Guest requests use Bash/curl and never copy the Agent API token to the host.
On macOS retain the operator-approved VZ wrapper and authorized port settings.

--probe-recovery selects only the failed-harness/probe/config-repair journey on
the retained worker.sh fixture. Its saved command must run /workspace/worker.sh,
which reads /home/agent/.config/worker.conf and writes /tmp/worker-ready. The
driver changes only that owned config, preserves the script, observes the
managed process through the guest helper, and prints receipts and status polls
before assertions. It does not repeat the model diagnosis.
"""

from __future__ import annotations

import argparse
import datetime
import json
import shlex
import subprocess
import time
import uuid
from pathlib import Path


def run(args):
    """Check real guest-origin calls and independently observe host state."""
    cli = [str(args.cli.resolve()), "--root", str(args.root.resolve())]
    args.scratch.mkdir(mode=0o700)
    grant_name = "installed-support-control"
    proposal_file = args.scratch / "proposal.json"
    revision = None

    def host(*words):
        result = subprocess.run([*cli, *words], capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, (words, result.stderr[-2000:], result.stdout[-2000:])
        return json.loads(result.stdout)

    def status(name):
        observed = host("agent", "status", name)
        if args.probe_recovery:
            print(json.dumps({"host_status": observed}), flush=True)
        return observed

    support, target = status(args.support), status(args.target)
    assert support["runtime_state"] == target["runtime_state"] == "stopped", (support, target)
    assert support["agent_id"] != target["agent_id"]
    instance = host("support", "grants", "--json")["instance_id"]
    grant = {
        "instance_id": instance,
        "support": {"name": args.support, "agent_id": support["agent_id"]},
        "targets": [{"name": args.target, "agent_id": target["agent_id"]}],
        "guest_admin": False, "guest_logs": [], "lifecycle": [],
        "expires_at": None, "acknowledgment": None,
    }

    def apply():
        nonlocal revision
        grant["acknowledgment"] = None
        proposal = {"expected_revision": revision, "grant": grant}
        proposal_file.write_text(json.dumps(proposal))
        preview = host("support", "preview", grant_name, "--file", str(proposal_file), "--json")
        assert preview["warnings"] and preview["after"]["support"] == grant["support"], preview
        grant["acknowledgment"] = preview["acknowledgment"]
        proposal_file.write_text(json.dumps(proposal))
        applied = host("support", "apply", grant_name, "--file", str(proposal_file), "--json")
        revision = applied["revision"]
        return applied

    def request(method, path, body=None):
        payload = "" if body is None else " --header 'Content-Type: application/json' --data-binary " + shlex.quote(json.dumps(body))
        command = (
            "agent_token=$(cat /app/agent_token) || exit; "
            "printf 'Authorization: Bearer %s\\n' \"$agent_token\" | "
            "curl --silent --show-error --max-time 150 --header @- "
            "--write-out '\\n%{http_code}' --request " + shlex.quote(method) + payload + " "
            + shlex.quote("http://_safeyolo.proxy.internal" + path)
        )
        completed = subprocess.run(
            [*cli, "agent", "shell", args.support, "-c", command],
            capture_output=True, text=True, timeout=180,
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        content, code = completed.stdout.rsplit("\n", 1)
        return int(code), json.loads(content)

    def operation(action, *, expected=None, target_id=None):
        return {"operation_id": uuid.uuid4().hex, "grant": grant_name,
                "target_id": target_id or target["agent_id"], "expected_run": expected,
                "operation": action}

    def execute(body, *, states=("completed",)):
        code, receipt = request("POST", "/support/operations", body)
        if args.probe_recovery:
            print(json.dumps({"http_status": code, "receipt": receipt}), flush=True)
        assert code == 200 and receipt["state"] in states, (code, receipt)
        assert receipt["initiator"]["agent_id"] == support["agent_id"], receipt
        assert receipt["target_id"] == target["agent_id"], receipt
        return receipt

    def inspect():
        return execute(operation({"action": "inspect"}))["result"]

    def lifecycle(name, expected):
        original = execute(operation({"action": "lifecycle", "operation": name}, expected=expected),
                           states=("completed", "outcome_unknown"))["result"]
        deadline = time.monotonic() + 15
        while True:
            # Publication and guest observation can complete at different times.
            # Observe the exact resulting run/launch without another mutation.
            observed = status(args.target)
            assert observed["run_id"] == original["run_id"], (original, observed)
            assert observed["launch_id"] == original["launch_id"], (original, observed)
            if name == "stop_sandbox":
                ready = observed["runtime_state"] == "stopped"
            elif name == "start_sandbox":
                ready = observed["runtime_state"] == "running" and observed["exec"] is True
            else:
                ready = observed["runtime_state"] == "running" and observed["agent_state"] == "running"
            if ready:
                return observed
            assert time.monotonic() < deadline, observed
            time.sleep(.05)

    def guest(command, expected, timeout=10):
        return execute(operation({"action": "guest_command", "command": command,
                                  "timeout_seconds": timeout}, expected=expected))["result"]

    try:
        if args.probe_recovery:
            expiry = datetime.datetime.now().astimezone() + datetime.timedelta(minutes=20)
            grant.update(guest_admin=True, expires_at=expiry.isoformat(),
                         lifecycle=["start_harness", "restart_harness"])
            apply()
            host("agent", "start", args.support, "--sandbox-only")
            booted = host("agent", "start", args.target, "--sandbox-only")
            generation = booted["run_id"]
            script_hash = guest("sha256sum /workspace/worker.sh", generation)["stdout"]
            guest("printf 'WORKER_MODE=disabled\\n' > /home/agent/.config/worker.conf; "
                  "rm -f /tmp/worker-ready", generation)
            first = execute(operation({"action": "lifecycle", "operation": "start_harness"},
                                      expected=generation), states=("completed", "outcome_unknown"))
            assert first["result"] is not None, first
            launch_id = first["result"]["launch_id"]
            deadline = time.monotonic() + 30
            while True:
                failed = status(args.target)
                assert failed["run_id"] == generation and failed["launch_id"] == launch_id, failed
                if failed["agent_state"] == "failed":
                    break
                assert time.monotonic() < deadline, failed
                time.sleep(.1)
            assert inspect()["agent_state"] == "failed"
            execute(operation({"action": "guest_probe", "timeout_seconds": 15}, expected=generation))
            after_probe = inspect()
            assert after_probe["run_id"] == generation and after_probe["launch_id"] == launch_id, after_probe
            assert after_probe["agent_state"] == "failed", after_probe
            repair = guest("printf 'WORKER_MODE=ready\\n' > /home/agent/.config/worker.conf; "
                           "stat -c '%a %u %g' /home/agent/.config/worker.conf", generation)
            assert repair["stdout"].strip() == "644 1000 1000", repair
            recovered = lifecycle("restart_harness", generation)
            assert recovered["launch_id"] != launch_id, recovered
            # Independent host observer verifies guest process births and the
            # exact saved managed command, rather than a manually launched worker.
            checked = host("agent", "shell", args.target, "-c",
                           "/safeyolo/safeyolo-guest supervise check")
            launch = json.loads((args.root / "agents" / args.target / "current-launch.json").read_text())
            print(json.dumps({"independent_supervisor": checked,
                              "managed_launch": {key: launch[key] for key in
                                                 ("agent_id", "launch_id", "command")}}), flush=True)
            assert launch["agent_id"] == target["agent_id"]
            assert checked["generation"] == generation and checked["state"] == "running", checked
            assert checked["supervision_id"] == launch["launch_id"] == recovered["launch_id"]
            assert checked["command"] == launch["command"] and checked["command_pid"] > 0, checked
            verified = guest("cat /tmp/worker-ready; sha256sum /workspace/worker.sh", generation)
            assert verified["stdout"].endswith(script_hash), verified
            assert verified["stdout"].startswith("ready:"), verified
            print("PASS failed harness -> authorized probe -> owned config repair -> managed restart; "
                  "independent supervisor identity/process verified, sandbox generation and worker script unchanged", flush=True)
            proposal_file.write_text(json.dumps({"expected_revision": revision}))
            host("support", "revoke", grant_name, "--file", str(proposal_file), "--json")
            return
        assert apply()["lifetime"] == "standing"
        host("agent", "start", args.support, "--sandbox-only")
        stopped = inspect()
        assert stopped["runtime_state"] == "stopped", stopped
        for action in [
            {"action": "guest_command", "command": "true", "timeout_seconds": 5},
            {"action": "guest_log", "path": "/etc/passwd"},
            {"action": "lifecycle", "operation": "start_sandbox"},
        ]:
            assert request("POST", "/support/operations", operation(action))[0] == 403
        forged = operation({"action": "inspect"}, target_id=support["agent_id"])
        assert request("POST", "/support/operations", forged)[0] == 403
        print("PASS standing inspection of stopped target and guest/log/lifecycle/unrelated-target denials", flush=True)

        expiry = datetime.datetime.now().astimezone() + datetime.timedelta(minutes=20)
        grant.update(guest_admin=True, expires_at=expiry.isoformat(), lifecycle=[
            "start_sandbox", "start_harness", "restart_harness", "stop_sandbox", "restart_sandbox",
        ])
        assert apply()["lifetime"] == "temporary"
        booted = lifecycle("start_sandbox", stopped["run_id"])
        generation = booted["run_id"]
        assert booted["runtime_state"] == "running" and booted["agent_state"] != "running", booted
        assert inspect()["exec"] is True
        assert guest("sudo -n id -u", generation)["stdout"].strip() == "0"
        failed = guest("printf diagnostic; printf problem >&2; exit 7", generation)
        assert failed["exit_code"] == 7 and failed["stdout"] == "diagnostic" and failed["stderr"] == "problem", failed
        bounded = guest("head -c 16384 /dev/zero | tr '\\000' x", generation)
        assert len(bounded["stdout"]) == 8192 and bounded["stdout_truncated"] is True, bounded
        timed = execute(operation({"action": "guest_command", "command": "exec sleep 3",
                                   "timeout_seconds": 1}, expected=generation), states=("timed_out",))
        assert timed["result"]["exit_code"] is None and timed["result"]["guest_descendants_terminated"] is None
        print("PASS stopped-target start, guest sudo, nonzero status, bounded output and honest timeout", flush=True)

        once = operation({"action": "guest_command", "command": "printf receipt-once", "timeout_seconds": 5}, expected=generation)
        first = execute(once)
        assert execute(once) == first
        assert request("GET", "/support/operations/" + once["operation_id"]) == (200, first)
        once["operation"]["command"] = "false"
        assert request("POST", "/support/operations", once)[0] == 409

        launched = lifecycle("start_harness", generation)
        assert launched["agent_state"] == "running", launched
        restarted = lifecycle("restart_harness", generation)
        assert restarted["run_id"] == generation and restarted["launch_id"] != launched["launch_id"], restarted
        assert restarted["agent_state"] == "running", restarted
        # The saved command does not use the proxy. Missing attachment must not
        # cause a second live harness when start is repeated deliberately.
        again = lifecycle("start_harness", generation)
        assert again["run_id"] == generation and again["launch_id"] == restarted["launch_id"], again
        replacement = lifecycle("restart_sandbox", generation)
        assert replacement["runtime_state"] == "running" and replacement["run_id"] != generation, replacement
        execute(operation({"action": "guest_command", "command": "true", "timeout_seconds": 5}, expected=generation), states=("refused",))
        lifecycle("stop_sandbox", replacement["run_id"])
        assert inspect()["runtime_state"] == "stopped"
        print("PASS original receipts, changed-input refusal, separate harness/sandbox recovery and stale-run refusal", flush=True)

        grant.update(guest_admin=False, lifecycle=[], expires_at=None)
        apply()
        host("agent", "stop", args.support)
        host("agent", "start", args.support, "--sandbox-only")
        assert inspect()["runtime_state"] == "stopped"
        assert request("POST", "/support/operations", operation({"action": "guest_command", "command": "true", "timeout_seconds": 5}))[0] == 403
        grant["expires_at"] = (datetime.datetime.now().astimezone() - datetime.timedelta(seconds=1)).isoformat()
        apply()
        assert request("POST", "/support/operations", operation({"action": "inspect"}))[0] == 403
        proposal_file.write_text(json.dumps({"expected_revision": revision}))
        host("support", "revoke", grant_name, "--file", str(proposal_file), "--json")
        assert request("POST", "/support/operations", operation({"action": "inspect"}))[0] == 403
        print("PASS narrowing, standing authority across support restart, expiry and revocation", flush=True)
    finally:
        # Preserve canonical receipts and stopped diagnostic records for review.
        # These names are explicitly supplied disposable workers, never donors.
        host("agent", "stop", args.target)
        host("agent", "stop", args.support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--support", default="support")
    parser.add_argument("--target", default="target")
    parser.add_argument("--probe-recovery", action="store_true")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
