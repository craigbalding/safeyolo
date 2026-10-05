#!/usr/bin/env python3
"""Selected #818 G1 probe on an owned, already prepared Ubuntu/systrap guest.

Only the host test driver and retained harness transport use Python. The
installed guest operation, PID-1 owner and configured marker use native/shell
executables. This does not supply the later Coord/MCP or VZ G7 results.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path

if __package__:
    from .installed_host_smoke import _agent_map, _sha256
    from .installed_ingress import runsc_identity
    from .installed_lifecycle import stop_guest
else:
    from installed_host_smoke import _agent_map, _sha256
    from installed_ingress import runsc_identity
    from installed_lifecycle import stop_guest


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.chmod(0o600)
    temporary.replace(path)


def run(args):
    root = args.config_dir.resolve()
    os.environ["SAFEYOLO_CONFIG_DIR"] = str(root)
    os.environ["SAFEYOLO_LOGS_DIR"] = str(root / "logs")
    home, share = root / "agents" / args.agent / "home", root / "agents" / args.agent / "config-share"
    state_path, stop = home / ".safeyolo-command-supervisor.json", home / ".safeyolo-command-supervisor.stop"
    listener = next(item for item in _agent_map(root) if item["agent_id"] == args.agent)
    runtime = runsc_identity(root, args.agent, Path(listener["path"]), platform="systrap")
    context = json.loads((share / "host-launch-context.json").read_text())
    assert context["generation"], "current-run generation is missing"
    payload = home / ".safeyolo-command.payload"
    assert payload.read_bytes() == Path(__file__).with_name("native-command-marker.sh").read_bytes(), "prepare the owned marker payload before boot"
    assert payload.stat().st_mode & 0o111, "marker payload is not executable"
    if state_path.exists():
        previous = json.loads(state_path.read_text())
        assert previous["state"] in {"stopped", "failed", "exited"} and previous.get("command_pid") is None, "supervisor is occupied; existing work was left intact"

    def shell(command, *, valid=True):
        result = subprocess.run([args.transport_cli, "agent", "shell", args.agent, "-c", command],
                                capture_output=True, text=True, timeout=8)
        if valid:
            assert result.returncode == 0, result.stderr[-1000:]
        return result

    native = subprocess.check_output([args.native_cli, "--version"], text=True).strip()
    guest_version = shell("/safeyolo/safeyolo-guest --version").stdout.strip()
    assert f"commit={args.commit} profile=" in native, "native CLI is not this candidate"
    assert f"commit={args.commit} profile=" in guest_version, "guest executable is not this candidate"
    assert shell("id -u").stdout.strip() == "1000", "fixture requires the maintained agent UID"
    if args.python_unavailable:
        shell("! command -v python && ! command -v python3 && test ! -x /usr/bin/python3 && test ! -x /usr/local/bin/python3")
    run_id = uuid.uuid4().hex
    marker = home / f".g1-{run_id}"
    literal = "literal argument with spaces $(no-substitution)"
    command = shlex.join(["/home/agent/.safeyolo-command", f"/home/agent/{marker.name}", literal])
    state = {"schema_version": 1, "name": args.agent, "command": "exec " + command,
             "supervision_id": run_id, "generation": context["generation"], "state": "starting",
             "runtime_owner": "guest-pid1", "started_at": time.time(), "restart_count": 0, "consecutive_failures": 0}

    def read():
        observed = json.loads(state_path.read_text())
        assert observed["supervision_id"] == run_id and observed["generation"] == context["generation"], "ownership changed"
        return observed

    def wait(predicate):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            observed = read()
            if predicate(observed):
                return observed
            time.sleep(0.05)
        raise AssertionError(f"guest observation deadline expired: {read()}")

    try:
        stop.unlink(missing_ok=True)
        write_json(state_path, state)
        (share / "command-supervisor-enabled").touch()
        running = wait(lambda value: value["state"] == "running" and value["restart_count"] == 1 and (marker / "marker").exists())
        actual = json.loads(shell("/safeyolo/safeyolo-guest supervise check").stdout)
        assert actual["command_start_token"] == running["command_start_token"]
        assert actual["supervisor_parent_pid"] == 1 and actual["supervisor_uid"] == 1000, "native supervisor is not PID-1-owned under the agent UID"
        assert actual["guest_helper_version"] == guest_version
        assert running["last_exit_code"] == 41 and running["last_stderr"] == "configured-crash\n"
        assert (marker / "attempts").read_text() == "2\n" and (marker / "argument").read_text() == literal + "\n"
        assert shell("/safeyolo/safeyolo-guest observe check").stdout.strip() == "running"
        write_json(stop, {"supervision_id": run_id})
        (share / "command-supervisor-enabled").unlink()
        stopped = wait(lambda value: value["state"] == "stopped")
        assert stopped["command_pid"] is None
        assert shell("/safeyolo/safeyolo-guest observe check").stdout.strip() == "stopped"
        time.sleep(10)  # Full configured maximum restart interval.
        assert read() == stopped and (marker / "attempts").read_text() == "2\n"
        helper = share / "safeyolo-guest"
        held = share / "safeyolo-guest.missing-fixture"
        helper.rename(held)
        try:
            missing = shell("/home/agent/.safeyolo-command", valid=False)
            assert missing.returncode == 127 and "Required native guest helper is missing" in missing.stderr
        finally:
            held.rename(helper)
        recovery = subprocess.run([args.native_cli, "--root", str(root), "agent", "recover", args.agent],
                                  capture_output=True, text=True, timeout=18)
        assert recovery.returncode == 0, recovery.stderr
        recovered = json.loads(recovery.stdout)
        assert recovered["result"]["uid"] == 1000 and recovered["state"]["restart_count"] == 0
        result = {"commit": args.commit, "native_cli": native, "guest_helper": guest_version,
                          "guest_sha256": _sha256(helper), "runsc": runtime, "generation": context["generation"],
                          "running": running, "stopped": stopped, "recovery": recovered,
                  "python_unavailable": args.python_unavailable}
    finally:
        # This caller supplies a disposable agent owned by the probe. Do not
        # use this entry point on an operator's working agent.
        stop_guest(args.transport_cli, root, args.agent)
    result["owned_guest_stopped"] = True
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", required=True, type=Path)
    parser.add_argument("--transport-cli", required=True)
    parser.add_argument("--native-cli", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--python-unavailable", action="store_true")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
