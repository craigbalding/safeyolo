#!/usr/bin/env python3
"""Operator recipe: one bounded guest probe over the existing shared home.

Run from a SafeYolo checkout with ``uv run python contrib/vm-guest-probe.py NAME``.
This uses PID 1's existing supervisor; no SSH or helper control socket is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import signal
import tempfile
import time
import uuid
from pathlib import Path

from safeyolo.agent_command_supervisor import (
    read_command_supervisor_state,
    request_command_supervisor_stop,
    start_command_supervisor,
)
from safeyolo.agent_launchers import launch_lock, read_launch
from safeyolo.commands.agent import _agent_host_setup_lock
from safeyolo.config import get_data_dir
from safeyolo.sockets import _AGENT_NAME_RE
from safeyolo.vm import get_agent_config_share_dir, get_agent_home_dir


def deadline_expired(*_args: object) -> None:
    raise TimeoutError("host recovery deadline expired; guest completion is unverified")


def save(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def require_idle(name: str) -> dict | None:
    state = read_command_supervisor_state(name)
    if state and state.get("state") not in {"stopped", "failed", "exited"}:
        raise RuntimeError("command supervisor is occupied or unverified; its state was left intact")
    launch = read_launch(name)
    if launch and launch.get("state") in {"starting", "launching", "stopping", "finishing"}:
        raise RuntimeError("a launcher transition is in progress; its state was left intact")
    return state


def wait_for_result(name: str, command: str, probe_id: str) -> dict:
    while True:
        state = read_command_supervisor_state(name)
        if not state or state.get("command") != command:
            raise RuntimeError("supervisor ownership changed; recovery completion is unverified")
        if state["state"] in {"stopped", "failed", "exited"}:
            try:
                result = json.loads(state.get("last_stderr", ""))
            except (ValueError, TypeError) as error:
                raise RuntimeError("guest did not record a complete probe result") from error
            if (not isinstance(result, dict) or result.get("probe_id") != probe_id
                    or state.get("last_stderr_truncated") or state.get("last_exit_code") != 0):
                raise RuntimeError("guest probe result or exit status is incomplete; inspect the saved supervisor state")
            return result
        time.sleep(0.05)


def probe(name: str, *, timeout: float = 15.0) -> Path:
    if _AGENT_NAME_RE.fullmatch(name) is None:
        raise ValueError(f"invalid agent name: {name!r}")
    config_share = get_agent_config_share_dir(name)
    if not get_agent_home_dir(name).is_dir() or not (config_share / "guest-command-supervisor.py").is_file():
        raise RuntimeError("existing guest home/config share required; boot this agent first")
    payload = Path(__file__).with_name("vm-guest-probe-payload.py").read_text()
    probe_id = uuid.uuid4().hex
    command = "exec " + shlex.join(["python3", "-c", payload, probe_id])
    audit_root = get_data_dir() / "vm-recovery"
    audit_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=audit_root))
    save(output / "invocation.json", {"name": name, "probe_id": probe_id,
         "operator_uid": os.getuid(), "requested_at": time.time(), "timeout_seconds": timeout,
         "payload_sha256": hashlib.sha256(payload.encode()).hexdigest()})
    previous_handler = signal.signal(signal.SIGALRM, deadline_expired)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        # Use the same order as agent run. This serializes normal starts/stops
        # and simultaneous probes, including the check before publication.
        with _agent_host_setup_lock(name), launch_lock(name):
            previous = require_idle(name)
            if previous:
                save(output / "previous-state.json", previous)
            try:
                start_command_supervisor(name, command)
                result = wait_for_result(name, command, probe_id)
                save(output / "result.json", result)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                current = read_command_supervisor_state(name)
                if current and current.get("command") == command:
                    save(output / "supervisor-state.json", current)
                    # This publishes a fence; it does not prove termination.
                    request_command_supervisor_stop(name)
    except (OSError, ValueError, RuntimeError) as error:
        save(output / "error.json", {"error": str(error)})
        raise RuntimeError(f"{error}; evidence: {output}") from error
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="existing agent with an idle PID-1 command supervisor")
    args = parser.parse_args()
    try:
        output = probe(args.name)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Guest probe completed; evidence: {output}")
    print((output / "result.json").read_text(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
