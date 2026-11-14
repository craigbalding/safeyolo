"""Run blackbox guest commands without restoring the retired package shell.

Commands use the selected instance's native shell. Root checks use guest sudo
after native exec validation on both supported platforms. Sandbox selection,
process identity, and platform-specific login limits remain with the native host
and guest owners.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import uuid
from pathlib import Path

if __package__:
    from .execution_receipt import pytest_problems
else:
    from execution_receipt import pytest_problems


def guest_command_args(
    cli: str, agent: str, command: str, *, guest_root: bool = False, env: dict[str, str] | None = None
) -> list[str]:
    """Invoke the installed native shell; Python remains only a test workload.

    Use the supplied invocation environment, or the current environment by default.
    """
    if guest_root:
        command = "exec sudo -n /bin/bash -lc " + shlex.quote(command)
    environment = os.environ if env is None else env
    root = environment.get("SAFEYOLO_CONFIG_DIR")
    selected = [cli, "--root", root] if root else [cli]
    return [*selected, "agent", "shell", agent, "-c", command]


def prepare_guest_tests(cli: str, agent: str, *, env: dict[str, str] | None = None) -> None:
    """Install test dependencies in the owned test guest after each boot.

    Ephemeral guests discard OS package files on stop. Keep this outside the
    production image and prepare restarted guests, peers and lifecycle owners.
    """
    command = "bash /workspace/tests/blackbox/prepare-guest-tests.sh"
    environment = os.environ if env is None else env
    if inputs := environment.get("SAFEYOLO_GUEST_TEST_INPUTS"):
        # Pass the guest path inside sudo; host environment variables do not
        # survive the native shell and guest sudo boundary automatically.
        command += " " + shlex.quote(inputs)
    try:
        subprocess.run(guest_command_args(cli, agent, command, guest_root=True, env=env),
                       env=env, check=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as error:
        # All callers are fixture entry points. Preserve the runner's setup
        # failure exit, including when a peer/owner/restart calls us directly.
        print(f"Test guest dependencies could not be prepared: {error}", file=sys.stderr)
        raise SystemExit(2) from error


def run_guest_pytest(cli: str, agent: str, phase: str, lane: str, output: Path,
                     arguments: list[str], *, run_id: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a named phase and copy its report from the same guest identity."""
    selected_run = run_id or os.environ.get("SAFEYOLO_BLACKBOX_RUN_ID") or uuid.uuid4().hex
    guest_output = "/tmp/blackbox-" + uuid.uuid4().hex + ".json"
    command = shlex.join([
        "/usr/bin/python3", "/workspace/tests/blackbox/execution_receipt.py", "--phase", phase,
        "--lane", lane, "--output", guest_output, "--run-id", selected_run, "--", *arguments,
    ])
    root = phase == "guest-root" or phase == "listener-guest-root"
    environment = "SAFEYOLO_BLACKBOX_ISOLATION=1 "
    if context := os.environ.get("SAFEYOLO_BLACKBOX_GUEST_IDENTITY"):
        environment += "SAFEYOLO_BLACKBOX_GUEST_IDENTITY=" + shlex.quote(context) + " "
    result = subprocess.run(guest_command_args(cli, agent, environment + command, guest_root=root),
                            capture_output=True, text=True, check=False)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    copy_command = shlex.join(["cat", guest_output]) + " && " + shlex.join(["rm", "--", guest_output])
    copied = subprocess.run(guest_command_args(cli, agent, copy_command, guest_root=root),
                            capture_output=True, text=True, check=False, timeout=30)
    if copied.returncode:
        print(f"Guest phase {phase} did not retain a readable report", file=sys.stderr)
        return subprocess.CompletedProcess(result.args, 2, result.stdout, result.stderr)
    document = json.loads(copied.stdout)
    if document.get("run_id") != selected_run or document.get("phase") != phase:
        raise ValueError("guest receipt does not match the selected phase/run")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n")
    if result.returncode == 0 and pytest_problems(document, phase, lane):
        return subprocess.CompletedProcess(result.args, 2, result.stdout, result.stderr)
    return result


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("-c", "--command")
    operation.add_argument("--prepare-tests", action="store_true")
    operation.add_argument("--pytest-phase")
    parser.add_argument("--lane", default="unknown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--user", choices=("agent", "root"), default="agent")
    parser.add_argument("--cli", help="installed native CLI")
    selected_args = sys.argv[1:] if arguments is None else arguments
    forwarded = []
    if "--" in selected_args:
        boundary = selected_args.index("--")
        forwarded = selected_args[boundary + 1:]
        selected_args = selected_args[:boundary]
    args = parser.parse_args(selected_args)
    cli = args.cli or os.environ.get("SAFEYOLO_CLI", "safeyolo")
    if args.prepare_tests:
        prepare_guest_tests(cli, args.agent)
        return 0
    if args.pytest_phase:
        if args.output is None:
            parser.error("--pytest-phase requires --output")
        return run_guest_pytest(cli, args.agent, args.pytest_phase, args.lane, args.output, forwarded).returncode
    command = guest_command_args(cli, args.agent, args.command, guest_root=args.user == "root")
    os.execvp(command[0], command)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Guest command failed: {error}", file=sys.stderr)
        sys.exit(1)
