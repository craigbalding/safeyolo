"""Run blackbox guest commands without restoring the retired package shell.

Commands use the selected instance's native shell. Root checks use guest sudo
after native exec validation on both supported platforms. Sandbox selection,
process identity, and platform-specific login limits remain with the native host
and guest owners.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys


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


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("-c", "--command")
    operation.add_argument("--prepare-tests", action="store_true")
    parser.add_argument("--user", choices=("agent", "root"), default="agent")
    parser.add_argument("--cli", help="installed native CLI")
    args = parser.parse_args(arguments)
    cli = args.cli or os.environ.get("SAFEYOLO_CLI", "safeyolo")
    if args.prepare_tests:
        prepare_guest_tests(cli, args.agent)
        return 0
    command = guest_command_args(cli, args.agent, args.command, guest_root=args.user == "root")
    os.execvp(command[0], command)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Guest command failed: {error}", file=sys.stderr)
        sys.exit(1)
