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
import sys


def guest_command_args(cli: str, agent: str, command: str, *, guest_root: bool = False) -> list[str]:
    """Invoke the installed native shell; Python remains only a test workload."""
    if guest_root:
        command = "exec sudo -n /bin/bash -lc " + shlex.quote(command)
    root = os.environ.get("SAFEYOLO_CONFIG_DIR")
    selected = [cli, "--root", root] if root else [cli]
    return [*selected, "agent", "shell", agent, "-c", command]


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent")
    parser.add_argument("-c", "--command", required=True)
    parser.add_argument("--user", choices=("agent", "root"), default="agent")
    parser.add_argument("--cli", help="installed native CLI")
    args = parser.parse_args(arguments)
    command = guest_command_args(args.cli or os.environ.get("SAFEYOLO_CLI", "safeyolo"),
                                 args.agent, args.command, guest_root=args.user == "root")
    os.execvp(command[0], command)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"Guest command failed: {error}", file=sys.stderr)
        sys.exit(1)
