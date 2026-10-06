"""Run blackbox guest commands without restoring the retired package shell.

Ordinary commands use the selected instance's native shell. Linux root checks
use guest sudo after native exec validation. macOS retains direct root SSH,
including its identity-specific login limits. Sandbox selection and control
remain with the existing native and platform owners.
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path


def guest_command_args(cli: str, agent: str, command: str, *, guest_root: bool = False) -> list[str]:
    """Use the installed package's interpreter, not the runner's ambient Python."""
    if __package__:
        from .installed_host_smoke import _interpreter_from_shebang, _resolve_executable
    else:
        from installed_host_smoke import _interpreter_from_shebang, _resolve_executable

    interpreter = _interpreter_from_shebang(_resolve_executable(cli, "installed package CLI"))
    if interpreter is None:
        raise RuntimeError(f"Installed package CLI has no usable Python interpreter: {cli}")
    return [str(interpreter), "-I", str(Path(__file__).resolve()), agent,
            "--user", "root" if guest_root else "agent", "-c", command]


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent")
    parser.add_argument("-c", "--command", required=True)
    parser.add_argument("--user", choices=("agent", "root"), default="agent")
    parser.add_argument("--cli", help="installed package entry point supplying the test interpreter")
    args = parser.parse_args(arguments)
    if args.cli:
        command = guest_command_args(args.cli, args.agent, args.command,
                                     guest_root=args.user == "root")
        os.execv(command[0], command)

    from safeyolo.agent_lifecycle import _native_cli, native_agent_status

    if args.user == "agent":
        return _native_cli(["agent", "shell", args.agent, "-c", args.command]).returncode

    if sys.platform == "linux":
        from safeyolo.platform.linux import _wrap_runsc_command

        # The old Python runsc primitive uses safeyolo-NAME, whereas native
        # runs use safeyolo-RUN_ID and validate the holder's birth/namespaces.
        # Keep that native selection, then use the supported guest sudo helper.
        command = "exec sudo -n /bin/bash -lc " + shlex.quote(_wrap_runsc_command(args.command))
        return _native_cli(["agent", "shell", args.agent, "-c", command]).returncode

    from safeyolo.platform import get_platform

    if native_agent_status(args.agent).get("exec") is not True:
        raise RuntimeError(f"Guest runtime or exec control is unavailable: {args.agent}")
    return get_platform().exec_in_sandbox(args.agent, args.command, user="root", interactive=False)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"Guest command failed: {error}", file=sys.stderr)
        sys.exit(1)
