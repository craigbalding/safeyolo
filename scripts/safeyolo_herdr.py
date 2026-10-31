#!/usr/bin/env python3
"""Run a native SafeYolo terminal in a trusted-host Herdr 0.9.5 pane."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

STATUS_FIELDS = (
    "name", "agent_id", "run_id", "launch_id", "harness",
    "runtime_state", "control_state", "terminal_state", "agent_state",
)
AGENT_SOURCE = "custom:safeyolo"
METADATA_SOURCE = "user:safeyolo"


class HerdrError(RuntimeError):
    """Herdr refused a host-side request."""


class Herdr:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    def call(self, method: str, params: dict | None = None) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(self.socket_path)
            connection.sendall((json.dumps({"id": "safeyolo", "method": method,
                                            "params": params or {}}) + "\n").encode())
            with connection.makefile("rb") as response:
                reply = json.loads(response.readline())
        if "error" in reply:
            raise HerdrError(f"{method}: {reply['error'].get('code', 'unknown error')}")
        return reply["result"]


def native_status(command: list[str], name: str) -> dict:
    response = subprocess.run([*command, "agent", "status", name], check=True,
                              capture_output=True, text=True, timeout=30)
    status = json.loads(response.stdout)
    if status.get("name") != name or not status.get("agent_id"):
        raise ValueError("native status did not identify the named agent")
    return {key: status.get(key) for key in STATUS_FIELDS}


def report(herdr: Herdr, pane: str, name: str, status: dict | None) -> None:
    # Native process liveness supplies no working/idle or Factory disposition.
    herdr.call("pane.report_agent", {
        "pane_id": pane, "source": AGENT_SOURCE, "agent": "safeyolo", "state": "unknown",
    })
    tokens = {key: str(status[key]) if status and status.get(key) is not None else None
              for key in STATUS_FIELDS}
    herdr.call("pane.report_metadata", {
        "pane_id": pane, "source": METADATA_SOURCE, "agent": "safeyolo",
        "title": name, "display_agent": f"SafeYolo: {name}",
        "state_labels": {"unknown": "Harness activity unknown"},
        "tokens": tokens, "ttl_ms": 5000,
    })


def terminal_command(command: list[str], name: str, attach: bool) -> list[str]:
    if attach:
        return [*command, "agent", "attach", name]
    return [*command, "agent", "start", name, "--foreground"]


def refresh(command: list[str], name: str, herdr: Herdr, pane: str) -> str | None:
    try:
        status = native_status(command, name)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        status = None
        problem = f"native status unavailable ({type(error).__name__})"
    else:
        problem = None
    try:
        report(herdr, pane, name, status)
    except (OSError, ValueError, HerdrError) as error:
        problem = f"Herdr display unavailable ({type(error).__name__})"
    return problem


def observe_terminal(child: subprocess.Popen, command: list[str], name: str, herdr: Herdr, pane: str) -> int:
    last_problem = None
    while child.poll() is None:
        problem = refresh(command, name, herdr, pane)
        if problem and problem != last_problem:
            print(problem, file=sys.stderr, flush=True)
        last_problem = problem
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            continue  # Refresh the short-lived metadata while the terminal is live.
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


def run_terminal(command: list[str], name: str, herdr: Herdr, pane: str, *, attach: bool = False) -> int:
    status = native_status(command, name)
    # These are host frontend controls. Keep the native terminal's environment
    # free of Herdr controls and an unrelated outer tmux pane identity.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("HERDR_") and key not in ("TMUX", "TMUX_PANE")}
    child = None
    previous = {}

    def forward(signum, _frame):
        if child.poll() is None:
            child.send_signal(signum)

    try:
        report(herdr, pane, name, status)
        herdr.call("agent.rename", {"target": pane, "name": name})
        child = subprocess.Popen(terminal_command(command, name, attach), env=environment)
        # Ctrl+C also reaches the child's foreground process group. Preserve
        # the wrapper while the harness cancels a turn.
        previous[signal.SIGINT] = signal.signal(signal.SIGINT, lambda _signum, _frame: None)
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, forward)
        return observe_terminal(child, command, name, herdr, pane)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        try:
            herdr.call("pane.release_agent", {
                "pane_id": pane, "source": AGENT_SOURCE, "agent": "safeyolo",
            })
            herdr.call("pane.report_metadata", {
                "pane_id": pane, "source": METADATA_SOURCE,
                "clear_title": True, "clear_display_agent": True, "clear_state_labels": True,
                "tokens": dict.fromkeys(STATUS_FIELDS),
            })
        except (OSError, ValueError, HerdrError) as error:
            # Losing the frontend must not stop the independently owned sandbox.
            # Metadata also expires if the server cannot receive this release.
            print(f"Herdr release unavailable ({type(error).__name__})", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="existing native SafeYolo agent")
    parser.add_argument("--safeyolo", required=True, type=Path, help="installed native CLI")
    parser.add_argument("--root", required=True, type=Path, help="existing SafeYolo root")
    parser.add_argument("--attach", action="store_true", help="use native attach for an existing attachable launch")
    args = parser.parse_args()
    try:
        return run_terminal([str(args.safeyolo), "--root", str(args.root)], args.name,
                            Herdr(os.environ["HERDR_SOCKET_PATH"]), os.environ["HERDR_PANE_ID"],
                            attach=args.attach)
    except (KeyError, OSError, ValueError, HerdrError, subprocess.SubprocessError) as error:
        print(f"SafeYolo Herdr terminal failed ({type(error).__name__}): inspect the host setup", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
