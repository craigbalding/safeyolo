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
import unicodedata
from pathlib import Path

STATUS_FIELDS = (
    "name", "agent_id", "run_id", "launch_id", "harness",
    "runtime_state", "control_state", "terminal_state", "agent_state",
)
AGENT_SOURCE = "custom:safeyolo"
METADATA_SOURCE = "user:safeyolo"
# Herdr 0.9.5 permits 32 pane tokens and 16 token updates per request.
# The identity fields and two claim headings leave room for ten title/reference pairs.
CLAIM_SLOTS = 10
WORK_FIELDS = ("coord_room", "claimed_work", *(f"claim_{index}_{field}"
               for index in range(1, CLAIM_SLOTS + 1) for field in ("title", "ref")))


class HerdrError(RuntimeError):
    """A Herdr request failed or its response violated the protocol."""


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
                raw = response.readline()
        try:
            reply = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise HerdrError(f"{method}: invalid JSON response") from error
        if not isinstance(reply, dict):
            raise HerdrError(f"{method}: expected response object")
        if reply.get("id") != "safeyolo":
            raise HerdrError(f"{method}: response id does not match request")
        if "error" in reply:
            error = reply["error"]
            if not isinstance(error, dict) or not isinstance(error.get("code"), str):
                raise HerdrError(f"{method}: expected error code string")
            raise HerdrError(f"{method}: {error['code']}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise HerdrError(f"{method}: expected result object")
        return result


def native_status(command: list[str], name: str) -> dict:
    response = subprocess.run([*command, "agent", "status", name], check=True,
                              capture_output=True, text=True, timeout=30)
    status = json.loads(response.stdout)
    if (not isinstance(status, dict) or status.get("name") != name
            or not isinstance(status.get("agent_id"), str) or not status["agent_id"]):
        raise ValueError("native status did not identify the named agent")
    return {key: status.get(key) for key in STATUS_FIELDS}


def display_text(text: str, *, truncated: bool = False) -> str:
    """Mark excerpts before Herdr's 80-character normalization can hide them."""
    text = "".join(char for char in text.strip() if unicodedata.category(char) != "Cc")
    return text[:79] + "…" if len(text) > 80 or truncated else text


def claim_display(work: dict) -> tuple[str, str]:
    """Read the current Coord projection's title and preferred work reference."""
    if (not isinstance(work.get("title"), str) or type(work.get("title_truncated")) is not bool
            or not isinstance(work.get("work_id"), str) or not work["work_id"]
            or (work.get("target_ref") is not None and not isinstance(work["target_ref"], str))):
        raise ValueError("invalid claimed work display fields")
    reference = work.get("github_reference")
    if reference is not None and (not isinstance(reference, dict) or not isinstance(reference.get("url"), str)):
        raise ValueError("invalid claimed work reference")
    return (display_text(work["title"], truncated=work["title_truncated"]),
            display_text(reference["url"] if reference else work.get("target_ref") or work["work_id"]))


def claimed_work(command: list[str], room: str, agent_id: str) -> dict:
    """Build expiring display tokens from this agent's canonical room claims."""
    response = subprocess.run([*command, "coord", "status", room, "--json"], check=True,
                              capture_output=True, text=True, timeout=30)
    status = json.loads(response.stdout)
    page = status.get("active_work") if isinstance(status, dict) else None
    if not isinstance(page, dict) or not isinstance(page.get("items"), list):
        raise ValueError("expected active work page")
    total, shown, truncated = (page.get(key) for key in ("total", "shown", "truncated"))
    if (type(total) is not int or type(shown) is not int or type(truncated) is not bool
            or shown != len(page["items"]) or not 0 <= shown <= total or truncated != (shown < total)):
        raise ValueError("invalid active work counts")
    claims = []
    for work in page["items"]:
        if (not isinstance(work, dict) or work.get("state") not in ("open", "claimed")
                or "claim_agent_id" not in work
                or (work["state"] == "claimed" and
                    (not isinstance(work["claim_agent_id"], str) or not work["claim_agent_id"]))
                or (work["state"] == "open" and work["claim_agent_id"] is not None)):
            raise ValueError("invalid active work ownership")
        if work["state"] != "claimed" or work["claim_agent_id"] != agent_id:
            continue
        claims.append(claim_display(work))
    tokens = dict.fromkeys(WORK_FIELDS)
    tokens["coord_room"] = display_text(room)
    count = len(claims)
    summary = f"Claimed work: {count}" + (" seen" if truncated else "")
    if count > CLAIM_SLOTS:
        summary += f" ({CLAIM_SLOTS} shown; display truncated)"
    if truncated:
        summary += "; room truncated"
    tokens["claimed_work"] = summary
    for index, (title, reference) in enumerate(claims[:CLAIM_SLOTS], 1):
        tokens[f"claim_{index}_title"] = title
        tokens[f"claim_{index}_ref"] = reference
    return tokens


def report(herdr: Herdr, pane: str, name: str, status: dict | None, work: dict | None = None) -> None:
    # Native process liveness supplies no working/idle or Factory disposition.
    herdr.call("pane.report_agent", {
        "pane_id": pane, "source": AGENT_SOURCE, "agent": "safeyolo", "state": "unknown",
    })
    tokens = {key: str(status[key]) if status and status.get(key) is not None else None
              for key in STATUS_FIELDS}
    tokens.update(work or {})
    metadata = {
        "pane_id": pane, "source": METADATA_SOURCE, "agent": "safeyolo",
        "title": name, "display_agent": f"SafeYolo: {name}",
        "state_labels": {"unknown": "Harness activity unknown"},
        "ttl_ms": 5000,
    }
    items = list(tokens.items())
    for start in range(0, len(items), 16):
        herdr.call("pane.report_metadata", dict(metadata, tokens=dict(items[start:start + 16])))


def terminal_command(command: list[str], name: str, attach: bool) -> list[str]:
    if attach:
        return [*command, "agent", "attach", name]
    return [*command, "agent", "start", name, "--foreground"]


def refresh(command: list[str], name: str, herdr: Herdr, pane: str, *, room: str | None = None) -> str | None:
    problem: str | None = None
    try:
        status = native_status(command, name)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        status = None
        problem = f"native status unavailable ({type(error).__name__})"
    work = None
    if room is not None:
        work = dict.fromkeys(WORK_FIELDS)
        work.update(coord_room=display_text(room), claimed_work="Claimed work: unavailable")
        if status:
            try:
                work = claimed_work(command, room, status["agent_id"])
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                problem = f"Coord claimed work unavailable ({type(error).__name__})"
    try:
        report(herdr, pane, name, status, work)
    except (OSError, ValueError, HerdrError) as error:
        problem = f"Herdr display unavailable ({type(error).__name__})"
    return problem


def observe_terminal(child: subprocess.Popen, command: list[str], name: str, herdr: Herdr, pane: str,
                     *, room: str | None = None) -> int:
    last_problem = None
    while child.poll() is None:
        problem = refresh(command, name, herdr, pane, room=room)
        if problem and problem != last_problem:
            print(problem, file=sys.stderr, flush=True)
        last_problem = problem
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            continue  # Refresh the short-lived metadata while the terminal is live.
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


def run_terminal(command: list[str], name: str, herdr: Herdr, pane: str, *, attach: bool = False,
                 room: str | None = None) -> int:
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
        report(herdr, pane, name, status, dict.fromkeys(WORK_FIELDS) if room is not None else None)
        herdr.call("agent.rename", {"target": pane, "name": name})
        child = subprocess.Popen(terminal_command(command, name, attach), env=environment)
        # Ctrl+C also reaches the child's foreground process group. Preserve
        # the wrapper while the harness cancels a turn.
        previous[signal.SIGINT] = signal.signal(signal.SIGINT, lambda _signum, _frame: None)
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, forward)
        return observe_terminal(child, command, name, herdr, pane, room=room)
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
            fields = (*STATUS_FIELDS, *WORK_FIELDS) if room is not None else STATUS_FIELDS
            for start in range(0, len(fields), 16):
                herdr.call("pane.report_metadata", {
                    "pane_id": pane, "source": METADATA_SOURCE,
                    "clear_title": True, "clear_display_agent": True, "clear_state_labels": True,
                    "tokens": dict.fromkeys(fields[start:start + 16]),
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
    parser.add_argument("--coord-room", help="show this agent's claimed work in the named Coord room")
    args = parser.parse_args()
    try:
        return run_terminal([str(args.safeyolo), "--root", str(args.root)], args.name,
                            Herdr(os.environ["HERDR_SOCKET_PATH"]), os.environ["HERDR_PANE_ID"],
                            attach=args.attach, room=args.coord_room)
    except (KeyError, OSError, ValueError, HerdrError, subprocess.SubprocessError) as error:
        print(f"SafeYolo Herdr terminal failed ({type(error).__name__}): inspect the host setup", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
