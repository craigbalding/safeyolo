#!/usr/bin/env python3
"""Compare native harness evidence without changing support or authority.

The trace reader checks an ordinary task boundary. The production supervisor
remains the authority for Factory event parsing and checkpoint behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

SCHEMA = "safeyolo.harness-qualification/v1"
PROTOCOLS = {"codex", "pi"}


class QualificationError(Exception):
    """A failed observation with one actionable reason."""


def identity(path: Path) -> dict:
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path": str(path.resolve()), "sha256": digest}


def execute(command: list[str], directory: Path, output: Path, timeout: float,
            prompt: str | None = None) -> int:
    """Bound an owned process group; keep native output private and on disk."""
    with output.open("xb") as stdout, output.with_suffix(".stderr").open("xb") as stderr:
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.PIPE,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            process.communicate(None if prompt is None else prompt.encode(), timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise QualificationError("Harness deadline expired; inspect retained output before retrying") from error
        finally:
            # The group is created by this invocation. Kill remaining ordinary
            # children even if their leader exited while keeping a pipe open.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return process.returncode


def read_events(path: Path) -> Iterator[dict]:
    """Read native JSON lines, preserving a single actionable parse failure."""
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise QualificationError(f"Malformed JSON at line {number}; repair structured output") from error
            if not isinstance(event, dict):
                raise QualificationError(f"Event at line {number} is not an object; repair structured output")
            message = event.get("message")
            if (event.get("type") == "message_end" and isinstance(message, dict)
                    and message.get("role") == "assistant"):
                stop_reason = message.get("stopReason")
                if stop_reason is not None and not isinstance(stop_reason, str):
                    raise QualificationError("Invalid assistant stopReason; repair structured output")
                if stop_reason in {"error", "aborted"}:
                    raise QualificationError("Native model turn failed; inspect its private error output")
            if event.get("type") == "turn.failed":
                raise QualificationError("Native model turn failed; inspect its private error output")
            yield event


def tool_succeeded(event: dict, harness: str) -> bool:
    if harness == "pi":
        return event.get("type") == "tool_execution_end" and event.get("isError") is False
    item = event.get("item")
    return (event.get("type") == "item.completed" and isinstance(item, dict)
            and item.get("type") == "command_execution" and item.get("status") == "completed"
            and type(item.get("exit_code")) is int and item["exit_code"] == 0)


def session_identity(event: dict, previous: str | None, harness: str) -> str:
    observed = event.get("thread_id" if harness == "codex" else "id")
    if not isinstance(observed, str) or not observed:
        raise QualificationError("Session identity is missing; retain the native session ID")
    if previous is not None and observed != previous:
        raise QualificationError("Session identity changed within a turn; inspect native history")
    return observed


def events(path: Path, harness: str) -> dict:
    """Check session, terminal and tool observations, not model prose."""
    session = None
    started = completed = tool = False
    for event in read_events(path):
        kind = event.get("type")
        if kind == ("thread.started" if harness == "codex" else "session"):
            session = session_identity(event, session, harness)
        if kind == ("turn.started" if harness == "codex" else "agent_start"):
            if session is None:
                raise QualificationError("Turn started without session identity; repair structured output")
            started = True
            completed = tool = False
        terminal = kind == "turn.completed" if harness == "codex" else kind == "agent_end" and event.get("willRetry") is not True
        if terminal:
            if not started:
                raise QualificationError("Terminal event preceded turn start; repair structured output")
            completed = True
        tool |= started and not completed and tool_succeeded(event, harness)
    if not session:
        raise QualificationError("No native session identity observed; check the selected event protocol")
    if not completed:
        raise QualificationError("No successful terminal event observed; inspect the incomplete turn")
    if not tool:
        raise QualificationError("No successful native tool event observed; prose cannot prove execution")
    return {"session_id": session, "terminal_observed": True, "tool_observed": True}


def version(binary: Path, directory: Path, timeout: float) -> str:
    output = directory / "version.stdout"
    code = execute([str(binary), "--version"], directory, output, timeout)
    # A version command has no reason to return task output or credentials.
    # Retain raw output privately, but expose only the numeric version.
    with output.open("rb") as source:
        raw = source.read(4096).decode("utf-8", errors="replace")
    match = re.search(r"\b\d+\.\d+\.\d+(?:[-+][\w.-]+)?\b", raw)
    if code != 0 or match is None:
        raise QualificationError("Harness version is unavailable; repair the selected installation")
    return match[0]


def command(args, session: str | None = None) -> list[str]:
    if args.protocol == "codex":
        result = [str(args.binary), "--dangerously-bypass-approvals-and-sandbox", "exec"]
        if args.mode == "installed":
            result = [str(args.coord), "client-exec", "codex", "--", *result]
        if session:
            result += ["resume", "--json", "--skip-git-repo-check", session]
        else:
            result += ["--json", "--skip-git-repo-check"]
        if args.model:
            result += ["--model", args.model]
        return [*result, "-"]
    result = [str(args.binary), "--mode", "json", "--print"]
    if session:
        result += ["--session", session]
    if args.model:
        result += ["--model", args.model]
    if args.provider:
        result += ["--provider", args.provider]
    return result


def trial(args, report: dict) -> None:
    directory = args.output
    workspace = directory / "workspace"
    workspace.mkdir(mode=0o700)
    nonce = uuid.uuid4().hex
    target = workspace / "result.txt"
    prompt = ("This is an authorized SafeYolo harness integration test. Use a shell tool once to "
              f"write exactly {nonce!r} plus a newline to result.txt in the current directory. "
              "Do not read credentials, call Coord, use the network, or modify other files. "
              "Then finish the turn. Do not merely describe a command.")
    first_output = directory / "first.jsonl"
    first_command = command(args)
    report["commands"] = [first_command]
    if execute(first_command, workspace, first_output, args.timeout, prompt) != 0:
        raise QualificationError("First native turn exited unsuccessfully; inspect first.stderr")
    first = events(first_output, args.protocol)
    if not target.is_file() or target.read_bytes() != (nonce + "\n").encode():
        raise QualificationError("First tool effect differs from the task; inspect result.txt")
    # End the first native process, then resume by its observed identity. The
    # second request never contains the nonce; native session history carries it.
    second_output = directory / "resumed.jsonl"
    second_command = command(args, first["session_id"])
    report["commands"].append(second_command)
    prompt = ("Resume the integration test. Use a shell tool to append the nonce from the prior "
              "task plus a newline to result.txt. Use the retained task history to get that nonce; "
              "do not read result.txt before appending. Do not use the network, credentials or Coord. "
              "Do not modify other files. Then finish the turn.")
    if execute(second_command, workspace, second_output, args.timeout, prompt) != 0:
        raise QualificationError("Resumed native turn exited unsuccessfully; inspect resumed.stderr")
    second = events(second_output, args.protocol)
    if first["session_id"] != second["session_id"]:
        raise QualificationError("Resume opened a different session; inspect the native resume command")
    if target.read_bytes() != ((nonce + "\n") * 2).encode():
        raise QualificationError("Resumed tool effect differs from retained task; inspect result.txt")
    report.update(state="installed_qualified" if args.mode == "installed" else "fixture_passing",
                  boundary="ordinary.task_and_resume",
                  observations={"first": first, "resumed": second, "effect": identity(target)},
                  evidence=[identity(first_output), identity(second_output)],
                  reason="Two task/tool turns completed in the same session across process restart",
                  provenance="requested installed executable" if args.mode == "installed" else "deliberately constrained fixture")


def positive_seconds(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive and finite")
    return parsed


def arguments(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["probe", "trace", "fixture", "installed"])
    parser.add_argument("--harness", required=True)
    parser.add_argument("--protocol", help="explicitly reuse codex or pi event/command semantics for a candidate")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--output", type=Path, help="new private disk-backed attempt directory")
    parser.add_argument("--coord", type=Path, default=Path.home() / ".safeyolo/safeyolo-coord")
    parser.add_argument("--model")
    parser.add_argument("--provider")
    parser.add_argument("--timeout", type=positive_seconds, default=120)
    args = parser.parse_args(argv)
    args.protocol = args.protocol or args.harness
    return args


def qualify(args: argparse.Namespace, report: dict) -> None:
    if args.mode == "trace":
        if args.events is None:
            raise QualificationError("Select --events with a retained native capture")
        report.update(observations=events(args.events, args.protocol),
                      state="fixture_passing", boundary="ordinary.structured_turn",
                      evidence=[identity(args.events)],
                      reason="Captured events pass; this read does not establish installed provenance")
        return
    check_execution_inputs(args)
    args.binary = args.binary.resolve(strict=True)
    args.coord = args.coord.resolve()
    report["executable"] = identity(args.binary)
    if args.output is None:
        with tempfile.TemporaryDirectory(prefix="safeyolo-harness-version-") as scratch:
            report["version"] = version(args.binary, Path(scratch), min(args.timeout, 20))
    else:
        args.output = args.output.absolute()
        try:
            args.output.mkdir(mode=0o700)
        except FileExistsError as error:
            raise QualificationError("Output already exists; inspect the prior attempt and choose a new --output path") from error
        report["attempt_dir"] = str(args.output)
        report["version"] = version(args.binary, args.output, min(args.timeout, 20))
    if args.mode in {"fixture", "installed"}:
        if args.protocol == "codex" and args.mode == "installed":
            report["coord"] = identity(args.coord)
        trial(args, report)
    elif args.protocol not in PROTOCOLS:
        report.update(state="unsupported", reason="Version observed; no helper parser for this harness")
    else:
        report["reason"] = "Version observed; login, task execution and recovery remain not tested"


def check_execution_inputs(args: argparse.Namespace) -> None:
    if args.binary is None:
        raise QualificationError("Select --binary with the target executable")
    if args.mode in {"fixture", "installed"} and args.output is None:
        raise QualificationError("Select a new --output attempt directory for task proof")
    if args.mode == "installed" and not Path("/app/agent_token").is_file():
        raise QualificationError("Run the installed task probe inside the authorized SafeYolo guest")
    if args.protocol == "codex" and args.provider is not None:
        raise QualificationError("Select the Codex provider in its native configuration; --provider belongs to Pi")


def main(argv=None) -> int:
    args = arguments(argv)
    report = {"schema": SCHEMA, "contract_revision": 1, "harness": args.harness,
              "protocol": args.protocol,
              "tool": identity(Path(__file__)), "version": None,
              "state": "not_tested", "boundary": "none", "platform": platform.platform(),
              "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "limits": "Producer evidence for independent review; no support, acceptance or activation change"}
    if args.protocol not in PROTOCOLS and args.mode != "probe":
        report.update(state="unsupported", reason="No helper parser for this harness; inspect an existing adapter or propose one")
        print(json.dumps(report, indent=2))
        return 2
    try:
        qualify(args, report)
    except QualificationError as error:
        report.update(state="failed", reason=str(error))
    except (OSError, UnicodeError) as error:
        report.update(state="failed", reason=f"Cannot read or run the selected input ({type(error).__name__}); inspect its path and permissions")
    if "attempt_dir" in report:
        with (args.output / "report.json").open("x", encoding="utf-8") as output:
            output.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return {"failed": 1, "unsupported": 2}.get(report["state"], 0)


if __name__ == "__main__":
    sys.exit(main())
