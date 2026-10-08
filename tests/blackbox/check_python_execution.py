#!/usr/bin/env python3
"""Read private strace execution logs on the external Python test host.

This detector reports named Python execution attempts, including failed
execs and Python shebangs in retained files. Static package/dependency review
must account for renamed interpreters and embedded Python separately.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
from pathlib import Path

STRING = r'"(?:\\.|[^"\\])*"'
EXECUTION = re.compile(rf'\bexecve(?:\(({STRING})|at\([^,]+,\s*({STRING}))')
PYTHON = re.compile(r"(?:python(?:w|[0-9.]+t?)?|pypy[0-9.]*)")


def python_name(value: str) -> bool:
    return PYTHON.fullmatch(Path(value).name) is not None


def inspect_trace(trace: Path, filesystem: Path | None) -> dict:
    """Unreadable, empty, truncated or unfinished observations cannot pass."""
    if filesystem is not None and not filesystem.is_dir():
        raise ValueError(f"filesystem root is not an available directory: {filesystem}")
    attempts = 0
    violations = []
    incomplete = []
    executed_pids = set()
    finished_pids = set()
    pending = set()
    with trace.open(encoding="utf-8", errors="strict") as source:
        for number, line in enumerate(source, 1):
            pid = line.split()[0] if line.strip() else ""
            if "+++ exited with" in line or "+++ killed by" in line:
                finished_pids.add(pid)
            if "execve" not in line:
                continue
            if "<... execve" in line:
                if pid not in pending or not re.search(r'\)\s+=\s+-?\d+(?:\s|$)', line):
                    incomplete.append(number)
                pending.discard(pid)
                continue
            attempts += 1
            executed_pids.add(pid)
            if "<unfinished ...>" in line:
                pending.add(pid)
            elif not re.search(r'\)\s+=\s+-?\d+(?:\s|$)', line):
                incomplete.append(number)
            match = EXECUTION.search(line)
            if not match:
                incomplete.append(number)
                continue
            path = ast.literal_eval(match.group(1) or match.group(2))
            if not path or line[match.end():].startswith("..."):
                incomplete.append(number)
                continue
            reason = "interpreter" if python_name(path) else None
            # Read only an absolute pathname in the supplied filesystem. Never
            # substitute argv[0] for the kernel's selected executable.
            executable = filesystem / path.lstrip("/") if filesystem is not None else None
            if path.startswith("/") and executable is not None and executable.is_file():
                with executable.open("rb") as script:
                    first = script.read(256).split(b"\n", 1)[0]
                if first.startswith(b"#!"):
                    words = shlex.split(first[2:].decode("utf-8", errors="strict"))
                    if any(python_name(word) for word in words):
                        reason = "Python shebang"
            if reason:
                violations.append({"line": number, "path": path, "reason": reason})
    return {"exec_attempts": attempts, "python_attempts": violations,
            "incomplete_lines": incomplete, "unfinished_pids": sorted(executed_pids - finished_pids),
            "shebang_lookup": filesystem is not None,
            "complete": bool(attempts and executed_pids <= finished_pids and not incomplete and not pending)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--filesystem-root", type=Path,
                        help="retained filesystem for absolute script/shebang lookup")
    args = parser.parse_args()
    try:
        result = inspect_trace(args.trace, args.filesystem_root)
    except (OSError, ValueError, UnicodeError) as error:
        print(f"Execution observation unavailable: {error}")
        return 2
    print(json.dumps(result))
    if not result["complete"]:
        return 2
    return 1 if result["python_attempts"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
