#!/usr/bin/env python3
"""Record configured guest commands and check their process identities."""

from __future__ import annotations

import errno
import json
import os
import sys
from pathlib import Path

CONTEXT = Path("/safeyolo/host-launch-context.json")
RECORDS = Path("/safeyolo-status/guest-commands")


def process_token(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] in {"Z", "X"}:
            return None
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"{boot}:{fields[19]}"
    except (FileNotFoundError, ProcessLookupError):
        return None


def command_is_live(generation: str) -> bool:
    for path in RECORDS.glob("*.json"):
        try:
            with path.open() as handle:
                record = json.loads(handle.read(4096))
            pid = record.get("pid") if isinstance(record, dict) else None
            if (
                type(pid) is int and pid > 0
                and record.get("generation") == generation
                and isinstance(record.get("token"), str)
                and record["token"] == process_token(pid)
            ):
                return True
        except (FileNotFoundError, json.JSONDecodeError, UnicodeError):
            pass
        path.unlink(missing_ok=True)
    return False


def main() -> int:
    generation = json.loads(CONTEXT.read_text())["generation"]
    if sys.argv[1:] == ["--check"]:
        print("running" if command_is_live(generation) else "stopped")
        return 0
    pid = os.getpid()
    RECORDS.mkdir(exist_ok=True)
    record = {"pid": pid, "token": process_token(pid), "generation": generation}
    temporary = RECORDS / f".{pid}.tmp"
    temporary.write_text(json.dumps(record))
    temporary.replace(RECORDS / f"{pid}.json")
    try:
        os.execv(sys.argv[1], sys.argv[1:])
    except OSError as exc:
        if exc.errno != errno.ENOEXEC:
            raise
        # Bash previously ran executable custom scripts without a shebang.
        os.execv("/bin/bash", ["/bin/bash", *sys.argv[1:]])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"guest command observation: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
