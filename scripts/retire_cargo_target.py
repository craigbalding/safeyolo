#!/usr/bin/env python3
"""Retire one accepted candidate's Cargo target without touching its source."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def directory_size(path: Path) -> int:
    return sum(file.stat().st_size for file in path.rglob("*") if file.is_file())


def git_root(path: Path) -> Path:
    for parent in (path.parent, *path.parents):
        if (parent / ".git").exists():
            return Path(subprocess.check_output(["git", "-C", parent, "rev-parse", "--show-toplevel"], text=True).strip())
    raise SystemExit("target is not beneath a Git worktree; retire it manually with its experiment evidence")


def active_owner(target: Path) -> int | None:
    wanted = str(target)
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal() or int(proc.name) == os.getpid():
            continue
        try:
            command = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            environment = (proc / "environ").read_bytes().replace(b"\0", b"\n").decode(errors="replace")
        except OSError:
            continue
        if wanted in command or f"CARGO_TARGET_DIR={wanted}" in environment:
            return int(proc.name)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path, help="Sol acceptance/integration receipt containing --commit")
    parser.add_argument("--commit", required=True, help="exact accepted candidate commit")
    parser.add_argument("--record", required=True, type=Path, help="JSONL evidence file to append before deletion")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    target = args.target.resolve()
    receipt = args.receipt.resolve()
    if target.name != "target" or not target.is_dir():
        raise SystemExit("--target must name an existing Cargo target directory")
    if not receipt.is_file():
        raise SystemExit("--receipt must be an existing acceptance receipt")
    root = git_root(target)
    commit = subprocess.check_output(["git", "-C", root, "rev-parse", f"{args.commit}^{{commit}}"], text=True).strip()
    if commit not in receipt.read_text(errors="replace"):
        raise SystemExit("acceptance receipt does not name the exact candidate commit")
    owner = active_owner(target)
    if owner is not None:
        raise SystemExit(f"target is still referenced by live process {owner}")

    binaries = {}
    debug = target / "debug"
    if debug.is_dir():
        for path in sorted(debug.iterdir()):
            if path.is_file() and os.access(path, os.X_OK):
                binaries[path.name] = sha256(path)
    lockfile = root / "proxy" / "Cargo.lock"
    if not lockfile.is_file():
        lockfile = root / "Cargo.lock"
    event = {
        "event": "cargo_target_retired",
        "at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "candidate_commit": commit,
        "acceptance_receipt": str(receipt),
        "acceptance_receipt_sha256": sha256(receipt),
        "lockfile_sha256": sha256(lockfile) if lockfile.is_file() else None,
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
        "bytes_removed": directory_size(target),
        "top_level_debug_binaries": binaries,
    }
    print(json.dumps(event, sort_keys=True))
    if args.dry_run:
        return 0
    args.record.parent.mkdir(parents=True, exist_ok=True)
    with args.record.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    shutil.rmtree(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
