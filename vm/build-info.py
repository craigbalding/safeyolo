#!/usr/bin/env python3
"""Embed VM-helper build identity and verify the signed build profile."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTITLEMENT = "com.apple.security.get-task-allow"
VIRTUALIZATION = "com.apple.security.virtualization"


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, timeout=30).strip()


def source_revision() -> tuple[str, bool | None]:
    """Allow an explicit source identity when building an exported checkout."""
    supplied = os.environ.get("SAFEYOLO_BUILD_REVISION")
    if supplied:
        if not re.fullmatch(r"[0-9a-f]{40}", supplied):
            raise ValueError("SAFEYOLO_BUILD_REVISION must be a full Git SHA")
        dirty = os.environ.get("SAFEYOLO_BUILD_DIRTY", "unknown")
        if dirty not in {"yes", "no", "unknown"}:
            raise ValueError("SAFEYOLO_BUILD_DIRTY must be yes, no or unknown")
        return supplied, {"yes": True, "no": False, "unknown": None}[dirty]
    git = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    if git.returncode:
        return "unknown", None
    return git.stdout.strip(), bool(command("git", "status", "--porcelain", "--untracked-files=normal"))


def generate(profile: str, output: Path) -> None:
    revision, dirty = source_revision()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    metadata = {
        "schema_version": 1,
        "version": project["version"],
        "git_sha": revision,
        "git_dirty": dirty,
        "build_profile": profile,
        "swift_compiler": command("swift", "--version").splitlines()[0],
        "optimization": "release",
        "symbols": "DWARF+dSYM",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metadata, sort_keys=True) + "\n")


def verify(profile: str, binary: Path) -> None:
    """Check the actual signature before an artifact can be installed/packaged."""
    subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True, timeout=30)
    signature = subprocess.run(
        ["codesign", "--display", "--entitlements", ":-", "--verbose=2", str(binary)],
        check=True, capture_output=True, timeout=30,
    )
    entitlements = plistlib.loads(signature.stdout)
    expected = {VIRTUALIZATION: True}
    if profile == "development":
        expected[ENTITLEMENT] = True
    if entitlements != expected:  # DOC: docs/DEVELOPERS.md
        raise ValueError(f"{profile} signature has unexpected entitlements: {entitlements}")
    match = re.search(rb"flags=0x([0-9a-fA-F]+)", signature.stderr)
    if match is None or not int(match.group(1), 16) & 0x10000:
        raise ValueError("VM-helper signature must retain hardened runtime")
    identity = json.loads(command(str(binary.resolve()), "--version", "--json"))
    if identity.get("build_profile") != profile:
        raise ValueError("Embedded helper profile does not match the signed artifact")
    if identity.get("get_task_allow") is not (profile == "development"):
        raise ValueError("Running helper debug posture does not match its build profile")
    if identity.get("hardened_runtime") is not True:
        raise ValueError("Running helper does not report hardened runtime")
    print(f"Verified {profile} VM helper: {binary}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("generate", "verify"))
    parser.add_argument("--profile", choices=("production", "development"), required=True)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "generate":
            generate(args.profile, args.path)
        else:
            verify(args.profile, args.path)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"VM helper {args.operation} failed: {error}\n")


if __name__ == "__main__":
    main()
