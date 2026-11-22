#!/usr/bin/env python3
"""Build a standalone native executor archive; Python is only a build dependency."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import urljoin

from build_host_packages import ROOT, commit, output, sha256


def operator_guide(revision: str) -> str:
    source = ROOT / "docs/host-operations.md"
    base = f"https://github.com/craigbalding/safeyolo/blob/{revision}/docs/host-operations.md"
    return re.sub(r"(?<=\]\()[^)]+(?=\))", lambda link: urljoin(base, link.group()), source.read_text())


def build_executor(revision: str, target: str) -> Path:
    command = [
        "bash", str(ROOT / "scripts/cargo_with_space.sh"), "build", "--release", "--locked",
        "--manifest-path", str(ROOT / "host-executor/Cargo.toml"), "--target", target,
        "--bin", "safeyolo-host-executor",
        "--message-format=json-render-diagnostics",
    ]
    result = subprocess.run(command, cwd=ROOT, env={
        **os.environ, "SAFEYOLO_BUILD_REVISION": revision,
        "CARGO_BUILD_JOBS": os.environ.get("CARGO_BUILD_JOBS", "1"),
        "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", str(ROOT / "host-executor/target")),
    }, stdout=subprocess.PIPE, text=True, check=False)
    binary = None
    for line in result.stdout.splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-message":
            print(record["message"]["rendered"], end="", file=sys.stderr)
        if (record.get("reason") == "compiler-artifact"
                and record.get("manifest_path") == str(ROOT / "host-executor/Cargo.toml")
                and record["target"]["kind"] == ["bin"]
                and record["target"]["name"] == "safeyolo-host-executor"
                and record.get("executable")):
            binary = Path(record["executable"])
    result.check_returncode()
    if binary is None:
        raise ValueError("Cargo did not report the selected executor executable")
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new .zip archive")
    parser.add_argument("--target", help="Rust target triple; default is the build host")
    args = parser.parse_args()
    revision = commit()
    compiler = output("rustc", "-vV")
    host = next(line.removeprefix("host: ") for line in compiler.splitlines() if line.startswith("host: "))
    selected_target = args.target or os.environ.get("CARGO_BUILD_TARGET")
    target = selected_target or host
    binary = build_executor(revision, target)
    if host == target:
        version = output(str(binary), "--version")
        if f"commit={revision} profile=production target={target}" not in version:
            raise ValueError("executor identity differs from the selected source, profile or target")
    metadata = {
        "git_sha": revision,
        "target": target,
        "profile": "production",
        "rustc": compiler,
        "binary_sha256": sha256(binary),
        "documentation": f"https://github.com/craigbalding/safeyolo/blob/{revision}/docs/host-execution-contract.md",
        "build_environment": {
            name: value for name, value in sorted(os.environ.items())
            if name in {
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                "MACOSX_DEPLOYMENT_TARGET", "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR",
            } or (
                name.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CC_", "CFLAGS_", "CPPFLAGS_", "AR_"))
                and name != "CARGO_TARGET_DIR"
            )
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary, binary.name)
        archive.write(ROOT / "LICENSE", "LICENSE")
        archive.writestr("HOST-OPERATIONS.md", operator_guide(revision))
        archive.write(ROOT / "host-executor/examples/windows-starter.json", "examples/windows-starter.json")
        archive.write(ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo/scripts/host-operation.py", "agent/host-operation.py")
        archive.writestr("host-executor.json", json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({"archive": str(args.output), "archive_sha256": sha256(args.output), **metadata}))


if __name__ == "__main__":
    main()
