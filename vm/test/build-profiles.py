#!/usr/bin/env python3
"""Validate real signed macOS build artifacts, including a forbidden re-signing."""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VM = Path(__file__).resolve().parents[1]


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=30).strip()


def uuid(path: Path) -> str:
    result = run("dwarfdump", "--uuid", str(path))
    match = re.search(r"UUID: ([0-9A-F-]+)", result)
    assert match is not None, result
    return match.group(1)


def main() -> None:
    assert sys.platform == "darwin", "Run on the approved Mac after make build and make debug"
    for profile, folder in (("production", ".build"), ("development", ".build/development")):
        binary = VM / folder / "release/safeyolo-vm"
        identity = json.loads(run(str(binary), "--version", "--json"))
        assert identity["build_profile"] == profile, identity
        assert identity["get_task_allow"] is (profile == "development"), identity
        assert identity["hardened_runtime"] is True, identity
        assert identity["architecture"] == "arm64", identity
        assert len(identity["git_sha"]) == 40, identity
        assert identity["swift_compiler"] != "unknown", identity
        assert uuid(binary) == uuid(Path(str(binary) + ".dSYM"))
        print(f"PASS {profile}: signing posture, embedded identity, matching dSYM")

    with tempfile.TemporaryDirectory(prefix="profile-check-", dir=VM / ".build") as temporary:
        candidate = Path(temporary) / "safeyolo-vm"
        shutil.copy2(VM / ".build/release/safeyolo-vm", candidate)
        subprocess.run([
            "codesign", "--force", "--sign", "-", "--options", "runtime",
            "--entitlements", str(VM / "safeyolo-vm.development.entitlements"), str(candidate),
        ], check=True, timeout=30)
        observed = json.loads(run(str(candidate), "--version", "--json"))
        assert observed["build_profile"] == "production"
        assert observed["get_task_allow"] is True
        check = subprocess.run([
            sys.executable, str(VM / "build-info.py"), "verify", "--profile", "production", str(candidate),
        ], capture_output=True, text=True, timeout=30)
        assert check.returncode != 0, check.stdout
        assert "unexpected entitlements" in check.stderr, check.stderr
        print("PASS production packaging rejects a helper re-signed with debugger access")


if __name__ == "__main__":
    main()
