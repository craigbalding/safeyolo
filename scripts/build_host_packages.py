#!/usr/bin/env python3
"""Retain debug outputs from CI; native product packages use the shell producer."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

try:
    from scripts.verify_host_package import host_platform, sha256
except ModuleNotFoundError:
    from verify_host_package import host_platform, sha256

ROOT = Path(__file__).resolve().parents[1]


def output(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, timeout=60).strip()


def commit() -> str:
    revision = output("git", "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("host packages require a full source commit")
    if os.environ.get("SAFEYOLO_BUILD_REVISION", revision) != revision:
        raise ValueError("build source differs from SAFEYOLO_BUILD_REVISION")
    if output("git", "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("host packages require a clean committed source checkout")
    return revision


def proxy_settings(profile: str) -> dict:
    environment = {
        key: value for key, value in os.environ.items()
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "MACOSX_DEPLOYMENT_TARGET",
                   "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR"}
        or (key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_")) and key != "CARGO_TARGET_DIR")
    }
    return {
        "profile": "release" if profile == "production" else "dev",
        "rustc": output("rustc", "-vV", cwd=ROOT / "proxy"),
        "cargo_lock_sha256": sha256(ROOT / "proxy/Cargo.lock"),
        "environment": environment,
        "host_runtime": platform.mac_ver()[0] if platform.system() == "Darwin" else list(platform.libc_ver()),
    }


def helper_settings() -> dict:
    return {
        "swift": output("swift", "--version").splitlines()[0],
        "makefile_sha256": sha256(ROOT / "vm/Makefile"),
        "package_sha256": sha256(ROOT / "vm/Package.swift"),
        "swift_build_flags": os.environ.get("SWIFT_BUILD_FLAGS", ""),
        "environment": {key: os.environ[key] for key in ("SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "SWIFT_EXEC") if key in os.environ},
    }


def verify_proxy(binary: Path, profile: str) -> None:
    with binary.open("rb") as stream:
        magic = stream.read(4)
    if magic not in {b"\x7fELF", b"\xcf\xfa\xed\xfe"} or not os.access(binary, os.X_OK):
        raise ValueError(f"not an executable host runtime: {binary}")
    version = output(str(binary.resolve()), "--version")
    if (not version.startswith("safeyolo-proxy ") or
            f"commit={commit()} profile={profile}" not in version):
        raise ValueError(f"not the proxy runtime: {binary}")


def verify_helper(binary: Path, profile: str) -> dict:
    subprocess.run(
        [str(binary.resolve()), "verify", "--profile", profile, "--source", commit()],
        check=True, timeout=60,
    )
    identity = json.loads(output(str(binary.resolve()), "--version", "--json"))
    if identity["git_sha"] != commit() or identity["build_profile"] != profile:
        raise ValueError("helper source/profile differs from selected build")
    return identity


def save_debug(directory: Path) -> None:
    """Only maintained runtime output paths are eligible; caches/tests are absent."""
    binaries = {"proxy": ROOT / "proxy/target/debug/safeyolo-proxy"}
    if host_platform() == "darwin-arm64":
        binaries["helper"] = ROOT / "vm/.build/development/release/safeyolo-vm"
    metadata = {
        "commit": commit(), "platform": host_platform(), "profile": "debug",
        "run_id": os.environ.get("GITHUB_RUN_ID"), "components": {},
    }
    for component, binary in binaries.items():
        if not binary.is_file():
            continue
        if component == "proxy":
            verify_proxy(binary, "debug")
            settings = proxy_settings("debug")
        else:
            verify_helper(binary, "development")
            settings = helper_settings()
        directory.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, directory / binary.name)
        if component == "helper":
            shutil.copytree(Path(str(binary) + ".dSYM"), directory / "safeyolo-vm.dSYM")
            shutil.copy2(binary.parent.parent / "build-info.json", directory / "safeyolo-vm.build-info.json")
        files = [directory / binary.name]
        if component == "helper":
            files += [directory / "safeyolo-vm.build-info.json"]
            files += [p for p in (directory / "safeyolo-vm.dSYM").rglob("*") if p.is_file()]
        metadata["components"][component] = {
            "sha256": sha256(binary), "settings": settings,
            "files": {p.relative_to(directory).as_posix(): sha256(p) for p in files},
        }
    if metadata["components"]:
        (directory / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    else:
        print("No usable debug runtime was produced by this CI job")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("save-debug",))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    save_debug(args.output)


if __name__ == "__main__":
    main()
