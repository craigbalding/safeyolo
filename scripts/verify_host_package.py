#!/usr/bin/env python3
"""Verify an extracted host download before installing its wheel and helper."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def host_platform() -> str:
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    result = f"{system}-{arch}"
    if result not in {"darwin-arm64", "linux-amd64", "linux-arm64"}:
        raise ValueError(f"unsupported host platform: {result}")
    return result


def verify_compatibility(compatibility: dict) -> None:
    def version(value: str) -> tuple[int, ...]:
        return tuple(map(int, value.split(".")))

    if platform.system() == "Linux":
        libc, current = platform.libc_ver()
        if libc != "glibc" or version(current) < version(compatibility["minimum_glibc"]):
            raise ValueError(f"host package requires glibc {compatibility['minimum_glibc']} or newer")
    elif version(platform.mac_ver()[0]) < version(compatibility["minimum_macos"]):
        raise ValueError(f"host package requires macOS {compatibility['minimum_macos']} or newer")


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    native = manifest["native"]
    if manifest["schema_version"] != 1 or not re.fullmatch(r"[0-9a-f]{40}", native["commit"]):
        raise ValueError("invalid host package identity")
    if native["platform"] != host_platform() or native["profile"] not in {"production", "debug"}:
        raise ValueError("host package platform/profile mismatch")
    verify_compatibility(manifest["compatibility"])
    actual_files = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    if actual_files != set(manifest["files"]) | {"manifest.json", "SHA256SUMS"}:
        raise ValueError("host package has missing or unexpected files")
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        sums[name] = digest
    if sums != {**manifest["files"], "manifest.json": sha256(directory / "manifest.json")}:
        raise ValueError("host package checksum list differs from manifest")
    for name, digest in manifest["files"].items():
        if sha256(directory / name) != digest:
            raise ValueError(f"host package checksum mismatch: {name}")
    verify_wheel(directory / manifest["wheel"], native)
    if native["platform"] == "darwin-arm64":
        verify_helper(directory, native)
    return manifest


def verify_wheel(wheel: Path, native: dict) -> None:
    with zipfile.ZipFile(wheel) as archive:
        if json.loads(archive.read("safeyolo/_native_build.json")) != native:
            raise ValueError("wheel native identity differs from package")
        identity = json.loads(archive.read("safeyolo/_build_identity.json"))
        if (identity["source_revision"] != native["commit"] or
                identity["build_identifier"] != f"host-{native['platform']}-{native['profile']}"):
            raise ValueError("wheel source/profile differs from package")
        expected_profile = "release" if native["profile"] == "production" else "dev"
        if native["proxy"]["settings"]["profile"] != expected_profile:
            raise ValueError("proxy build profile differs from package")
        binary = archive.read("safeyolo/bin/safeyolo-proxy")
        if hashlib.sha256(binary).hexdigest() != native["proxy"]["sha256"]:
            raise ValueError("wheel proxy bytes differ from built runtime")
        guest = archive.read("safeyolo/bin/safeyolo-guest")
        if hashlib.sha256(guest).hexdigest() != native["guest_command"]["sha256"]:
            raise ValueError("wheel guest command bytes differ from built runtime")
        if f"commit={native['commit']} profile={native['profile']}" not in native["guest_command"]["identity"]:
            raise ValueError("guest command source/profile differs from package")
        with tempfile.TemporaryDirectory(prefix="safeyolo-package-proxy-", dir=wheel.parent.parent) as temporary:
            executable = Path(temporary) / "safeyolo-proxy"
            executable.write_bytes(binary)
            executable.chmod(0o755)
            result = subprocess.check_output([str(executable), "--version"], text=True, timeout=15)
            if (not result.startswith("safeyolo-proxy ") or
                    f"commit={native['commit']} profile={native['profile']}" not in result):
                raise ValueError("wheel executable source/profile differs from package")
            print(result.strip())


def verify_helper(directory: Path, native: dict) -> None:
    helper = native["helper"]
    subprocess.run(
        [sys.executable, str(directory / "build-info.py"), "verify", "--profile", helper["profile"],
         str(directory / "safeyolo-vm")], check=True, timeout=60,
    )
    actual = json.loads(subprocess.check_output(
        [str(directory / "safeyolo-vm"), "--version", "--json"], text=True, timeout=15,
    ))
    if actual["git_sha"] != native["commit"] or actual["build_profile"] != helper["profile"]:
        raise ValueError("helper source/profile differs from package")
    if actual != helper["identity"]:
        raise ValueError("helper build identity differs from signed executable")
    expected_profile = "production" if native["profile"] == "production" else "development"
    if helper["profile"] != expected_profile or actual["architecture"] != "arm64":
        raise ValueError("helper signing profile/architecture differs from package")
    guest = json.loads((directory / "vsock-term.build-info.json").read_text())
    if guest["commit"] != native["commit"] or guest["sha256"] != sha256(directory / "vsock-term"):
        raise ValueError("guest terminal helper identity differs from package")


if __name__ == "__main__":
    try:
        result = verify(Path(__file__).resolve().parent)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        sys.exit(f"Host package verification failed: {error}")
    print(f"Verified {result['native']['platform']} {result['native']['profile']} at {result['native']['commit']}")
