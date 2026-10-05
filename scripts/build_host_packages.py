#!/usr/bin/env python3
"""Save CI debug runtimes or build and package the two host profiles."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

try:
    from scripts.verify_host_package import host_platform, sha256, verify
    from scripts.verify_native_package import inspect_wheel
except ModuleNotFoundError:
    # Direct invocation from Actions or a source checkout.
    from verify_host_package import host_platform, sha256, verify
    from verify_native_package import inspect_wheel

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
        [sys.executable, str(ROOT / "vm/build-info.py"), "verify", "--profile", profile, str(binary)],
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


def reusable_debug(directory: Path, component: str, settings: dict) -> Path | None:
    """Missing or incompatible outputs take the component's single fallback build."""
    metadata_path = directory / "build.json"
    if not metadata_path.is_file():
        return None
    try:
        metadata = json.loads(metadata_path.read_text())
        if not isinstance(metadata, dict) or not isinstance(metadata.get("components"), dict):
            return None
        expected = (commit(), host_platform(), "debug")
        if tuple(metadata[key] for key in ("commit", "platform", "profile")) != expected:
            return None
        item = metadata["components"].get(component)
        if not isinstance(item, dict) or item.get("settings") != settings or not isinstance(item.get("files"), dict):
            return None
        binary = directory / ("safeyolo-proxy" if component == "proxy" else "safeyolo-vm")
        if sha256(binary) != item["sha256"]:
            raise ValueError("runtime checksum differs from saved artifact")
        for name, digest in item["files"].items():
            if sha256(directory / name) != digest:
                raise ValueError(f"artifact checksum differs: {name}")
        # upload-artifact does not retain executable permission bits.
        binary.chmod(0o755)
        if component == "proxy":
            verify_proxy(binary, "debug")
        else:
            verify_helper(binary, "development")
            if not (directory / "safeyolo-vm.dSYM").is_dir():
                raise ValueError("saved helper debug symbols are missing")
        return binary
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Debug {component} artifact is unusable; building the missing output: {error}")
        return None


def build_runtimes(profile: str, debug_directory: Path) -> tuple[dict, dict]:
    settings = proxy_settings(profile)
    proxy = reusable_debug(debug_directory, "proxy", settings) if profile == "debug" else None
    proxy_origin = "master-ci" if proxy else "postmerge-build"
    if proxy is None:
        args = [str(ROOT / "scripts/cargo_with_space.sh"), "build", "--locked", "--bin", "safeyolo-proxy"]
        if profile == "production":
            args.append("--release")
        subprocess.run(args, cwd=ROOT / "proxy", env={**os.environ, "SAFEYOLO_BUILD_REVISION": commit()}, check=True)
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "proxy/target"))
        if not target.is_absolute():
            target = ROOT / "proxy" / target
        if os.environ.get("CARGO_BUILD_TARGET"):
            target /= os.environ["CARGO_BUILD_TARGET"]
        proxy = target / ("release" if profile == "production" else "debug") / "safeyolo-proxy"
    verify_proxy(proxy, profile)
    paths = {"proxy": proxy}
    native = {
        "commit": commit(), "platform": host_platform(), "profile": profile,
        "proxy": {"sha256": sha256(proxy), "settings": settings, "origin": proxy_origin},
    }
    if host_platform() == "darwin-arm64":
        settings = helper_settings()
        helper = reusable_debug(debug_directory, "helper", settings) if profile == "debug" else None
        origin = "master-ci" if helper else "postmerge-build"
        helper_profile = "production" if profile == "production" else "development"
        if helper is None:
            subprocess.run(
                ["make", "-C", str(ROOT / "vm"), f"PROFILE={helper_profile}", f"PYTHON={sys.executable}", "build"],
                check=True,
            )
            build = ROOT / "vm/.build"
            if profile == "debug":
                build /= "development"
            helper = build / "release/safeyolo-vm"
        identity = verify_helper(helper, helper_profile)
        paths["helper"] = helper
        native["helper"] = {
            "sha256": sha256(helper), "settings": settings, "origin": origin,
            "profile": helper_profile, "identity": identity,
        }
    return paths, native


def runtime_compatibility(paths: dict) -> tuple[str, dict]:
    """Record actual dynamic-library or deployment requirements of the built bytes."""
    if host_platform().startswith("linux-"):
        versions = re.findall(r"GLIBC_(\d+\.\d+)", output("readelf", "--version-info", str(paths["proxy"])))
        minimum = max(versions, key=lambda version: tuple(map(int, version.split("."))))
        tag = "linux_x86_64" if host_platform() == "linux-amd64" else "linux_aarch64"
        return tag, {"libc": "glibc", "minimum_glibc": minimum}
    versions = []
    for binary in paths.values():
        binary_versions = []
        command = ""
        for line in output("otool", "-l", str(binary)).splitlines():
            fields = line.strip().split(maxsplit=1)
            if len(fields) != 2:
                continue
            name, value = fields
            if name == "cmd":
                command = value
            elif (command, name) in {("LC_BUILD_VERSION", "minos"), ("LC_VERSION_MIN_MACOSX", "version")}:
                if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value):
                    binary_versions.append(value)
        if not binary_versions:
            raise ValueError(f"macOS deployment minimum is missing from {binary}")
        versions.extend(binary_versions)
    minimum = max(versions, key=lambda version: tuple(map(int, version.split("."))))
    major, minor, *_ = minimum.split(".")
    return f"macosx_{major}_{minor}_arm64", {"minimum_macos": minimum}


def package(profile: str, paths: dict, native: dict, directory: Path, vsock_directory: Path) -> Path:
    """Hatch packages the selected bytes; no compiler is invoked in this function."""
    directory.mkdir(parents=True)
    tag, compatibility = runtime_compatibility(paths)
    metadata = directory / "native.json"
    metadata.write_text(json.dumps(native, indent=2) + "\n")
    environment = {
        **os.environ, "SAFEYOLO_BUILD_REVISION": native["commit"],
        "SAFEYOLO_BUILD_PROFILE": profile,
        "SAFEYOLO_BUILD_ID": f"host-{native['platform']}-{profile}",
        "SAFEYOLO_NATIVE_BINARY": str(paths["proxy"].resolve()), "SAFEYOLO_NATIVE_PLATFORM_TAG": tag,
        "SAFEYOLO_NATIVE_BUILD_METADATA": str(metadata.resolve()),
        "SAFEYOLO_GUEST_HELPER": str(paths["guest_command"].resolve()),
    }
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(directory)], cwd=ROOT, env=environment, check=True)
    metadata.unlink()
    wheel, = directory.glob("*.whl")
    inspect_wheel(wheel, expected_binary_sha256=native["proxy"]["sha256"])
    dependencies = output("uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--package", "safeyolo", "--no-hashes")
    (directory / "dependencies.txt").write_text(dependencies + "\n")
    requirement = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["requires-python"]
    installer = (ROOT / "scripts/install_host_package.sh").read_text().replace("@PYTHON_REQUIREMENT@", requirement)
    (directory / "install.sh").write_text(installer)
    (directory / "install.sh").chmod(0o755)
    shutil.copy2(ROOT / "scripts/verify_host_package.py", directory / "verify.py")
    if "helper" in paths:
        helper = paths["helper"]
        shutil.copy2(helper, directory / "safeyolo-vm")
        shutil.copytree(Path(str(helper) + ".dSYM"), directory / "safeyolo-vm.dSYM")
        shutil.copy2(helper.parent.parent / "build-info.json" if helper.is_relative_to(ROOT / "vm")
                     else helper.parent / "safeyolo-vm.build-info.json", directory / "safeyolo-vm.build-info.json")
        shutil.copy2(ROOT / "vm/build-info.py", directory / "build-info.py")
        guest = json.loads((vsock_directory / "build.json").read_text())
        if guest["commit"] != native["commit"] or sha256(vsock_directory / "vsock-term") != guest["sha256"]:
            raise ValueError("guest terminal helper source/checksum mismatch")
        shutil.copy2(vsock_directory / "vsock-term", directory / "vsock-term")
        (directory / "vsock-term").chmod(0o755)
        (directory / "vsock-term.build-info.json").write_text(json.dumps(guest, indent=2) + "\n")
    files = {p.relative_to(directory).as_posix(): sha256(p) for p in directory.rglob("*") if p.is_file()}
    manifest = {
        "schema_version": 1, "native": native, "wheel": wheel.name, "python": requirement,
        "compatibility": compatibility, "files": files,
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    sums = {**files, "manifest.json": sha256(directory / "manifest.json")}
    (directory / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())))
    verify(directory)
    archive = directory.parent / f"{directory.name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(directory, arcname=directory.name)
    return archive


def build_guest_command(profile: str, guest_directory: Path) -> Path:
    """Use the Linux artifact on Mac; build the missing Linux output once."""
    binary = guest_directory / profile / "safeyolo-guest"
    if not binary.is_file():
        if host_platform() == "darwin-arm64":
            raise ValueError(f"required Linux guest artifact is missing: {binary}")
        subprocess.run([str(ROOT / "scripts/build_guest_command.sh")], cwd=ROOT, check=True,
                       env={**os.environ, "SAFEYOLO_BUILD_REVISION": commit(), "SAFEYOLO_BUILD_PROFILE": profile})
        target = Path(os.environ.get("SAFEYOLO_GUEST_TARGET_DIR", str(ROOT / "guest/command/target")))
        if os.environ.get("SAFEYOLO_GUEST_TARGET"):
            target /= os.environ["SAFEYOLO_GUEST_TARGET"]
        binary = target / ("release" if profile == "production" else "debug") / "safeyolo-guest"
    identity = Path(str(binary) + ".version").read_text().strip()
    if identity != f"safeyolo-guest 0.1.0 commit={commit()} profile={profile}":
        raise ValueError("guest command source/profile identity differs from the selected package")
    if sha256(binary) != Path(str(binary) + ".sha256").read_text().strip():
        raise ValueError("guest command checksum differs from the built artifact")
    with binary.open("rb") as stream:
        header = stream.read(20)
    machine = 62 if host_platform() == "linux-amd64" else 183
    if header[:4] != b"\x7fELF" or int.from_bytes(header[18:20], "little") != machine:
        raise ValueError("guest command artifact has the wrong Linux architecture")
    return binary


def build(directory: Path, debug_directory: Path, vsock_directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="host-packages-", dir=directory) as temporary:
        for profile in ("production", "debug"):
            paths, native = build_runtimes(profile, debug_directory)
            paths["guest_command"] = build_guest_command(profile, vsock_directory / "guest-command")
            native["guest_command"] = {"sha256": sha256(paths["guest_command"]), "identity": Path(str(paths["guest_command"]) + ".version").read_text().strip()}
            name = f"safeyolo-{native['platform']}-{profile}"
            archive = package(profile, paths, native, Path(temporary) / name, vsock_directory)
            shutil.move(str(archive), directory / archive.name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("save-debug", "build"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--debug-directory", type=Path, default=Path("debug-input"))
    parser.add_argument("--vsock-directory", type=Path, default=Path("vsock-input"))
    args = parser.parse_args()
    if args.operation == "save-debug":
        save_debug(args.output)
    else:
        build(args.output.resolve(), args.debug_directory.resolve(), args.vsock_directory.resolve())


if __name__ == "__main__":
    main()
