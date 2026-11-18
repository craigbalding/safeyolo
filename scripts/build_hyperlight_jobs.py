#!/usr/bin/env python3
"""Build a pinned Hyperlight job bundle. Python is a build tool, not a runtime."""

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOTFS_REPOSITORY = "hyperlight-dev/hyperlight-unikraft/python"
# These release layers each contain one initrd.cpio. The selected index is
# sha256:68ac56aeed6e769340f6c9d827c56e889e504beaf263936ab9c46ac69aea7bb9.
ROOTFS_LAYERS = {
    "aarch64": ("448fbf853530c9a78f238b1eb3f6782c3d5162b516d2701bdcc1d7620b435b9d", 14181185),
    "x86_64": ("79215ef44af8f66fcf068c8d9f487d93a39daad476b4dcdb0a5b4ad5fb81ac26", 14651436),
}
# The upstream Python image is based on Debian 12 but omits the native
# libraries needed by its _ssl and _hashlib extensions. Keep the same glibc
# ABI; do not copy build-host libraries into a cross-platform guest bundle.
OPENSSL_VERSION = "3.0.22-1~deb12u2"
OPENSSL_PACKAGES = {
    "aarch64": ("arm64", "aarch64-linux-gnu", 1829128,
                "3d04ecd8d0f57fed50d205abaeedfcc84c1960073ea085719c00add44b0ccd7f"),
    "x86_64": ("amd64", "x86_64-linux-gnu", 2039888,
               "cb4784740daa9b3b0eaea2b444bbefa686794afbbf3d678d238c1fd9875f2efd"),
}


def cpio_entry(stream, name: str, data: bytes, mode: int) -> None:
    """Write one newc entry, the format of the pinned Unikraft image."""
    encoded = name.encode() + b"\0"
    fields = (0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded
    stream.write(header + b"\0" * (-len(header) % 4))
    stream.write(data + b"\0" * (-len(data) % 4))


def add_ssl_to_rootfs(image: Path, files: dict[str, bytes]) -> None:
    """Insert SSL dependencies and expose the image's existing public CA roots."""
    files = dict(files)
    with image.open("r+b") as stream:
        names = set()
        while True:
            offset = stream.tell()
            header = stream.read(110)
            if len(header) != 110 or header[:6] != b"070701":
                raise ValueError("Python runtime has an invalid newc archive")
            size, name_size = int(header[54:62], 16), int(header[94:102], 16)
            name = stream.read(name_size).rstrip(b"\0").decode()
            if name == "TRAILER!!!":
                break
            names.add(name.removeprefix("./"))
            start = (offset + 110 + name_size + 3) & ~3
            if name == "usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem":
                stream.seek(start)
                files["usr/lib/ssl/cert.pem"] = stream.read(size)
            stream.seek((start + size + 3) & ~3)
        if "usr/lib/ssl/cert.pem" not in files:
            raise ValueError("Python runtime is missing its bundled public CA roots")
        if names.intersection(files):
            raise ValueError("Python runtime already contains the added libraries")
        stream.seek(offset)
        for name, data in files.items():
            for parent in reversed(Path(name).parents):
                if str(parent) != "." and str(parent) not in names:
                    cpio_entry(stream, str(parent), b"", 0o40755)
                    names.add(str(parent))
            cpio_entry(stream, name, data, 0o100644)
        cpio_entry(stream, "TRAILER!!!", b"", 0)
        stream.truncate()


def add_openssl(image: Path, scratch: Path, architecture: str) -> None:
    """Add only the pinned guest's SSL dependencies and their copyright notice."""
    debian_arch, library_arch, expected_size, digest = OPENSSL_PACKAGES[architecture]
    url = ("https://security.debian.org/debian-security/pool/updates/main/o/openssl/"
           f"libssl3_{OPENSSL_VERSION}_{debian_arch}.deb")
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(expected_size + 1)
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("OpenSSL guest package size or digest mismatch")
    package = scratch / "openssl.deb"
    package.write_bytes(data)
    # ar is supplied by the native toolchain already needed to build the helper.
    result = subprocess.run(["ar", "p", str(package), "data.tar.xz"], check=True, capture_output=True)
    names = [f"usr/lib/{library_arch}/{name}" for name in ("libssl.so.3", "libcrypto.so.3")]
    names.append("usr/share/doc/libssl3/copyright")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:xz") as archive:
        for name in names:
            member = archive.getmember("./" + name)
            if not member.isfile():
                raise ValueError("OpenSSL guest package member is not a regular file")
            files[name] = archive.extractfile(member).read()
    files["usr/share/common-licenses/Apache-2.0"] = (
        Path(__file__).resolve().parents[1] / "jobs/licenses/hyperlight-LICENSE.txt"
    ).read_bytes()
    add_ssl_to_rootfs(image, files)


def file_digest(path: Path) -> str:
    """Hash the exact bytes used in the bundle."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rootfs(output: Path, architecture: str) -> str:
    """Download one immutable release layer and extract only its CPIO member."""
    digest, expected_size = ROOTFS_LAYERS[architecture]
    with urllib.request.urlopen(
        f"https://ghcr.io/token?service=ghcr.io&scope=repository:{ROOTFS_REPOSITORY}:pull",
        timeout=30,
    ) as response:
        auth = json.loads(response.read(64 * 1024))
    url = f"https://ghcr.io/v2/{ROOTFS_REPOSITORY}/blobs/sha256:{digest}"
    # The token stays in memory and the request header. No auth state is kept
    # in the bundle, the command arguments or the build output.
    with tempfile.TemporaryDirectory(prefix="rootfs-", dir=output) as scratch:
        layer = Path(scratch) / "layer.tar.gz"
        # curl strips Authorization when a registry redirects to another host.
        # Supply the ephemeral pull token on stdin, never in process arguments.
        subprocess.run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-time",
                "90",
                "--max-filesize",
                str(expected_size),
                "--header",
                "@-",
                "--output",
                str(layer),
                url,
            ],
            input="Authorization: Bearer " + auth["token"] + "\n",
            text=True,
            check=True,
        )
        if layer.stat().st_size != expected_size:
            raise ValueError("Python runtime layer has an unexpected size")
        if file_digest(layer) != digest:
            raise ValueError("Python runtime layer digest mismatch")
        with tarfile.open(layer, "r:gz") as archive:
            members = [member for member in archive if member.name.lstrip("./") == "initrd.cpio"]
            if len(members) != 1 or not members[0].isfile():
                raise ValueError("Python runtime layer does not contain one regular initrd.cpio")
            with archive.extractfile(members[0]) as source, (output / "python.cpio").open("xb") as stream:
                shutil.copyfileobj(source, stream)
        add_openssl(output / "python.cpio", Path(scratch), architecture)
    return f"https://ghcr.io/v2/{ROOTFS_REPOSITORY}/blobs/sha256:{digest}"


def build(repository: Path, crate: str, arguments: list[str]) -> Path:
    """Use the repository's space guard and a separate warm target per crate."""
    target = repository / "jobs" / crate / "target"
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target)
    environment["CARGO_BUILD_JOBS"] = "1"
    subprocess.run(
        [str(repository / "scripts/cargo_with_space.sh"), *arguments],
        cwd=repository,
        env=environment,
        check=True,
    )
    return target


def copy_licenses(repository: Path, output: Path) -> None:
    """Keep dependency license declarations and the available upstream notices."""
    destination = output / "licenses"
    shutil.copytree(repository / "jobs/licenses", destination)
    shutil.copyfile(repository / "jobs/THIRD-PARTY.md", destination / "THIRD-PARTY.md")
    dependencies = {}
    for crate in ("hyperlight-host", "hyperlight-guest"):
        metadata = json.loads(
            subprocess.check_output(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--format-version",
                    "1",
                    "--manifest-path",
                    str(repository / "jobs" / crate / "Cargo.toml"),
                ],
                text=True,
            )
        )
        for package in metadata["packages"]:
            if package["id"] in metadata["workspace_members"]:
                continue
            name = package["name"] + "-" + package["version"]
            dependencies[name] = {key: package[key] for key in ("name", "version", "license", "source")}
            directory = Path(package["manifest_path"]).parent
            notices = [
                path
                for path in directory.iterdir()
                if path.is_file() and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "COPYRIGHT"))
            ]
            if package["license_file"]:
                notices.append(directory / package["license_file"])
            for path in set(notices):
                target = destination / name
                target.mkdir(exist_ok=True)
                shutil.copyfile(path, target / path.name)
    (destination / "dependencies.json").write_text(json.dumps(dependencies, indent=2) + "\n", encoding="utf-8")


def write_job_definitions(output: Path) -> None:
    """Pin the offline and mediated examples to the collected bundle bytes."""
    common = {
        "gate_id": "hyperlight-example",
        "argv": ["checker"],
        "timeout_seconds": 5,
        "max_input_bytes": 16384,
        "max_input_entries": 16,
        "retain_bytes": 16384,
    }
    for kind, artifact, memory in [("hyperlight", "core.elf", 16), ("hyperlight-unikraft", "checker.py", 256)]:
        engine = {"kind": kind, "runtime": {"path": "runtime.json", "sha256": file_digest(output / "runtime.json")}}
        engine["guest" if kind == "hyperlight" else "checker"] = {
            "path": artifact,
            "sha256": file_digest(output / artifact),
        }
        if kind == "hyperlight":
            engine["function"] = "Check"
        spec = {**common, "memory_mb": memory, "engine": engine}
        if kind == "hyperlight-unikraft":
            # Retained jobs took 7.2–8.3s; the five-second installed example
            # expired before delegation. This covers the whole job.
            spec["timeout_seconds"] = 15
        (output / f"{kind}.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
        service_spec = {**spec, "gate_id": "hyperlight-service-check", "network": False,
                        "mediated_services": {"services": ["github"], "max_calls": 4,
                                              "max_request_bytes": 49152, "max_response_bytes": 1048576}}
        service_spec["engine"] = dict(engine)
        if kind == "hyperlight":
            service_spec["engine"]["function"] = "ServiceCheck"
        else:
            service_spec["engine"]["checker"] = {"path": "service_checker.py",
                                               "sha256": file_digest(output / "service_checker.py")}
        (output / f"{kind}-service.json").write_text(json.dumps(service_spec, indent=2) + "\n", encoding="utf-8")
        artifact_spec = {**spec, "gate_id": "hyperlight-artifact-check", "network": False, "engine": dict(engine)}
        if kind == "hyperlight":
            artifact_spec["engine"]["function"] = "ArtifactCheck"
        else:
            artifact_spec["engine"]["checker"] = {"path": "artifact_checker.py",
                                                "sha256": file_digest(output / "artifact_checker.py")}
        (output / f"{kind}-artifact.json").write_text(json.dumps(artifact_spec, indent=2) + "\n", encoding="utf-8")
        network_spec = {**spec, "gate_id": "hyperlight-network-check", "network": True, "engine": dict(engine)}
        if kind == "hyperlight":
            network_spec["engine"]["function"] = "NetworkCheck"
        else:
            network_spec["engine"]["checker"] = {"path": "network_checker.py",
                                                "sha256": file_digest(output / "network_checker.py")}
        (output / f"{kind}-network.json").write_text(json.dumps(network_spec, indent=2) + "\n", encoding="utf-8")


def bundle(repository: Path, output: Path, profile: str) -> None:
    """Build both guest forms and write their portable, pinned job definitions."""
    architecture = platform.machine().lower()
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(architecture, architecture)
    if architecture not in ROOTFS_LAYERS or platform.system() not in {"Linux", "Darwin"}:
        raise ValueError("Hyperlight bundles require Linux x86_64/aarch64 or Apple-silicon macOS")
    if platform.system() == "Darwin" and architecture != "aarch64":
        raise ValueError("Hyperlight macOS jobs require Apple silicon")
    guest_tool = subprocess.check_output(["cargo", "hyperlight", "--version"], text=True).strip()
    if guest_tool.split()[:2] != ["cargo-hyperlight", "0.1.15"]:
        raise ValueError("Install the pinned cargo-hyperlight 0.1.15 build tool")
    options = ["--release"] if profile == "production" else []
    host_target = build(
        repository,
        "hyperlight-host",
        [
            "build",
            "--locked",
            "--manifest-path",
            "jobs/hyperlight-host/Cargo.toml",
            *options,
        ],
    )
    guest_target = build(
        repository,
        "hyperlight-guest",
        [
            "hyperlight",
            "build",
            "--locked",
            "--manifest-path",
            "jobs/hyperlight-guest/Cargo.toml",
            "--target",
            f"{architecture}-hyperlight-none",
            *options,
        ],
    )
    output.mkdir(parents=True, exist_ok=False)
    cargo_profile = "release" if profile == "production" else "debug"
    helper = output / "safeyolo-hyperlight"
    shutil.copyfile(host_target / cargo_profile / helper.name, helper)
    helper.chmod(0o755)
    if platform.system() == "Darwin":
        subprocess.run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--entitlements",
                str(repository / "jobs/hypervisor.plist"),
                str(helper),
            ],
            check=True,
        )
    identity = json.loads(subprocess.check_output([str(helper), "--identity"], text=True))
    if identity["hyperlight"] != "0.19.0" or identity["unikraft"] != "0.21.0":
        raise ValueError("built helper version differs from the selected runtime set")
    shutil.copyfile(
        guest_target / f"{architecture}-hyperlight-none" / cargo_profile / "safeyolo-checker", output / "core.elf"
    )
    shutil.copyfile(repository / "jobs/checker.py", output / "checker.py")
    shutil.copyfile(repository / "jobs/network_checker.py", output / "network_checker.py")
    shutil.copyfile(repository / "jobs/service_checker.py", output / "service_checker.py")
    shutil.copyfile(repository / "jobs/artifact_checker.py", output / "artifact_checker.py")
    source = rootfs(output, architecture)
    copy_licenses(repository, output)
    manifest = {
        key: identity[key] for key in ("protocol", "os", "architecture", "hyperlight", "unikraft", "kernel_contract")
    }
    manifest.update(
        {
            "helper": {"file": helper.name, "sha256": file_digest(helper)},
            "rootfs": {"file": "python.cpio", "sha256": file_digest(output / "python.cpio")},
            "rootfs_source": source,
        }
    )
    (output / "runtime.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    write_job_definitions(output)
    print(
        json.dumps(
            {
                "bundle": str(output),
                "profile": profile,
                "manifest_sha256": file_digest(output / "runtime.json"),
                **identity,
            }
        )
    )


def main() -> None:
    """Build in the selected source checkout; never alter an installed instance."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", choices=("production", "debug"), default="production")
    arguments = parser.parse_args()
    bundle(Path(__file__).resolve().parent.parent, arguments.output.resolve(), arguments.profile)


if __name__ == "__main__":
    main()
