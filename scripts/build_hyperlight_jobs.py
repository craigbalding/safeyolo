#!/usr/bin/env python3
"""Build a pinned Hyperlight job bundle. Python is a build tool, not a runtime."""

import argparse
import hashlib
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
            if package["source"] is None:
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
