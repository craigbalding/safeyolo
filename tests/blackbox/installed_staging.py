"""Package and verify the inputs for offline installed VZ sections.

Run packaging on the trusted macOS build host after building the selected
wheel and signed helper. The execution host needs uv, a compatible Python
interpreter and the transferred payload. It does not build or download inputs.
The trusted caller must supply the payload index's SHA-256 separately.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

if __package__:
    from .installed_host_smoke import SmokeError, _installed_rust_binary, _sha256
else:
    # The packaging entrypoint can run before a CLI environment is installed.
    # Reuse only the source tree's stdlib process-identity helper in this parent.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cli/src"))
    from installed_host_smoke import SmokeError, _installed_rust_binary, _sha256

BOOT_FILES = ("Image", "initramfs.cpio.gz", "rootfs-base.ext4")
INDEX_NAME = "staged-inputs.json"


def selected_source(checkout: Path, revision: str) -> None:
    """Reject a moving, dirty or mismatched source selection."""
    actual = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None or actual != revision:
        raise ValueError("staged inputs require the exact full selected source commit")
    if subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True).strip():
        raise ValueError("staged source checkout must be clean")


def requirements(checkout: Path, *, dev: bool) -> str:
    """Use uv's frozen lock exporter for both offline dependency closures."""
    return subprocess.check_output(
        ["uv", "export", "--offline", "--frozen", "--no-emit-workspace", "--no-header", "--no-annotate",
         *(["--group", "dev"] if dev else ["--no-dev"])],
        cwd=checkout, text=True, timeout=60,
    )


def wheel_identity(wheel: Path, revision: str) -> dict:
    """Read the existing wheel stamp and the packaged native binary hash."""
    import hashlib

    with zipfile.ZipFile(wheel) as archive:
        stamp = json.loads(archive.read("safeyolo/_build_identity.json"))
        if not isinstance(stamp, dict) or stamp.get("state") != "known" or stamp.get("source_revision") != revision:
            raise ValueError("staged wheel source revision does not match selected commit")
        native = archive.open("safeyolo/bin/safeyolo-proxy")
        with native:
            digest = hashlib.file_digest(native, "sha256").hexdigest()
    return {"source_revision": revision, "native_sha256": digest}


def helper_identity(checkout: Path, helper: Path, revision: str) -> dict:
    """Reuse the helper's embedded identity and existing signing verifier."""
    subprocess.run(["codesign", "--verify", "--strict", str(helper)], check=True, timeout=30)
    identity = json.loads(subprocess.check_output(
        [str(helper), "--version", "--json"], text=True, timeout=30,
    ))
    if (not isinstance(identity, dict) or identity.get("git_sha") != revision or identity.get("git_dirty") is not False
            or identity.get("architecture") != "arm64"
            or identity.get("build_profile") not in ("production", "development")):
        raise ValueError("staged VM helper does not identify the clean selected arm64 commit")
    subprocess.run(
        ["python3", str(checkout / "vm/build-info.py"), "verify", "--profile",
         identity["build_profile"], str(helper)], check=True, timeout=60,
    )
    return identity


def package_inputs(checkout: Path, revision: str, wheel: Path, wheelhouse: Path,
                   prepared: Path, boot_provenance: Path, output: Path) -> Path:
    """Copy only installation inputs; exclude credentials and instance state."""
    selected_source(checkout, revision)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("VZ inputs must be packaged on the arm64 macOS build host")
    boot_inputs = verify_boot_provenance(
        json.loads(boot_provenance.read_text()), {name: _sha256(prepared / "share" / name) for name in BOOT_FILES},
    )
    wheel_stamp = wheel_identity(wheel, revision)
    native = checkout / "proxy/target/release/safeyolo-proxy"
    if _sha256(native) != wheel_stamp["native_sha256"]:
        raise ValueError("staged wheel differs from the selected source release binary")
    helper = helper_identity(checkout, prepared / "bin/safeyolo-vm", revision)
    runtime_requirements = requirements(checkout, dev=False)
    test_requirements = requirements(checkout, dev=True)
    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels:
        raise ValueError("staged dependencies require a populated wheelhouse")
    # Resolve the selected NATS pin from the selected installed CLI, rather
    # than maintaining another version/checksum map in this harness.
    nats = list((prepared / "data/coord/nats/bin").glob("*/nats-server"))
    if len(nats) != 1:
        raise ValueError("prepared inputs must contain one verified NATS executable")
    output.mkdir(parents=True, exist_ok=False)
    inputs = {f"wheel/{wheel.name}": wheel, "native/safeyolo-proxy": native, "nats/nats-server": nats[0],
              "bin/safeyolo-vm": prepared / "bin/safeyolo-vm",
              "bin/vsock-term": prepared / "bin/vsock-term"}
    inputs.update({f"share/{name}": prepared / "share" / name for name in BOOT_FILES})
    inputs.update({f"wheelhouse/{path.name}": path for path in wheels})
    for relative, source in inputs.items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    (output / "runtime-requirements.txt").write_text(runtime_requirements)
    (output / "test-requirements.txt").write_text(test_requirements)
    index = {
        "schema_version": 1, "source_revision": revision,
        "host": {"system": "Darwin", "machine": "arm64"},
        "source_hashes": {name: _sha256(checkout / name) for name in ("uv.lock", "pyproject.toml")},
        "wheel": f"wheel/{wheel.name}", "wheel_identity": wheel_stamp,
        "vm_helper": helper, "boot_inputs": boot_inputs,
        "files": {path.relative_to(output).as_posix(): _sha256(path)
                  for path in output.rglob("*") if path.is_file()},
    }
    index_path = output / INDEX_NAME
    index_path.write_text(json.dumps(index, indent=2) + "\n")
    return index_path


def verify_boot_provenance(provenance: object, hashes: dict) -> dict:
    """Verify and retain only each boot file's original source and hash."""
    if not isinstance(provenance, dict) or set(provenance) != set(BOOT_FILES):
        raise ValueError("boot inputs need provenance for each required file")
    verified = {}
    for name in BOOT_FILES:
        origin = provenance[name]
        if (not isinstance(origin, dict) or origin.get("sha256") != hashes[name]
                or re.fullmatch(r"[0-9a-f]{40}", str(origin.get("source_revision"))) is None):
            raise ValueError(f"boot input has missing or mismatched original provenance: {name}")
        verified[name] = {"source_revision": origin["source_revision"], "sha256": origin["sha256"]}
    return verified


def verified_inputs(payload: Path, expected_hash: str, checkout: Path, revision: str) -> dict:
    """Validate a transferred payload before executing any of its bytes."""
    index_path = payload / INDEX_NAME
    if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None or _sha256(index_path) != expected_hash:
        raise ValueError("staged input index does not match the trusted SHA-256")
    index = json.loads(index_path.read_text())
    if (not isinstance(index, dict) or type(index.get("schema_version")) is not int
            or index["schema_version"] != 1 or index.get("source_revision") != revision
            or index.get("host") != {"system": platform.system(), "machine": platform.machine()}):
        raise ValueError("staged inputs do not match the selected commit and execution platform")
    if index.get("source_hashes") != {name: _sha256(checkout / name) for name in ("uv.lock", "pyproject.toml")}:
        raise ValueError("staged lock/project inputs differ from the selected source")
    files = index.get("files")
    if not isinstance(files, dict):
        raise ValueError("staged inputs have no file hashes")
    for relative, digest in files.items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("staged input path must remain within the payload")
        selected = (payload / path).resolve(strict=True)
        if not selected.is_relative_to(payload.resolve()) or not selected.is_file():
            raise ValueError("staged input is not a regular payload file")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None or _sha256(selected) != digest:
            raise ValueError(f"staged input hash mismatch: {relative}")
    wheel = index.get("wheel")
    if not isinstance(wheel, str) or not wheel.startswith("wheel/") or not wheel.endswith(".whl"):
        raise ValueError("staged inputs have no selected wheel")
    required = {wheel, "native/safeyolo-proxy", "runtime-requirements.txt", "test-requirements.txt", "bin/safeyolo-vm",
                "bin/vsock-term", "nats/nats-server", *(f"share/{name}" for name in BOOT_FILES)}
    if not required.issubset(files):
        raise ValueError("staged inputs are incomplete")
    index["boot_inputs"] = verify_boot_provenance(
        index.get("boot_inputs"), {name: files[f"share/{name}"] for name in BOOT_FILES},
    )
    # uv must not select an extra unverified distribution from the directory.
    actual_wheels = {path.relative_to(payload).as_posix() for path in (payload / "wheelhouse").iterdir()}
    indexed_wheels = {name for name in files if name.startswith("wheelhouse/")}
    if not actual_wheels or actual_wheels != indexed_wheels or any(not name.endswith(".whl") for name in actual_wheels):
        raise ValueError("staged wheelhouse must contain only indexed wheels")
    for name, dev in (("runtime-requirements.txt", False), ("test-requirements.txt", True)):
        if (payload / name).read_text() != requirements(checkout, dev=dev):
            raise ValueError("staged requirements differ from the frozen selected lock")
    if index.get("wheel_identity") != wheel_identity(payload / wheel, revision):
        raise ValueError("staged wheel identity differs from its index")
    if files["native/safeyolo-proxy"] != index["wheel_identity"]["native_sha256"]:
        raise ValueError("staged source release binary differs from its packaged wheel")
    return index


def prepare_inputs(payload: Path, expected_hash: str, checkout: Path, revision: str,
                   directory: Path, python: Path, env: dict) -> dict:
    """Install verified wheels offline once and reuse immutable boot inputs."""
    selected_source(checkout, revision)
    index = verified_inputs(payload, expected_hash, checkout, revision)
    helper = helper_identity(checkout, payload / "bin/safeyolo-vm", revision)
    if helper != index["vm_helper"]:
        raise ValueError("transferred VM helper identity differs from its build identity")
    version = subprocess.check_output([str(python), "-I", "-c", "import sys; print(sys.version_info[:2])"], text=True).strip()
    if version not in {"(3, 12)", "(3, 13)"}:
        raise ValueError("offline preparation needs an installed Python 3.12 or 3.13 interpreter")
    # Installed identity checks compare the original source release artifact
    # with the packaged and running binary. Restore that transferred artifact
    # to its maintained location; no compiler runs on the execution host.
    native = checkout / "proxy/target/release/safeyolo-proxy"
    if native.exists() and _sha256(native) != index["files"]["native/safeyolo-proxy"]:
        raise ValueError("execution checkout contains a different source release binary")
    native.parent.mkdir(parents=True, exist_ok=True)
    if not native.exists():
        shutil.copy2(payload / "native/safeyolo-proxy", native)
    for name, requirement_file in (("cli", "runtime-requirements.txt"), ("tests", "test-requirements.txt")):
        target = directory / name
        subprocess.run(["uv", "--no-config", "venv", "--offline", "--no-python-downloads",
                        "--python", str(python), str(target)], env=env, check=True)
        base = ["uv", "--no-config", "pip", "install", "--offline", "--no-index", "--no-build",
                "--no-deps", "--python", str(target / "bin/python")]
        subprocess.run([*base, "--find-links", str(payload / "wheelhouse"), "--require-hashes",
                        "-r", str(payload / requirement_file)], env=env, check=True)
        subprocess.run([*base, str(payload / index["wheel"])], env=env, check=True)
    cli = directory / "cli/bin/safeyolo"
    binary, cli_identity = _installed_rust_binary(cli)
    if _sha256(binary) != index["wheel_identity"]["native_sha256"]:
        raise ValueError("installed native binary differs from the staged wheel")
    (directory / "bin").mkdir()
    (directory / "bin/safeyolo").symlink_to(cli)
    source = directory / "prepared"
    subprocess.run([str(cli), "init", "--no-interactive"], env=env, check=True)
    # init creates empty input directories. Never copy live configuration,
    # tokens, vaults, keys, NATS credentials or streams from the build host.
    for relative in (*(f"share/{name}" for name in BOOT_FILES), "bin/safeyolo-vm", "bin/vsock-term"):
        (source / relative).symlink_to(payload / relative)
    code = """
import shutil, sys
from pathlib import Path
from safeyolo.coord import nats_runtime as n
source = Path(sys.argv[1])
if n._sha256_of(source) != n._expected_binary_sha256():
    raise ValueError('staged NATS executable differs from the selected pin')
target = n.nats_binary_path()
target.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(source, target)
target.chmod(0o755)
assert n.ensure_binary() == target
print(n.NATS_VERSION)
"""
    nats_version = subprocess.check_output(
        [str(directory / "cli/bin/python"), "-I", "-c", code, str(payload / "nats/nats-server")],
        env=env, text=True, timeout=30,
    ).strip()
    return {"input_index_sha256": expected_hash, "source_revision": revision,
            "wheel_sha256": index["files"][index["wheel"]], "cli": cli_identity,
            "native_sha256": _sha256(binary), "vm_helper": helper, "nats_version": nats_version,
            "boot_inputs": index["boot_inputs"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--install-commit", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--prepared-config", type=Path, required=True)
    parser.add_argument("--boot-provenance", type=Path, required=True,
                        help="JSON mapping of boot file names to original source_revision and sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        index = package_inputs(args.checkout.resolve(), args.install_commit, args.wheel.resolve(),
                               args.wheelhouse.resolve(), args.prepared_config.resolve(),
                               args.boot_provenance.resolve(), args.output.resolve())
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError, SmokeError) as exc:
        parser.exit(2, f"Staged input packaging failed: {exc}\n")
    print(f"Staged inputs: {index}\nSHA-256: {_sha256(index)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
