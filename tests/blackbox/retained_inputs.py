#!/usr/bin/env python3
"""Run maintained installed sections with one frozen retained-artifact selection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    from scripts.select_blackbox_artifacts import installed_binaries
else:
    from scripts.select_blackbox_artifacts import installed_binaries


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def controller_identity() -> dict:
    try:
        revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.SubprocessError):
        # A standalone copied instrument has no verifiable source revision.
        return {"controller_revision": None, "controller_dirty": True}
    return {"controller_revision": None if dirty else revision, "controller_dirty": dirty}


def selected(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if value["schema"] != "safeyolo.blackbox-inputs/v1" or value["status"] != "selected":
        raise ValueError("installed run requires a completed artifact selection")
    return value


def prepare_guest(selection_path: Path, archive: Path, bundle: Path, root: Path, directory: Path, *, yes: bool) -> Path:
    """Reuse the existing retained-archive extraction and Linux ownership mapping."""
    # The blackbox development environment already locks this test dependency.
    import zstandard

    selection = selected(selection_path)
    guest = selection["guest"]
    if "sha256:" + sha256(archive) != guest["archive"]["digest"] or archive.stat().st_size != guest["archive"]["size"]:
        raise ValueError("offline guest archive checksum/size differs")
    directory.mkdir(parents=True, exist_ok=False)
    unpacked = directory / "guest.tar"
    with archive.open("rb") as source, unpacked.open("xb") as output:
        zstandard.ZstdDecompressor().copy_stream(source, output)
    assets = directory / "assets"
    assets.mkdir()
    try:
        if selection["platform"].startswith("linux-"):
            subprocess.run(["sudo", "-n", "tar", "--numeric-owner", "--same-owner", "--same-permissions",
                            "--sparse", "--acls", "--xattrs", "--xattrs-include=*", "-xf", str(unpacked),
                            "-C", str(assets), "--", "rootfs-tree", "cache-paths.txt"], check=True)
            settings = directory / "linux-settings.toml"
            subprocess.run([str(bundle / "bin/safeyolo"), "--root", str(root), "host", "prepare",
                            "--package-root", str(bundle), "--installed-root", str(bundle),
                            "--write-settings", str(settings), *(["--yes"] if yes else [])], check=True, stdout=sys.stderr)
            import tomllib
            mapping = tomllib.loads(settings.read_text())["linux"]
            subprocess.run(["sudo", "-n", str(bundle / "bin/safeyolo"), "--root", str(root), "host", "remap-rootfs",
                            str(assets / "rootfs-tree"), *(str(mapping[key]) for key in
                            ("uid_base", "gid_base", "host_uid", "host_gid"))], check=True, stdout=sys.stderr)
        else:
            subprocess.run(["tar", "--no-same-owner", "-xpf", str(unpacked), "-C", str(assets),
                            "--", "Image", "initramfs.cpio.gz", "rootfs-base.ext4"], check=True)
    finally:
        unpacked.unlink()
    root.joinpath("share").mkdir(parents=True, exist_ok=True)
    installed = {"version": guest["version"], "repository": "ghcr.io/craigbalding/safeyolo-guest",
                 "compatibility": guest["compatibility"], "platform": selection["platform"].replace("-", "/", 1),
                 "assets": str(assets)}
    for field, expected in (("index", "index"), ("manifest", "child"), ("archive", "archive")):
        installed[field] = {key: guest[expected][key] for key in ("digest", "size")}
    (root / "share/guest-selection.json").write_text(json.dumps(installed, indent=2) + "\n")
    return assets


def verify_installed(selection_path: Path, root: Path, artifacts: Path) -> dict:
    selection = selected(selection_path)
    fields = dict(line.split("=", 1) for line in (root / "package-info").read_text().splitlines())
    for key, expected in {"source_commit": selection["host"]["source_revision"], "profile": "production",
                          "platform": selection["platform"], "guest_compatibility": selection["guest"]["compatibility"]}.items():
        if fields.get(key) != expected:
            raise ValueError(f"installed host differs from frozen selection: {key}")
    guest = json.loads((root / "share/guest-selection.json").read_bytes())
    if (guest["version"] != selection["guest"]["version"] or guest["compatibility"] != selection["guest"]["compatibility"]
            or guest["repository"] != "ghcr.io/craigbalding/safeyolo-guest"):
        raise ValueError("installed guest identity differs from frozen selection")
    for actual, expected in ((guest["index"], selection["guest"]["index"]),
                             (guest["manifest"], selection["guest"]["child"]),
                             (guest["archive"], selection["guest"]["archive"])):
        if any(actual.get(key) != expected[key] for key in ("digest", "size")):
            raise ValueError("installed guest differs from frozen selection")
    if guest["platform"] != selection["platform"].replace("-", "/", 1):
        raise ValueError("installed guest platform differs from frozen selection")
    identities = {name: sha256(root / name) for name in installed_binaries(selection["platform"])}
    if identities != selection["host"]["executables_sha256"]:
        raise ValueError("installed host/helper bytes differ from the selected package")
    # The archive installer verifies the package's complete SHA256SUMS and the
    # executable source/profile identities before this independent attribution.
    result = {"host_source_revision": fields["source_commit"], "profile": fields["profile"],
              "platform": fields["platform"], "installed_files_sha256": identities,
              "guest": {key: guest[key] for key in ("version", "compatibility", "platform")}}
    result["guest"].update({field: {key: guest[field][key] for key in ("digest", "size")}
                            for field in ("index", "manifest", "archive")})
    (artifacts / "installed-inputs.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run(selection_path: Path, lane: str, artifacts: Path, sections: list[str], yes: bool, *,
        guest_archive: Path | None = None) -> int:
    artifacts.mkdir(parents=True, exist_ok=False)
    report = {"started_at": datetime.now(UTC).isoformat(), "finished_at": None, "exit": None,
              "lane": lane, "host_system": platform.system(), "host_architecture": platform.machine(),
              "guest_input_mode": "retained-archive" if guest_archive else "native-index",
              "guest_test_provisioning": "offline" if os.environ.get("SAFEYOLO_GUEST_TEST_INPUTS") else "online",
              **controller_identity()}

    def save() -> None:
        (artifacts / "retained-run.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        selection = selected(selection_path)
        # Freeze a local copy for the installer and reports. Neither the default
        # branch nor a guest tag is consulted by any execution step.
        frozen = artifacts / "selection.json"
        frozen.write_text(json.dumps(selection, indent=2) + "\n")
        package = selection_path.parent / selection["host"]["archive"]["name"]
        if sha256(package) != selection["host"]["archive"]["sha256"]:
            raise ValueError("selected host archive checksum differs before installation")
        options = ["--package", str(package), "--sha256", selection["host"]["archive"]["sha256"]]
        if guest_archive is not None:
            options += ["--guest-archive", str(guest_archive)]
        else:
            options += ["--guest-index", selection["guest"]["index"]["digest"]]
        if lane != "package":
            options += ["--lane", lane]
        for section in sections:
            options += ["--section", section]
        if yes:
            options += ["--yes"]
        environment = dict(os.environ, SAFEYOLO_BLACKBOX_ARTIFACTS_DIR=str(artifacts),
                           SAFEYOLO_BLACKBOX_INPUT_SELECTION=str(frozen), SAFEYOLO_BLACKBOX_FULL_SECTIONS="1")
        result = subprocess.run([str(ROOT / "tests/blackbox/run-installed-package.sh"), *options],
                                cwd=ROOT, env=environment, check=False)
        report["exit"] = result.returncode
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report["exit"] = 2
        report["failure"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        save()
    return report["exit"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    execute = commands.add_parser("run")
    execute.add_argument("--selection", type=Path, required=True)
    execute.add_argument("--lane", choices=("systrap", "kvm", "vz", "package"), required=True)
    execute.add_argument("--artifacts", type=Path, required=True, help="New private report directory")
    execute.add_argument("--section", action="append", default=[])
    execute.add_argument("--yes", action="store_true")
    execute.add_argument("--guest-archive", type=Path, help="Exact archive from --download-guest-archive for offline execution")
    verify = commands.add_parser("verify-installed")
    verify.add_argument("--selection", type=Path, required=True)
    verify.add_argument("--root", type=Path, required=True)
    prepare = commands.add_parser("prepare-guest")
    prepare.add_argument("--selection", type=Path, required=True)
    prepare.add_argument("--archive", type=Path, required=True)
    prepare.add_argument("--bundle", type=Path, required=True)
    prepare.add_argument("--root", type=Path, required=True)
    prepare.add_argument("--directory", type=Path, required=True)
    prepare.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    if args.operation == "verify-installed":
        verify_installed(args.selection, args.root, Path(os.environ["SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"]))
        return 0
    if args.operation == "prepare-guest":
        print(prepare_guest(args.selection, args.archive, args.bundle, args.root, args.directory, yes=args.yes))
        return 0
    return run(args.selection.resolve(), args.lane, args.artifacts.resolve(), args.section, args.yes,
               guest_archive=args.guest_archive.resolve() if args.guest_archive else None)


if __name__ == "__main__":
    raise SystemExit(main())
