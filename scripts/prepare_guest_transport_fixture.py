#!/usr/bin/env python3
"""Prepare the bounded, nonbootable #239 transport fixture from verified seed files."""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "guest-2026-10-16.239"
COMPATIBILITY = "v1"
RANDOM_IMAGE_BYTES = 2 * 1024**3 + 1024**2
MINIMUM_ARCHIVE_BYTES = 2 * 1024**3


def blob(layout: Path, digest: str) -> Path:
    return layout / "blobs/sha256" / digest.removeprefix("sha256:")


def prepare(seed_layout: Path, seed_index: str, output: Path, revision: str, verifier: Path) -> dict:
    """Reuse the archive producer and native validator; write actual OCI identities."""
    subprocess.run([str(verifier), str(seed_layout), seed_index, COMPATIBILITY], check=True)
    output.mkdir(parents=True, exist_ok=False)
    if shutil.disk_usage(output).free < 8 * 1024**3:
        raise RuntimeError("Transport fixture preparation needs 8 GiB of free disk space.")
    seed = json.loads(blob(seed_layout, seed_index).read_bytes())
    for descriptor in seed["manifests"]:
        platform = descriptor["platform"]["os"] + "-" + descriptor["platform"]["architecture"]
        child = json.loads(blob(seed_layout, descriptor["digest"]).read_bytes())
        archive = blob(seed_layout, child["layers"][0]["digest"])
        built = output / "built" / platform
        built.mkdir(parents=True)
        (built / "build-base.txt").write_text(
            "ghcr.io/craigbalding/safeyolo-guest@" + descriptor["digest"] + "\n"
        )
        if platform == "darwin-arm64":
            members = ["Image", "initramfs.cpio.gz"]
        else:
            (built / "rootfs-tree/etc").mkdir(parents=True)
            (built / "rootfs-tree/TRANSPORT_FIXTURE_ONLY").write_text("Not a runnable guest: " + platform + "\n")
            members = ["rootfs-tree/etc/os-release", "cache-paths.txt"]
        for member in members:
            # Read only named seed files. Never extract or rebuild a complete rootfs.
            with (built / member).open("xb") as target:
                subprocess.run(["tar", "--zstd", "-xOf", str(archive), member], stdout=target, check=True)
        if platform == "darwin-arm64":
            with (built / "rootfs-base.ext4").open("xb") as image:
                for offset in range(0, RANDOM_IMAGE_BYTES, 1024**2):
                    image.write(os.urandom(min(1024**2, RANDOM_IMAGE_BYTES - offset)))
        subprocess.run([
            str(ROOT / "guest/archive-default.sh"), platform.replace("-", "/"), str(built),
            str(output / "archives" / platform),
        ], check=True)
        if platform == "darwin-arm64":
            if (output / "archives" / platform / "guest.tar.zst").stat().st_size <= MINIMUM_ARCHIVE_BYTES:
                raise RuntimeError("The compressed transport archive must exceed 2 GiB.")
            # The archive retains these random bytes. Drop the raw copy to bound disk use.
            (built / "rootfs-base.ext4").unlink()
    layout = output / "layout"
    subprocess.run([
        str(ROOT / "scripts/publish_guest_oci.sh"), "--artifacts", str(output / "archives"),
        "--layout", str(layout), "--version", VERSION, "--compatibility", COMPATIBILITY,
        "--revision", revision, "--verifier", str(verifier),
    ], check=True)
    index = subprocess.check_output([
        os.environ.get("ORAS", "oras"), "resolve", "--oci-layout", str(layout) + ":" + VERSION,
    ], text=True).strip()
    raw_index = blob(layout, index).read_bytes()
    platforms = {}
    for descriptor in json.loads(raw_index)["manifests"]:
        platform = descriptor["platform"]["os"] + "/" + descriptor["platform"]["architecture"]
        child = json.loads(blob(layout, descriptor["digest"]).read_bytes())
        platforms[platform] = {
            "child": {key: descriptor[key] for key in ("digest", "size")},
            "archive": {key: child["layers"][0][key] for key in ("digest", "size")},
            "config": {key: child["config"][key] for key in ("digest", "size")},
            "build_base": child["annotations"]["dev.safeyolo.guest.build-base"],
        }
    result = {
        "scope": "Synthetic transport fixture. The random disk is not a filesystem. Never boot it.",
        "version": VERSION, "compatibility": COMPATIBILITY, "revision": revision,
        "seed_index": seed_index, "random_image_bytes": RANDOM_IMAGE_BYTES,
        "index": {"digest": index, "size": len(raw_index)}, "platforms": platforms,
    }
    (output / "fixture.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-layout", type=Path, required=True)
    parser.add_argument("--seed-index", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.seed_layout.resolve(), args.seed_index, args.output.resolve(),
                     args.revision, args.verifier.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
