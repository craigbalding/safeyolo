#!/usr/bin/env python3
"""Bind a verified retained custom guest layout to the operator's selected inputs."""

import argparse
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path


def unpack_layout(archive: Path, expected_sha256: str, layout: Path) -> None:
    """Verify the transported layout archive before extracting into a new directory."""
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected_sha256:
        raise ValueError("Custom layout archive SHA-256 differs from the request")
    layout.mkdir(mode=0o700)
    with tarfile.open(archive) as stream:
        stream.extractall(layout, filter="data")


def verify(layout: Path, request: dict, compatibility: str, verifier: Path) -> dict:
    """Use the shared validator, then compare the requested publication identities."""
    index_digest = request["index"]
    subprocess.run([str(verifier), str(layout), index_digest, compatibility], check=True)
    blobs = layout / "blobs/sha256"
    raw_index = (blobs / index_digest.removeprefix("sha256:")).read_bytes()
    index = json.loads(raw_index)
    annotations = index["annotations"]
    profile = request["profile"]
    if not isinstance(profile, str) or not profile:
        raise ValueError("Select a nonempty custom profile name")
    if (annotations["org.opencontainers.image.revision"] != request["source_revision"]
            or annotations.get("dev.safeyolo.guest.profile") != profile):
        raise ValueError("Guest layout does not match the requested source revision or custom profile")
    platforms = {}
    for descriptor in index["manifests"]:
        consumer = descriptor["platform"]
        platform = consumer["os"] + "/" + consumer["architecture"]
        child = json.loads((blobs / descriptor["digest"].removeprefix("sha256:")).read_bytes())
        platforms[platform] = {
            "manifest": {key: descriptor[key] for key in ("digest", "size")},
            "config": {key: child["config"][key] for key in ("digest", "size")},
            "archive": {key: child["layers"][0][key] for key in ("digest", "size")},
            "build_base": child["annotations"]["dev.safeyolo.guest.build-base"],
            "build_inputs": child["annotations"]["dev.safeyolo.guest.build-inputs"],
        }
    selected = {platform: {"archive": row["archive"]["digest"], "build_inputs": row["build_inputs"]}
                for platform, row in platforms.items()}
    if selected != request["platforms"]:
        raise ValueError("Guest layout platforms, archive digests or build-input digests differ from the request")
    return {
        "request": request,
        "version": annotations["org.opencontainers.image.version"],
        "compatibility": compatibility,
        "index": {"digest": index_digest, "size": len(raw_index)},
        "platforms": platforms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--layout-archive", type=Path)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--compatibility", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_bytes())
    if args.layout_archive is not None:
        unpack_layout(args.layout_archive, request["layout_sha256"], args.layout)
    result = verify(args.layout, request, args.compatibility, args.verifier.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
