#!/usr/bin/env python3
"""Run one media control in a disposable, network-disabled Linux job."""

import argparse
import hashlib
import json
import math
import subprocess
import time
from pathlib import Path


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate(media, selected):
    """Inspect the selected container and streams; do not claim full decoding."""
    result = subprocess.run([
        "ffprobe", "-v", "error", "-protocol_whitelist", "file", "-of", "json",
        "-show_entries", "format=format_name,duration:stream=codec_type,codec_name:stream_tags=language",
        str(media),
    ], check=True, capture_output=True, text=True, timeout=selected["timeout_seconds"])
    observation = json.loads(result.stdout)
    container = observation["format"]
    duration = float(container["duration"])
    if not math.isfinite(duration) or not 0 < duration <= selected["max_duration_seconds"]:
        raise ValueError("Media duration is missing or outside the selected bound")
    if not set(container["format_name"].split(",")) & set(selected["formats"]):
        raise ValueError("Container is outside the selected formats")
    streams = observation["streams"]
    if not any(item.get("codec_type") == "video" for item in streams):
        raise ValueError("No video stream observed")
    language = selected.get("subtitle_language")
    if language and not any(item.get("codec_type") == "subtitle" and
                            item.get("tags", {}).get("language") == language for item in streams):
        raise ValueError("No embedded subtitle stream with the selected language tag")
    version = subprocess.run(["ffprobe", "-version"], check=True, capture_output=True, text=True, timeout=10)
    return {"ffprobe": version.stdout.splitlines()[0], "observation": observation,
            "meaning": "Container, duration, video and selected subtitle metadata observed; not full decoding or translation verification"}


def scan(media, selected, directory):
    """Scan with exactly the adopted database bytes and selected expiry."""
    if time.time() >= selected["valid_until_unix"]:
        raise ValueError("The adopted scanner database qualification has expired")
    database = directory / "signatures"
    actual = {path.name: sha256(path) for path in database.iterdir() if path.is_file()}
    if not actual or actual != selected["database_sha256"]:
        raise ValueError("Scanner database differs from the adopted bytes")
    version = subprocess.run(["clamscan", "--version", "--database", str(database)],
                             check=True, capture_output=True, text=True, timeout=10)
    result = subprocess.run([
        "clamscan", "--stdout", "--no-summary", "--alert-exceeds-max=yes",
        "--max-filesize", str(media.stat().st_size + 1),
        "--max-scansize", str(selected["max_scan_bytes"]),
        "--database", str(database), str(media),
    ], capture_output=True, text=True, timeout=selected["timeout_seconds"])
    if result.returncode != 0 or not result.stdout.rstrip().endswith(": OK"):
        raise ValueError(f"Scanner did not establish a completed no-detection result (exit {result.returncode})")
    return {"clamscan": version.stdout.strip(), "database_sha256": actual,
            "valid_until_unix": selected["valid_until_unix"],
            "warnings": result.stderr,
            "meaning": "No detection by this scanner and these signatures; not proof of malware-free content"}


def check(control, directory):
    request = json.loads((directory / "request.json").read_text())
    media = directory / "media"
    before = sha256(media)
    if before != request["sha256"]:
        raise ValueError("Input artifact differs from the acquired bytes")
    evidence = (validate(media, request["validation"]) if control == "validate"
                else scan(media, request["scan"], directory))
    if sha256(media) != before:
        raise ValueError("Artifact changed during the check")
    return {"control": control, "sha256": before, "checker_sha256": sha256(Path(__file__)),
            "passed": True, "evidence": evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", choices=["validate", "scan"])
    parser.add_argument("--input", type=Path, default=Path("/input"))
    args = parser.parse_args()
    # Unexpected faults and cancellation remain nonzero job outcomes.
    print(json.dumps(check(args.control, args.input)))


if __name__ == "__main__":
    main()
