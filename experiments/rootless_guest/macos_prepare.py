#!/usr/bin/env python3
"""Observe native macOS extraction only; this does not start Virtualization.framework.

Use an ordinary Apple Silicon account, an inspected compatible published
archive and a new disk-backed output. Keep the prototype alongside this file.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64" or os.getuid() == 0:
        raise RuntimeError("This witness needs an ordinary native Apple Silicon macOS account")
    # This attempt's inspected image needs under2.5GiB allocated. Preserve the
    # separately specified20GiB operator-home reserve during preparation.
    if shutil.disk_usage(args.output.parent).free < int(22.5 * 1024**3):
        raise RuntimeError("Insufficient space for this inspected image plus the20GiB host reserve")
    args.output.mkdir(mode=0o700)
    tools = args.output / "tools"
    tools.mkdir(mode=0o700)
    for name in ("tar", "zstd", "rm"):
        selected = shutil.which(name)
        if selected is None:
            raise RuntimeError(f"Missing prerequisite: {name}")
        (tools / name).symlink_to(selected)
    environment = dict(os.environ, PATH=str(tools))
    prototype = Path(__file__).with_name("import_guest.py")
    command = [sys.executable, str(prototype), "prepare", "--platform", "darwin", "--archive",
               str(args.archive), "--sha256", args.sha256, "--output", str(args.output / "prepared")]
    report = {"observed_at": datetime.now(UTC).isoformat(), "platform": platform.uname()._asdict(),
              "uid": os.getuid(), "gid": os.getgid(), "command": command,
              "prototype_sha256": hashlib.sha256(prototype.read_bytes()).hexdigest(),
              "package_info": (args.package / "package-info").read_text(),
              "sudo_in_candidate_path": shutil.which("sudo", path=environment["PATH"]),
              "tools": {name: str((tools / name).resolve()) for name in ("tar", "zstd", "rm")},
              "result": "incomplete", "host_files": []}
    try:
        result = subprocess.run(command, env=environment, text=True, capture_output=True,
                                check=False, timeout=660)
        report.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode:
            raise RuntimeError("Native extraction failed; preserve this attempt and inspect witness.json")
        preparation = json.loads((args.output / "prepared/preparation.json").read_text())
        stage = Path(preparation["stage"])
        for path in sorted(stage.iterdir()):
            info = path.lstat()
            report["host_files"].append({"name": path.name, "uid": info.st_uid, "gid": info.st_gid,
                                         "mode": oct(info.st_mode), "logical_bytes": info.st_size,
                                         "allocated_bytes": info.st_blocks * 512})
        report["result"] = "native extraction succeeded; VM startup and Linux metadata unproved"
    finally:
        report["free_bytes_after"] = shutil.disk_usage(args.output).free
        (args.output / "witness.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
