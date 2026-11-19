#!/usr/bin/env python3
"""Trusted executor: acquire, require two exact-byte controls, then import.

Run only with an operator-adopted configuration outside worker-writable mounts.
The worker must not select this command's executable, configuration or paths.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

from check_media import sha256


def acquire(config, directory):
    """Download only the exact adopted HTTPS source, with byte and time bounds."""
    source = config["source"]
    url = urllib.parse.urlsplit(source["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError("Select an HTTPS source without credentials or a fragment")
    media = directory / "media"
    result = subprocess.run([
        "curl", "--disable", "--silent", "--show-error", "--fail", "--proto", "=https",
        "--max-time", str(config["download_timeout_seconds"]), "--max-filesize", str(config["max_bytes"]),
        "--output", str(media), "--write-out", "%{http_code}", "--url", source["url"],
    ], check=True, capture_output=True, text=True, timeout=config["download_timeout_seconds"] + 5)
    # curl does not follow redirects without --location. A redirect is not an acquisition.
    if result.stdout != "200":
        raise ValueError(f"Acquisition returned HTTP {result.stdout}")
    if not 0 < media.stat().st_size <= config["max_bytes"] or sha256(media) != source["sha256"]:
        raise ValueError("Acquired artifact is empty or differs from the selected digest")
    return media


def required_check(config, control, directory):
    """Observe a fresh native job; caller-supplied check reports are never inputs."""
    spec_path = Path(config["jobs"][control])
    spec = json.loads(spec_path.read_text())
    expected_argv = ["/usr/bin/python3", "/input/check_media.py", control]
    if (spec["argv"] != expected_argv or spec.get("network", False) or
            spec.get("privilege", "unprivileged") != "unprivileged" or
            spec.get("engine", {"kind": "platform"}) != {"kind": "platform"}):
        raise ValueError("Media control needs its fixed, network-disabled Linux job")
    result = subprocess.run([
        config["safeyolo"], "--root", config["instance_root"], "job", "run", str(spec_path),
        "--input", str(directory),
    ], capture_output=True, text=True, timeout=spec["timeout_seconds"] + 120)
    (directory / f"{control}-job-result.json").write_text(result.stdout)
    (directory / f"{control}-job-stderr.txt").write_text(result.stderr)
    if result.returncode != 0:
        raise ValueError(f"Required {control} job failed (exit {result.returncode}); original result retained")
    job = json.loads(result.stdout)
    if (job["outcome"] != {"kind": "exit", "code": 0} or job.get("observation_error") is not None or
            job["outcome_source"] != "guest_process" or job["engine"] not in {"gvisor", "vz"} or
            job["gate_id"] != spec["gate_id"]):
        raise ValueError("Required job did not complete with observable success")
    output = job["stdout"]
    retained = base64.b64decode(output["retained_base64"], validate=True)
    if len(retained) != output["bytes"] or hashlib.sha256(retained).hexdigest() != output["sha256"]:
        raise ValueError("Required job output is incomplete or inconsistent")
    report = json.loads(retained)
    if (report.get("passed") is not True or report.get("control") != control or
            report.get("sha256") != config["source"]["sha256"] or
            report.get("checker_sha256") != sha256(directory / "check_media.py")):
        raise ValueError("Required check does not pass for this artifact and checker")
    return {"run_id": job["run_id"], "engine": job["engine"], "rootfs": job["rootfs"],
            "gate_definition_sha256": job["gate_definition_sha256"], "report": report}


def import_media(media, config):
    """Publish exact checked bytes atomically without replacing another item."""
    filename = config["filename"]
    if filename in {"", ".", ".."} or Path(filename).name != filename or "\\" in filename:
        raise ValueError("Library filename must be one path component")
    library = Path(config["library"]).resolve(strict=True)
    target = library / filename
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or sha256(target) != config["source"]["sha256"]:
            raise ValueError("Library target already exists with a different identity")
        return {"path": str(target), "sha256": sha256(target), "effect": "already_present"}
    descriptor, staging_name = tempfile.mkstemp(prefix=".media-", dir=library)
    staging = Path(staging_name)
    try:
        with os.fdopen(descriptor, "wb") as out, media.open("rb") as source:
            shutil.copyfileobj(source, out, length=65536)
            out.flush()
            os.fsync(out.fileno())
        # DOC: cli/src/safeyolo/agent_context/skills/safeyolo-commission/recipes/media-ingestion/v1/recipe.md
        if sha256(staging) != config["source"]["sha256"]:
            raise ValueError("Import bytes differ from the checked artifact")
        # Ownership uses the executor and any existing directory setgid group.
        staging.chmod(int(config["file_mode"], 8))
        os.link(staging, target)
    finally:
        staging.unlink()
    return {"path": str(target), "sha256": sha256(target), "effect": "imported"}


def ingest(config):
    """Required ordering lives at the trusted effect, not in worker instructions."""
    started = time.time()
    if config["version"] != 1:
        raise ValueError("Unsupported media recipe version")
    if time.time() >= config["scan"]["valid_until_unix"]:
        raise ValueError("The adopted scanner qualification has expired")
    quarantine = Path(config["quarantine"]).resolve(strict=True)
    library = Path(config["library"]).resolve(strict=True)
    if quarantine.is_relative_to(library):
        raise ValueError("Quarantine must be outside the selected library's watched root")
    # The executor owns this directory; never expose it as a writable worker mount.
    directory = Path(tempfile.mkdtemp(prefix="media-", dir=quarantine))
    receipt = {"version": 1, "source": config["source"], "controls": {}, "status": "incomplete",
               "started_unix": started, "receipt": str(directory / "receipt.json"), "stage": "acquisition"}
    try:
        media = acquire(config, directory)
        shutil.copyfile(Path(__file__).with_name("check_media.py"), directory / "check_media.py")
        shutil.copytree(config["signatures"], directory / "signatures", symlinks=False)
        request = {"sha256": config["source"]["sha256"], "validation": config["validation"], "scan": config["scan"]}
        (directory / "request.json").write_text(json.dumps(request))
        # DOC: cli/src/safeyolo/agent_context/skills/safeyolo-commission/recipes/media-ingestion/v1/recipe.md
        for control in ("validate", "scan"):
            receipt["stage"] = control
            receipt["controls"][control] = required_check(config, control, directory)
        if time.time() >= config["scan"]["valid_until_unix"]:
            raise ValueError("Scanner qualification expired before import")
        receipt["stage"] = "import"
        receipt["import"] = import_media(media, config)
        receipt["status"] = "imported_pending_application"
        receipt["library_verification"] = "pending independent application readback; filesystem import is not library indexing"
        media.unlink()  # Successful import retains the artifact in the selected library.
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        # Cancellation stays incomplete and propagates; the reached evidence remains private.
        receipt["ended_unix"] = time.time()
        (directory / "receipt.json").write_text(json.dumps(receipt))
        if receipt["status"] == "incomplete":
            print(f"Media import is incomplete at {receipt['stage']}; inspect {receipt['receipt']}", file=sys.stderr)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text())
        print(json.dumps(ingest(config)))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Media ingestion failed for {args.config}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
