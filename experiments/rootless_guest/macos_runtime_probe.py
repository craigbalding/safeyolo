#!/usr/bin/env python3
"""Follow the retained #1553 Mac preparation into its existing VZ backend.

Run as Bristol UID 502 with the compatible h1552 installation and an unused
disk-backed output. No acquisition, host sudo or production instance is used.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/blackbox/harness"))
from macos_process_argv import account_pids, process_argv  # noqa: E402
from process_identity import _darwin_process_info, process_start_token  # noqa: E402

INSTALL = Path("/Users/sy-agent/h1552")
PREPARED = Path("/Users/sy-agent/f1553-20261115/native/prepared/extract-kiyduh7b")
BASELINE = INSTALL / "share-kali-failed-1050"
WRAPPER = Path("/Users/sy-agent/bin/run-vz-test")
SOURCE = "c6dd3b8bfef1a2e5f49e1fbc273c4b2ac2b46a52"
IMAGES = {
    "Image": "cfb99c160084f605b4acf9e7d7a50e4805e07de0c6fa7a88918067100a9066c0",
    "initramfs.cpio.gz": "1ca27b00cef28f6e7065f84524fc65bf48ed71c91b1bf498a4dc8532c5a6ec15",
    "rootfs-base.ext4": "5d2286d5deb330073b9af96b54a62ee1982707308a52223e2e714fc642f0063f",
}


def file_info(path):
    info = path.stat()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"sha256": digest, "bytes": info.st_size, "allocated_bytes": info.st_blocks * 512,
            "uid": info.st_uid, "gid": info.st_gid, "mode": oct(info.st_mode & 0o7777)}


def vm_processes():
    """Use the maintained kernel observer rather than seatbelt-denied ps."""
    observed = []
    for pid in account_pids(os.getuid()):
        if pid == os.getpid():
            continue
        try:
            argv = [os.fsdecode(value) for value in process_argv(pid)]
        except ProcessLookupError:
            continue  # The process exited between the account snapshot and argv read.
        if any(Path(value).name in ("safeyolo-vm", "run-vz-test") for value in argv):
            observed.append({"pid": pid, "birth": process_start_token(pid), "argv": argv})
    return observed


def preserve_during_runtime(output, environment):
    """Fail and cancel small private preparations while the original VM waits.

    The selected symlink tests cleanup of an external target. Cancellation is
    explicitly after extraction children finish, not an active-tar witness.
    """
    target = output / "external-target"
    target.write_bytes(b"external target must survive\n")
    target.chmod(0o600)
    before = file_info(target) | {"inode": target.stat().st_ino}
    archive = output / "preservation.tar.zst"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as entries:
        for name in IMAGES:
            member = tarfile.TarInfo(name)
            if name == "Image":
                member.type, member.linkname = tarfile.SYMTYPE, str(target)
                entries.addfile(member)
            else:
                member.size = 8
                entries.addfile(member, io.BytesIO(b"specimen"))
    compressed = subprocess.run(["zstd", "-q", "-c"], input=raw.getvalue(),
                                capture_output=True, check=True)
    archive.write_bytes(compressed.stdout)
    observed = {"scope": "small synthetic image bundle; cancellation after child completion", "attempts": []}
    try:
        for name, extra in (("failed", []), ("cancelled", ["--cancel-after-extract"])):
            attempt = output / name
            command = [sys.executable, str(Path(__file__).with_name("import_guest.py")), "prepare",
                       "--platform", "darwin", "--archive", str(archive), "--sha256", file_info(archive)["sha256"],
                       "--output", str(attempt), *extra]
            result = subprocess.run(command, env=environment, text=True, capture_output=True, check=False, timeout=30)
            row = {"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
            observed["attempts"].append(row)
            row["preparation"] = json.loads((attempt / "preparation.json").read_text())
            after = file_info(target) | {"inode": target.stat().st_ino}
            row["external_preserved"] = before == after
            row["stage_removed"] = not Path(row["preparation"]["stage"]).exists()
            if not result.returncode or not row["stage_removed"] or not row["external_preserved"]:
                raise RuntimeError("Private preparation did not fail cleanly and preserve the external target")
    finally:
        (output / "preservation.json").write_text(json.dumps(observed, indent=2) + "\n")
    return observed


def main(output, *, baseline_preservation=False):
    if platform.system() != "Darwin" or platform.machine() != "arm64" or os.getuid() != 502:
        raise RuntimeError("Run this retained-input proof as ordinary Bristol UID 502")
    output.mkdir(mode=0o700)
    report = {"started_at": datetime.now(UTC).isoformat(), "platform": platform.platform(),
              "uid": os.getuid(), "gid": os.getgid(), "result": "incomplete", "actions": [],
              "controller": file_info(Path(__file__))}
    child = None
    held = {pid: process_start_token(pid) for pid in (93166, 93168)}

    def save():
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    try:
        report["free_bytes_before"] = shutil.disk_usage(output).free
        # Budget the bounded overlay plus copied guest assets/logs, retaining
        # the operator's existing 20 GiB reserve on this backing filesystem.
        if report["free_bytes_before"] < 20 * 1024**3 + 384 * 1024**2:
            raise RuntimeError("Selected overlay/assets do not fit above the operator-home reserve")
        report["prior_vm_processes"] = vm_processes()
        if report["prior_vm_processes"]:
            raise RuntimeError("Another VM consumer needs serialization; preserve its owner")
        report["held_processes_before"] = held
        report["package_info"] = (INSTALL / "package-info").read_text()
        if f"source_commit={SOURCE}\n" not in report["package_info"]:
            raise RuntimeError("Retained installation source changed")
        report["files"] = {}
        for directory in (PREPARED, BASELINE):
            values = {name: file_info(directory / name) for name in IMAGES}
            report["files"][str(directory)] = values
            save()
            if any(values[name]["sha256"] != digest for name, digest in IMAGES.items()):
                raise RuntimeError("Prepared/baseline published image identity changed")
        report["helper"] = file_info(INSTALL / "bin/safeyolo-vm")
        report["wrapper"] = file_info(WRAPPER)
        for argument in ("version", "check"):
            result = subprocess.run([str(INSTALL / "bin/safeyolo-vm"), argument],
                                    text=True, capture_output=True, check=False, timeout=10)
            report["actions"].append({"command": [argument], "exit": result.returncode,
                                      "stdout": result.stdout, "stderr": result.stderr})
            save()
            if result.returncode:
                raise RuntimeError(f"Retained helper {argument} failed")

        for name in ("config", "status", "home", "workspace", "tools"):
            (output / name).mkdir(mode=0o700)
        # These shares are inside the private UID502-owned output. VZ presents
        # guest IDs independently; match the existing snapshot fixture here.
        for name in ("status", "home", "workspace"):
            (output / name).chmod(0o777)
        config = output / "config"
        report["assets"] = {}
        for name in ("guest-init", "guest-init-static", "guest-init-per-run", "safeyolo-guest",
                     "guest-proxy-forwarder", "guest-shell-bridge", "guest-sudo", "guest-desktop"):
            source = INSTALL / "assets/guest" / name
            report["assets"][name] = file_info(source)
            shutil.copyfile(source, config / name)
            (config / name).chmod(0o755)
        (config / "guest-init-static").rename(config / "guest-init-static-original")
        (config / "guest-init-static").write_text(
            "#!/bin/bash\nset -e\n/safeyolo/guest-init-static-original\n"
            "/bin/bash /safeyolo/macos_runtime_guest.sh > /safeyolo-status/guest.log 2>&1 &\n")
        (config / "guest-init-static").chmod(0o755)
        guest_script = Path(__file__).with_name("macos_runtime_guest.sh")
        shutil.copyfile(guest_script, config / guest_script.name)
        report["guest_probe"] = file_info(guest_script)
        (config / "agent.env").write_text("SAFEYOLO_DETACH=1\nTZ=UTC\n")
        (config / "agent-name").write_text("rootless-1553\n")
        (config / "per-run-go").touch()
        (output / "tools/python3").symlink_to(sys.executable)
        environment = dict(os.environ, PATH=str(output / "tools"))
        if baseline_preservation:
            for name in ("tar", "zstd", "rm"):
                selected = shutil.which(name)
                if selected is None:
                    raise RuntimeError(f"Missing existing preservation tool: {name}")
                (output / "tools" / name).symlink_to(selected)
            (config / "wait-for-preservation").touch()
        report["sudo_on_candidate_path"] = shutil.which("sudo", path=environment["PATH"])
        overlay = output / "overlay.ext4"
        with overlay.open("xb") as stream:
            stream.truncate(256 * 1024**2)
        images = BASELINE if baseline_preservation else PREPARED
        report["runtime_images"] = str(images)
        command = [str(WRAPPER), "--timeout-seconds", "150", "--", str(INSTALL / "bin/safeyolo-vm"),
                   "run", "--kernel", str(images / "Image"), "--initrd", str(images / "initramfs.cpio.gz"),
                   "--rootfs", str(images / "rootfs-base.ext4"), "--overlay", str(overlay),
                   "--cpus", "2", "--memory", "1024", "--no-terminal",
                   "--serial-log", str(output / "serial.log")]
        for name in ("config", "status", "home", "workspace"):
            command += ["--share", f"{output / name}:{name}:{'ro' if name == 'config' else 'rw'}"]
        report["command"] = command
        save()
        with (output / "helper.log").open("w") as log:
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, env=environment, start_new_session=True)
            report["wrapper_process"] = {"pid": child.pid, "birth": process_start_token(child.pid)}
            report["owned_helpers"] = []
            deadline = time.monotonic() + 120
            while not (output / "status/probe.done").exists():
                if child.poll() is not None:
                    report["early_wrapper_exit"] = child.returncode
                    raise RuntimeError("VM runner exited before the guest probe completed")
                if not report["owned_helpers"]:
                    for item in vm_processes():
                        info = _darwin_process_info(item["pid"])
                        if info is not None and info.pbi_ppid == child.pid:
                            report["owned_helpers"].append(item)
                    save()
                if baseline_preservation and (output / "status/preservation.ready").exists():
                    if not (output / "status/preservation.done").exists():
                        report["preservation"] = preserve_during_runtime(output, environment)
                        save()
                        (output / "status/preservation.done").touch()
                if time.monotonic() >= deadline:
                    raise RuntimeError("Guest probe deadline; retain helper/serial/guest output")
                time.sleep(0.1)
            report["guest_probe_exit"] = (output / "status/probe.done").read_text().strip()
            if report["guest_probe_exit"] != "0":
                raise RuntimeError("Guest identity/read/write/execute probe failed")
            report["result"] = "published preparation reached VZ guest identity/read/write/execute"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    child.terminate()  # The maintained wrapper stops and reaps its own VM helper.
                report["wrapper_exit"] = child.wait(timeout=15)
            except (OSError, subprocess.TimeoutExpired) as error:
                report["cleanup_error"] = f"Owned wrapper stop failed: {error}; inspect exact births before retry"
        report["free_bytes_after"] = shutil.disk_usage(output).free
        report["held_processes_after"] = {pid: process_start_token(pid) for pid in held}
        report["held_processes_unchanged"] = report["held_processes_after"] == held
        try:
            report["remaining_vm_processes"] = vm_processes()
            tracked = [(item["pid"], item["birth"]) for item in report.get("owned_helpers", [])]
            if child is not None:
                tracked.append((child.pid, report["wrapper_process"]["birth"]))
            report["owned_survivors"] = [item for item in report["remaining_vm_processes"]
                                         if (item["pid"], item["birth"]) in tracked]
        except (OSError, ValueError, RuntimeError) as error:
            report["cleanup_inspection_error"] = str(error)
        if (output / "overlay.ext4").exists():
            info = (output / "overlay.ext4").stat()
            report["overlay"] = {"bytes": info.st_size, "allocated_bytes": info.st_blocks * 512}
        report["finished_at"] = datetime.now(UTC).isoformat()
        save()
    if (report.get("cleanup_error") or report.get("cleanup_inspection_error")
            or report.get("owned_survivors") or not report["held_processes_unchanged"]):
        raise RuntimeError("Inspect retained cleanup observations before further effects")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--baseline-preservation", action="store_true")
    args = parser.parse_args()
    main(args.output.resolve(), baseline_preservation=args.baseline_preservation)
