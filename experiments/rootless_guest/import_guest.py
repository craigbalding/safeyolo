#!/usr/bin/env python3
"""Bounded #1553 prototype; not the production guest installer.

Verify and inventory a retained published archive, or extract its selected
backend files into a fresh private directory. Linux uses the installed
namespace entry and delegated-ID helpers. macOS uses its native tar directly.
"""

import argparse
import contextlib
import hashlib
import json
import os
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from collections import Counter
from pathlib import Path

ARCHIVE_BASE = 100000
ID_COUNT = 65536


def import_ids(base, operator):
    """Map archive coordinates directly; namespace root uses the unused ID.

    Guest1000 maps to the operator, leaving base+1000 free. Mapping namespace
    root there allows nsenter to execute tar with namespace capabilities while
    keeping host root outside the map. UID and GID allocations are independent.
    """
    if operator <= 0 or base <= 0 or base + ID_COUNT > 2**32 - 1:
        raise ValueError("Use an ordinary account and a valid delegated 65536-ID range")
    if base <= operator < base + ID_COUNT:
        raise ValueError("Operator ID overlaps the delegated range")
    return [(0, base + 1000, 1), (ARCHIVE_BASE, base, 1000),
            (ARCHIVE_BASE + 1000, operator, 1),
            (ARCHIVE_BASE + 1001, base + 1001, ID_COUNT - 1001)]


def verify_archive(stream, expected):
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        raise ValueError("The selected archive must be a regular file")
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected.removeprefix("sha256:"):
        raise ValueError("Archive SHA-256 differs from the selected published descriptor")
    stream.seek(0)
    return digest


def inventory(stream):
    """Read all tar headers without materializing host files or special nodes."""
    records = []
    with subprocess.Popen(["zstd", "-dc"], stdin=stream, stdout=subprocess.PIPE) as decoder:
        try:
            with tarfile.open(fileobj=decoder.stdout, mode="r|") as archive:
                for member in archive:
                    records.append({"name": member.name, "type": member.type.decode("ascii"),
                                    "uid": member.uid, "gid": member.gid, "mode": oct(member.mode),
                                    "size": member.size, "link": member.linkname,
                                    "device": [member.devmajor, member.devminor],
                                    "sparse": member.sparse, "pax": member.pax_headers})
            # tar's end marker may precede a compressed-frame checksum. Drain
            # and check the decoder instead of accepting a truncated stream.
            while decoder.stdout.read(1024 * 1024):
                pass
        finally:
            decoder.stdout.close()
        if decoder.wait() != 0:
            raise RuntimeError("zstd could not decode the verified archive")
    return {"counts": dict(Counter(row["type"] for row in records)),
            "owners": sorted({(row["uid"], row["gid"]) for row in records}),
            "logical_regular_bytes": sum(row["size"] for row in records if row["type"] in ("0", "7")),
            "records": records}


def namespace_command(host_root, program):
    """Mirror linux_host::namespace_command, reusing its prepared entry."""
    setting = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if setting.exists() and setting.read_text().strip() == "1":
        entry = host_root / "host/namespace-entry"
        if not entry.is_file():
            raise RuntimeError(f"Prepared namespace entry is missing: {entry}")
        return [str(entry), program]
    return [program]


@contextlib.contextmanager
def import_namespace(host_root, uid_base, gid_base):
    """Reuse the runtime's unshare-holder, new*idmap and nsenter sequence."""
    uid_map = import_ids(uid_base, os.getuid())
    gid_map = import_ids(gid_base, os.getgid())
    command = namespace_command(host_root, "unshare") + ["-U", "tail", "-f", "/dev/null"]
    with tempfile.TemporaryFile() as errors, subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors,
    ) as holder:
        try:
            parent = Path("/proc/self/ns/user").stat().st_ino
            deadline = time.monotonic() + 5
            while True:
                if holder.poll() is not None:
                    errors.seek(0)
                    raise RuntimeError("Namespace entry failed: " + errors.read().decode(errors="replace"))
                if Path(f"/proc/{holder.pid}/ns/user").stat().st_ino != parent:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("Namespace holder did not enter its user namespace")
                time.sleep(0.02)
            for tool, mapping in [("newuidmap", uid_map), ("newgidmap", gid_map)]:
                arguments = [str(number) for row in mapping for number in row]
                subprocess.run([tool, str(holder.pid), *arguments], check=True, timeout=15)
            maps = {name: Path(f"/proc/{holder.pid}/{name}").read_text()
                    for name in ("uid_map", "gid_map")}
            yield ["nsenter", f"--user=/proc/{holder.pid}/ns/user", "--setuid=0", "--setgid=0", "--"], maps
        finally:
            if holder.poll() is None:
                holder.terminate()
            try:
                holder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait()


def extract(stream, stage, prefix, linux):
    # Keep the exact maintained selected-member and tar confinement options.
    arguments = ["tar", "-xpf", "-", "-C", str(stage)]
    if linux:
        arguments += ["--blocking-factor=256", "--numeric-owner", "--same-owner",
                      "--acls", "--xattrs", "--xattrs-include=*"]
    members = ["rootfs-tree", "cache-paths.txt"] if linux else ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]
    arguments += ["--", *members]
    with subprocess.Popen(["zstd", "-dc"], stdin=stream, stdout=subprocess.PIPE) as decoder:
        try:
            result = subprocess.run(prefix + arguments, stdin=decoder.stdout, timeout=600, check=False)
        finally:
            decoder.stdout.close()
            # Reap both writers before cleanup, including cancellation/failure.
            try:
                decoder_status = decoder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                decoder.kill()
                decoder.wait()
                raise
    if result.returncode or decoder_status:
        raise RuntimeError(f"Extraction failed: tar={result.returncode}, zstd={decoder_status}")
    return arguments


def prepare(args, stream, digest):
    if os.getuid() == 0:
        raise ValueError("Run this witness as an ordinary native host account")
    linux = args.platform == "linux"
    args.output.mkdir(mode=0o700)  # Existing guest/output stays untouched.
    started = time.monotonic()
    with (import_namespace(args.host_root, args.uid_base, args.gid_base)
          if linux else contextlib.nullcontext(([], {}))) as (prefix, maps):
        stage = Path(tempfile.mkdtemp(prefix="extract-", dir=args.output))
        report = {"uid": os.getuid(), "gid": os.getgid(), "maps": maps,
                  "stage": str(stage), "archive_sha256": digest, "result": "incomplete"}
        try:
            report["tar"] = extract(stream, stage, prefix, linux)
            if args.cancel_after_extract:
                raise InterruptedError("Requested cancellation after child completion")
            if linux:
                root = stage / "rootfs-tree"
                info = root.lstat()
                if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (args.uid_base, args.gid_base):
                    raise RuntimeError("Extracted root is not the expected mapped directory")
                if not stat.S_ISREG((stage / "cache-paths.txt").lstat().st_mode):
                    raise RuntimeError("cache-paths.txt must be regular")
            else:
                for name in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]:
                    if not stat.S_ISREG((stage / name).lstat().st_mode):
                        raise RuntimeError(f"Expected regular backend file: {name}")
            report["result"] = "prepared; backend startup and metadata comparison still required"
        except BaseException as error:
            # Cancellation propagates after the same namespace removes its
            # private stage. rm does not follow an external-target symlink.
            report["error"] = str(error)
            subprocess.run(prefix + ["rm", "-rf", "--", str(stage)], check=True, timeout=60)
            report["result"] = "failed/cancelled; private stage removed"
            raise
        finally:
            report["elapsed_seconds"] = time.monotonic() - started
            (args.output / "preparation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "prepare"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--platform", choices=("linux", "darwin"), default="linux")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--host-root", type=Path, default=Path.home() / ".safeyolo")
    parser.add_argument("--uid-base", type=int, default=100000)
    parser.add_argument("--gid-base", type=int, default=100000)
    parser.add_argument("--cancel-after-extract", action="store_true")
    args = parser.parse_args()
    with args.archive.open("rb") as stream:
        digest = verify_archive(stream, args.sha256)
        if args.operation == "inventory":
            print(json.dumps({"archive_sha256": digest, **inventory(stream)}, indent=2))
        else:
            if args.output is None:
                parser.error("prepare requires --output, a fresh disk-backed directory")
            args.output = args.output.absolute()
            prepare(args, stream, digest)


if __name__ == "__main__":
    # SIGTERM follows the same cleanup path as Ctrl-C and explicit cancellation.
    def interrupted(signum, frame):
        raise InterruptedError(f"Interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    main()
