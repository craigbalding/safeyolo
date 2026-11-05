#!/usr/bin/env python3
"""Protect Devstack harness allocations and reclaim its abandoned temporary files.

The byte/inode observation and private atomic status follow the operator's
prepared storage-guard.py. Persistent inputs, VM disks and Rundeck history are
never cleanup candidates. Only a newly started download is stopped on pressure;
SSH command output is drained without interrupting the remote command.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import math
import os
import selectors
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

GIB = 1024**3
CHUNK = 64 * 1024


class NoSpace(Exception):
    """A required storage observation or status write refused new work."""


def observe(config: dict, required: int = 0, extra_path: Path | None = None) -> dict:
    paths = [Path(path) for path in config["filesystems"]]
    if extra_path is not None:
        paths.append(extra_path)
    floor = float(config["minimum_free_gib"]) * GIB
    if not math.isfinite(floor) or floor < 0 or config["minimum_free_inodes"] < 0 or required < 0:
        raise ValueError("storage thresholds must be finite and nonnegative")
    rows = []
    for path in dict.fromkeys(paths):
        try:
            space = os.statvfs(path)
            free = space.f_bavail * space.f_frsize
            low = free < floor + required or (space.f_files > 0 and space.f_favail < config["minimum_free_inodes"])
            rows.append({"path": str(path), "available_bytes": free, "minimum_bytes": int(floor),
                             "required_bytes": required, "available_inodes": space.f_favail, "low": low})
        except OSError as error:
            rows.append({"path": str(path), "low": True, "error": str(error)})
    return {"observed_at": datetime.now(UTC).isoformat(),
                "state": "LOW_OR_UNKNOWN" if not rows or any(row["low"] for row in rows) else "READY",
                "filesystems": rows}


def save_status(config: dict, status: dict) -> None:
    destination = Path(config["status_file"])
    # A fresh file prevents a previous permissive mode from carrying forward.
    with tempfile.NamedTemporaryFile(mode="w", dir=destination.parent, prefix=".status-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(status, stream, sort_keys=True)
            stream.write("\n")
            stream.close()
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def emergency_allocation(path: Path, amount: int):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_size != amount or info.st_blocks * 512 < amount):
        raise NoSpace("emergency space is not the expected owned allocated file")
    return info


def storage_status(config: dict, required: int = 0, extra_path: Path | None = None,
                   *, release: bool = False) -> dict:
    """Keep an allocated emergency file; only the scheduled sweep releases it."""
    parent = Path(config["spool"]).parent
    reserve = parent / "emergency-space"
    staging = parent / "emergency-space.creating"
    amount = config["emergency_bytes"]
    if amount <= 0:
        raise ValueError("emergency space must be positive")
    with (parent / "emergency-space.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # This exact, private staging file can survive a killed allocator.
        # The lock proves no current allocator owns it.
        staging.unlink(missing_ok=True)
        allocation = emergency_allocation(reserve, amount)
        status = observe(config, required, extra_path)
        if status["state"] != "READY":
            if release and allocation is not None:
                status["released_emergency_bytes"] = allocation.st_blocks * 512
                reserve.unlink()
            status["emergency_state"] = "pressure"
            return status
        if allocation is None:
            # A released reserve cannot immediately re-admit jobs using the
            # space just released. Re-arming must leave the full floor free.
            if observe(config, required + amount, extra_path)["state"] != "READY":
                status.update(state="LOW_OR_UNKNOWN", emergency_state="waiting-for-recovery")
                return status
            try:
                with staging.open("xb") as output:
                    os.posix_fallocate(output.fileno(), 0, amount)
                os.replace(staging, reserve)
            finally:
                staging.unlink(missing_ok=True)
        emergency_allocation(reserve, amount)
        status = observe(config, required, extra_path)
        status["emergency_state"] = "armed"
        return status


def check(config: dict, required: int = 0, extra_path: Path | None = None, *, report: bool = True) -> None:
    status = storage_status(config, required, extra_path)
    try:
        if report or status["state"] != "READY":
            save_status(config, status)
    except OSError as error:
        raise NoSpace(f"cannot write storage status: {error}") from error
    if status["state"] != "READY":
        raise NoSpace("storage is below its byte/inode reserve or cannot be observed; see storage status")


@contextmanager
def temporary_directory(config: dict):
    directory = Path(tempfile.mkdtemp(prefix=".creating-", dir=config["spool"]))
    with (directory / "lock").open("xb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        published = directory.with_name(directory.name.replace(".creating-", "transfer-", 1))
        directory.rename(published)
        directory = published
        try:
            yield directory
        finally:
            # Retention is zero: these transport scratch files are never reports
            # or reusable inputs. Keep the lock through removal.
            shutil.rmtree(directory)


def sweep(config: dict) -> None:
    removed = 0
    spool = Path(config["spool"])
    for directory in spool.iterdir():
        try:
            info = directory.lstat()
        except FileNotFoundError:
            # Another sweep or the normal owner has already removed it.
            continue
        if not directory.name.startswith("transfer-") or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            continue
        try:
            descriptor = os.open(directory / "lock", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            # A creator has not installed its lock yet. No transport data is
            # written until that lock exists and is held.
            continue
        with os.fdopen(descriptor, "rb") as lock:
            lock_info = os.fstat(lock.fileno())
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid():
                continue
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            try:
                shutil.rmtree(directory)
            except FileNotFoundError:
                # Two sweep processes can open the same lock before either
                # obtains it; the first holder already completed removal.
                continue
            removed += 1
    status = storage_status(config, release=True)
    status["reclaimed_temporary_directories"] = removed
    save_status(config, status)
    if status["state"] != "READY":
        raise NoSpace("storage remains low or unknown after temporary-file cleanup")


def ssh(key: str, ip: str, command: str) -> list[str]:
    return ["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR", f"agent@{ip}", command]


def capture(command: list[str], limit: int, *, stdin=None) -> tuple[int, list[bytes], list[bool]]:
    """Drain both pipes, retaining a bounded prefix without stopping the child."""
    buffers = [bytearray(), bytearray()]
    truncated = [False, False]
    with subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 0)
            selector.register(child.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                for key, _ in selector.select():
                    chunk = os.read(key.fileobj.fileno(), CHUNK)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    index = key.data
                    keep = min(len(chunk), limit - len(buffers[index]))
                    buffers[index].extend(chunk[:keep])
                    truncated[index] |= keep < len(chunk)
        code = child.wait()
    return code, [bytes(value) for value in buffers], truncated


def remote_read(key: str, ip: str, command: str, limit: int) -> bytes:
    code, output, truncated = capture(ssh(key, ip, command), limit)
    if code != 0 or any(truncated):
        raise NoSpace("remote storage/file observation failed or exceeded its expected output")
    return output[0]


def check_image(config: dict, path: Path, size: str) -> None:
    check(config, extra_path=path)
    # qemu-img is already the provisioner's allocator. Its initial required
    # size accounts for the sparse format, unlike fully-allocated/virtual size.
    code, output, truncated = capture(
        ["qemu-img", "measure", "--output=json", "-O", "qcow2", "--size", size], 8192)
    if code != 0 or any(truncated):
        raise NoSpace("cannot measure the new sparse image allocation")
    measurement = json.loads(output[0])
    required = measurement.get("required") if isinstance(measurement, dict) else None
    if type(required) is not int or required < 0:
        raise NoSpace("sparse image measurement has no valid required byte count")
    check(config, required, path)


def check_copy(config: dict, args: argparse.Namespace) -> None:
    check(config)
    if args.direction == "to":
        required = Path(args.source).stat().st_size
        check(config, required)
        # Resolve directory destinations just as scp does. Guest capacity is
        # for this copy, independent of the host's service reserve.
        command = (f"target={shlex.quote(args.destination)}; "
                   f'if [ -d "$target" ]; then target="$target"/{shlex.quote(Path(args.source).name)}; fi; '
                   'parent=$(dirname -- "$target"); '
                   'df -Pk -- "$parent"; df -Pi -- "$parent"; stat -f -c %S -- "$parent"; '
                   'if [ -e "$target" ]; then echo 0; else echo 1; fi')
        data = remote_read(args.key, args.ip, command, 8192)
        rows = data.decode().splitlines()
        # Both df invocations have one header and one filesystem row.
        blocks, inodes = rows[1].split(), rows[3].split()
        block_size, new_file = int(rows[4]), int(rows[5])
        if block_size <= 0 or new_file not in (0, 1):
            raise NoSpace("cannot determine guest copy allocation")
        # Round the payload to actual blocks. A new file can also need a
        # directory-entry block and one inode; an overwrite needs no new inode.
        required = ((required + block_size - 1) // block_size + new_file) * block_size
        if (int(blocks[3]) * 1024 < required
                or (int(inodes[1]) > 0 and int(inodes[3]) < new_file)):
            raise NoSpace("guest destination cannot fit this copy's payload and metadata")
    else:
        data = remote_read(args.key, args.ip, f"stat -c%s -- {shlex.quote(args.source)}", 128)
        required = int(data.strip())
        check(config, required, Path(args.destination).parent)


def execute(config: dict, args: argparse.Namespace) -> None:
    check(config)
    started = time.monotonic()
    with temporary_directory(config) as directory:
        script = directory / "script"
        # The existing shell decoder accepts line-wrapped base64 input.
        script.write_bytes(base64.b64decode("".join(args.script.splitlines()), validate=True))
        with script.open("rb") as source:
            code, output, truncated = capture(
                ["timeout", "--kill-after=5", str(args.timeout), *ssh(args.key, args.ip, "bash -s")],
                config["maximum_output_bytes"], stdin=source)
    print("HARNESS_JSON:" + json.dumps({"ip": args.ip, "exit_code": code,
          "stdout_b64": base64.b64encode(output[0]).decode(), "stderr_b64": base64.b64encode(output[1]).decode(),
          "stdout_truncated": truncated[0], "stderr_truncated": truncated[1],
          "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": code in (124, 137)}))


def fetch(config: dict, args: argparse.Namespace) -> None:
    check(config)
    path = shlex.quote(args.path)
    size = int(remote_read(args.key, args.ip, f"stat -c%s -- {path}", 128).strip())
    checksum = remote_read(args.key, args.ip, f"sha256sum < {path}", 128).decode().split()[0]
    keep = min(size, args.maximum_bytes)
    check(config, keep)
    # Apply the existing MAX_BYTES contract before transfer, rather than after
    # a full scp. Hashing still covers the original complete remote file.
    data = remote_read(args.key, args.ip, f"head -c {keep} -- {path}", keep)
    if len(data) != keep:
        raise ValueError("remote file changed during fetch")
    if size == keep:
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError("remote file changed during fetch")
    print("HARNESS_JSON:" + json.dumps({"path": args.path, "size": size, "sha256": checksum,
          "content_b64": base64.b64encode(data).decode(), "truncated": size > keep}))


def download(config: dict, args: argparse.Namespace) -> None:
    destination = Path(args.destination)
    check(config, CHUNK, destination.parent)
    # On this host the observed pool and harness share /dev/sda2. Keeping the
    # private stage on that filesystem permits an atomic, no-copy promotion.
    if destination.parent.stat().st_dev != Path(config["spool"]).stat().st_dev:
        raise ValueError("download destination and storage spool must share a filesystem")
    with temporary_directory(config) as directory:
        partial = directory / "download"
        with partial.open("xb") as output, subprocess.Popen(
                ["curl", "-fsSL", args.url], stdout=subprocess.PIPE) as child:
            try:
                while chunk := child.stdout.read(CHUNK):
                    check(config, len(chunk), destination.parent, report=False)
                    output.write(chunk)
                if child.wait() != 0:
                    raise ValueError("cloud-image download failed")
            except (OSError, NoSpace):
                # This process owns only the new, read-only download. It never
                # signals a VM, a guest command, or an existing host writer.
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                raise
        os.replace(partial, destination)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path, required=True)
    commands = result.add_subparsers(dest="operation", required=True)
    capacity = commands.add_parser("check")
    capacity.add_argument("--required-bytes", type=int, default=0)
    capacity.add_argument("--path", type=Path)
    image_space = commands.add_parser("check-image")
    image_space.add_argument("--path", type=Path, required=True)
    image_space.add_argument("--size", required=True)
    commands.add_parser("sweep")
    image = commands.add_parser("download")
    image.add_argument("destination")
    image.add_argument("url")
    for name in ("ssh-exec", "ssh-fetch", "check-copy"):
        command = commands.add_parser(name)
        command.add_argument("--key", required=True)
        command.add_argument("--ip", required=True)
        if name == "ssh-exec":
            command.add_argument("--script", required=True)
            command.add_argument("--timeout", default="1800")
        elif name == "ssh-fetch":
            command.add_argument("--path", required=True)
            command.add_argument("--maximum-bytes", type=int, default=1048576)
        else:
            command.add_argument("direction", choices=("to", "from"))
            command.add_argument("source")
            command.add_argument("destination")
    return result


def main() -> int:
    os.umask(0o077)
    args = parser().parse_args()
    try:
        config = json.loads(args.config.read_bytes())
        if config["maximum_output_bytes"] < 0 or getattr(args, "maximum_bytes", 0) < 0:
            raise ValueError("output limits must be nonnegative")
        if args.operation == "check":
            check(config, args.required_bytes, args.path)
        elif args.operation == "check-image":
            check_image(config, args.path, args.size)
        elif args.operation == "sweep":
            sweep(config)
        elif args.operation == "download":
            download(config, args)
        elif args.operation == "ssh-exec":
            execute(config, args)
        elif args.operation == "ssh-fetch":
            fetch(config, args)
        else:
            check_copy(config, args)
    except (NoSpace, OSError, ValueError, IndexError) as error:
        print(f"Devstack storage: {error}", file=sys.stderr)
        return 75
    return 0


if __name__ == "__main__":
    sys.exit(main())
