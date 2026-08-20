#!/usr/bin/env python3
"""Run a host/guest gVisor ETXTBSY experiment matrix for SafeYolo.

Run this on the host as the normal operator user. The controller uses sudo
only for read-only /proc descriptor inspection; SafeYolo itself never runs as
root. Results are appended to a directory under this repository's .git dir.
Probe files are created temporarily in the selected agent's actual workspace;
the guest helper is sent inline and is never staged there as another script.

If the selected agent is the one hosting the current coding session, the
session will disconnect while the controller cycles the sandbox. The host
controller continues independently and preserves all results for inspection
after the agent is started again.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import json
import mmap
import os
import re
import selectors
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

JSON_PREFIX = "SAFEYOLO_EXPERIMENT_JSON="
READY_PREFIX = "SAFEYOLO_EXPERIMENT_READY="
AGENT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EXPERIMENT_ENV_NAMES = (
    "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE",
    "SAFEYOLO_EXPERIMENT_RUNSC_DCACHE",
    "SAFEYOLO_EXPERIMENT_RUNSC_DIRECTFS",
)
VARIANTS = {
    "baseline": {
        "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE": "default",
    },
    "workspace-dcache-0": {
        "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE": "0",
    },
    "global-dcache-0": {
        "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE": "default",
        "SAFEYOLO_EXPERIMENT_RUNSC_DCACHE": "0",
    },
    "directfs-false": {
        "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE": "default",
        "SAFEYOLO_EXPERIMENT_RUNSC_DIRECTFS": "false",
    },
    "workspace-dcache-0-directfs-false": {
        "SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE": "0",
        "SAFEYOLO_EXPERIMENT_RUNSC_DIRECTFS": "false",
    },
}

# Linux inotify constants from include/uapi/linux/inotify.h.
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_NONBLOCK = os.O_NONBLOCK
IN_CLOEXEC = os.O_CLOEXEC
WATCH_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)
INOTIFY_EVENT = struct.Struct("iIII")


def emit_json(value: dict[str, Any]) -> None:
    print(JSON_PREFIX + json.dumps(value, sort_keys=True), flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stat_record(path: Path) -> dict[str, Any]:
    value = path.stat()
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
    }


class Inotify:
    def __init__(self, path: Path):
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add = libc.inotify_add_watch
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int

        self.fd = init(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        self.path = path
        self.wd = add(self.fd, os.fsencode(path), WATCH_MASK)
        if self.wd < 0:
            error = ctypes.get_errno()
            os.close(self.fd)
            raise OSError(error, os.strerror(error), path)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def wait(self, timeout: float, wanted_name: str | None = None) -> list[dict[str, Any]]:
        selector = selectors.DefaultSelector()
        selector.register(self.fd, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        events: list[dict[str, Any]] = []
        try:
            while time.monotonic() < deadline:
                remaining = max(0.0, deadline - time.monotonic())
                if not selector.select(remaining):
                    break
                try:
                    data = os.read(self.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                offset = 0
                while offset + INOTIFY_EVENT.size <= len(data):
                    wd, mask, cookie, length = INOTIFY_EVENT.unpack_from(data, offset)
                    offset += INOTIFY_EVENT.size
                    raw_name = data[offset : offset + length]
                    offset += length
                    name = raw_name.split(b"\0", 1)[0].decode(errors="replace")
                    event = {"wd": wd, "mask": mask, "cookie": cookie, "name": name}
                    events.append(event)
                    if wanted_name is None or name == wanted_name:
                        return events
        finally:
            selector.close()
        return events

    def __enter__(self) -> Inotify:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class Recorder:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        output_dir.mkdir(parents=True, exist_ok=False)
        self.events_path = output_dir / "events.jsonl"
        self.log_path = output_dir / "run.log"

    def log(self, message: str, **fields: Any) -> None:
        now = dt.datetime.now(dt.UTC).isoformat()
        rendered = f"[{now}] {message}"
        print(rendered, flush=True)
        with self.log_path.open("a", encoding="utf-8") as target:
            target.write(rendered + "\n")
            target.flush()
            os.fsync(target.fileno())
        event = {"time": now, "message": message, **fields}
        with self.events_path.open("a", encoding="utf-8") as target:
            target.write(json.dumps(event, sort_keys=True) + "\n")
            target.flush()
            os.fsync(target.fileno())

    def write_summary(self, summary: dict[str, Any]) -> None:
        destination = self.output_dir / "summary.json"
        temporary = destination.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, destination)


def proc_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return "?"


def process_parent(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("PPid:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0


def sentry_root(pid: int) -> int:
    """Walk a gvisor_sentry process tree to its top sentry process."""
    current = pid
    seen: set[int] = set()
    while current > 1 and current not in seen:
        seen.add(current)
        parent = process_parent(current)
        if parent <= 1 or proc_text(Path(f"/proc/{parent}/comm")) != "gvisor_sentry":
            return current
        current = parent
    return current


def process_metrics(pid: int) -> dict[str, Any]:
    status: dict[str, str] = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                status[key] = value.strip()
    except OSError:
        pass
    try:
        fd_count = sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        fd_count = None
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
    except OSError:
        command = "?"
    cpu: dict[str, Any] = {}
    try:
        raw_stat = Path(f"/proc/{pid}/stat").read_text()
        # comm is parenthesized and may itself contain spaces or parentheses.
        fields = raw_stat[raw_stat.rfind(")") + 2 :].split()
        ticks = os.sysconf("SC_CLK_TCK")
        cpu = {
            "user_ticks": int(fields[11]),
            "system_ticks": int(fields[12]),
            "user_seconds": int(fields[11]) / ticks,
            "system_seconds": int(fields[12]) / ticks,
        }
    except (OSError, ValueError, IndexError):
        pass
    io: dict[str, int] = {}
    try:
        for line in Path(f"/proc/{pid}/io").read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                io[key] = int(value.strip())
    except (OSError, ValueError):
        pass
    return {
        "pid": pid,
        "ppid": process_parent(pid),
        "fd_count": fd_count,
        "vm_rss": status.get("VmRSS"),
        "threads": status.get("Threads"),
        "voluntary_context_switches": status.get("voluntary_ctxt_switches"),
        "nonvoluntary_context_switches": status.get("nonvoluntary_ctxt_switches"),
        "cpu": cpu,
        "io": io,
        "command": command,
    }


def scan_fds(target: Path) -> dict[str, Any]:
    identity_stat = target.stat()
    identity = (identity_stat.st_dev, identity_stat.st_ino)
    holders: list[dict[str, Any]] = []
    denied = 0
    for fd_path in Path("/proc").glob("[0-9]*/fd/[0-9]*"):
        try:
            current = fd_path.stat()
            if (current.st_dev, current.st_ino) != identity:
                continue
            pid = int(fd_path.parts[2])
            fd = int(fd_path.name)
            flags_line = next(
                line for line in Path(f"/proc/{pid}/fdinfo/{fd}").read_text().splitlines() if line.startswith("flags:")
            )
            flags_text = flags_line.split()[1]
            flags = int(flags_text, 8)
            if flags & os.O_ACCMODE == os.O_RDONLY:
                continue
            try:
                executable = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                executable = "?"
            holders.append(
                {
                    "pid": pid,
                    "root_pid": sentry_root(pid),
                    "fd": fd,
                    "flags_octal": flags_text,
                    "access_mode": flags & os.O_ACCMODE,
                    "command": proc_text(Path(f"/proc/{pid}/comm")),
                    "executable": executable,
                }
            )
        except PermissionError:
            denied += 1
        except (OSError, StopIteration, ValueError):
            continue

    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for holder in holders:
        key = (
            holder["root_pid"],
            holder["fd"],
            holder["flags_octal"],
            holder["command"],
            holder["executable"],
        )
        group = groups.setdefault(
            key,
            {
                "root_pid": holder["root_pid"],
                "fd": holder["fd"],
                "flags_octal": holder["flags_octal"],
                "access_mode": holder["access_mode"],
                "command": holder["command"],
                "executable": holder["executable"],
                "pids": [],
            },
        )
        group["pids"].append(holder["pid"])

    roots = sorted({holder["root_pid"] for holder in holders})
    return {
        "target": str(target),
        "identity": {"device": identity[0], "inode": identity[1]},
        "writable_holder_tasks": len(holders),
        "groups": [
            {**group, "pids": sorted(group["pids"]), "task_count": len(group["pids"])} for group in groups.values()
        ],
        "runtime_roots": [process_metrics(pid) for pid in roots],
        "permission_denied": denied,
    }


def scan_fds_tree(target: Path) -> dict[str, Any]:
    identities: dict[tuple[int, int], str] = {}
    for path in target.rglob("*"):
        try:
            current = path.stat()
        except OSError:
            continue
        if stat.S_ISREG(current.st_mode):
            identities[(current.st_dev, current.st_ino)] = str(path)

    holders: list[dict[str, Any]] = []
    denied = 0
    for fd_path in Path("/proc").glob("[0-9]*/fd/[0-9]*"):
        try:
            current = fd_path.stat()
            matched = identities.get((current.st_dev, current.st_ino))
            if matched is None:
                continue
            pid = int(fd_path.parts[2])
            fd = int(fd_path.name)
            flags_line = next(
                line for line in Path(f"/proc/{pid}/fdinfo/{fd}").read_text().splitlines() if line.startswith("flags:")
            )
            flags_text = flags_line.split()[1]
            flags = int(flags_text, 8)
            if flags & os.O_ACCMODE == os.O_RDONLY:
                continue
            holders.append(
                {
                    "pid": pid,
                    "root_pid": sentry_root(pid),
                    "fd": fd,
                    "flags_octal": flags_text,
                    "path": matched,
                    "command": proc_text(Path(f"/proc/{pid}/comm")),
                }
            )
        except PermissionError:
            denied += 1
        except (OSError, StopIteration, ValueError):
            continue

    roots = sorted({holder["root_pid"] for holder in holders})
    return {
        "target": str(target),
        "regular_file_inodes": len(identities),
        "writable_holder_tasks": len(holders),
        "writable_holder_inodes": len({holder["path"] for holder in holders}),
        "holders": holders[:100],
        "holders_truncated": len(holders) > 100,
        "runtime_roots": [process_metrics(pid) for pid in roots],
        "permission_denied": denied,
    }


def runtime_metrics(agent: str) -> dict[str, Any]:
    if not AGENT_RE.fullmatch(agent):
        raise ValueError(f"invalid agent name: {agent!r}")
    needle = f"safeyolo-{agent}"
    roots: set[int] = set()
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(proc.name)
            command = proc_text(proc / "cmdline").replace("\x00", " ")
            executable = os.readlink(proc / "exe")
            comm = proc_text(proc / "comm")
        except (OSError, ValueError):
            continue
        if needle not in command:
            continue
        if comm == "gvisor_sentry" or executable.endswith("/gvisor_sentry"):
            roots.add(sentry_root(pid))
        elif executable.endswith("/runsc"):
            roots.add(pid)
    return {"agent": agent, "processes": [process_metrics(pid) for pid in sorted(roots)]}


def tree_manifest(root: Path) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    hardlink_members: dict[tuple[int, int], list[str]] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        current = path.lstat()
        record: dict[str, Any] = {
            "mode": stat.S_IMODE(current.st_mode),
            "uid": current.st_uid,
            "gid": current.st_gid,
            "mtime_ns": current.st_mtime_ns,
        }
        if stat.S_ISREG(current.st_mode):
            record.update(
                {
                    "type": "file",
                    "size": current.st_size,
                    "sha256": sha256_file(path),
                    "blocks": current.st_blocks,
                }
            )
            if current.st_nlink > 1:
                hardlink_members.setdefault((current.st_dev, current.st_ino), []).append(relative)
        elif stat.S_ISDIR(current.st_mode):
            record["type"] = "directory"
        elif stat.S_ISLNK(current.st_mode):
            record.update({"type": "symlink", "target": os.readlink(path)})
        else:
            record["type"] = "other"
        entries[relative] = record
    hardlinks = sorted(sorted(members) for members in hardlink_members.values())
    return {"entries": entries, "hardlinks": hardlinks}


def guest_write(target: Path, host_marker: Path, guest_marker: Path, method: str) -> None:
    before = stat_record(target) if target.exists() else None
    payload = f"#!/bin/sh\n# guest-{method}-{time.time_ns()}\nexit 0\n"
    if method == "in-place":
        with target.open("w", encoding="utf-8") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        target.chmod(0o755)
    elif method == "atomic":
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            temporary.chmod(0o755)
            os.replace(temporary, target)
            directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        raise ValueError(f"unknown write method: {method}")

    observed_host_marker = host_marker.read_text()
    guest_payload = f"guest-visible-{time.time_ns()}\n"
    with guest_marker.open("w", encoding="utf-8") as destination:
        destination.write(guest_payload)
        destination.flush()
        os.fsync(destination.fileno())

    mountinfo = ""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == "/workspace":
            mountinfo = line
            break
    emit_json(
        {
            "before": before,
            "after": stat_record(target),
            "sha256": sha256_file(target),
            "observed_host_marker": observed_host_marker,
            "guest_marker": guest_payload,
            "mountinfo": mountinfo,
            "method": method,
        }
    )


def guest_bench(directory: Path, files: int) -> None:
    if not directory.name.startswith(".safeyolo-etxtbsy-bench-"):
        raise ValueError(f"refusing benchmark outside scoped directory: {directory}")
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    payload = b"x" * 128

    start = time.perf_counter_ns()
    paths = []
    for index in range(files):
        path = directory / f"entry-{index:05d}"
        with path.open("wb") as destination:
            destination.write(payload)
        paths.append(path)
    create_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    total_size = 0
    for _ in range(3):
        for path in paths:
            total_size += path.stat().st_size
    stat_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    total_read = 0
    for path in paths:
        with path.open("rb") as source:
            total_read += len(source.read(1))
    open_read_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    misses = 0
    for index in range(files):
        try:
            (directory / f"missing-{index:05d}").stat()
        except FileNotFoundError:
            misses += 1
    negative_stat_ns = time.perf_counter_ns() - start

    emit_json(
        {
            "directory": str(directory),
            "files": files,
            "create_ns_per_file": create_ns / files,
            "stat_ns_per_call": stat_ns / (files * 3),
            "open_read_ns_per_file": open_read_ns / files,
            "negative_stat_ns_per_call": negative_stat_ns / files,
            "total_size": total_size,
            "total_read": total_read,
            "misses": misses,
        }
    )


def guest_cleanup(directory: Path) -> None:
    if not directory.name.startswith(".safeyolo-etxtbsy-bench-"):
        raise ValueError(f"refusing cleanup outside scoped directory: {directory}")
    if directory.exists():
        shutil.rmtree(directory)
    emit_json({"removed": str(directory), "exists": directory.exists()})


def require_deep_path(path: Path) -> None:
    if not any(part.startswith(".safeyolo-etxtbsy-deep-") for part in path.parts):
        raise ValueError(f"refusing deep operation outside scoped directory: {path}")


def deep_payload(round_index: int, method: str, index: int, cycle: int) -> str:
    token = f"deep-r{round_index}-{method}-{index}-c{cycle}"
    return f"#!/bin/sh\nprintf '%s\\n' '{token}'\n"


def guest_deep_prepare(
    directory: Path,
    handoffs: int,
    cycles: int,
    round_index: int,
) -> None:
    require_deep_path(directory)
    handoff_dir = directory / "handoffs"
    semantic_dir = directory / "semantics"
    semantic_dir.mkdir(parents=True, exist_ok=True)

    start = time.perf_counter_ns()
    for cycle in range(cycles):
        for method in ("in-place", "atomic"):
            for index in range(handoffs):
                target = handoff_dir / f"{method}-{index:05d}.sh"
                payload = deep_payload(round_index, method, index, cycle)
                if method == "in-place":
                    with target.open("w", encoding="utf-8") as destination:
                        destination.write(payload)
                        if cycle == cycles - 1:
                            destination.flush()
                            os.fsync(destination.fileno())
                    target.chmod(0o755)
                else:
                    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=handoff_dir)
                    temporary = Path(temporary_name)
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as destination:
                            destination.write(payload)
                            if cycle == cycles - 1:
                                destination.flush()
                                os.fsync(destination.fileno())
                        temporary.chmod(0o755)
                        os.replace(temporary, target)
                    finally:
                        temporary.unlink(missing_ok=True)
        if cycle == cycles - 1:
            directory_fd = os.open(handoff_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    handoff_elapsed_ns = time.perf_counter_ns() - start

    lock_blocked = False
    with (directory / "lock-target").open("r+", encoding="utf-8") as lock_target:
        try:
            fcntl.flock(lock_target.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_blocked = True
        else:
            fcntl.flock(lock_target.fileno(), fcntl.LOCK_UN)

    (semantic_dir / "plain.txt").write_text("created-by-guest\n")
    (semantic_dir / "append.txt").write_text("first\n")
    with (semantic_dir / "append.txt").open("a", encoding="utf-8") as destination:
        destination.write("second\n")
    (semantic_dir / "truncate.txt").write_text("discard-this-content\n")
    with (semantic_dir / "truncate.txt").open("w", encoding="utf-8") as destination:
        destination.write("short\n")
    (semantic_dir / "binary.bin").write_bytes(bytes(range(256)) * 16)
    (semantic_dir / "empty").touch()
    (semantic_dir / "executable.sh").write_text("#!/bin/sh\nexit 0\n")
    (semantic_dir / "executable.sh").chmod(0o751)
    nested = semantic_dir / "nested" / "deeper"
    nested.mkdir(parents=True)
    (nested / "spaces and ünicode.txt").write_text("Δguest\n")
    rename_source = semantic_dir / "rename-source"
    rename_source.write_text("renamed\n")
    rename_source.rename(semantic_dir / "renamed")
    deleted = semantic_dir / "deleted"
    deleted.write_text("gone\n")
    deleted.unlink()
    hard_a = semantic_dir / "hard-a"
    hard_a.write_text("hardlinked\n")
    os.link(hard_a, semantic_dir / "hard-b")
    os.symlink("plain.txt", semantic_dir / "relative-link")
    with (semantic_dir / "sparse.bin").open("wb") as sparse:
        sparse.seek(8 * 1024 * 1024)
        sparse.write(b"x")
    large_payload = hashlib.sha256(f"round-{round_index}".encode()).digest() * (256 * 1024)
    (semantic_dir / "large.bin").write_bytes(large_payload)

    mountinfo = ""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == "/workspace":
            mountinfo = line
            break
    emit_json(
        {
            "handoff_write_operations": handoffs * cycles * 2,
            "handoff_elapsed_ns": handoff_elapsed_ns,
            "lock_blocked": lock_blocked,
            "manifest": tree_manifest(semantic_dir),
            "mountinfo": mountinfo,
        }
    )


def guest_manifest(directory: Path) -> None:
    require_deep_path(directory)
    emit_json({"manifest": tree_manifest(directory)})


def guest_deep_bench(directory: Path, files: int, repetitions: int) -> None:
    if not directory.name.startswith(".safeyolo-etxtbsy-bench-"):
        raise ValueError(f"refusing benchmark outside scoped directory: {directory}")
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    payload = b"x" * 128
    paths: list[Path] = []

    start = time.perf_counter_ns()
    for index in range(files):
        path = directory / f"entry-{index:05d}"
        path.write_bytes(payload)
        paths.append(path)
    create_ns_per_file = (time.perf_counter_ns() - start) / files

    samples: list[dict[str, float]] = []
    rename_count = min(200, files)
    for repetition in range(repetitions):
        start = time.perf_counter_ns()
        total_size = sum(path.stat().st_size for path in paths)
        stat_ns_per_file = (time.perf_counter_ns() - start) / files

        start = time.perf_counter_ns()
        total_read = sum(len(path.read_bytes()[:1]) for path in paths)
        read_ns_per_file = (time.perf_counter_ns() - start) / files

        start = time.perf_counter_ns()
        misses = 0
        for index in range(files):
            try:
                (directory / f"missing-{repetition}-{index:05d}").stat()
            except FileNotFoundError:
                misses += 1
        negative_ns_per_file = (time.perf_counter_ns() - start) / files

        start = time.perf_counter_ns()
        entries = sum(1 for _ in os.scandir(directory))
        readdir_ns_per_file = (time.perf_counter_ns() - start) / files

        start = time.perf_counter_ns()
        for path in paths[:rename_count]:
            path.rename(path.with_suffix(".moved"))
        for path in paths[:rename_count]:
            path.with_suffix(".moved").rename(path)
        rename_ns_per_operation = (time.perf_counter_ns() - start) / (rename_count * 2)

        samples.append(
            {
                "repetition": repetition,
                "stat_ns_per_file": stat_ns_per_file,
                "read_ns_per_file": read_ns_per_file,
                "negative_ns_per_file": negative_ns_per_file,
                "readdir_ns_per_file": readdir_ns_per_file,
                "rename_ns_per_operation": rename_ns_per_operation,
                "total_size": total_size,
                "total_read": total_read,
                "misses": misses,
                "entries": entries,
            }
        )
    emit_json(
        {
            "directory": str(directory),
            "files": files,
            "repetitions": repetitions,
            "create_ns_per_file": create_ns_per_file,
            "samples": samples,
        }
    )


def guest_git_bench(directory: Path, files: int, repetitions: int) -> None:
    if not directory.name.startswith(".safeyolo-etxtbsy-bench-"):
        raise ValueError(f"refusing git benchmark outside scoped directory: {directory}")
    git = shutil.which("git")
    if not git:
        emit_json({"skipped": "git unavailable"})
        return
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)

    def invoke(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [git, *arguments],
            cwd=directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )

    for index in range(files):
        subdir = directory / f"group-{index % 20:02d}"
        subdir.mkdir(exist_ok=True)
        (subdir / f"file-{index:05d}.txt").write_text(f"initial-{index}\n")
    commands = [
        ("init", "-q"),
        ("config", "user.email", "etxtbsy@example.invalid"),
        ("config", "user.name", "ETXTBSY experiment"),
        ("add", "."),
        ("commit", "-qm", "initial"),
    ]
    setup = [invoke(*command) for command in commands]
    if any(result.returncode != 0 for result in setup):
        emit_json(
            {
                "error": "git setup failed",
                "outputs": [result.stdout.decode(errors="replace")[-1000:] for result in setup],
            }
        )
        return

    clean_samples = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        result = invoke("status", "--porcelain")
        clean_samples.append(time.perf_counter_ns() - start)
        if result.returncode != 0 or result.stdout:
            raise RuntimeError(f"unexpected clean git status: {result.stdout!r}")
    for index in range(min(100, files)):
        path = directory / f"group-{index % 20:02d}" / f"file-{index:05d}.txt"
        with path.open("a", encoding="utf-8") as destination:
            destination.write("dirty\n")
    dirty_samples = []
    dirty_entries = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        result = invoke("status", "--porcelain")
        dirty_samples.append(time.perf_counter_ns() - start)
        if result.returncode != 0:
            raise RuntimeError(f"git status failed: {result.stdout!r}")
        dirty_entries.append(len(result.stdout.splitlines()))
    emit_json(
        {
            "directory": str(directory),
            "files": files,
            "repetitions": repetitions,
            "clean_status_ns": clean_samples,
            "dirty_status_ns": dirty_samples,
            "dirty_entries": dirty_entries,
        }
    )


def guest_watch(path: Path, timeout: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with Inotify(path.parent) as watcher:
        print("SAFEYOLO_EXPERIMENT_READY", flush=True)
        events = watcher.wait(timeout, path.name)
    emit_json({"path": str(path), "events": events, "observed": bool(events)})


def write_executable_payload(target: Path, label: str, minimum_size: int = 0) -> str:
    """Rewrite target in place and return the exact expected stdout."""
    expected = f"edge-{label}\n"
    payload = f"#!/bin/sh\nprintf '%s\\n' 'edge-{label}'\n".encode()
    if len(payload) < minimum_size:
        payload += b"#" * (minimum_size - len(payload))
    with target.open("r+b", buffering=0) as destination:
        destination.seek(0)
        destination.write(payload)
        destination.truncate()
        os.fsync(destination.fileno())
    target.chmod(0o755)
    return expected


def wait_for_release(path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.002)
    raise TimeoutError(f"host did not create release marker {path} within {timeout}s")


def guest_edge_hold(
    target: Path,
    alias: Path,
    release: Path,
    scenario: str,
    timeout: float,
) -> None:
    """Create one precisely synchronized guest reference-lifetime scenario."""
    target.parent.mkdir(parents=True, exist_ok=True)
    release.unlink(missing_ok=True)
    expected = f"edge-{scenario}\n"
    watcher: Inotify | None = None
    held_fd: int | None = None
    held_mapping: mmap.mmap | None = None
    try:
        if scenario == "idle-closed":
            expected = write_executable_payload(target, scenario)
        elif scenario == "parent-watch":
            watcher = Inotify(target.parent)
            expected = write_executable_payload(target, scenario)
        elif scenario == "direct-watch":
            watcher = Inotify(target)
            expected = write_executable_payload(target, scenario)
        elif scenario == "open-writer":
            payload = f"#!/bin/sh\nprintf '%s\\n' 'edge-{scenario}'\n".encode()
            held_fd = os.open(target, os.O_RDWR | os.O_TRUNC)
            os.write(held_fd, payload)
            os.fsync(held_fd)
            os.chmod(target, 0o755)
        elif scenario == "writable-mmap":
            expected = write_executable_payload(target, scenario, minimum_size=4096)
            held_fd = os.open(target, os.O_RDWR)
            held_mapping = mmap.mmap(
                held_fd,
                0,
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
            # Keep only the writable mapping live, not the ordinary file description.
            os.close(held_fd)
            held_fd = None
        elif scenario == "live-hardlink-alias":
            alias.unlink(missing_ok=True)
            os.link(target, alias)
            held_fd = os.open(alias, os.O_RDONLY)
            expected = write_executable_payload(target, scenario)
        else:
            raise ValueError(f"unknown edge scenario: {scenario}")

        print(READY_PREFIX + scenario, flush=True)
        wait_for_release(release, timeout)
    finally:
        if held_mapping is not None:
            held_mapping.close()
        if held_fd is not None:
            os.close(held_fd)
        if watcher is not None:
            watcher.close()
    emit_json(
        {
            "scenario": scenario,
            "target": str(target),
            "alias": str(alias),
            "expected_stdout": expected,
            "released": True,
        }
    )


def parse_json_output(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        if line.startswith(JSON_PREFIX):
            return json.loads(line[len(JSON_PREFIX) :])
    raise RuntimeError(f"command did not emit {JSON_PREFIX}: {output[-1000:]}")


def load_agent_workspace(agent: str) -> Path:
    config_dir = Path(os.environ.get("SAFEYOLO_CONFIG_DIR", Path.home() / ".safeyolo"))
    policy_path = config_dir / "policy.toml"
    with policy_path.open("rb") as source:
        policy = tomllib.load(source)
    metadata = policy.get("agents", {}).get(agent)
    if not isinstance(metadata, dict) or not metadata.get("folder"):
        raise RuntimeError(f"agent {agent!r} has no folder in {policy_path}")
    return Path(metadata["folder"]).expanduser().resolve()


def find_repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / ".git").exists() and (candidate / "cli" / "src" / "safeyolo").is_dir():
            return candidate
    raise RuntimeError(f"could not locate SafeYolo repository above {Path(__file__).resolve()}")


def local_cli_env(repo_root: Path, overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for name in EXPERIMENT_ENV_NAMES:
        env.pop(name, None)
    source_path = str(repo_root / "cli" / "src")
    old_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_path if not old_pythonpath else f"{source_path}:{old_pythonpath}"
    if overrides:
        env.update(overrides)
    return env


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def direct_exec(path: Path) -> dict[str, Any]:
    start = time.perf_counter_ns()
    try:
        result = subprocess.run(
            [str(path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=3,
            check=False,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "errno": None,
            "stdout": result.stdout.decode(errors="replace"),
            "message": result.stderr.decode(errors="replace"),
            "elapsed_ns": time.perf_counter_ns() - start,
        }
    except OSError as error:
        return {
            "ok": False,
            "returncode": None,
            "errno": error.errno,
            "stdout": "",
            "message": str(error),
            "elapsed_ns": time.perf_counter_ns() - start,
        }


def poll_exec_release(path: Path, timeout: float) -> dict[str, Any]:
    start = time.monotonic_ns()
    attempts = 0
    last: dict[str, Any] = {}
    while (time.monotonic_ns() - start) / 1e9 <= timeout:
        attempts += 1
        last = direct_exec(path)
        if last["ok"]:
            return {
                "released": True,
                "latency_ms": (time.monotonic_ns() - start) / 1e6,
                "attempts": attempts,
                "last": last,
            }
        if last.get("errno") != errno.ETXTBSY:
            break
        time.sleep(0.025)
    return {
        "released": False,
        "latency_ms": (time.monotonic_ns() - start) / 1e6,
        "attempts": attempts,
        "last": last,
    }


def guest_command(*arguments: object) -> str:
    """Run this file's internal helper without copying it into the workspace."""
    encoded = base64.b64encode(Path(__file__).resolve().read_bytes()).decode("ascii")
    loader = f'import base64;exec(compile(base64.b64decode("{encoded}"),"<safeyolo-etxtbsy-helper>","exec"))'
    items = ["python3", "-c", loader, *map(str, arguments)]
    return shlex.join(items)


def scan_with_sudo(script: Path, target: Path, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"skipped": "--no-sudo"}
    result = run_command(
        ["sudo", "-n", sys.executable, str(script), "scan-fds", str(target)],
        timeout=30,
    )
    if result.returncode != 0:
        return {"error": result.stdout, "returncode": result.returncode}
    return parse_json_output(result.stdout)


def privileged_helper(
    script: Path,
    mode: str,
    arguments: list[str],
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        return {"skipped": "--no-sudo"}
    result = run_command(
        ["sudo", "-n", sys.executable, str(script), mode, *arguments],
        timeout=120,
    )
    if result.returncode != 0:
        return {"error": result.stdout, "returncode": result.returncode}
    return parse_json_output(result.stdout)


def run_guest(
    cli: str,
    agent: str,
    command: str,
    env: dict[str, str],
    *,
    timeout: float = 180,
) -> dict[str, Any]:
    result = run_command(
        [cli, "agent", "shell", agent, "--command", command],
        env=env,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"guest command failed ({result.returncode}):\n{result.stdout}")
    return parse_json_output(result.stdout)


def guest_notification_probe(
    cli: str,
    agent: str,
    guest_path: Path,
    host_path: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    command = guest_command("guest-watch", guest_path, "5")
    process = subprocess.Popen(
        [cli, "agent", "shell", agent, "--command", command],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output_lines: list[str] = []
    ready = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline and not ready:
            if not selector.select(max(0.0, deadline - time.monotonic())):
                break
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line)
            ready = "SAFEYOLO_EXPERIMENT_READY" in line
        if not ready:
            process.kill()
            remainder, _ = process.communicate(timeout=5)
            return {"ready": False, "output": "".join(output_lines) + remainder}

        with host_path.open("w", encoding="utf-8") as destination:
            destination.write(f"host-notify-{time.time_ns()}\n")
            destination.flush()
            os.fsync(destination.fileno())
        remainder, _ = process.communicate(timeout=10)
        output = "".join(output_lines) + remainder
        return {"ready": True, "returncode": process.returncode, **parse_json_output(output)}
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def generated_workspace_mount(agent: str) -> dict[str, Any] | None:
    config_dir = Path(os.environ.get("SAFEYOLO_CONFIG_DIR", Path.home() / ".safeyolo"))
    config_path = config_dir / "agents" / agent / "config.json"
    try:
        spec = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return next(
        (mount for mount in spec.get("mounts", []) if mount.get("destination") == "/workspace"),
        None,
    )


def run_variant(
    *,
    name: str,
    overrides: dict[str, str],
    agent: str,
    cli: str,
    repo_root: Path,
    workspace: Path,
    artifact_root: Path,
    recorder: Recorder,
    sudo_enabled: bool,
    release_timeout: float,
    churn_files: int,
) -> dict[str, Any]:
    variant_dir = artifact_root / name
    variant_dir.mkdir()
    relative_variant = variant_dir.relative_to(workspace)
    guest_variant = Path("/workspace") / relative_variant
    script_host = Path(__file__).resolve()
    env = local_cli_env(repo_root, overrides)
    result: dict[str, Any] = {"name": name, "overrides": overrides}

    recorder.log(f"{name}: stopping stale/running sandbox")
    run_command([cli, "agent", "stop", agent], env=env, timeout=120)

    started = False
    try:
        recorder.log(f"{name}: booting detached", overrides=overrides)
        boot_start = time.perf_counter_ns()
        boot = run_command(
            [cli, "agent", "run", agent, "--detach"],
            env=env,
            timeout=240,
        )
        result["boot"] = {
            "returncode": boot.returncode,
            "elapsed_ms": (time.perf_counter_ns() - boot_start) / 1e6,
            "output": boot.stdout[-4000:],
        }
        if boot.returncode != 0:
            recorder.log(f"{name}: boot failed", output=boot.stdout[-2000:])
            return result
        started = True
        result["workspace_mount"] = generated_workspace_mount(agent)

        host_marker = variant_dir / "host-marker.txt"
        guest_marker = variant_dir / "guest-marker.txt"
        notify_path = variant_dir / "host-notify.txt"
        host_marker.write_text(f"host-visible-{time.time_ns()}\n")
        notify_path.write_text("initial\n")

        for method in ("in-place", "atomic"):
            target = variant_dir / f"probe-{method}.sh"
            target.write_text("#!/bin/sh\nexit 0\n")
            target.chmod(0o755)
            before = stat_record(target)
            before_scan = scan_with_sudo(script_host, target, sudo_enabled)
            guest_target = guest_variant / target.name
            guest_host_marker = guest_variant / host_marker.name
            guest_guest_marker = guest_variant / guest_marker.name

            with Inotify(variant_dir) as host_watcher:
                guest_result = run_guest(
                    cli,
                    agent,
                    guest_command(
                        "guest-write",
                        guest_target,
                        guest_host_marker,
                        guest_guest_marker,
                        method,
                    ),
                    env,
                )
                host_events = host_watcher.wait(2, target.name)

            immediate_exec = direct_exec(target)
            immediate_scan = scan_with_sudo(script_host, target, sudo_enabled)
            release = poll_exec_release(target, release_timeout)
            bash_result = run_command(["bash", str(target)], timeout=10)
            method_result = {
                "host_before": before,
                "guest": guest_result,
                "host_after": stat_record(target),
                "host_sha256": sha256_file(target),
                "guest_marker_content": guest_marker.read_text(),
                "host_inotify": {"observed": bool(host_events), "events": host_events},
                "exec_immediate": immediate_exec,
                "exec_release_poll": release,
                "bash_interpreter": {
                    "returncode": bash_result.returncode,
                    "output": bash_result.stdout,
                },
                "writers_before": before_scan,
                "writers_immediate": immediate_scan,
            }
            result[method] = method_result
            recorder.log(
                f"{name}/{method}: exec errno={immediate_exec.get('errno')} "
                f"writers={immediate_scan.get('writable_holder_tasks', 'unknown')}",
                result=method_result,
            )

        result["guest_inotify_from_host"] = guest_notification_probe(
            cli,
            agent,
            guest_variant / notify_path.name,
            notify_path,
            env,
        )

        workspace_bench_guest = guest_variant / f".safeyolo-etxtbsy-bench-{name}"
        home_bench_guest = Path("/home/agent") / f".safeyolo-etxtbsy-bench-{name}"
        result["workspace_benchmark"] = run_guest(
            cli,
            agent,
            guest_command("guest-bench", workspace_bench_guest, churn_files),
            env,
            timeout=300,
        )
        result["home_benchmark"] = run_guest(
            cli,
            agent,
            guest_command("guest-bench", home_bench_guest, max(200, churn_files // 4)),
            env,
            timeout=300,
        )

        in_place_target = variant_dir / "probe-in-place.sh"
        result["after_churn"] = {
            "exec": direct_exec(in_place_target),
            "writers": scan_with_sudo(script_host, in_place_target, sudo_enabled),
        }
        recorder.log(
            f"{name}: churn complete; exec errno={result['after_churn']['exec'].get('errno')}",
            result=result["after_churn"],
        )

        # Cleanup is performed by the same bounded helper that created the
        # benchmark directories. Measure first, clean second.
        result["cleanup"] = {
            "workspace": run_guest(
                cli,
                agent,
                guest_command("guest-cleanup", workspace_bench_guest),
                env,
            ),
            "home": run_guest(
                cli,
                agent,
                guest_command("guest-cleanup", home_bench_guest),
                env,
            ),
        }
        return result
    finally:
        if started:
            recorder.log(f"{name}: stopping sandbox")
            stop = run_command([cli, "agent", "stop", agent], env=env, timeout=180)
            result["stop"] = {"returncode": stop.returncode, "output": stop.stdout[-2000:]}
            for method in ("in-place", "atomic"):
                target = variant_dir / f"probe-{method}.sh"
                if target.exists():
                    result[f"{method}_after_stop"] = {
                        "exec": direct_exec(target),
                        "writers": scan_with_sudo(script_host, target, sudo_enabled),
                    }
            recorder.log(f"{name}: stopped", stop=result.get("stop"))


def compare_manifests(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    expected_entries = expected.get("entries", {})
    observed_entries = observed.get("entries", {})
    missing = sorted(set(expected_entries) - set(observed_entries))
    unexpected = sorted(set(observed_entries) - set(expected_entries))
    changed: dict[str, Any] = {}
    allocation_differences: dict[str, Any] = {}
    for path in sorted(set(expected_entries) & set(observed_entries)):
        expected_record = expected_entries[path]
        observed_record = observed_entries[path]
        expected_core = {key: value for key, value in expected_record.items() if key != "blocks"}
        observed_core = {key: value for key, value in observed_record.items() if key != "blocks"}
        if expected_core != observed_core:
            changed[path] = {"expected": expected_core, "observed": observed_core}
        if expected_record.get("blocks") != observed_record.get("blocks"):
            allocation_differences[path] = {
                "expected": expected_record.get("blocks"),
                "observed": observed_record.get("blocks"),
            }
    hardlinks_match = expected.get("hardlinks") == observed.get("hardlinks")
    return {
        "ok": not missing and not unexpected and not changed and hardlinks_match,
        "missing": missing,
        "unexpected": unexpected,
        "changed": changed,
        "allocation_differences": allocation_differences,
        "hardlinks_match": hardlinks_match,
    }


def mutate_semantics_from_host(directory: Path, round_index: int) -> None:
    with (directory / "plain.txt").open("a", encoding="utf-8") as destination:
        destination.write(f"host-append-{round_index}\n")
        destination.flush()
        os.fsync(destination.fileno())
    binary = directory / "binary.bin"
    temporary = binary.with_suffix(".host-tmp")
    temporary.write_bytes(hashlib.sha256(f"host-{round_index}".encode()).digest() * 256)
    temporary.chmod(binary.stat().st_mode & 0o777)
    os.replace(temporary, binary)
    executable = directory / "executable.sh"
    executable.chmod(0o705)
    (directory / "empty").unlink()
    (directory / "host-created.txt").write_text(f"host-created-{round_index}\n")
    renamed = directory / "renamed"
    renamed.rename(directory / "renamed-by-host")
    relative_link = directory / "relative-link"
    relative_link.unlink()
    os.symlink("host-created.txt", relative_link)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def percentile(values: list[int], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index] / 1e6


def execute_handoff_batch(
    directory: Path,
    handoffs: int,
    cycles: int,
    round_index: int,
) -> dict[str, Any]:
    by_method: dict[str, Any] = {}
    for method in ("in-place", "atomic"):
        successes = 0
        errno_counts: dict[str, int] = {}
        bad_output: list[dict[str, Any]] = []
        elapsed: list[int] = []
        for index in range(handoffs):
            target = directory / f"{method}-{index:05d}.sh"
            result = direct_exec(target)
            elapsed.append(result["elapsed_ns"])
            expected = f"deep-r{round_index}-{method}-{index}-c{cycles - 1}\n"
            if result["ok"] and result["stdout"] == expected:
                successes += 1
            else:
                errno_key = str(result.get("errno"))
                errno_counts[errno_key] = errno_counts.get(errno_key, 0) + 1
                if len(bad_output) < 20:
                    bad_output.append(
                        {
                            "path": str(target),
                            "expected": expected,
                            "result": result,
                        }
                    )
        by_method[method] = {
            "attempts": handoffs,
            "successes": successes,
            "failures": handoffs - successes,
            "errno_counts": errno_counts,
            "bad_output": bad_output,
            "latency_ms": {
                "p50": percentile(elapsed, 0.50),
                "p95": percentile(elapsed, 0.95),
                "max": max(elapsed) / 1e6 if elapsed else None,
            },
        }
    return by_method


def precreate_deep_round(directory: Path, handoffs: int) -> dict[str, Any]:
    handoff_dir = directory / "handoffs"
    handoff_dir.mkdir(parents=True)
    initial = "#!/bin/sh\nprintf '%s\\n' 'host-initial'\n".ljust(128, "#")
    before: dict[str, dict[str, Any]] = {}
    for method in ("in-place", "atomic"):
        for index in range(handoffs):
            target = handoff_dir / f"{method}-{index:05d}.sh"
            target.write_text(initial)
            target.chmod(0o755)
        before[method] = stat_record(handoff_dir / f"{method}-00000.sh")
    (directory / "lock-target").write_text("lock\n")
    return {"initial_payload": initial, "before": before}


def run_deep_round(
    *,
    round_index: int,
    artifact_root: Path,
    workspace: Path,
    cli: str,
    agent: str,
    env: dict[str, str],
    script_host: Path,
    handoffs: int,
    cycles: int,
    sudo_enabled: bool,
) -> dict[str, Any]:
    round_dir = artifact_root / f"round-{round_index:02d}"
    round_dir.mkdir()
    precreated = precreate_deep_round(round_dir, handoffs)
    handoff_dir = round_dir / "handoffs"
    guest_round = Path("/workspace") / round_dir.relative_to(workspace)

    in_place_path = handoff_dir / "in-place-00000.sh"
    atomic_path = handoff_dir / "atomic-00000.sh"
    in_place_handle = in_place_path.open("rb")
    atomic_handle = atomic_path.open("rb")
    atomic_mapping = mmap.mmap(atomic_handle.fileno(), 0, access=mmap.ACCESS_READ)
    lock_handle = (round_dir / "lock-target").open("r+", encoding="utf-8")
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    try:
        guest = run_guest(
            cli,
            agent,
            guest_command(
                "guest-deep-prepare",
                guest_round,
                handoffs,
                cycles,
                round_index,
            ),
            env,
            timeout=600,
        )
        in_place_handle.seek(0)
        in_place_old_handle = in_place_handle.read().decode(errors="replace")
        atomic_handle.seek(0)
        atomic_old_handle = atomic_handle.read().decode(errors="replace")
        atomic_old_mapping = atomic_mapping[:].decode(errors="replace")
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()
        atomic_mapping.close()
        atomic_handle.close()
        in_place_handle.close()

    after = {
        "in-place": stat_record(in_place_path),
        "atomic": stat_record(atomic_path),
    }
    handle_semantics = {
        "in_place_same_inode": (precreated["before"]["in-place"]["inode"] == after["in-place"]["inode"]),
        "atomic_new_inode": precreated["before"]["atomic"]["inode"] != after["atomic"]["inode"],
        "in_place_old_handle_saw_new_payload": in_place_old_handle.startswith(
            f"#!/bin/sh\nprintf '%s\\n' 'deep-r{round_index}-in-place-0-c{cycles - 1}'"
        ),
        "atomic_old_handle_retained_original": atomic_old_handle == precreated["initial_payload"],
        "atomic_old_mapping_retained_original": atomic_old_mapping == precreated["initial_payload"],
    }
    guest_to_host_manifest = compare_manifests(guest["manifest"], tree_manifest(round_dir / "semantics"))
    executions = execute_handoff_batch(handoff_dir, handoffs, cycles, round_index)
    holders = privileged_helper(
        script_host,
        "scan-fds-tree",
        [str(handoff_dir)],
        sudo_enabled,
    )

    mutate_semantics_from_host(round_dir / "semantics", round_index)
    host_manifest = tree_manifest(round_dir / "semantics")
    guest_after_host = run_guest(
        cli,
        agent,
        guest_command("guest-manifest", guest_round / "semantics"),
        env,
        timeout=180,
    )
    host_to_guest_manifest = compare_manifests(host_manifest, guest_after_host["manifest"])
    return {
        "round": round_index,
        "guest": guest,
        "handle_semantics": handle_semantics,
        "guest_lock_blocked_by_host": guest.get("lock_blocked"),
        "guest_to_host_manifest": guest_to_host_manifest,
        "host_to_guest_manifest": host_to_guest_manifest,
        "executions": executions,
        "writable_holders": holders,
        "runtime": privileged_helper(
            script_host,
            "runtime-metrics",
            [agent],
            sudo_enabled,
        ),
    }


EDGE_SCENARIOS = (
    "idle-closed",
    "parent-watch",
    "direct-watch",
    "open-writer",
    "writable-mmap",
    "live-hardlink-alias",
)


def parallel_direct_exec(path: Path, attempts: int) -> dict[str, Any]:
    """Launch host execve attempts together and retain every result."""
    if attempts < 1:
        raise ValueError("parallel attempt count must be positive")
    with concurrent.futures.ThreadPoolExecutor(max_workers=attempts) as executor:
        futures = [executor.submit(direct_exec, path) for _ in range(attempts)]
        results = [future.result() for future in futures]
    return {
        "attempts": attempts,
        "successes": sum(result["ok"] for result in results),
        "etxtbsy": sum(result.get("errno") == errno.ETXTBSY for result in results),
        "other_failures": sum(not result["ok"] and result.get("errno") != errno.ETXTBSY for result in results),
        "results": results,
    }


def exec_matches(result: dict[str, Any], expected_stdout: str) -> bool:
    return result["ok"] and result["stdout"] == expected_stdout


def run_edge_scenario(
    *,
    scenario: str,
    directory: Path,
    guest_directory: Path,
    cli: str,
    agent: str,
    env: dict[str, str],
    script_host: Path,
    sudo_enabled: bool,
    hold_timeout: float,
    parallel_attempts: int,
) -> dict[str, Any]:
    target = directory / f"{scenario}.sh"
    alias = directory / f"{scenario}.alias"
    release = directory / f"{scenario}.release"
    target.write_text("#!/bin/sh\nprintf '%s\\n' 'edge-host-initial'\n".ljust(4096, "#"))
    target.chmod(0o755)
    guest_target = guest_directory / target.name
    guest_alias = guest_directory / alias.name
    guest_release = guest_directory / release.name
    command = guest_command(
        "guest-edge-hold",
        guest_target,
        guest_alias,
        guest_release,
        scenario,
        hold_timeout,
    )
    process = subprocess.Popen(
        [cli, "agent", "shell", agent, "--command", command],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output_lines: list[str] = []
    ready = False
    ready_seen_ns: int | None = None
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline and not ready:
            if not selector.select(max(0.0, deadline - time.monotonic())):
                break
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line)
            if READY_PREFIX + scenario in line:
                ready = True
                ready_seen_ns = time.monotonic_ns()
        if not ready:
            process.kill()
            remainder, _ = process.communicate(timeout=5)
            raise RuntimeError(
                f"guest edge scenario {scenario} did not become ready:\n"
                + "".join(output_lines)
                + remainder
            )

        # Execute before the deliberately expensive /proc scan. This is the
        # closest host-side handoff measurable through `agent shell` stdout.
        held_exec = direct_exec(target)
        ready_to_first_exec_ms = (time.monotonic_ns() - ready_seen_ns) / 1e6
        expected_stdout = f"edge-{scenario}\n"
        parallel = None
        if scenario == "idle-closed":
            parallel = parallel_direct_exec(target, parallel_attempts)
        held_scan = scan_with_sudo(script_host, target, sudo_enabled)
        held_checks_complete_ms = (time.monotonic_ns() - ready_seen_ns) / 1e6

        release.write_text("release\n")
        with release.open("rb") as marker:
            os.fsync(marker.fileno())
        remainder, _ = process.communicate(timeout=hold_timeout + 10)
        output = "".join(output_lines) + remainder
        guest_result = parse_json_output(output)
        post_release_scan = scan_with_sudo(script_host, target, sudo_enabled)
        post_release_exec = poll_exec_release(target, 2.0)
        return {
            "scenario": scenario,
            "ready": True,
            "ready_to_first_exec_ms": ready_to_first_exec_ms,
            "ready_to_held_checks_complete_ms": held_checks_complete_ms,
            "target_stat": stat_record(target),
            "guest": guest_result,
            "held_writable_descriptors": held_scan,
            "exec_while_held": held_exec,
            "exec_while_held_matches_payload": exec_matches(held_exec, expected_stdout),
            "parallel_exec_while_guest_alive": parallel,
            "post_release_writable_descriptors": post_release_scan,
            "exec_after_release": post_release_exec,
            "guest_process_returncode": process.returncode,
            "guest_process_output": output[-4000:],
        }
    finally:
        selector.close()
        if process.poll() is None:
            release.write_text("release after controller cleanup\n")
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def edge_controller(args: argparse.Namespace) -> int:
    if not AGENT_RE.fullmatch(args.agent):
        raise RuntimeError(f"invalid SafeYolo agent name: {args.agent!r}")
    if args.parallel_attempts < 1 or args.hold_timeout <= 0:
        raise RuntimeError("edge experiment counts and timeouts must be positive")
    repo_root = find_repo_root()
    workspace = load_agent_workspace(args.agent)
    if not workspace.is_dir():
        raise RuntimeError(f"agent workspace does not exist or is not a directory: {workspace}")
    cli = shutil.which("safeyolo")
    if not cli:
        raise RuntimeError("safeyolo is not on PATH")
    if not args.no_sudo:
        sudo = subprocess.run(["sudo", "-v"], check=False)
        if sudo.returncode != 0:
            raise RuntimeError("sudo authentication failed; use --no-sudo to omit FD attribution")

    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = (
        repo_root
        / "tests"
        / "rootless-experiments"
        / "etxtbsy-dcache"
        / "results"
        / f"edge-{timestamp}"
    )
    artifact_root = workspace / f".safeyolo-etxtbsy-edge-{timestamp}"
    artifact_root.mkdir(mode=0o700)
    recorder = Recorder(output_dir)
    script_host = Path(__file__).resolve()
    overrides = VARIANTS[args.variant]
    env = local_cli_env(repo_root, overrides)
    summary: dict[str, Any] = {
        "schema": 1,
        "mode": "edge",
        "agent": args.agent,
        "workspace": str(workspace),
        "artifact_root": str(artifact_root),
        "output_dir": str(output_dir),
        "settings": {
            "variant": args.variant,
            "overrides": overrides,
            "scenarios": list(EDGE_SCENARIOS),
            "parallel_attempts": args.parallel_attempts,
            "hold_timeout": args.hold_timeout,
        },
        "scenarios": {},
        "started_at": dt.datetime.now(dt.UTC).isoformat(),
        "instrumentation_note": (
            "CPU ticks, process I/O counters, FD counts, and exact target holders are sampled. "
            "Syscall tracing is intentionally excluded because ptrace/strace can pause the sentry "
            "and perturb the close-to-exec race being measured."
        ),
    }
    recorder.log("edge experiment started", settings=summary["settings"], output_dir=str(output_dir))
    started = False
    exit_code = 1
    try:
        recorder.log("stopping stale/running sandbox")
        run_command([cli, "agent", "stop", args.agent], env=env, timeout=180)
        recorder.log(f"booting edge variant {args.variant}")
        boot = run_command([cli, "agent", "run", args.agent, "--detach"], env=env, timeout=240)
        summary["boot"] = {"returncode": boot.returncode, "output": boot.stdout[-4000:]}
        if boot.returncode != 0:
            raise RuntimeError(f"edge experiment boot failed:\n{boot.stdout[-2000:]}")
        started = True
        summary["workspace_mount"] = generated_workspace_mount(args.agent)
        summary["runtime_before"] = privileged_helper(
            script_host, "runtime-metrics", [args.agent], not args.no_sudo
        )
        scenario_directory = artifact_root / "scenarios"
        scenario_directory.mkdir()
        guest_directory = Path("/workspace") / scenario_directory.relative_to(workspace)
        recorder.write_summary(summary)

        for scenario in EDGE_SCENARIOS:
            recorder.log(f"edge scenario {scenario} starting")
            result = run_edge_scenario(
                scenario=scenario,
                directory=scenario_directory,
                guest_directory=guest_directory,
                cli=cli,
                agent=args.agent,
                env=env,
                script_host=script_host,
                sudo_enabled=not args.no_sudo,
                hold_timeout=args.hold_timeout,
                parallel_attempts=args.parallel_attempts,
            )
            result["runtime_after"] = privileged_helper(
                script_host, "runtime-metrics", [args.agent], not args.no_sudo
            )
            summary["scenarios"][scenario] = result
            recorder.log(
                f"edge scenario {scenario} complete",
                held_exec_ok=result["exec_while_held"]["ok"],
                held_exec_errno=result["exec_while_held"].get("errno"),
                post_release_ok=result["exec_after_release"]["released"],
            )
            recorder.write_summary(summary)

        mount_has_zero = "dcache=0" in (summary.get("workspace_mount") or {}).get("options", [])
        idle = summary["scenarios"]["idle-closed"]
        idle_parallel = idle["parallel_exec_while_guest_alive"]
        open_writer = summary["scenarios"]["open-writer"]
        post_release_ok = all(
            result["exec_after_release"]["released"]
            and exec_matches(
                result["exec_after_release"]["last"],
                f"edge-{scenario}\n",
            )
            for scenario, result in summary["scenarios"].items()
        )
        normative = {
            "workspace_mount_matches_variant": (
                mount_has_zero if args.variant == "workspace-dcache-0" else not mount_has_zero
            ),
            "idle_closed_executes_while_guest_alive": idle[
                "exec_while_held_matches_payload"
            ],
            "idle_closed_parallel_executes": (
                idle_parallel["successes"] == args.parallel_attempts
                and all(
                    exec_matches(result, "edge-idle-closed\n")
                    for result in idle_parallel["results"]
                )
            ),
            "active_writer_returns_etxtbsy": open_writer["exec_while_held"].get("errno") == errno.ETXTBSY,
            "all_targets_execute_after_release": post_release_ok,
            "all_guest_sessions_clean": all(
                result["guest_process_returncode"] == 0 for result in summary["scenarios"].values()
            ),
        }
        summary["verdict"] = {
            "normative_checks": normative,
            "passed": all(normative.values()),
            "characterization": {
                scenario: {
                    "exec_while_held_ok": result["exec_while_held"]["ok"],
                    "exec_while_held_errno": result["exec_while_held"].get("errno"),
                    "writable_holder_tasks": result["held_writable_descriptors"].get(
                        "writable_holder_tasks"
                    ),
                }
                for scenario, result in summary["scenarios"].items()
            },
        }
        summary["runtime_after"] = privileged_helper(
            script_host, "runtime-metrics", [args.agent], not args.no_sudo
        )
        exit_code = 0 if summary["verdict"]["passed"] else 1
        recorder.write_summary(summary)
        recorder.log("edge experiment complete", verdict=summary["verdict"])
    except Exception as error:
        summary["error"] = repr(error)
        recorder.log("edge experiment failed", error=repr(error))
        exit_code = 1
    finally:
        if started:
            recorder.log("stopping sandbox")
        stop = run_command([cli, "agent", "stop", args.agent], env=env, timeout=180)
        summary["stop"] = {"returncode": stop.returncode, "output": stop.stdout[-2000:]}
        summary["finished_at"] = dt.datetime.now(dt.UTC).isoformat()
        summary["agent_left_stopped"] = True
        if artifact_root.is_dir() and not artifact_root.is_symlink():
            shutil.rmtree(artifact_root)
            summary["artifact_root_removed"] = True
        else:
            summary["artifact_root_removed"] = False
        recorder.write_summary(summary)
        recorder.log("edge experiment finished; agent left stopped", exit_code=exit_code)

    print(f"\nResults: {output_dir / 'summary.json'}")
    print(f"Live log: {output_dir / 'run.log'}")
    print(f"Restart: safeyolo agent run {args.agent}")
    return exit_code


def controller(args: argparse.Namespace) -> int:
    if not AGENT_RE.fullmatch(args.agent):
        raise RuntimeError(f"invalid SafeYolo agent name: {args.agent!r}")
    repo_root = find_repo_root()
    workspace = load_agent_workspace(args.agent)
    if not workspace.is_dir():
        raise RuntimeError(f"agent workspace does not exist or is not a directory: {workspace}")

    cli = shutil.which("safeyolo")
    if not cli:
        raise RuntimeError("safeyolo is not on PATH")
    selected = args.variants or list(VARIANTS)
    unknown = sorted(set(selected) - set(VARIANTS))
    if unknown:
        raise RuntimeError(f"unknown variants: {', '.join(unknown)}")

    if not args.no_sudo:
        sudo = subprocess.run(["sudo", "-v"], check=False)
        if sudo.returncode != 0:
            raise RuntimeError("sudo authentication failed; use --no-sudo to omit FD attribution")

    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    base = repo_root / ".git" / "etxtbsy-experiment"
    output_dir = base / timestamp
    artifact_root = workspace / f".safeyolo-etxtbsy-experiment-{timestamp}"
    artifact_root.mkdir(mode=0o700)
    recorder = Recorder(output_dir)
    summary: dict[str, Any] = {
        "schema": 1,
        "agent": args.agent,
        "workspace": str(workspace),
        "repo_root": str(repo_root),
        "artifact_root": str(artifact_root),
        "output_dir": str(output_dir),
        "variants": {},
        "started_at": dt.datetime.now(dt.UTC).isoformat(),
        "notes": [
            "Normal SafeYolo settings are unchanged; overrides exist only in each start command environment.",
            "The selected agent is left stopped so an interactive session is never silently started.",
        ],
    }
    recorder.log(
        "experiment started",
        agent=args.agent,
        variants=selected,
        output_dir=str(output_dir),
    )
    exit_code = 0
    try:
        for name in selected:
            try:
                result = run_variant(
                    name=name,
                    overrides=VARIANTS[name],
                    agent=args.agent,
                    cli=cli,
                    repo_root=repo_root,
                    workspace=workspace,
                    artifact_root=artifact_root,
                    recorder=recorder,
                    sudo_enabled=not args.no_sudo,
                    release_timeout=args.release_timeout,
                    churn_files=args.churn_files,
                )
            except Exception as error:  # Continue matrix after one failed cell.
                result = {"name": name, "error": repr(error)}
                recorder.log(f"{name}: failed", error=repr(error))
                exit_code = 1
            summary["variants"][name] = result
            recorder.write_summary(summary)
    finally:
        baseline_env = local_cli_env(repo_root)
        run_command([cli, "agent", "stop", args.agent], env=baseline_env, timeout=180)
        summary["finished_at"] = dt.datetime.now(dt.UTC).isoformat()
        summary["agent_left_stopped"] = True
        if artifact_root.is_dir() and not artifact_root.is_symlink():
            shutil.rmtree(artifact_root)
            summary["artifact_root_removed"] = True
        else:
            summary["artifact_root_removed"] = False
        recorder.write_summary(summary)
        recorder.log("experiment finished; agent left stopped", exit_code=exit_code)

    print(f"\nResults: {output_dir / 'summary.json'}")
    print(f"Restart: safeyolo agent run {args.agent}")
    return exit_code


def deep_controller(args: argparse.Namespace) -> int:
    if not AGENT_RE.fullmatch(args.agent):
        raise RuntimeError(f"invalid SafeYolo agent name: {args.agent!r}")
    if min(args.rounds, args.handoffs, args.cycles, args.benchmark_files, args.repetitions) < 1:
        raise RuntimeError("deep experiment counts must all be positive")
    repo_root = find_repo_root()
    workspace = load_agent_workspace(args.agent)
    if not workspace.is_dir():
        raise RuntimeError(f"agent workspace does not exist or is not a directory: {workspace}")
    cli = shutil.which("safeyolo")
    if not cli:
        raise RuntimeError("safeyolo is not on PATH")
    if not args.no_sudo:
        sudo = subprocess.run(["sudo", "-v"], check=False)
        if sudo.returncode != 0:
            raise RuntimeError("sudo authentication failed; use --no-sudo to omit runtime attribution")

    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = repo_root / ".git" / "etxtbsy-deep" / timestamp
    artifact_root = workspace / f".safeyolo-etxtbsy-deep-{timestamp}"
    artifact_root.mkdir(mode=0o700)
    recorder = Recorder(output_dir)
    script_host = Path(__file__).resolve()
    selected_overrides = VARIANTS[args.variant]
    env = local_cli_env(repo_root, selected_overrides)
    summary: dict[str, Any] = {
        "schema": 1,
        "mode": "deep",
        "agent": args.agent,
        "workspace": str(workspace),
        "artifact_root": str(artifact_root),
        "output_dir": str(output_dir),
        "settings": {
            "rounds": args.rounds,
            "handoffs_per_method_per_round": args.handoffs,
            "write_cycles_per_handoff": args.cycles,
            "total_guest_write_closes": args.rounds * args.handoffs * args.cycles * 2,
            "total_host_executions": args.rounds * args.handoffs * 2,
            "benchmark_files": args.benchmark_files,
            "benchmark_repetitions": args.repetitions,
            "variant": args.variant,
            "skip_workloads": args.skip_workloads,
            "overrides": selected_overrides,
        },
        "rounds": [],
        "started_at": dt.datetime.now(dt.UTC).isoformat(),
    }
    recorder.log(
        "deep experiment started",
        agent=args.agent,
        settings=summary["settings"],
        output_dir=str(output_dir),
    )
    started = False
    exit_code = 1
    try:
        recorder.log("stopping stale/running sandbox")
        run_command([cli, "agent", "stop", args.agent], env=env, timeout=180)
        recorder.log(f"booting deep variant {args.variant}")
        boot_start = time.perf_counter_ns()
        boot = run_command(
            [cli, "agent", "run", args.agent, "--detach"],
            env=env,
            timeout=240,
        )
        summary["boot"] = {
            "returncode": boot.returncode,
            "elapsed_ms": (time.perf_counter_ns() - boot_start) / 1e6,
            "output": boot.stdout[-4000:],
        }
        if boot.returncode != 0:
            raise RuntimeError(f"deep experiment boot failed:\n{boot.stdout[-2000:]}")
        started = True
        summary["workspace_mount"] = generated_workspace_mount(args.agent)
        summary["runtime_before"] = privileged_helper(
            script_host,
            "runtime-metrics",
            [args.agent],
            not args.no_sudo,
        )
        recorder.write_summary(summary)

        for round_index in range(args.rounds):
            recorder.log(f"deep round {round_index + 1}/{args.rounds} starting")
            result = run_deep_round(
                round_index=round_index,
                artifact_root=artifact_root,
                workspace=workspace,
                cli=cli,
                agent=args.agent,
                env=env,
                script_host=script_host,
                handoffs=args.handoffs,
                cycles=args.cycles,
                sudo_enabled=not args.no_sudo,
            )
            summary["rounds"].append(result)
            failures = sum(result["executions"][method]["failures"] for method in ("in-place", "atomic"))
            recorder.log(
                f"deep round {round_index + 1}: execution_failures={failures} "
                f"writable_holders={result['writable_holders'].get('writable_holder_tasks', 'unknown')}",
                result=result,
            )
            recorder.write_summary(summary)

        summary["runtime_after_rounds"] = privileged_helper(
            script_host,
            "runtime-metrics",
            [args.agent],
            not args.no_sudo,
        )
        summary["tree_holders_after_rounds"] = privileged_helper(
            script_host,
            "scan-fds-tree",
            [str(artifact_root)],
            not args.no_sudo,
        )
        if not args.skip_workloads:
            guest_artifact = Path("/workspace") / artifact_root.relative_to(workspace)
            workspace_bench = guest_artifact / ".safeyolo-etxtbsy-bench-deep-workspace"
            home_bench = Path("/home/agent") / f".safeyolo-etxtbsy-bench-deep-home-{timestamp}"
            git_bench = guest_artifact / ".safeyolo-etxtbsy-bench-deep-git"
            recorder.log("deep metadata and git workloads starting")
            summary["workspace_benchmark"] = run_guest(
                cli,
                args.agent,
                guest_command(
                    "guest-deep-bench",
                    workspace_bench,
                    args.benchmark_files,
                    args.repetitions,
                ),
                env,
                timeout=900,
            )
            summary["runtime_after_workspace_benchmark"] = privileged_helper(
                script_host, "runtime-metrics", [args.agent], not args.no_sudo
            )
            summary["home_control_benchmark"] = run_guest(
                cli,
                args.agent,
                guest_command(
                    "guest-deep-bench",
                    home_bench,
                    max(500, args.benchmark_files // 4),
                    args.repetitions,
                ),
                env,
                timeout=900,
            )
            summary["runtime_after_home_benchmark"] = privileged_helper(
                script_host, "runtime-metrics", [args.agent], not args.no_sudo
            )
            summary["git_benchmark"] = run_guest(
                cli,
                args.agent,
                guest_command(
                    "guest-git-bench",
                    git_bench,
                    min(2000, args.benchmark_files),
                    args.repetitions,
                ),
                env,
                timeout=900,
            )
            summary["runtime_after_workload"] = privileged_helper(
                script_host, "runtime-metrics", [args.agent], not args.no_sudo
            )
            summary["tree_holders_after_workload"] = privileged_helper(
                script_host,
                "scan-fds-tree",
                [str(artifact_root)],
                not args.no_sudo,
            )
            summary["guest_cleanup"] = {
                "workspace": run_guest(
                    cli,
                    args.agent,
                    guest_command("guest-cleanup", workspace_bench),
                    env,
                ),
                "home": run_guest(
                    cli,
                    args.agent,
                    guest_command("guest-cleanup", home_bench),
                    env,
                ),
                "git": run_guest(
                    cli,
                    args.agent,
                    guest_command("guest-cleanup", git_bench),
                    env,
                ),
            }
            summary["runtime_after_cleanup"] = privileged_helper(
                script_host, "runtime-metrics", [args.agent], not args.no_sudo
            )

        mount_ok = "dcache=0" in (summary.get("workspace_mount") or {}).get("options", [])
        variant_mount_ok = mount_ok if args.variant == "workspace-dcache-0" else not mount_ok
        round_checks = []
        for result in summary["rounds"]:
            round_checks.append(
                {
                    "handle_semantics": all(result["handle_semantics"].values()),
                    "lock_semantics": result["guest_lock_blocked_by_host"] is True,
                    "guest_to_host_manifest": result["guest_to_host_manifest"]["ok"],
                    "host_to_guest_manifest": result["host_to_guest_manifest"]["ok"],
                    "executions": all(
                        result["executions"][method]["failures"] == 0 for method in ("in-place", "atomic")
                    ),
                    "no_writable_holders": result["writable_holders"].get("writable_holder_tasks") == 0,
                }
            )
        summary["verdict"] = {
            "variant_mount_matches": variant_mount_ok,
            "rounds": round_checks,
            "all_correctness_checks_passed": variant_mount_ok and all(all(check.values()) for check in round_checks),
        }
        if args.variant == "baseline":
            summary["verdict"]["baseline_control_completed"] = True
            exit_code = 0
        else:
            exit_code = 0 if summary["verdict"]["all_correctness_checks_passed"] else 1
        recorder.write_summary(summary)
        recorder.log("deep workloads complete", verdict=summary["verdict"])
    except Exception as error:
        summary["error"] = repr(error)
        recorder.log("deep experiment failed", error=repr(error))
        exit_code = 1
    finally:
        if started:
            recorder.log("stopping sandbox")
        stop = run_command([cli, "agent", "stop", args.agent], env=env, timeout=180)
        summary["stop"] = {"returncode": stop.returncode, "output": stop.stdout[-2000:]}
        summary["finished_at"] = dt.datetime.now(dt.UTC).isoformat()
        summary["agent_left_stopped"] = True
        if artifact_root.is_dir() and not artifact_root.is_symlink():
            shutil.rmtree(artifact_root)
            summary["artifact_root_removed"] = True
        else:
            summary["artifact_root_removed"] = False
        recorder.write_summary(summary)
        recorder.log("deep experiment finished; agent left stopped", exit_code=exit_code)

    print(f"\nResults: {output_dir / 'summary.json'}")
    print(f"Restart: safeyolo agent run {args.agent}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode")

    run = subparsers.add_parser("run", help="run the host-controlled matrix")
    run.add_argument("agent")
    run.add_argument("--variants", nargs="+", choices=sorted(VARIANTS))
    run.add_argument("--release-timeout", type=float, default=2.0)
    run.add_argument("--churn-files", type=int, default=1200)
    run.add_argument("--no-sudo", action="store_true")

    deep = subparsers.add_parser("deep", help="run focused workspace dcache=0 side-effect tests")
    deep.add_argument("agent")
    deep.add_argument("--rounds", type=int, default=3)
    deep.add_argument("--handoffs", type=int, default=250)
    deep.add_argument("--cycles", type=int, default=4)
    deep.add_argument("--benchmark-files", type=int, default=4000)
    deep.add_argument("--repetitions", type=int, default=5)
    deep.add_argument(
        "--variant",
        choices=("workspace-dcache-0", "baseline"),
        default="workspace-dcache-0",
    )
    deep.add_argument("--skip-workloads", action="store_true")
    deep.add_argument("--no-sudo", action="store_true")

    edge = subparsers.add_parser(
        "edge",
        help="characterize watched and live-reference ETXTBSY boundary cases",
    )
    edge.add_argument("agent")
    edge.add_argument(
        "--variant",
        choices=("workspace-dcache-0", "baseline"),
        default="workspace-dcache-0",
    )
    edge.add_argument("--parallel-attempts", type=int, default=32)
    edge.add_argument("--hold-timeout", type=float, default=30.0)
    edge.add_argument("--no-sudo", action="store_true")

    scan = subparsers.add_parser("scan-fds", help=argparse.SUPPRESS)
    scan.add_argument("target", type=Path)

    scan_tree = subparsers.add_parser("scan-fds-tree", help=argparse.SUPPRESS)
    scan_tree.add_argument("target", type=Path)

    metrics = subparsers.add_parser("runtime-metrics", help=argparse.SUPPRESS)
    metrics.add_argument("agent")

    write = subparsers.add_parser("guest-write", help=argparse.SUPPRESS)
    write.add_argument("target", type=Path)
    write.add_argument("host_marker", type=Path)
    write.add_argument("guest_marker", type=Path)
    write.add_argument("method", choices=("in-place", "atomic"))

    bench = subparsers.add_parser("guest-bench", help=argparse.SUPPRESS)
    bench.add_argument("directory", type=Path)
    bench.add_argument("files", type=int)

    cleanup = subparsers.add_parser("guest-cleanup", help=argparse.SUPPRESS)
    cleanup.add_argument("directory", type=Path)

    watch = subparsers.add_parser("guest-watch", help=argparse.SUPPRESS)
    watch.add_argument("path", type=Path)
    watch.add_argument("timeout", type=float)

    edge_hold = subparsers.add_parser("guest-edge-hold", help=argparse.SUPPRESS)
    edge_hold.add_argument("target", type=Path)
    edge_hold.add_argument("alias", type=Path)
    edge_hold.add_argument("release", type=Path)
    edge_hold.add_argument("scenario", choices=EDGE_SCENARIOS)
    edge_hold.add_argument("timeout", type=float)

    deep_prepare = subparsers.add_parser("guest-deep-prepare", help=argparse.SUPPRESS)
    deep_prepare.add_argument("directory", type=Path)
    deep_prepare.add_argument("handoffs", type=int)
    deep_prepare.add_argument("cycles", type=int)
    deep_prepare.add_argument("round_index", type=int)

    manifest = subparsers.add_parser("guest-manifest", help=argparse.SUPPRESS)
    manifest.add_argument("directory", type=Path)

    deep_bench = subparsers.add_parser("guest-deep-bench", help=argparse.SUPPRESS)
    deep_bench.add_argument("directory", type=Path)
    deep_bench.add_argument("files", type=int)
    deep_bench.add_argument("repetitions", type=int)

    git_bench = subparsers.add_parser("guest-git-bench", help=argparse.SUPPRESS)
    git_bench.add_argument("directory", type=Path)
    git_bench.add_argument("files", type=int)
    git_bench.add_argument("repetitions", type=int)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.mode == "run":
        return controller(args)
    if args.mode == "deep":
        return deep_controller(args)
    if args.mode == "edge":
        return edge_controller(args)
    if args.mode == "scan-fds":
        emit_json(scan_fds(args.target.resolve()))
        return 0
    if args.mode == "scan-fds-tree":
        emit_json(scan_fds_tree(args.target.resolve()))
        return 0
    if args.mode == "runtime-metrics":
        emit_json(runtime_metrics(args.agent))
        return 0
    if args.mode == "guest-write":
        guest_write(args.target, args.host_marker, args.guest_marker, args.method)
        return 0
    if args.mode == "guest-bench":
        guest_bench(args.directory, args.files)
        return 0
    if args.mode == "guest-cleanup":
        guest_cleanup(args.directory)
        return 0
    if args.mode == "guest-watch":
        guest_watch(args.path, args.timeout)
        return 0
    if args.mode == "guest-edge-hold":
        guest_edge_hold(args.target, args.alias, args.release, args.scenario, args.timeout)
        return 0
    if args.mode == "guest-deep-prepare":
        guest_deep_prepare(args.directory, args.handoffs, args.cycles, args.round_index)
        return 0
    if args.mode == "guest-manifest":
        guest_manifest(args.directory)
        return 0
    if args.mode == "guest-deep-bench":
        guest_deep_bench(args.directory, args.files, args.repetitions)
        return 0
    if args.mode == "guest-git-bench":
        guest_git_bench(args.directory, args.files, args.repetitions)
        return 0
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
