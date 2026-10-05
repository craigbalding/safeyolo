#!/usr/bin/env python3
"""Retire one accepted candidate's Cargo target without touching its source."""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def directory_size(path: Path) -> int:
    return sum(file.stat().st_size for file in path.rglob("*") if file.is_file())


def git_root(path: Path) -> Path | None:
    for parent in (path.parent, *path.parents):
        if (parent / ".git").exists():
            return Path(subprocess.check_output(["git", "-C", parent, "rev-parse", "--show-toplevel"], text=True).strip())
    return None


def source_git_root(target: Path) -> Path:
    """Find the checkout whose commit and lockfile produced this target.

    Cargo targets may be kept outside a checkout so concurrent candidates do
    not share a worktree. In that case this helper's own checkout is the
    source of the accepted commit and lockfile evidence.
    """
    root = git_root(target)
    if root is not None:
        return root
    root = git_root(Path(__file__).resolve())
    if root is not None:
        return root
    raise SystemExit(
        "target is not beneath a Git worktree and the retirement helper has no Git worktree"
    )


def path_is_within(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def resolved_process_path(value: str, cwd: Path | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        if cwd is None:
            return None
        path = cwd / path
    try:
        return path.resolve()
    except OSError:
        return None


def argv_references_target(argv: list[str], cwd: Path | None, target: Path) -> bool:
    for index, argument in enumerate(argv):
        candidates = []
        if argument == "--target-dir" and index + 1 < len(argv):
            candidates.append(argv[index + 1])
        elif argument.startswith("--target-dir="):
            candidates.append(argument.partition("=")[2])
        elif argument.startswith("CARGO_TARGET_DIR="):
            candidates.append(argument.partition("=")[2])
        else:
            candidates.append(argument)
        if any(resolved_process_path(candidate, cwd) == target for candidate in candidates):
            return True
    return False


def environment_references_target(
    environment: list[str], cwd: Path | None, target: Path
) -> bool:
    for entry in environment:
        if entry.startswith("CARGO_TARGET_DIR=") and resolved_process_path(
            entry.partition("=")[2], cwd
        ) == target:
            return True
    return False


def active_owner(target: Path) -> int | None:
    if sys.platform == "darwin":
        return darwin_active_owner(target)
    self_pid = os.getpid()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        pid = int(proc.name)
        try:
            argv = [
                argument.decode(errors="replace")
                for argument in (proc / "cmdline").read_bytes().split(b"\0")
                if argument
            ]
        except OSError:
            argv = []
        try:
            environment = [
                entry.decode(errors="replace")
                for entry in (proc / "environ").read_bytes().split(b"\0")
                if entry
            ]
        except OSError:
            environment = []
        try:
            cwd = (proc / "cwd").resolve()
        except OSError:
            cwd = None
        if pid != self_pid and (
            argv_references_target(argv, cwd, target)
            or environment_references_target(environment, cwd, target)
        ):
            return pid
        if cwd is not None and path_is_within(cwd, target):
            return pid
        try:
            for descriptor in (proc / "fd").iterdir():
                try:
                    opened = descriptor.resolve()
                except OSError:
                    continue
                if path_is_within(opened, target):
                    return pid
        except OSError:
            continue
    return None


def darwin_process_arguments(pid: int) -> tuple[list[str], list[str]]:
    """Read NUL-delimited argv/environment without printing process secrets."""
    # Apple's KERN_PROCARGS2 returns argc, executable, padding, argv, then env.
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    size = ctypes.c_size_t()
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0):
        raise OSError(ctypes.get_errno(), "cannot inspect process", pid)
    buffer = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0):
        raise OSError(ctypes.get_errno(), "cannot inspect process", pid)
    data = buffer.raw[:size.value]
    argc = int.from_bytes(data[:4], sys.byteorder, signed=True)
    offset = data.index(b"\0", 4) + 1
    while offset < len(data) and data[offset] == 0:
        offset += 1
    argv = []
    for _ in range(argc):
        end = data.index(b"\0", offset)
        argv.append(os.fsdecode(data[offset:end]))
        offset = end + 1
    environment = [os.fsdecode(entry) for entry in data[offset:].split(b"\0") if entry]
    return argv, environment


def darwin_process_files(pid: int, libproc: ctypes.CDLL) -> tuple[Path, list[Path]]:
    """Read raw cwd and vnode paths; lsof escapes names even with -F0.

    These fixed public Darwin layouts come from sys/proc_info.h:
    proc_vnodepathinfo is two 1176-byte vnode_info_path entries (path at152);
    vnode_fdinfowithpath is 1200 bytes (path at176); proc_fdinfo is8 bytes.
    Native paths also avoid lsof's ambiguous caret notation for control bytes.
    """
    cwd_info = ctypes.create_string_buffer(2352)
    ctypes.set_errno(0)
    if libproc.proc_pidinfo(pid, 9, 0, cwd_info, len(cwd_info)) != len(cwd_info):
        raise OSError(ctypes.get_errno() or errno.EIO, "cannot inspect process cwd", pid)
    cwd = Path(os.fsdecode(cwd_info.raw[152:1176].split(b"\0", 1)[0])).resolve()

    ctypes.set_errno(0)
    size = libproc.proc_pidinfo(pid, 1, 0, None, 0)
    if size == 0:
        if ctypes.get_errno():
            raise OSError(ctypes.get_errno(), "cannot list process files", pid)
        return cwd, []
    # Leave room for descriptors opened between the size query and inspection.
    descriptors = ctypes.create_string_buffer(size + 32 * 8)
    ctypes.set_errno(0)
    count = libproc.proc_pidinfo(pid, 1, 0, descriptors, len(descriptors))
    if count == 0 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), "cannot inspect process files", pid)
    if count < 0 or count % 8 or count >= len(descriptors):
        raise OSError(errno.EIO, "incomplete process file listing", pid)
    files = []
    for offset in range(0, count, 8):
        fd = int.from_bytes(descriptors.raw[offset:offset + 4], sys.byteorder, signed=True)
        fd_type = int.from_bytes(descriptors.raw[offset + 4:offset + 8], sys.byteorder)
        if fd_type != 1:  # PROX_FDTYPE_VNODE
            continue
        info = ctypes.create_string_buffer(1200)
        ctypes.set_errno(0)
        length = libproc.proc_pidfdinfo(pid, fd, 2, info, len(info))
        if length != len(info):
            # A descriptor or its process can close during this inspection.
            if length == 0 and ctypes.get_errno() in (errno.EBADF, errno.ENOENT, errno.ESRCH):
                continue
            raise OSError(ctypes.get_errno() or errno.EIO, "cannot inspect open file", pid)
        name = info.raw[176:1200].split(b"\0", 1)[0]
        if name:
            files.append(Path(os.fsdecode(name)).resolve())
    return cwd, files


def darwin_active_owner(target: Path) -> int | None:
    """Use Mac process facilities for the same argv/env/cwd/FD protections."""
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libproc.proc_pidinfo.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
    ]
    libproc.proc_pidfdinfo.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
    ]
    processes = subprocess.check_output(["ps", "-axo", "pid="], text=True)
    for pid in map(int, processes.split()):
        try:
            cwd, files = darwin_process_files(pid, libproc)
        except OSError as exc:
            # Like /proc, vanished and inaccessible foreign processes are absent.
            if exc.errno in (errno.ESRCH, errno.EINVAL, errno.EPERM, errno.EACCES):
                continue
            raise SystemExit(f"cannot inspect Mac process {pid}; target retained") from exc
        if path_is_within(cwd, target) or any(path_is_within(path, target) for path in files):
            return pid
        if pid == os.getpid():
            continue
        try:
            argv, environment = darwin_process_arguments(pid)
        except OSError as exc:
            if exc.errno in (errno.ESRCH, errno.EINVAL, errno.EPERM, errno.EACCES):
                continue  # The process vanished or its arguments are inaccessible.
            raise SystemExit(f"cannot inspect Mac process {pid}; target retained") from exc
        if argv_references_target(argv, cwd, target) or environment_references_target(
            environment, cwd, target
        ):
            return pid
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path, help="Sol acceptance/integration receipt containing --commit")
    parser.add_argument("--commit", required=True, help="exact accepted candidate commit")
    parser.add_argument("--record", required=True, type=Path, help="JSONL evidence file to append before deletion")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    target = args.target.resolve()
    receipt = args.receipt.resolve()
    record = args.record.resolve()
    if (target.name != "target" and not target.name.startswith("target-")) or not target.is_dir():
        raise SystemExit("--target must name an existing Cargo target directory (target or target-*)")
    for option, path in (("receipt", receipt), ("record", record)):
        if path_is_within(path, target):
            raise SystemExit(f"--{option} must be outside --target so retirement evidence survives")
    if not receipt.is_file():
        raise SystemExit("--receipt must be an existing acceptance receipt")
    root = source_git_root(target)
    commit = subprocess.check_output(["git", "-C", root, "rev-parse", f"{args.commit}^{{commit}}"], text=True).strip()
    if commit not in receipt.read_text(errors="replace"):
        raise SystemExit("acceptance receipt does not name the exact candidate commit")
    owner = active_owner(target)
    if owner is not None:
        raise SystemExit(f"target is still referenced by live process {owner}")

    binaries = {}
    debug = target / "debug"
    if debug.is_dir():
        for path in sorted(debug.iterdir()):
            if path.is_file() and os.access(path, os.X_OK):
                binaries[path.name] = sha256(path)
    lockfile = root / "proxy" / "Cargo.lock"
    if not lockfile.is_file():
        lockfile = root / "Cargo.lock"
    event = {
        "event": "cargo_target_retired",
        "at": datetime.now(UTC).isoformat(),
        "target": str(target),
        "candidate_commit": commit,
        "acceptance_receipt": str(receipt),
        "acceptance_receipt_sha256": sha256(receipt),
        "lockfile_sha256": sha256(lockfile) if lockfile.is_file() else None,
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
        "bytes_removed": directory_size(target),
        "top_level_debug_binaries": binaries,
    }
    print(json.dumps(event, sort_keys=True))
    if args.dry_run:
        return 0
    record.parent.mkdir(parents=True, exist_ok=True)
    with record.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    shutil.rmtree(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
