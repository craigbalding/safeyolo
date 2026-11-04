#!/usr/bin/env python3
"""Check final-symlink refusal and directory traversal in an owned guest.

Run inside the disposable runtime being qualified. The caller records the
host runtime's source, version and binary identities separately.
"""

import errno
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


def probe_directory(base):
    """Record every control before reporting whether the runtime passed."""
    results = []
    combined = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with tempfile.TemporaryDirectory(prefix="safeyolo-nofollow-", dir=base) as scratch:
        root = Path(scratch)
        (root / "dir").mkdir()
        (root / "file").write_text("owned canary\n")
        (root / "dir" / "child").write_text("owned child\n")
        (root / "dir-link").symlink_to("dir")
        (root / "file-link").symlink_to("file")
        (root / "chain-link").symlink_to("dir-link/")
        cases = (
            ("dir-link", combined, errno.ENOTDIR, "dir"),
            ("dir-link", os.O_RDONLY | os.O_NOFOLLOW, errno.ELOOP, "dir"),
            ("file-link", os.O_RDONLY | os.O_NOFOLLOW, errno.ELOOP, "file"),
            ("dir", combined, None, "dir"),
            ("file", combined, errno.ENOTDIR, "file"),
            ("dir-link", os.O_RDONLY | os.O_DIRECTORY, None, "dir"),
            ("dir-link/", combined, None, "dir"),
            ("file-link/", combined, errno.ENOTDIR, "file"),
            ("dir-link/child", os.O_RDONLY | os.O_NOFOLLOW, None, "dir/child"),
            ("chain-link", os.O_RDONLY | os.O_DIRECTORY, None, "dir"),
        )
        for name, flags, expected_errno, target in cases:
            # Keep a trailing slash in the syscall operand; Path would drop it.
            path = f"{scratch}/{name}"
            result = {
                "filesystem_path": base,
                "name": name,
                "flags": flags,
                "lstat_symlink": stat.S_ISLNK(os.lstat(path.rstrip("/")).st_mode),
                "expected_errno": expected_errno,
            }
            try:
                fd = os.open(path, flags)
            except OSError as error:
                result.update(opened=False, errno=error.errno, error=error.strerror,
                              passed=error.errno == expected_errno)
            else:
                try:
                    observed = os.fstat(fd)
                    wanted = os.stat(root / target)
                    same_inode = (observed.st_dev, observed.st_ino) == (
                        wanted.st_dev, wanted.st_ino)
                    same_type = stat.S_IFMT(observed.st_mode) == stat.S_IFMT(wanted.st_mode)
                    result.update(opened=True, mode=stat.S_IFMT(observed.st_mode),
                                  same_inode_as_target=same_inode,
                                  passed=expected_errno is None and same_inode and same_type)
                finally:
                    os.close(fd)
            results.append(result)
    return results


def main():
    bases = sys.argv[1:] or ["/tmp", "/home/agent"]
    cases = [case for base in bases for case in probe_directory(base)]
    passed = all(case["passed"] for case in cases)
    print(json.dumps({
        "machine": os.uname().machine,
        "kernel": os.uname().release,
        "flags": {"O_DIRECTORY": os.O_DIRECTORY, "O_NOFOLLOW": os.O_NOFOLLOW},
        "cases": cases,
        "passed": passed,
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
