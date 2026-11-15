#!/usr/bin/env python3
"""Read nonsecret #1553 host prerequisites and retained prebuilt input identities.

Run on the selected native host as its ordinary account. This probe starts no
guest, installs nothing, and reads no credential or personal-account files.
"""

import argparse
import hashlib
import json
import os
import platform
import pwd
import shutil
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=15, check=False)
    return {"command": arguments, "exit": result.returncode,
            "stdout": result.stdout[:4096], "stderr": result.stderr[:2048]}


def metadata(path):
    info = path.lstat()
    return {"path": str(path), "uid": info.st_uid, "gid": info.st_gid,
            "mode": oct(info.st_mode), "bytes": info.st_size, "blocks": info.st_blocks}


def inspect(roots, store):
    account = pwd.getpwuid(os.getuid()).pw_name
    result = {"observed_at": datetime.now(UTC).isoformat(),
              "platform": platform.uname()._asdict(), "uid": os.getuid(), "gid": os.getgid(),
              "groups": os.getgroups(), "account": account, "roots": [], "tools": {}, "blobs": []}
    for tool in ["tar", "zstd", "unshare", "nsenter", "newuidmap", "newgidmap", "getfacl", "getcap"]:
        if executable := shutil.which(tool):
            result["tools"][tool] = metadata(Path(executable))
            if tool in ("tar", "zstd", "unshare", "nsenter"):
                result["tools"][tool]["version"] = command([executable, "--version"])
        else:
            result["tools"][tool] = None
    for name in ["/etc/os-release", "/proc/sys/user/max_user_namespaces",
                 "/proc/sys/kernel/unprivileged_userns_clone",
                 "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"]:
        path = Path(name)
        if path.is_file():
            result[name] = path.read_text()
    for name in ["/etc/subuid", "/etc/subgid"]:
        path = Path(name)
        if path.is_file():
            result[name] = [line for line in path.read_text().splitlines()
                            if line.split(":", 1)[0] in (account, str(os.getuid()))]
    for root in roots:
        row = {"path": str(root), "exists": root.exists(), "files": []}
        configuration = root / "config.toml"
        if configuration.is_file():
            row["linux_settings"] = tomllib.loads(configuration.read_text()).get("linux")
        for name in ["package-info", "share/guest-selection.json", "host/namespace-entry",
                     "bin/safeyolo", "bin/safeyolo-vm", "libexec/runsc"]:
            path = root / name
            if path.exists():
                item = metadata(path)
                if name in ("package-info", "share/guest-selection.json"):
                    item["text"] = path.read_text()
                if name == "host/namespace-entry":
                    item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                row["files"].append(item)
        result["roots"].append(row)
    result["store"] = str(store)
    if store.is_dir():
        result["store_space"] = shutil.disk_usage(store)._asdict()
        result["filesystem"] = command(["df", "-Pk", str(store)])
        for path in sorted((store / "blobs/sha256").glob("*")):
            row = metadata(path)
            if path.is_file() and path.stat().st_size < 65536:
                row["text"] = path.read_text()
            result["blobs"].append(row)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, action="append", default=[])
    parser.add_argument("--store", type=Path,
                        default=Path.home() / ".local/share/safeyolo/guests")
    args = parser.parse_args()
    print(json.dumps(inspect(args.root, args.store), indent=2))


if __name__ == "__main__":
    main()
