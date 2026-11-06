#!/usr/bin/env python3
"""Install reviewed storage protection in Devstack's existing harness jobs.

Run as the existing harness owner. The supplied host binding must identify the
four actual job sources. Backups preserve those inputs; rerunning the same
installation is safe. A changed job source needs inspection before installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

NAMES = ("_common.sh", "provision.sh", "ssh_exec.sh", "ssh_fetch.sh")


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"expected exactly one job source anchor: {old.splitlines()[0]}")
    return source.replace(old, new, 1)


def jobs_with_guard(original: dict[str, str], command: list[str]) -> dict[str, str]:
    result = dict(original)
    common = result["_common.sh"]
    common = replace_once(common, 'SSH_PUB="$HARNESS_DIR/ssh/id_ed25519.pub"',
                          'SSH_PUB="$HARNESS_DIR/ssh/id_ed25519.pub"\n\n'
                          f'harness_storage() {{\n  {shlex.join(command)} "$@"\n}}')
    common = replace_once(common, 'curl -fsSL -o "$img.part" "$url"',
                          'harness_storage download "$img.part" "$url"')
    for direction in ("to", "from"):
        anchor = f'harness_scp_{direction}() {{\n  local ip="$1" src="$2" dst="$3"\n'
        common = replace_once(common, anchor, anchor +
                              f'  harness_storage check-copy --key "$SSH_KEY" --ip "$ip" {direction} "$src" "$dst" || return $?\n')
    result["_common.sh"] = common
    provision = result["provision.sh"]
    start = provision.index("# Clean mode (default):")
    end = provision.index("# Emits:", start)
    provision = provision[:start] + (
        "# Existing disks require explicit owner/next-use selection for retirement.\n"
        "# Provisioning never reclaims arbitrary inactive guests.\n#\n") + provision[end:]
    provision = replace_once(provision, "CLEAN=1\n", "")
    provision = replace_once(provision, "--clean)        CLEAN=1; shift ;;",
                              '--clean)        echo "select exact retired guests separately; --clean cannot preserve retained inputs" >&2; exit 64 ;;')
    provision = replace_once(provision, "--reuse)        CLEAN=0; shift ;;", "--reuse)        shift ;;")
    start = provision.index("# Fresh-VM discipline:")
    end = provision.index("RUN_ID=", start)
    provision = provision[:start] + provision[end:]
    provision = replace_once(provision, 'reserve_guest_lease "$GUEST_NAME"',
                              'harness_storage check-image --path "$POOL_DIR" --size "${DISK_GB}G"\n'
                              'reserve_guest_lease "$GUEST_NAME"')
    result["provision.sh"] = provision
    for name, arguments in (
        ("ssh_exec.sh", 'ssh-exec --key "$SSH_KEY" --ip "${1:?GUEST_IP required}" --script "${2:?SCRIPT_B64 required}" --timeout "${3:-1800}"'),
        ("ssh_fetch.sh", 'ssh-fetch --key "$SSH_KEY" --ip "${1:?GUEST_IP required}" --path "${2:?PATH required}" --maximum-bytes "${3:-1048576}"'),
    ):
        result[name] = ('#!/bin/bash\n# Storage-protected existing harness interface.\nset -euo pipefail\n'
                        '. "$(dirname "$0")/_common.sh"\n' + f"harness_storage {arguments}\n")
    return result


def install(args: argparse.Namespace) -> dict:
    bindings = json.loads(args.bindings.read_bytes())
    expected = {Path(row["path"]).name: row["sha256"] for row in bindings["scripts"]}
    backup = args.state / "original-jobs"
    original = {}
    for name in NAMES:
        source = backup / name if (backup / name).exists() else args.jobs / name
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected[name]:
            raise ValueError(f"{source} differs from the observed host binding")
        original[name] = data.decode()
    command = [str(args.python), str(args.state / "guard.py"), "--config", str(args.state / "config.json")]
    replacements = jobs_with_guard(original, command)
    for name in NAMES:
        current = (args.jobs / name).read_text()
        if current not in (original[name], replacements[name]):
            raise ValueError(f"{name} changed after the bound observation/installation; inspect before writing")
    # Prepare every input before changing a live entry point.
    args.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.state, 0o700)
    backup.mkdir(mode=0o700, exist_ok=True)
    for name in NAMES:
        if not (backup / name).exists():
            (backup / name).write_text(original[name])
    spool = args.state / "temporary"
    spool.mkdir(mode=0o700, exist_ok=True)
    os.chmod(spool, 0o700)
    config = {"filesystems": [str(args.pool), str(args.harness), str(spool)],
                  "minimum_free_gib": args.minimum_free_gib, "minimum_free_inodes": args.minimum_free_inodes,
                  "maximum_output_bytes": args.maximum_output_bytes, "spool": str(spool),
                  "emergency_bytes": args.emergency_bytes,
                  "status_file": str(args.state / "status.json")}
    (args.state / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    guard = Path(__file__).with_name("guard.py")
    shutil.copyfile(guard, args.state / "guard.py")
    subprocess.run([str(args.python), str(args.state / "guard.py"), "--config", str(args.state / "config.json"),
                    "check"], check=True)
    for name, source in replacements.items():
        destination = args.jobs / name
        staged = args.jobs / (name + ".storage-new")
        staged.write_text(source)
        os.chmod(staged, destination.stat().st_mode & 0o777)
        os.replace(staged, destination)
    cron = shlex.join([*command, "sweep"]) + " >/dev/null 2>&1 # safeyolo-devstack-storage"
    if args.install_cron:
        current = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=False)
        if current.returncode != 0 and "no crontab for" not in current.stderr:
            raise ValueError("cannot read the current account's crontab")
        lines = [line for line in current.stdout.splitlines() if not line.endswith("# safeyolo-devstack-storage")]
        lines.append("* * * * * " + cron)
        subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
    return {"guard_sha256": hashlib.sha256(guard.read_bytes()).hexdigest(), "config": config,
                "cron_installed": args.install_cron, "cron_entry": "* * * * * " + cron,
                "jobs": {name: hashlib.sha256(source.encode()).hexdigest() for name, source in replacements.items()}}


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--jobs", type=Path, default=Path("/var/lib/rundeck/harness/jobs"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/rundeck/harness/storage"))
    parser.add_argument("--pool", type=Path, default=Path("/var/tmp/harness-vms"))
    parser.add_argument("--harness", type=Path, default=Path("/var/lib/rundeck/harness"))
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--minimum-free-gib", type=float, default=10)
    parser.add_argument("--minimum-free-inodes", type=int, default=4096)
    parser.add_argument("--maximum-output-bytes", type=int, default=1048576)
    parser.add_argument("--emergency-bytes", type=int, default=2 * 1024**3)
    parser.add_argument("--install-cron", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(install(args), indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Devstack storage installation: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
