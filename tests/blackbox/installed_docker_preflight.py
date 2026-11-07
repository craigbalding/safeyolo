#!/usr/bin/env python3
"""Probe nested Docker in one disposable installed Linux/systrap sandbox.

On an owned Linux host, supply a prepared installation, this source checkout,
Python 3.11+ with tomlkit, and a free Admin port. Root/output must be new,
disk-backed paths with traversable parents. --nested-docker selects the
candidate's guest configuration; without it the driver records the default.
The guest installs Debian Docker packages through its normal proxy, attempts
one local daemon/pull/container and stops. This is a preflight, not full #1436
acceptance. It preserves inputs, diagnostics and failures without retrying.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import tomlkit

from tests.blackbox.installed_host_smoke import _agent_listeners, _sha256
from tests.blackbox.installed_ingress import runsc_identity
from tests.blackbox.installed_lifecycle import running_guest
from tests.blackbox.installed_provider import checked
from tests.blackbox.installed_sections import (
    copy_prepared_nats,
    owned_processes,
    prepare_native_instance,
    surviving_processes,
)

POLICY = '''[hosts."deb.debian.org"]
egress = "allow"
[hosts."security.debian.org"]
egress = "allow"
[hosts."auth.docker.io"]
egress = "allow"
[hosts."registry-1.docker.io"]
egress = "allow"
[hosts."production.cloudflare.docker.com"]
egress = "allow"
[hosts."example.com"]
egress = "allow"
[hosts."*"]
egress = "deny"
[controls.network]
enabled = true
action = "block"
'''


def run(args):
    base, root, output = args.prepared_config.resolve(), args.root.resolve(), args.output.resolve()
    assert not root.exists(), "--root must be new"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli = str(base / "bin/safeyolo")
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_RUNSC_PLATFORM": "systrap",
                        "SAFEYOLO_NATS_TEST_INSTANCE": uuid.uuid4().hex, "SAFEYOLO_RUNSC_DEBUG": "1"}
    report = {"started_at": datetime.now(UTC).isoformat(), "status": "incomplete",
              "nested_docker": args.nested_docker, "revision": args.revision,
              "root": str(root), "cleanup": "unverified"}
    processes = []

    def native(*arguments, timeout=90):
        return checked([cli, "--root", str(root), *arguments], env=env, timeout=timeout,
                       diagnostics=output / "native.log")

    try:
        report["inputs"] = {}
        for name in ("package-info", "share/guest-selection.json"):
            if (base / name).is_file():
                report["inputs"][name] = (base / name).read_text()
        for name, path, revision in (
            ("cli", base / "bin/safeyolo", args.revision),
            ("proxy", base / "bin/safeyolo-proxy", args.revision),
            ("guest", base / "assets/guest/safeyolo-guest", args.guest_revision or args.revision),
        ):
            version = checked([str(path), "--version"]).strip()
            assert f"commit={revision}" in version, f"selected {name} revision differs"
            report["inputs"][name] = {"path": str(path), "sha256": _sha256(path), "version": version}
        prepare_native_instance(base, root)
        root.chmod(0o755)
        (root / "data").chmod(0o755)
        copy_prepared_nats(base, root)
        config = tomlkit.parse((root / "config.toml").read_text())
        assert "linux" in config, "the prepared installation needs native Linux settings"
        config["admin_port"] = args.admin_port
        # If this approved host uses a parent proxy, preserve that route.
        prepared = tomlkit.parse((base / "config.toml").read_text())
        if "parent_proxy" in prepared:
            config["parent_proxy"] = prepared["parent_proxy"]
        (root / "config.toml").write_text(tomlkit.dumps(config))
        (root / "policy.toml").write_text(POLICY)
        workspace = root / "workspace"
        workspace.mkdir(mode=0o755)
        source = Path(__file__).parent / "isolation/docker-preflight.sh"
        shutil.copy2(source, workspace / source.name)
        native("agent", "create", "notes", "--workspace", str(workspace), "--memory", "1536",
               "--nested-docker", str(args.nested_docker).lower())
        native("start")
        native("agent", "start", "notes", "--sandbox-only")
        status = json.loads(native("agent", "status", "notes"))
        report["runtime"] = running_guest(root, "notes", status)
        processes = owned_processes(root)
        listener = next(row for row in _agent_listeners(root) if row["agent_id"] == "notes")
        report["ingress"] = runsc_identity(root, "notes", Path(listener["path"]), platform="systrap")
        report["oci"] = json.loads((root / "agents/notes/config.json").read_text())
        report["doctor"] = json.loads(native("doctor"))
        with (output / "guest.log").open("w") as log:
            command = "sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends docker.io docker-cli docker-compose && sudo -n bash /workspace/docker-preflight.sh /home/agent/docker-preflight"
            result = subprocess.run([cli, "--root", str(root), "agent", "shell", "notes", "-c", command],
                                    env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        report["guest_exit"] = result.returncode
        observations = root / "agents/notes/home/docker-preflight"
        if observations.is_dir():
            for path in observations.iterdir():
                if path.is_file():
                    shutil.copy2(path, output / path.name)
            report["outcome"] = (observations / "outcome.txt").read_text().strip()
        report["status"] = "container-ran" if result.returncode == 0 else "preflight-failed"
    finally:
        failures = []
        if (root / "config.toml").is_file():
            try:
                processes.extend(owned_processes(root))
            except (OSError, ValueError, KeyError) as error:
                failures.append(f"cannot inspect owned process receipts: {error}")
        if (root / "agents/notes").is_dir():
            try:
                native("agent", "stop", "notes")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                failures.append(f"guest stop: {error}")
        if (root / "config.toml").exists():
            try:
                native("stop")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                failures.append(f"instance stop: {error}")
        failures.extend(surviving_processes(processes))
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures,
                      finished_at=datetime.now(UTC).isoformat())
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-config", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--guest-revision")
    parser.add_argument("--admin-port", required=True, type=int)
    parser.add_argument("--nested-docker", action="store_true")
    report = run(parser.parse_args())
    print(json.dumps({key: report.get(key) for key in ("status", "cleanup", "outcome")}))
    return int(report["status"] != "container-ran" or report["cleanup"] != "stopped")


if __name__ == "__main__":
    raise SystemExit(main())
