#!/usr/bin/env python3
"""Prepare two owned systrap guests for the maintained authority drivers.

Use the same prepared native installation and host prerequisites as the
installed sections runner. Supply a new root and an empty output directory.
This creates credential-free workers with a saved sleep command, runs peer
support or deterministic delegated approvals, and stops only its owned state.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import tomlkit

from tests.blackbox.execution_receipt import save
from tests.blackbox.installed_host_smoke import _sha256
from tests.blackbox.installed_lifecycle import running_guest
from tests.blackbox.installed_provider import capture_guest_command, checked, inputs
from tests.blackbox.installed_sections import (
    copy_prepared_nats,
    owned_processes,
    prepare_native_instance,
    surviving_processes,
)

NAMES = ("bbtest", "bbpeer")


def prepare_authority_guests(base, root, native):
    """Reuse one prepared installation for the two owned authority callers."""
    prepare_native_instance(base, root)
    root.chmod(0o755)
    (root / "data").chmod(0o755)
    (root / "data/tmp").mkdir(mode=0o755)
    (root / ".safeyolo-platform-smoke").touch()
    copy_prepared_nats(base, root)
    config = tomlkit.parse((root / "config.toml").read_text())
    assert "linux" in config, "the prepared installation needs native Linux settings"
    config.update(admin_port=0, flow_store_enabled=False)
    (root / "config.toml").write_text(tomlkit.dumps(config))
    for name in NAMES:
        workspace = root / "workspaces" / name
        workspace.mkdir(parents=True, mode=0o755)
        native("agent", "create", name, "--workspace", str(workspace), "--memory", "512",
               "--launcher", "supervisor", "--command", "exec sleep 300")


def run(args):
    root, base, output = args.root.resolve(), args.prepared_config.resolve(), args.output.resolve()
    assert not root.exists(), "--root must be new"
    output.mkdir(parents=True, exist_ok=True)
    assert not any(output.iterdir()), "--output must be empty"
    output.chmod(0o700)
    report = {"section": args.section, "status": "incomplete", "root": str(root),
              "inputs": inputs(base, args.revision), "cleanup": "unverified", "participants": {}}
    save(output / "result.json", report)
    cli = base / "bin/safeyolo"
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_NATIVE_CONFIG_PATH": str(root / "config.toml"),
                        "SAFEYOLO_COORD_DATA_DIR": str(root / "data/coord"),
                        "SAFEYOLO_NATS_TEST_INSTANCE": uuid.uuid4().hex, "SAFEYOLO_RUNSC_PLATFORM": "systrap",
                        "SAFEYOLO_LOGS_DIR": str(root / "logs"), "TMPDIR": str(root / "data/tmp")}

    def native(*arguments):
        return checked([str(cli), "--root", str(root), *arguments], env=env,
                       diagnostics=output / "native.log")

    capture_failures = []
    try:
        prepare_authority_guests(base, root, native)
        if args.section == "shared-approvals":
            fixture = Path(__file__).parent / "fixtures/delegated-approval-service.yaml"
            (root / "services/delegated-approval-service.yaml").write_bytes(fixture.read_bytes())
        native("start")
        if args.section == "peer-support":
            command = ["-m", "tests.blackbox.installed_peer_support", "--cli", str(cli), "--root", str(root),
                       "--support", "bbpeer", "--target", "bbtest", "--scratch", str(root / "support-scratch"),
                       "--output", str(output / "result.json"), "--platform", "systrap"]
        else:
            for name in NAMES:
                native("agent", "start", name, "--sandbox-only")
                status = json.loads(native("agent", "status", name))
                report["participants"][name] = running_guest(root, name, status)
                actual = _sha256(root / "agents" / name / "config-share/safeyolo-guest")
                assert actual == report["inputs"]["guest"]["sha256"]
                report["participants"][name]["guest_sha256"] = actual
            observed = report["participants"]["bbtest"]
            context = {"platform": "systrap", "agent": "bbtest", "pid": observed["backend_pid"],
                       "start_token": observed["backend_token"]}
            save(output / "platform.json", context)
            env["SAFEYOLO_BLACKBOX_GUEST_IDENTITY"] = json.dumps(context)
            command = ["-m", "tests.blackbox.installed_shared_approvals", "--config-dir", str(root),
                       "--transport-cli", str(cli), "--native-cli", str(cli),
                       "--native-proxy", str(base / "bin/safeyolo-proxy"), "--commit", args.revision,
                       "--worker", "bbtest", "--helper", "bbpeer", "--deterministic",
                       "--output", str(output / "approval-effects.json")]
        save(output / "result.json", report)
        child, reader, finished = capture_guest_command(
            [sys.executable, *command], env, output / "driver.log", capture_failures)
        try:
            report["exit"] = child.wait(timeout=900)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            finished.set()
            reader.join(timeout=5)
            if reader.is_alive():
                capture_failures.append("authority driver output capture survived child exit")
        assert not capture_failures, capture_failures
        assert report["exit"] == 0, "authority driver failed; inspect its retained private driver.log"
        report["status"] = "passed"
    finally:
        failures = list(capture_failures)
        if (root / ".safeyolo-platform-smoke").is_file():
            try:
                processes = owned_processes(root)
            except (OSError, ValueError, KeyError) as error:
                processes = []
                failures.append(f"owned process inspection failed: {error}")
            processes += [{"pid": row["backend_pid"], "start_token": row["backend_token"]}
                          for row in report["participants"].values()]
            for name in NAMES:
                if (root / "agents" / name).is_dir():
                    try:
                        native("agent", "stop", name)
                    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                        failures.append(f"{name} stop: {error}")
            try:
                native("stop")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                failures.append(f"proxy/broker stop: {error}")
            failures += surviving_processes(processes)
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures)
        save(output / "result.json", report)
        if report["status"] == "passed":
            assert not failures, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", choices=("peer-support", "shared-approvals"), required=True)
    parser.add_argument("--prepared-config", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
