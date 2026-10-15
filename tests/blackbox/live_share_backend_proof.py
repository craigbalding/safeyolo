"""Probe #1042 on one disposable installed macOS Virtualization.framework guest.

Run as the approved physical Mac account. ROOT must be an exclusively owned
disposable native instance with prepared boot inputs, this branch's signed
proof helper at bin/safeyolo-vm, a running proxy and no proof1042 agent. BASE
must be a new absolute path on disk-backed storage outside ROOT. Preserve the
proxy/CA environment and set the existing SAFEYOLO_VZ_TEST_RUNNER and positive
SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS deadline. The selected shell route must work.
This driver creates one guest and synthetic folders, then stops that guest
and ROOT's proxy on exit. It does not launch a model or modify another root.

    python3 -I -B tests/blackbox/live_share_backend_proof.py \
        --root /owned/short-root --base /owned/new-proof-directory

The Swift experiment exposes only named children, never their host parent.
Fixed host-only step files drive the runtime device; they are not a product
API. Busy export changes deliberately measure the raw backend on synthetic
data after an ordinary guest unmount attempt. They are not safe-removal policy.
The report remains an investigation result, not acceptance of #1042.
"""

from __future__ import annotations

import argparse
import json
import os
import runpy
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness.process_identity import process_start_token
from installed_sections import owned_processes, surviving_processes

# Reuse the same guest open-file/cwd/mmap witness on both backends.
LINUX_PROBE = Path(__file__).resolve().parents[1] / "nested-linux/live_mount_backend_proof.py"
GUEST_HOLDER = runpy.run_path(str(LINUX_PROBE))["GUEST_HOLDER"]


def run_proof(root: Path, base: Path):
    if sys.platform != "darwin":
        raise RuntimeError("this probe needs physical macOS Virtualization.framework")
    if list((root / "agents").glob("*")):
        raise RuntimeError("the selected root has agent state; preserve it and use a fresh disposable root")
    if root == base or root in base.parents or base in root.parents:
        raise ValueError("the new proof directory and disposable root must be separate")
    base.mkdir(mode=0o700)
    report = {"root": str(root), "base": str(base), "commands": [], "runtime_changes": []}
    agent = "proof1042"
    cli = [str(root / "bin/safeyolo"), "--root", str(root)]
    environment = {**os.environ, "SAFEYOLO_1042_PROOF_DIR": str(base)}
    started = False
    initial_run = None
    exports = "/mnt/proof1042exports"
    target = "/mnt/proof1042live"
    readonly = "/mnt/proof1042ro"
    startup = "/mnt/proof1042startup"
    alias = "/mnt/proof1042alias"

    def save():
        (base / "observed.json").write_text(json.dumps(report, indent=2) + "\n")

    def command(argv, *, check=True, timeout=40):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                env=environment, timeout=timeout)
        report["commands"].append({"argv": list(map(str, argv)), "exit": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        save()
        if check and result.returncode:
            raise RuntimeError(f"command exited {result.returncode}: {argv}")
        return result

    def guest(script, *, check=True):
        return command([*cli, "agent", "shell", agent, "-c", script], check=check)

    def wait_file(path, timeout=20):
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() > deadline:
                raise TimeoutError(f"missing result: {path}")
            time.sleep(.05)
        return path.read_text()

    def same_run():
        current = json.loads((root / "agents" / agent / "runtime.json").read_text())
        for key in ("run_id", "backend_pid", "backend_token", "helper_instance"):
            if not initial_run.get(key) or current.get(key) != initial_run[key]:
                raise RuntimeError(f"sandbox identity changed or is missing: {key}")
        if process_start_token(current["backend_pid"]) != current["backend_token"]:
            raise RuntimeError("VZ helper OS process identity changed")
        context = root / "agents" / agent / "config-share/host-launch-context.json"
        if json.loads(context.read_text())["generation"] != initial_run["run_id"]:
            raise RuntimeError("sandbox launch generation changed")

    def step(number):
        same_run()
        temporary = base / "step.next"
        temporary.write_text(str(number))
        temporary.replace(base / "step")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if (base / "failed.json").exists():
                raise RuntimeError((base / "failed.json").read_text())
            if (base / "applied.json").exists():
                applied = json.loads((base / "applied.json").read_text())
                if applied["step"] == number:
                    assert applied["helper_pid"] == initial_run["backend_pid"]
                    report["runtime_changes"].append(applied)
                    save()
                    same_run()
                    return
            time.sleep(.05)
        raise TimeoutError(f"runtime did not apply proof step {number}")

    def holder(mode):
        result = base / "workspace" / (mode + "-holder")
        guest("( python3 -I -B /workspace/holder.py " + " ".join(map(shlex.quote,
              [mode, target, "/workspace/" + result.name])) +
              f'; printf \'%s\' "$?" > /workspace/{mode}-holder.exit )' +
              f" </dev/null > /workspace/{mode}.log 2>&1 &")
        identity = json.loads(wait_file(result.with_suffix(".ready")))
        return result, identity

    def release(result):
        result.with_suffix(".release").touch()
        # A revoked mapped file can terminate the child with SIGBUS instead
        # of raising OSError. The guest shell records that exit separately.
        code = int(wait_file(result.with_suffix(".exit")))
        observation = (json.loads(result.with_suffix(".result").read_text())
                       if result.with_suffix(".result").exists() else {"accessible": None})
        read_after = (json.loads(result.with_suffix(".read-result").read_text())
                      if result.with_suffix(".read-result").exists() else None)
        mapped_before = (result.with_suffix(".mapped-before").read_text()
                         if result.with_suffix(".mapped-before").exists() else None)
        return {**observation, "exit": code, "read_after": read_after, "mapped_before": mapped_before}

    def bind_live():
        guest(f"sudo -n mkdir -p {target} && sudo -n mount --bind {exports}/live {target}")

    def change_host(label):
        with (base / "live/host.txt").open("r+") as changed:
            changed.write((label + ":host-after-export-removal").ljust(64, "."))
            changed.flush()
            os.fsync(changed.fileno())

    try:
        for name in ("workspace", "kept", "startup", "live", "readonly"):
            directory = base / name
            directory.mkdir()
            (directory / "host.txt").write_text((name + ":host-before").ljust(4096, "."))
        (base / "workspace/holder.py").write_text(GUEST_HOLDER)
        report["os"] = command(["sw_vers"]).stdout.strip()
        report["kernel"] = command(["uname", "-a"]).stdout.strip()
        report["host_version"] = command([root / "bin/safeyolo", "--version"]).stdout.strip()
        report["helper_version"] = command([root / "bin/safeyolo-vm", "version", "--json"]).stdout.strip()
        command([*cli, "agent", "create", agent, "--workspace", base / "workspace", "--memory", "1024",
                 "--mount", f"{base}/kept:{exports}", "--mount", f"{base}/startup:{startup}"])
        started = True  # Reconcile a failed start through the normal stop path too.
        command([*cli, "agent", "start", agent, "--sandbox-only"], timeout=150)
        initial_run = json.loads((root / "agents" / agent / "runtime.json").read_text())
        report["initial_run"] = initial_run
        same_run()
        report["guest_kernel"] = guest("uname -a").stdout.strip()
        report["guest_boot_id"] = guest("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        marker, marker_identity = holder("marker")
        report["marker_before"] = marker_identity
        before = wait_file(marker.with_suffix(".heartbeat"))
        guest(f"test -f {exports}/kept/host.txt && test -f {startup}/host.txt && "
              f"test ! -e {exports}/live && test ! -e {exports}/readonly")
        step(1)
        bind_live()
        guest(f"grep -q 'live:host-before' {target}/host.txt && printf guest-write > {target}/guest.txt")
        assert (base / "live/guest.txt").read_text() == "guest-write"
        step(2)
        guest(f"sudo -n mkdir -p {readonly} && sudo -n mount --bind {exports}/readonly {readonly} && "
              f"grep -q 'readonly:host-before' {readonly}/host.txt")
        refused = guest(f"printf forbidden > {readonly}/forbidden", check=False)
        assert refused.returncode != 0 and not (base / "readonly/forbidden").exists()
        guest(f"grep -q 'live:host-before' {target}/host.txt && "
              f"grep -q 'kept:host-before' {exports}/kept/host.txt")
        for number, mode in ((3, "file"), (5, "cwd"), (7, "mmap")):
            handle, identity = holder(mode)
            ordinary = guest(f"sudo -n umount {target}", check=False)
            step(number)
            change_host(mode)
            path = guest(f"cat {target}/host.txt", check=False)
            observation = release(handle)
            report.setdefault("busy", []).append({"kind": mode, "identity": identity,
                "ordinary_umount_exit": ordinary.returncode, "ordinary_umount_error": ordinary.stderr,
                "pathname_exit_after_export_removal": path.returncode,
                "pathname_stdout_after_export_removal": path.stdout, "handle_after": observation})
            save()
            if ordinary.returncode:
                guest(f"sudo -n umount {target}")
            step(number + 1)
            bind_live()
        bound = guest(f"sudo -n mkdir -p {alias} && sudo -n mount --bind {target} {alias}", check=False)
        report["bind_alias"] = {"create_exit": bound.returncode, "stderr": bound.stderr}
        guest(f"sudo -n umount {target}")
        step(9)
        change_host("alias")
        if bound.returncode == 0:
            access = guest(f"cat {alias}/host.txt; printf alias-write > {alias}/alias.txt", check=False)
            report["bind_alias"].update(access_exit=access.returncode, stdout=access.stdout, stderr=access.stderr,
                                       host_write=(base / "live/alias.txt").read_text()
                                       if (base / "live/alias.txt").exists() else None)
            guest(f"sudo -n umount {alias}")
        step(10)
        bind_live()
        guest(f"sudo -n umount {target}")
        step(11)
        guest(f"test ! -e {exports}/live/host.txt && test ! -e {target}/host.txt")
        guest(f"sudo -n umount {readonly}")
        step(12)
        guest(f"test ! -e {exports}/readonly/host.txt")
        guest(f"sudo -n umount {startup}")
        step(13)
        guest(f"test ! -e {startup}/host.txt")
        # An already-running device began as a single directory. Test the
        # multiple-directory form at runtime, with its guest mount removed.
        step(14)
        guest(f"sudo -n mount -t virtiofs extra1 {startup} && "
              f"test -f {startup}/startup/host.txt && test -f {startup}/late/host.txt && "
              f"sudo -n mount --bind {startup}/late {target} && "
              f"printf converted-write > {target}/converted.txt")
        assert (base / "live/converted.txt").read_text() == "converted-write"
        guest(f"sudo -n umount {target} && sudo -n umount {startup}")
        step(15)
        guest(f"grep -q 'kept:host-before' {exports}/kept/host.txt && "
              "test -d /workspace && test -d /home/agent && test -f /safeyolo/host-mounts")
        for name in ("kept", "startup", "live", "readonly"):
            assert (base / name / "host.txt").is_file()
            if name != "live":
                assert (base / name / "host.txt").read_text() == (name + ":host-before").ljust(4096, ".")
        same_run()
        assert guest("cat /proc/sys/kernel/random/boot_id").stdout.strip() == report["guest_boot_id"]
        assert marker.with_suffix(".heartbeat").read_text() != before
        report["marker_after"] = release(marker)
        assert report["marker_after"]["identity"] == marker_identity
        report["backend_operations_completed"] = True
    finally:
        failures = []
        try:
            processes = owned_processes(root)
        except (OSError, ValueError, KeyError) as error:
            processes = []
            failures.append(f"owned process inspection failed: {error}")
        stops = [[*cli, "agent", "stop", agent]] if started else []
        stops.append([*cli, "stop"])
        for arguments in stops:
            try:
                result = command(arguments, check=False, timeout=150)
                if result.returncode:
                    failures.append(f"cleanup exited {result.returncode}: {arguments}")
            except (OSError, subprocess.SubprocessError) as error:
                failures.append(f"cleanup failed: {arguments}: {error}")
        failures.extend(surviving_processes(processes))
        report["cleanup_failures"] = failures
        save()
        if failures:
            raise RuntimeError(f"owned instance cleanup failed; inspect {base}/observed.json")
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    args = parser.parse_args()
    run_proof(args.root.resolve(strict=True), args.base.absolute())
