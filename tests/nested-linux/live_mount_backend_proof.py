"""Probe #1042 on one disposable, installed Linux SafeYolo instance.

Run as the ordinary host account from this checkout. The selected ROOT must
have the normal Linux preparation, guest assets, and a running native proxy.
BASE must not exist. This driver creates one sandbox, uses only synthetic
directories, and stops its sandbox and proxy on every exit. It does not start
a model. Use the checkout's Python 3.12 environment on disk-backed storage:

    .venv/bin/python tests/nested-linux/live_mount_backend_proof.py \
        --root /owned/installed-root --base /owned/new-proof-directory

This is an investigation, not an operator interface or acceptance result.
The Gofer is the installed runsc's ordinary isolated Gofer, with a synthetic
directory as its entire root. No host parent or new host RPC is exported.
"""

from __future__ import annotations

import argparse
import array
import json
import os
import select
import shlex
import signal
import socket
import subprocess
import sys
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "blackbox"))
from harness.process_identity import process_start_token
from installed_sections import owned_processes, surviving_processes


def receive_json(connection):
    data = b""
    while len(data) < 65536:
        chunk = connection.recv(4096)
        if not chunk:
            raise EOFError("control connection closed before a complete response")
        data += chunk
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            # urpc sends one JSON value over a stream, without a length header.
            continue
    raise ValueError("control response exceeds 64 KiB")


def rpc_child(arguments):
    """Enter the existing holder before this mode; never select a host path."""
    path, method, container_id, target, mode, descriptor = arguments
    if method == "Fs.Umount":
        argument = {"container_id": container_id, "target": target, "flags": 0}
    elif method == "Fs.Mount":
        # release-20261005.0 rejects the historical "cache=remote" spelling.
        # Shared host/guest writes need the runtime's revalidating cache mode.
        argument = {"container_id": container_id, "source": "proof1042", "target": target,
                    "fs_type": "gofer", "flags": 6 | int(mode), "data": "cache=remote_revalidating"}
    else:
        raise ValueError("the probe supports only Fs.Mount and Fs.Umount")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(20)
        connection.connect(path)
        ancillary = []
        if int(descriptor) >= 0:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array("i", [int(descriptor)]))]
        payload = json.dumps({"method": method, "arg": argument}).encode()
        count = connection.sendmsg([payload], ancillary)
        connection.sendall(payload[count:])
        print(json.dumps(receive_json(connection)))


GUEST_HOLDER = '''import json, mmap, os, sys, time
from pathlib import Path
mode, target, result = sys.argv[1:]
result = Path(result)
opened = mapped = None
if mode == "file":
    opened = open(target + "/host.txt", "r+b", buffering=0)
elif mode == "cwd":
    os.chdir(target)
elif mode == "mmap":
    opened = open(target + "/host.txt", "r+b", buffering=0)
    mapped = mmap.mmap(opened.fileno(), 4096)
elif mode != "marker":
    raise ValueError(mode)
identity = {"pid":os.getpid(), "start":Path("/proc/self/stat").read_text().split(") ")[1].split()[19]}
result.with_suffix(".ready").write_text(json.dumps(identity))
deadline = time.monotonic() + 300
while not result.with_suffix(".release").exists():
    if time.monotonic() > deadline:
        raise TimeoutError("host did not release owned holder")
    result.with_suffix(".heartbeat").write_text(str(time.monotonic()))
    time.sleep(.1)
try:
    if mode == "file":
        opened.seek(0); data=opened.read(64).decode()
        opened.seek(128); opened.write(b"guest-open-handle-write")
    elif mode == "cwd":
        data=Path("host.txt").read_text()[:64]
        Path("guest-cwd-write").write_text("guest-cwd-write")
    elif mode == "mmap":
        data=mapped[:64].decode(); mapped[128:151]=b"guest-open-handle-write"; mapped.flush()
    else:
        data="marker survived"
    observation={"identity":identity, "accessible":True, "data":data}
except OSError as error:
    observation={"identity":identity, "accessible":False, "errno":error.errno, "error":str(error)}
result.with_suffix(".result").write_text(json.dumps(observation))
'''


def wait_file(path, timeout=20):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"missing probe result: {path}")
        time.sleep(.05)
    return path.read_text()


def run_proof(root: Path, base: Path):
    base.mkdir(mode=0o755)
    report = {"root": str(root), "base": str(base), "commands": [], "rpc": []}
    agent = "proof1042"
    cli = [str(root / "bin/safeyolo"), "--root", str(root)]
    gofers = []
    started = False
    initial_run = None

    def save():
        (base / "observed.json").write_text(json.dumps(report, indent=2) + "\n")

    def command(argv, *, check=True, timeout=40, pass_fds=()):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                                timeout=timeout, pass_fds=pass_fds)
        row = {"argv": list(map(str, argv)), "exit": result.returncode,
               "stdout": result.stdout, "stderr": result.stderr}
        report["commands"].append(row)
        save()
        if check and result.returncode:
            raise RuntimeError(f"command exited {result.returncode}: {argv}")
        return result

    def guest(script, *, check=True):
        return command([*cli, "agent", "shell", agent, "-c", script], check=check)

    def holder(mode, target):
        result = base / "workspace" / (mode + "-holder")
        guest("( python3 -I -B /workspace/holder.py " + " ".join(map(shlex.quote,
              [mode, target, "/workspace/" + result.name])) +
              f'; printf \'%s\' "$?" > /workspace/{mode}-holder.exit )' +
              f" </dev/null > /workspace/{mode}.log 2>&1 &")
        identity = json.loads(wait_file(result.with_suffix(".ready")))
        return result, identity

    def release(result):
        result.with_suffix(".release").touch()
        # mmap access can end with SIGBUS instead of a Python exception.
        code = int(wait_file(result.with_suffix(".exit")))
        observation = (json.loads(result.with_suffix(".result").read_text())
                       if result.with_suffix(".result").exists() else {"accessible": None})
        return {**observation, "exit": code}

    def same_run():
        current = json.loads((root / "agents" / agent / "runtime.json").read_text())
        if any(current.get(key) != initial_run.get(key) for key in
               ("run_id", "holder_pid", "holder_token", "backend_pid", "backend_token")):
            raise RuntimeError("sandbox runtime record changed during the proof")
        context = root / "agents" / agent / "config-share/host-launch-context.json"
        if json.loads(context.read_text())["generation"] != generation:
            raise RuntimeError("sandbox incarnation changed during the proof")
        for kind in ("holder", "backend"):
            if process_start_token(current[kind + "_pid"]) != current[kind + "_token"]:
                raise RuntimeError(f"{kind} process identity changed")

    def rpc(method, target, read_only=False, descriptor=-1):
        same_run()
        path = root / "run" / ("runsc-" + container_id + ".sock")
        result = command([*namespace, sys.executable, Path(__file__).resolve(), "--rpc",
                          path, method, container_id, target, int(read_only), descriptor],
                         pass_fds=() if descriptor < 0 else (descriptor,))
        value = json.loads(result.stdout)
        report["rpc"].append({"method": method, "target": target, "result": value})
        save()
        same_run()
        return value

    def add_gofer(source, target, read_only=False):
        """Use the installed Gofer with its normal chroot/caps/seccomp setup."""
        same_run()
        directory = base / f"{source.name}-gofer-{len(gofers)}"
        directory.mkdir()
        spec = json.loads((root / "agents" / agent / "config.json").read_text())
        spec["root"] = {"path": str(source), "readonly": read_only}
        spec["mounts"] = []
        spec["hooks"] = {}
        (directory / "config.json").write_text(json.dumps(spec))
        sentry_end, gofer_end = socket.socketpair()
        rpc_parent, rpc_end = socket.socketpair()
        mounts_read, mounts_write = os.pipe()
        with (directory / "config.json").open("rb") as spec_file, (directory / "stderr.log").open("w") as log:
            arguments = [*namespace, "unshare", "--mount", "--ipc", "--uts", "--pid", "--net",
                         "--fork", "--kill-child=SIGKILL", "--", runsc, "--host-uds=open", "gofer",
                         "--bundle", directory, "--gofer-mount-confs=lisafs:none",
                         f"--spec-fd={spec_file.fileno()}", f"--io-fds={gofer_end.fileno()}",
                         f"--rpc-fd={rpc_end.fileno()}", f"--mounts-fd={mounts_write}", container_id]
            process = subprocess.Popen(list(map(str, arguments)), stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=log, start_new_session=True,
                                       pass_fds=(spec_file.fileno(), gofer_end.fileno(),
                                                 rpc_end.fileno(), mounts_write))
        gofers.append((process, directory))
        gofer_end.close()
        rpc_end.close()
        os.close(mounts_write)
        try:
            if not select.select([mounts_read], [], [], 15)[0]:
                raise TimeoutError(f"Gofer startup timed out: {directory}")
            mounts = os.read(mounts_read, 4096)
            if not mounts:
                raise RuntimeError(f"Gofer startup failed: {directory}")
            report.setdefault("gofers", []).append({"pid": process.pid, "argv": list(map(str, arguments)),
                                                    "resolved_mounts": mounts.decode()})
            value = rpc("Fs.Mount", target, read_only, sentry_end.fileno())
            if not value["success"]:
                raise RuntimeError(f"Fs.Mount failed: {value}")
        finally:
            sentry_end.close()
            rpc_parent.close()
            os.close(mounts_read)

    try:
        for name in ("workspace", "startup", "unrelated", "live", "readonly"):
            directory = base / name
            directory.mkdir()
            (directory / "host.txt").write_text((name + ":host-before").ljust(4096, "."))
        (base / "workspace/holder.py").write_text(GUEST_HOLDER)
        report["os"] = command(["uname", "-a"]).stdout.strip()
        report["host_version"] = command([root / "bin/safeyolo", "--version"]).stdout.strip()
        settings = tomllib.loads((root / "config.toml").read_text())["linux"]
        runsc = settings["runsc"]
        report["runsc_version"] = command([runsc, "--version"]).stdout.strip()
        command([*cli, "agent", "create", agent, "--workspace", base / "workspace",
                 "--memory", "1024", "--mount", f"{base}/startup:/mnt/proof1042startup",
                 "--mount", f"{base}/unrelated:/mnt/proof1042unrelated"])
        started = True  # Cleanup also reconciles a failed start.
        command([*cli, "agent", "start", agent, "--sandbox-only"], timeout=150)
        agent_dir = root / "agents" / agent
        initial_run = json.loads((agent_dir / "runtime.json").read_text())
        report["initial_run"] = initial_run
        generation = json.loads((agent_dir / "config-share/host-launch-context.json").read_text())["generation"]
        container_id = "safeyolo-" + generation
        namespace = ["nsenter", "--user", "--net", "--target", str(initial_run["holder_pid"]), "--"]
        report["uid_map"] = command([*namespace, "cat", "/proc/self/uid_map"]).stdout
        report["gid_map"] = command([*namespace, "cat", "/proc/self/gid_map"]).stdout
        report["guest_kernel"] = guest("uname -a").stdout.strip()
        marker, marker_identity = holder("marker", "/workspace")
        report["marker_before"] = marker_identity
        before = marker.with_suffix(".heartbeat").read_text()
        report["debug_mount_directory"] = command([
            *namespace, runsc, "--root", root / "run", "debug", "--mount",
            f"gofer:{base}/live:/mnt/proof1042live", container_id], check=False).stderr
        guest("test ! -e /mnt/proof1042live/host.txt && test ! -e /mnt/proof1042ro/host.txt")
        add_gofer(base / "live", "/mnt/proof1042live")
        guest("grep -q 'live:host-before' /mnt/proof1042live/host.txt && "
              "printf guest-write > /mnt/proof1042live/guest.txt")
        assert (base / "live/guest.txt").read_text() == "guest-write"
        add_gofer(base / "readonly", "/mnt/proof1042ro", read_only=True)
        guest("grep -q 'readonly:host-before' /mnt/proof1042ro/host.txt")
        refused = guest("printf forbidden > /mnt/proof1042ro/forbidden", check=False)
        assert refused.returncode != 0 and not (base / "readonly/forbidden").exists()
        for mode in ("file", "cwd", "mmap"):
            handle, identity = holder(mode, "/mnt/proof1042live")
            removed = rpc("Fs.Umount", "/mnt/proof1042live")
            with (base / "live/host.txt").open("r+") as changed:
                changed.write((mode + ":host-after-removal").ljust(64, "."))
                changed.flush()
                os.fsync(changed.fileno())
            observation = release(handle)
            report.setdefault("busy", []).append({"kind": mode, "identity": identity,
                                                  "umount": removed, "access_after": observation})
            save()
            if removed["success"]:
                add_gofer(base / "live", "/mnt/proof1042live")
        alias = guest("sudo -n mkdir -p /mnt/proof1042alias && "
                      "sudo -n mount --bind /mnt/proof1042live /mnt/proof1042alias", check=False)
        report["bind_alias"] = {"exit": alias.returncode, "stderr": alias.stderr}
        if alias.returncode == 0:
            report["bind_alias"]["umount_original"] = rpc("Fs.Umount", "/mnt/proof1042live")
            with (base / "live/host.txt").open("r+") as changed:
                changed.write("host-after-alias-removal")
                changed.flush()
                os.fsync(changed.fileno())
            report["bind_alias"]["access_after"] = guest("cat /mnt/proof1042alias/host.txt", check=False).stdout
            guest("sudo -n umount /mnt/proof1042alias")
        for target in ("/mnt/proof1042live", "/mnt/proof1042ro", "/mnt/proof1042startup"):
            removed = rpc("Fs.Umount", target)
            report.setdefault("removed", []).append({"target": target, "result": removed})
            if target != "/mnt/proof1042live" or alias.returncode != 0 or not report["bind_alias"]["umount_original"]["success"]:
                assert removed["success"], removed
            guest(f"test ! -e {target}/host.txt")
        guest("grep -q 'unrelated:host-before' /mnt/proof1042unrelated/host.txt && "
              "test -d /workspace && test -d /home/agent && test -f /safeyolo/host-mounts")
        for name in ("startup", "unrelated", "live", "readonly"):
            assert (base / name / "host.txt").is_file()
            if name != "live":
                assert (base / name / "host.txt").read_text() == (name + ":host-before").ljust(4096, ".")
        same_run()
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
        for process, directory in gofers:
            try:
                try:
                    code = process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    # This process group belongs only to this probe's Gofer.
                    # No shared startup Gofer is signalled during teardown.
                    os.killpg(process.pid, signal.SIGTERM)
                    code = process.wait(timeout=8)
            except (OSError, subprocess.SubprocessError) as error:
                failures.append(f"Gofer {process.pid} cleanup failed: {error}")
                code = None
            report.setdefault("gofer_cleanup", []).append({"pid": process.pid, "exit": code,
                                                            "stderr": (directory / "stderr.log").read_text()})
        failures.extend(surviving_processes(processes))
        if initial_run is not None:
            for kind in ("holder", "backend"):
                if process_start_token(initial_run[kind + "_pid"]) == initial_run[kind + "_token"]:
                    failures.append(f"{kind} remains live")
        report["cleanup_failures"] = failures
        save()
        if failures:
            raise RuntimeError(f"owned instance cleanup failed; inspect {base}/observed.json")
    print(json.dumps(report))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--rpc"]:
        rpc_child(sys.argv[2:])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--root", type=Path, required=True)
        parser.add_argument("--base", type=Path, required=True)
        args = parser.parse_args()
        run_proof(args.root.resolve(strict=True), args.base.absolute())
