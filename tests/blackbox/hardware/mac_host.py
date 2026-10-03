"""Own one offline physical-Mac lane and its independent process teardown.

Run from the trusted installation through Bristol sy-agent SSH. No hardware
control or publication credentials are installed in the tested run tree.
The foreground invocation cleans up after timeout, cancellation and SSH loss.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from harness.macos_process_argv import process_argv
    from installed_sections import check_vz_ports, cleanup_instance, owned_processes
else:
    from ..harness.macos_process_argv import process_argv
    from ..installed_sections import check_vz_ports, cleanup_instance, owned_processes

from safeyolo.runtime_identity import process_is_alive, process_start_token


def process_arguments(pid: int) -> list[str]:
    """Read actual argv, including on the ps-denied Bristol account."""
    if platform.system() == "Linux":
        return Path(f"/proc/{pid}/cmdline").read_bytes().decode().rstrip("\0").split("\0")
    return [os.fsdecode(value) for value in process_argv(pid)]


def same_process_live(row: dict) -> bool:
    """Observe the recorded identity; zombies and reused PIDs have exited."""
    pid = row["pid"]
    if type(pid) is not int or pid <= 1 or not isinstance(row["start_token"], str):
        raise ValueError("invalid recorded hardware process")
    if not process_is_alive(pid):
        return False
    token = process_start_token(pid)
    if token is None:
        if not process_is_alive(pid):
            return False  # The owned process exited between state and identity reads.
        raise ValueError("cannot inspect hardware process identity")
    if token != row["start_token"]:
        return False
    return True


def is_owned_process(row: dict, roots: tuple[Path, ...]) -> bool:
    """A marker also needs an actual argv in this run before it can signal."""
    if not same_process_live(row):
        return False
    pid, token = row["pid"], row["start_token"]
    try:
        arguments = process_arguments(pid)
    except (FileNotFoundError, ProcessLookupError):
        if not process_is_alive(pid):
            return False  # Kernel argv disappeared after the identity read.
        raise
    if not any(argument == str(root) or argument.startswith(str(root) + "/")
               for root in roots for argument in arguments):
        if not process_is_alive(pid) or process_start_token(pid) != token:
            return False  # An exited process can have an empty argv before reaping.
        raise ValueError("recorded process has no argument in the owned run tree")
    return True


def stop_processes(rows: list[dict], roots: tuple[Path, ...], timeout: float = 10) -> None:
    """Signal only verified identities and observe exit; time is never success."""
    for signum in (signal.SIGTERM, signal.SIGKILL):
        for row in rows:
            if is_owned_process(row, roots):
                try:
                    os.kill(row["pid"], signum)
                except ProcessLookupError:
                    pass  # The verified owned process exited before its signal.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not any(same_process_live(row) for row in rows):
                return
            time.sleep(0.1)
    if any(same_process_live(row) for row in rows):
        raise ValueError("owned hardware process survived teardown")


def save_owner(path: Path, row: dict) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as stream:
        json.dump(row, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def snapshot(row: dict, journal: Path) -> None:
    """Retain identities outside candidate state while each section is live."""
    state = Path(row["state_parent"])
    if str(state) not in row["created_trees"]:
        return  # A colliding pre-existing directory is foreign, not this run's state.
    seen = {(item["pid"], item["start_token"]) for item in row["processes"]}
    for section in state.glob("sy-vz-*/*"):
        if section.is_dir():
            for item in owned_processes(section):
                key = (item["pid"], item["start_token"])
                if key not in seen:
                    # Markers alone cannot give a foreign process signal authority.
                    if is_owned_process(item, (Path(row["run_root"]), state)):
                        row["processes"].append(item)
                        seen.add(key)
    save_owner(journal, row)


def verify(row: dict) -> bool:
    roots = (Path(row["run_root"]), Path(row["state_parent"]))
    if any(is_owned_process(item, roots) for item in row["processes"]):
        return False
    instances = roots[1].glob("sy-vz-*/*") if str(roots[1]) in row["created_trees"] else ()
    for instance in instances:
        if instance.is_dir() and any(same_process_live(item) for item in owned_processes(instance)):
            return False
    return not check_vz_ports()


def cleanup(row: dict) -> bool:
    """Current-attempt teardown can stop live owned resources after failure."""
    roots = (Path(row["run_root"]), Path(row["state_parent"]))
    state = roots[1]
    if str(state) not in row["created_trees"]:
        return not row["processes"] and not check_vz_ports()
    # Stop the caller first so it cannot launch another helper during teardown.
    stop_processes(row["processes"][:1], roots)
    failures = []
    for prepared in state.glob("sy-vz-*"):
        cli = prepared / "bin/safeyolo"
        if cli.is_file():
            for instance in prepared.iterdir():
                if instance.is_dir() and (instance / "config.yaml").is_file():
                    failures.extend(cleanup_instance(cli, instance, owner=instance.name == "lifecycle-owner"))
    stop_processes(row["processes"][1:], roots)
    # A runner killed between launch and the periodic snapshot still has its
    # exact owned marker. Observe and stop that identity before declaring exit.
    for instance in state.glob("sy-vz-*/*"):
        if instance.is_dir():
            stop_processes(owned_processes(instance), roots)
    return not failures and verify(row)


def recover(journal: Path) -> None:
    """Reclaim an old claim only after owner and resource inactivity are proven."""
    if not journal.exists():
        return
    row = json.loads(journal.read_text())
    pid = row["pid"]
    if process_is_alive(pid):
        token = process_start_token(pid)
        if token is None or token == row["start_token"]:
            raise ValueError("previous physical-Mac owner remains active or unknown")
    if not verify(row):
        raise ValueError("previous physical-Mac resources remain active")
    # Keep prior failed reports for diagnosis; release only the inactive claim.
    journal.unlink()


def preflight(root: Path, required_bytes: int) -> dict:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("physical Apple Silicon is required")
    model = subprocess.check_output(["sysctl", "-n", "hw.model"], text=True, timeout=10).strip()
    if not model.startswith("Mac") or "virtual" in model.lower():
        raise ValueError("a virtual macOS build host is not physical VZ evidence")
    memory = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=10))
    cpus = int(subprocess.check_output(["sysctl", "-n", "hw.ncpu"], text=True, timeout=10))
    statistics = subprocess.check_output(["vm_stat"], text=True, timeout=10)
    page_size = int(re.search(r"page size of ([0-9]+) bytes", statistics)[1])
    available = sum(int(re.search(rf"^{name}:\s+([0-9]+)", statistics, re.M)[1])
                    for name in ("Pages free", "Pages inactive", "Pages speculative")) * page_size
    free = shutil.disk_usage(root).free
    if cpus < 2 or available < 8 * 1024**3 or free < required_bytes:
        raise ValueError("physical host capacity is unavailable")
    if check_vz_ports():
        raise ValueError("one or more allocated VZ fixture ports are unavailable")
    return {"system": "Darwin", "machine": "arm64", "model": model,
            "memory_bytes": memory, "available_memory_bytes": available, "cpus": cpus, "free_disk_bytes": free}


def receive_inputs(root: Path, archive_input, archive_digest: str) -> None:
    """Bound and verify transferred bytes before extracting any candidate file."""
    archive = root / "inputs.tar"
    source = archive_input
    received = 0
    with archive.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            received += len(chunk)
            if received > 32 * 1024**3:
                raise ValueError("transferred input exceeds the disk-backed bound")
            output.write(chunk)
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != archive_digest:
            raise ValueError("transferred inputs differ from the Tart build digest")
    with tarfile.open(archive) as bundle:
        bundle.extractall(root, filter="data")


def run_lane(owner: str, root: Path, state: Path, python: Path, revision: str,
             run_id: str, digest: str, timeout: int, helper_timeout: int, journal: Path,
             archive_digest: str, *, archive_input=None) -> dict:
    """Invoke every maintained section offline through the signed deadline runner."""
    result = {"owner": owner, "source_revision": revision, "run_id": run_id,
              "exit": None, "cleanup": "unverified", "stage": "preflight"}
    row = {"owner": owner, "run_root": str(root), "state_parent": str(state), "pid": os.getpid(),
           "start_token": process_start_token(os.getpid()), "processes": [], "created_trees": []}
    if row["start_token"] is None:
        raise ValueError("physical-host owner identity is unavailable")
    with journal.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recover(journal)
        result["platform"] = preflight(root.parent, 10 * 1024**3)
        save_owner(journal, row)
        process = None
        try:
            result["stage"] = "transfer"
            root.mkdir(mode=0o700)
            row["created_trees"].append(str(root))
            save_owner(journal, row)
            state.mkdir(mode=0o700)
            row["created_trees"].append(str(state))
            save_owner(journal, row)
            receive_inputs(root, archive_input if archive_input is not None else sys.stdin.buffer, archive_digest)
            result["stage"] = "preflight"
            helper = root / "payload/bin/safeyolo-vm"
            subprocess.run([str(helper), "check"], check=True, capture_output=True, timeout=30)
            result["stage"] = "execution"
            env = {name: value for name, value in os.environ.items() if name in {
                "HOME", "USER", "PATH", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
            }}
            env.update(BASH_ENV="/dev/null", UV_OFFLINE="1", UV_PYTHON_DOWNLOADS="never", CARGO_BUILD_JOBS="1")
            arguments = [str(root / "source/tests/blackbox/run-installed.sh"), "vz", "--install-commit", revision,
                         "--run-id", run_id, "--staged-inputs", str(root / "payload"), "--staged-sha256", digest,
                         "--python", str(python), "--state-parent", str(state), "--artifacts", str(root / "results"),
                         "--vz-test-runner", "/Users/sy-agent/bin/run-vz-test", "--vz-test-timeout-seconds", str(helper_timeout)]
            with (root / "execution.log").open("xb") as log:
                process = subprocess.Popen(arguments, cwd=root / "source", env=env, stdout=log, stderr=log,
                                           start_new_session=True)
                token = process_start_token(process.pid)
                if token is None:
                    raise ValueError("section caller identity is unavailable")
                row["processes"].append({"pid": process.pid, "start_token": token})
                save_owner(journal, row)
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    snapshot(row, journal)
                    if time.monotonic() >= deadline:
                        raise TimeoutError("physical-Mac lane deadline expired")
                    time.sleep(0.2)
                result["exit"] = process.wait()
            result["stage"] = None
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
            result["exit"] = result["exit"] or 2
        finally:
            try:
                snapshot(row, journal)
                stopped = cleanup(row)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
                stopped = False
            if process is not None and process.poll() is None:
                # This still-live child cannot have been replaced by a foreign PID.
                process.kill()
            if process is not None:
                process.wait(timeout=15)
            result["cleanup"] = "verified" if stopped else "failed"
            if stopped:
                # Retain the journal for the second SSH teardown inspection.
                row["cleanup"] = "verified"
                save_owner(journal, row)
    return result


def release(row: dict) -> bool:
    """Remove verified inactive overlays and inputs; retain private reports/logs."""
    if not verify(row):
        return False
    identity = re.fullmatch(r"issue889-([0-9a-f]{32})", row["owner"])
    if identity is None:
        raise ValueError("invalid physical-host ownership record")
    root, state = Path(row["run_root"]), Path(row["state_parent"])
    if root.name != identity[1][:8] or state.name != identity[1][:8] or root.is_symlink() or state.is_symlink():
        raise ValueError("physical-host trees do not match the unique owner")
    # Never remove either trusted installation or an operator parent. These
    # exact child directories were created exclusively under the host lock.
    if str(state) in row["created_trees"] and state.exists():
        shutil.rmtree(state)
    if str(root) in row["created_trees"]:
        for name in ("source", "payload"):
            path = root / name
            if path.is_symlink():
                raise ValueError("transferred input directory became a symlink")
            if path.exists():
                shutil.rmtree(path)
        (root / "inputs.tar").unlink(missing_ok=True)
    return ((str(state) not in row["created_trees"] or not state.exists())
            and (str(root) not in row["created_trees"]
                 or not any((root / name).exists() for name in ("source", "payload", "inputs.tar"))))


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify", "release", "cleanup", "preflight"))
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--state-parent", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--install-commit")
    parser.add_argument("--run-id")
    parser.add_argument("--staged-sha256")
    parser.add_argument("--archive-sha256")
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    parser.add_argument("--helper-timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    if re.fullmatch(r"issue889-[0-9a-f]{32}", args.owner) is None:
        parser.error("a unique hardware owner is required")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if args.action == "preflight":
        result = preflight(args.run_root, 10 * 1024**3)
    elif args.action == "run":
        for item, length in ((args.install_commit, 40), (args.run_id, 32), (args.staged_sha256, 64), (args.archive_sha256, 64)):
            if not isinstance(item, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", item) is None:
                parser.error("run requires exact source, invocation and payload identities")
        if args.timeout_seconds < 1 or args.helper_timeout_seconds < 1:
            parser.error("positive deadlines are required")
        result = run_lane(args.owner, args.run_root, args.state_parent, args.python, args.install_commit,
                          args.run_id, args.staged_sha256, args.timeout_seconds, args.helper_timeout_seconds, args.journal,
                          args.archive_sha256)
    else:
        with args.journal.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            row = json.loads(args.journal.read_text())
            if row["owner"] != args.owner:
                raise ValueError("physical-host journal belongs to a different owner")
            pid = row["pid"]
            if process_is_alive(pid):
                token = process_start_token(pid)
                if token is None or token == row["start_token"]:
                    raise ValueError("original physical-Mac execution is still active or unknown")
            stopped = cleanup(row) if args.action == "cleanup" else verify(row)
            if stopped and args.action in {"release", "cleanup"}:
                stopped = release(row)
                if stopped:
                    args.journal.unlink()
            result = {"owner": args.owner, "removed": stopped}
    print("HARDWARE_RESULT=" + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
