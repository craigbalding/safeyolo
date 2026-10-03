"""Run one owned KVM lane on devstack, through the existing Rundeck harness.

Install this trusted checkout outside the guest. The host holds an advisory
lock for the whole invocation and retains its owner before provisioning.
Guest output never supplies host ownership or cleanup authority.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))

from safeyolo.runtime_identity import process_is_alive, process_start_token

if __package__:
    from ..installed_sections import PYTEST_SUITES, SECTIONS
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from installed_sections import PYTEST_SUITES, SECTIONS

JOBS = Path("/var/lib/rundeck/harness/jobs")
POOL = Path("/var/tmp/harness-vms")
MAX_BYTES = 8 * 1024 * 1024


def job_members(job: dict) -> list[int]:
    """Observe live members of the Linux session created for this host job."""
    pid, token = job["pid"], job["start_token"]
    if type(pid) is not int or pid <= 1 or not isinstance(token, str):
        raise ValueError("invalid recorded KVM job identity")
    current = process_start_token(pid)
    if current is not None and current != token:
        return []  # A reused leader PID proves the original session has gone.
    if current is None and process_is_alive(pid):
        raise ValueError("KVM job identity is unavailable")
    previous = None
    deadline = time.monotonic() + 10
    while True:
        members = []
        identities = {}
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            identities[path.name] = None  # Retain departures from the listing.
            try:
                fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError):
                continue  # Keep its departure in the identities to reconcile.
            session, alive = int(fields[3]), fields[0] != "Z"
            identities[path.name] = (session, fields[19], alive)
            if session == pid and alive:
                members.append(int(path.name))
        if members:
            return members
        # A parent may fork and exit after enumeration, hiding its child in
        # this pass. Reconcile fresh PID/session/start identities, including
        # departed and zombie entries, before accepting an empty observation.
        if identities == previous:
            return []
        previous = identities
        if time.monotonic() >= deadline:
            raise TimeoutError("KVM session inactivity could not be established")


def stop_job(job: dict) -> None:
    """Kill only the owned session and establish inactivity within a deadline."""
    deadline = time.monotonic() + 10
    while members := job_members(job):
        for pid in members:
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue  # This member exited after the session snapshot.
            try:
                # Job control creates other groups inside the owned session.
                # Pin each signal to its process, never a reusable group number.
                if os.getsid(pid) == job["pid"]:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass  # A departed/reused PID cannot redirect the opened handle.
            finally:
                os.close(descriptor)
        if time.monotonic() >= deadline:
            raise TimeoutError("owned KVM job survived termination")
        time.sleep(0.05)


def require_inactive_job(row: dict) -> None:
    if row.get("job") is not None and job_members(row["job"]):
        raise ValueError("previous KVM job is still active")


def command(arguments: list[str], *, timeout: int = 60, owner: dict | None = None) -> str:
    """Own job descendants through timeout/cancellation before resource cleanup."""
    with tempfile.TemporaryFile(mode="w+", dir=POOL) as output, tempfile.TemporaryFile(mode="w+", dir=POOL) as error:
        process = subprocess.Popen(arguments, stdout=output, stderr=error, text=True, start_new_session=True)
        job = {"pid": process.pid, "start_token": process_start_token(process.pid)}
        try:
            if owner is not None:
                owner["job"] = job
                save_owner(owner)
            deadline = time.monotonic() + timeout
            # WNOWAIT keeps the leader unreaped, reserving its PID/session ID
            # until the group is stopped. Neither a foreign PID nor a new
            # process group can take that ID between observation and signal.
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                time.sleep(0.01)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The original group is absent; the unreaped PID cannot be reused.
            try:
                stop_job(job)
            finally:
                process.wait(timeout=10)
            if owner is not None:
                owner.pop("job")
                save_owner(owner)
        output.seek(0)
        error.seek(0)
        stdout, stderr = output.read(), error.read()
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, arguments, stdout, stderr)
        return stdout


def harness_json(output: str, fields: set[str]) -> dict:
    """Read the one structured harness result, independently of wrapper exit."""
    found = []
    for line in output.splitlines():
        start = line.find("{")
        if start < 0:
            continue
        try:
            row = json.loads(line[start:])
        except json.JSONDecodeError:
            continue  # Harness progress is not its structured result.
        if isinstance(row, dict) and fields <= row.keys():
            found.append(row)
    if len(found) != 1:
        raise ValueError("missing or ambiguous harness result")
    return found[0]


def inventory() -> dict:
    row = harness_json(command(["bash", str(JOBS / "list_guests.sh")]), {"guests", "volumes"})
    if (not isinstance(row["guests"], list) or not isinstance(row["volumes"], list)
            or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                   or not isinstance(item.get("state"), str) for item in row["guests"])
            or any(not isinstance(name, str) for name in row["volumes"])):
        raise ValueError("invalid harness inventory")
    return row


def lease() -> str | None:
    try:
        return (POOL / ".guest-lease").read_text().strip() or None
    except FileNotFoundError:
        return None


def save_owner(row: dict) -> None:
    path = POOL / ".issue889-owner.json"
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as stream:
        json.dump(row, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def owned_guest(name: str, owner: str) -> None:
    """Require the unique host-recorded owner and exact libvirt disk bindings."""
    if re.fullmatch(rf"sy-{re.escape(owner)}-[0-9]{{1,20}}", name) is None:
        raise ValueError("domain does not belong to this attempt")
    for suffix in (".qcow2", "-seed.iso"):
        path = POOL / f"{name}{suffix}"
        if path.is_symlink():
            raise ValueError("owned disk binding is a symlink")
    if name not in command(["virsh", "list", "--all", "--name"]).splitlines():
        return  # Undefined owned disks are inactive; the journal binds their exact name.
    document = ET.fromstring(command(["virsh", "dumpxml", name]))
    paths = {disk.attrib["file"] for disk in document.findall("./devices/disk/source") if "file" in disk.attrib}
    expected = {str(POOL / f"{name}.qcow2"), str(POOL / f"{name}-seed.iso")}
    if document.findtext("name") != name or not paths or not paths <= expected or str(POOL / f"{name}.qcow2") not in paths:
        raise ValueError("domain disk bindings do not belong to this attempt")


def removed(name: str) -> bool:
    """Observe the domain, disk, seed and lease after error-suppressing teardown."""
    names = command(["virsh", "list", "--all", "--name"]).splitlines()
    current = inventory()
    return (name not in names and name not in {row["name"] for row in current["guests"]}
            and not {f"{name}.qcow2", f"{name}-seed.iso"} & set(current["volumes"])
            and not (POOL / f"{name}.qcow2").exists() and not (POOL / f"{name}-seed.iso").exists()
            and lease() != name)


def cleanup(row: dict, *, stale: bool = False) -> bool:
    """Stale reclamation requires independently inactive owner AND resource."""
    name = row.get("guest_name")
    if re.fullmatch(r"issue889-[0-9a-f]{32}", row["owner"]) is None:
        raise ValueError("invalid recorded hardware owner")
    if stale:
        require_inactive_owner(row)
    require_inactive_job(row)
    if name is None:
        current = inventory()
        names = {guest["name"] for guest in current["guests"]}
        names |= {re.sub(r"(?:\.qcow2|-seed\.iso)$", "", item) for item in current["volumes"]}
        candidates = [name for name in names if re.fullmatch(rf"sy-{re.escape(row['owner'])}-[0-9]{{1,20}}", name)]
        if len(candidates) > 1:
            raise ValueError("ambiguous owned provision result")
        name = candidates[0] if candidates else None
        if name is None:
            return True
        row["guest_name"] = name
        save_owner(row)
    if removed(name):
        return True
    owned_guest(name, row["owner"])
    if stale:
        if (name in command(["virsh", "list", "--all", "--name"]).splitlines()
                and command(["virsh", "domstate", name]).strip() != "shut off"):
            raise ValueError("previous owned KVM resource is still active")
    command(["bash", str(JOBS / "teardown.sh"), name], timeout=180, owner=row)
    return removed(name)


def require_inactive_owner(row: dict) -> None:
    pid = row["pid"]
    if process_is_alive(pid):
        token = process_start_token(pid)
        if token is None or token == row["start_token"]:
            raise ValueError("previous KVM owner is still active or unknown")


def absent_owner(owner: str) -> bool:
    """A missing journal is insufficient when an exact owned resource remains."""
    current = inventory()
    names = [guest["name"] for guest in current["guests"]]
    names.extend(current["volumes"])
    names.extend(command(["virsh", "list", "--all", "--name"]).splitlines())
    names.extend(path.name for path in POOL.glob(f"sy-{owner}-*"))
    if lease():
        names.append(lease())
    return not any(name.startswith(f"sy-{owner}-") for name in names)


def preflight() -> dict:
    """Check current capacity and preserve active or leased foreign resources."""
    with Path("/dev/kvm").open("rb") as device:
        if fcntl.ioctl(device, 0xAE00, 0) != 12:
            raise ValueError("KVM API is unavailable")
    available = int(re.search(r"^MemAvailable:\s+([0-9]+)", Path("/proc/meminfo").read_text(), re.M)[1]) * 1024
    free = shutil.disk_usage(POOL).free
    if available < 10 * 1024**3 or free < 90 * 1024**3 or (os.cpu_count() or 0) < 4:
        raise ValueError("capacity for the selected 4-vCPU/10-GiB/90-GiB guest is unavailable")
    row = inventory()
    if lease() or any(guest["state"] != "shut off" for guest in row["guests"]):
        raise ValueError("harness contains a leased or active foreign owner")
    return {"kvm_api": 12, "available_memory_bytes": available, "free_disk_bytes": free, "cpus": os.cpu_count()}


def guest_exit(row: dict, expected_ip: str) -> int:
    if row["ip"] != expected_ip or type(row["exit_code"]) is not int or type(row["timed_out"]) is not bool:
        raise ValueError("invalid guest execution identity or exit")
    for name in ("stdout_b64", "stderr_b64"):
        base64.b64decode(row[name], validate=True)
    if row["timed_out"] or row["exit_code"] != 0:
        return row["exit_code"] if row["exit_code"] > 0 else 2
    return 0


def fetched_report(row: dict, path: str) -> dict:
    if row["path"] != path or row["truncated"] is not False or type(row["size"]) is not int:
        raise ValueError("required artifact is mismatched or truncated")
    data = base64.b64decode(row["content_b64"], validate=True)
    if len(data) > MAX_BYTES or len(data) != row["size"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ValueError("required artifact transfer differs from its hash or size")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("required summary is not a mapping")
    return result


def report_names(lane: str) -> tuple[str, ...]:
    """Select runner reports from its maintained sections, never extensions."""
    names = ["installed-sections.json", "installed-summary.json"]
    for section in SECTIONS[lane]:
        if section == "continuity":
            names.append("continuity/installed-continuity.json")
        else:
            names.extend((f"{section}/doctor.json", f"{section}/installed-rust-runtime.json"))
            if section == "isolation":
                names.extend(f"isolation/pytest-{suite}.json" for suite in PYTEST_SUITES)
            else:
                names.append(f"{section}/installed-{section}.json")
    return tuple(names)


def retain_reports(ip: str, root: str, owner: str) -> list[str]:
    """Keep named private reports on devstack before destroying the guest."""
    target = JOBS.parent / "evidence" / owner
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    missing = []
    for name in report_names("kvm"):
        path = f"{root}/{name}"
        try:
            fetched = harness_json(command(["bash", str(JOBS / "ssh_fetch.sh"), ip, path, str(MAX_BYTES)]),
                                   {"path", "size", "sha256", "content_b64", "truncated"})
            data = fetched_report(fetched, path)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            missing.append(name)
            continue  # Missing/invalid evidence remains explicit; owned teardown still runs.
        output = target / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(data))
    return missing


def fetch_guest_reports(ip: str, run_id: str, owner: str) -> tuple[dict, list[str]]:
    """Retrieve every named private report before the guest is destroyed."""
    # ssh_fetch's path is explicit; it does not expand a shell $HOME.
    home = harness_json(command(["bash", str(JOBS / "ssh_exec.sh"), ip,
                                 base64.b64encode(b"printf '%s' \"$HOME\"").decode(), "30"]),
                        {"ip", "exit_code", "stdout_b64", "stderr_b64", "timed_out"})
    if guest_exit(home, ip):
        raise ValueError("guest report root is unavailable")
    home_path = base64.b64decode(home["stdout_b64"], validate=True).decode().strip()
    if not home_path.startswith("/") or "\n" in home_path:
        raise ValueError("guest report root is not an absolute path")
    path = f"{home_path}/hardware-{run_id}/results/installed-summary.json"
    fetched = harness_json(command(["bash", str(JOBS / "ssh_fetch.sh"), ip, path, str(MAX_BYTES)]),
                           {"path", "size", "sha256", "content_b64", "truncated"})
    summary = fetched_report(fetched, path)
    return summary, retain_reports(ip, str(Path(path).parent), owner)


def run_lane(owner: str, revision: str, run_id: str, timeout: int) -> dict:
    """Keep host teardown independent of guest exit, timeout or lost SSH."""
    result = {"owner": owner, "source_revision": revision, "run_id": run_id,
              "guest_name": None, "exit": None, "summary": None, "cleanup": "unverified", "stage": "preflight"}
    with (POOL / ".issue889.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal = POOL / ".issue889-owner.json"
        if journal.exists():
            previous = json.loads(journal.read_text())
            if not cleanup(previous, stale=True):
                raise ValueError("previous owned cleanup cannot be established")
            journal.unlink()
        result["platform"] = preflight()
        if not absent_owner(owner):
            raise ValueError("run owner already has guest or disk state; a fresh attempt is required")
        row = {"owner": owner, "pid": os.getpid(), "start_token": process_start_token(os.getpid()), "guest_name": None}
        if row["start_token"] is None:
            raise ValueError("host owner process identity is unavailable")
        save_owner(row)
        try:
            result["stage"] = "allocation"
            allocation = harness_json(command([
                "bash", str(JOBS / "provision.sh"), "--scenario", owner, "--safeyolo-ref", revision,
                "--flavor", "full", "--distro", "ubuntu", "--reuse", "--vcpus", "4", "--mem", "10240", "--disk", "90",
            ], timeout=900, owner=row), {"guest_name", "guest_ip", "safeyolo_sha"})
            if allocation["safeyolo_sha"] != revision:
                raise ValueError("provisioned source differs from selected commit")
            name = allocation["guest_name"]
            owned_guest(name, owner)
            ip = str(ipaddress.IPv4Address(allocation["guest_ip"]))
            if not ipaddress.ip_address(ip).is_private:
                raise ValueError("guest transport address is outside the private harness")
            row["guest_name"] = result["guest_name"] = name
            save_owner(row)
            root = f"$HOME/hardware-{run_id}"
            # The fresh guest gets public source and no host principals. The
            # maintained runner prepares once and selects every default section.
            script = ("set -euo pipefail\n"
                      f"mkdir {root}\ncd {root}\n"
                      "git init source\ngit -C source remote add origin https://github.com/craigbalding/safeyolo.git\n"
                      f"git -C source fetch --depth=1 origin {revision}\ngit -C source checkout --detach FETCH_HEAD\n"
                      "python3 - <<'PY'\nimport fcntl\nwith open('/dev/kvm', 'rb') as dev:\n"
                      "    assert fcntl.ioctl(dev, 0xAE00, 0) == 12\nPY\n"
                      f"cd source\n./tests/blackbox/run-installed.sh kvm --install-commit {revision} "
                      f"--run-id {run_id} --state-parent .. --artifacts ../results\n")
            result["stage"] = "execution"
            executed = harness_json(command(["bash", str(JOBS / "ssh_exec.sh"), ip,
                                            base64.b64encode(script.encode()).decode(), str(timeout)],
                                            timeout=timeout + 90, owner=row),
                                    {"ip", "exit_code", "stdout_b64", "stderr_b64", "timed_out"})
            result["exit"] = guest_exit(executed, ip)
            result["stage"] = "report"
            result["summary"], result["missing_reports"] = fetch_guest_reports(ip, run_id, owner)
            result["stage"] = "report" if result["missing_reports"] else None
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            # Preserve the failed stage, without publishing raw host/guest logs.
            result["exit"] = result["exit"] or 2
        finally:
            try:
                stopped = cleanup(row)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ET.ParseError):
                stopped = False
            result["guest_name"] = row["guest_name"]
            result["cleanup"] = "verified" if stopped else "failed"
            if stopped:
                journal.unlink()
    return result


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify", "cleanup", "preflight"))
    parser.add_argument("--owner", required=True)
    parser.add_argument("--install-commit")
    parser.add_argument("--run-id")
    parser.add_argument("--guest-name")
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    args = parser.parse_args()
    if re.fullmatch(r"issue889-[0-9a-f]{32}", args.owner) is None or args.timeout_seconds < 1:
        parser.error("a unique hardware owner and positive deadline are required")
    for item, size in ((args.install_commit, 40), (args.run_id, 32)):
        if args.action == "run" and (item is None or re.fullmatch(rf"[0-9a-f]{{{size}}}", item) is None):
            parser.error("run requires the full selected commit and invocation identity")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if args.action == "run":
        result = run_lane(args.owner, args.install_commit, args.run_id, args.timeout_seconds)
    elif args.action == "preflight":
        result = preflight()
    elif args.action == "cleanup":
        with (POOL / ".issue889.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = POOL / ".issue889-owner.json"
            if not path.exists():
                result = {"owner": args.owner, "removed": absent_owner(args.owner)}
            else:
                row = json.loads(path.read_text())
                if row["owner"] != args.owner:
                    raise ValueError("KVM journal belongs to a different owner")
                require_inactive_owner(row)
                stopped = cleanup(row)
                result = {"owner": args.owner, "guest_name": row["guest_name"], "removed": stopped}
                if stopped:
                    path.unlink()
    else:
        if args.guest_name is None or re.fullmatch(rf"sy-{re.escape(args.owner)}-[0-9]{{1,20}}", args.guest_name) is None:
            parser.error("verify requires this owner's exact guest name")
        journal = POOL / ".issue889-owner.json"
        if journal.exists():
            row = json.loads(journal.read_text())
            if row["owner"] != args.owner:
                raise ValueError("KVM journal belongs to a different owner")
            require_inactive_job(row)
        result = {"owner": args.owner, "guest_name": args.guest_name, "removed": removed(args.guest_name)}
    print("HARDWARE_RESULT=" + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
