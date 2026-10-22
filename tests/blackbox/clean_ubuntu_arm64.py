#!/usr/bin/env python3
"""Run the public onboarding observer inside one stock Ubuntu ARM64 VM.

Run on the owned ubuntu-24.04-arm hosted runner, from the repository checkout.
The outer runner needs qemu-system-aarch64, qemu-img, cloud-localds, ARM64 EFI
firmware, curl and OpenSSH. These are fixture tools, not target prerequisites.
The VM uses software execution, its own stock kernel and disk, and no host
mounts. Cloud-init adds only an SSH key and hostname to the normal Ubuntu user.
No product, vendor authentication, helper, package or host preparation is staged there.
Only reports/fixture.json and reports/observation.json may be uploaded.
Full boot logs and product terminal output remain private.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

IMAGE_URL = "https://cloud-images.ubuntu.com/releases/noble/release-20260705/ubuntu-24.04-server-cloudimg-arm64.img"
# Ubuntu redirects this dated release to its HTTP archive. The trusted task
# supplies the independent digest; unverified disk bytes never reach QEMU.
IMAGE_ARCHIVE_URL = "http://cloud-images-archive.ubuntu.com/releases/noble/release-20260705/ubuntu-24.04-server-cloudimg-arm64.img"
IMAGE_SHA256 = "7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc"
IMAGE_BYTES = 615630848
HOSTNAME = "sy1050-clean-arm64"
CPU_MODEL = "cortex-a72"
GUEST_INDEX = "sha256:14359301826746d088f124205de232c77c40567871550d38b035e6bfb53e5a2e"


def stamp():
    return {"at": dt.datetime.now(dt.UTC).isoformat(), "monotonic": time.monotonic()}


def verify_image(path):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if path.stat().st_size != IMAGE_BYTES or actual != IMAGE_SHA256:
        raise ValueError("Stock Ubuntu image size or SHA256 does not match the pinned public source.")


def verify_diagnostic_guest():
    """Stop before acquisition if the prior diagnostic's published guest changed."""
    # The pinned public bootstrap uses compat-v1 and has no guest-index option.
    # Check its public metadata without staging a guest, token or product input.
    repository = "craigbalding/safeyolo-guest"
    with urllib.request.urlopen(f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repository}:pull", timeout=30) as reply:
        token = json.load(reply)["token"]
    request = urllib.request.Request(f"https://ghcr.io/v2/{repository}/manifests/compat-v1",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.oci.image.index.v1+json"})
    with urllib.request.urlopen(request, timeout=30) as reply:
        index = "sha256:" + hashlib.sha256(reply.read(1024 * 1024)).hexdigest()
    if index != GUEST_INDEX:
        raise ValueError(f"Published compat-v1 index is {index}; diagnostic requires {GUEST_INDEX}. No VM was started.")
    return {"repository": "ghcr.io/" + repository, "discovery_tag": "compat-v1", "index": index, **stamp()}


def stop_vm(vm):
    """Reap only the child created by this invocation, including a failed boot."""
    if vm.poll() is None:
        vm.terminate()
    try:
        vm.wait(timeout=30)
    except subprocess.TimeoutExpired:
        vm.kill()
        vm.wait(timeout=10)
    return {"returncode": vm.returncode, "reaped": True, **stamp()}


def port_closed(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return False
    except ConnectionRefusedError:
        return True


def boot_observation(path):
    """Retain selected OS startup operands without publishing the console."""
    try:
        data = path.read_bytes()
    except OSError as error:
        # A missing/unreadable console must stay visible without blocking
        # disposal of this invocation's VM, disks and private SSH key.
        return {"available": False, "error": str(error)}
    plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data).decode(errors="replace")
    lines = [line.strip() for line in re.split(r"[\r\n]+", plain) if line.strip()]
    patterns = {
        "kernel": r"Linux version ", "systemd": r"systemd \d+.*running in system mode",
        "apparmor": r"Finished.*apparmor.service",
        "cloud_init_local": r"Cloud-init.*running 'init-local'",
        "network": r"networkd-wait-online|Network is Online|Network Configuration",
        "cloud_init_network": r"Cloud-init.*running 'init'|Finished.*cloud-init.service.*Network Stage",
        "ssh": r"(?:Listening on|Started).*ssh\.(?:socket|service)|OpenBSD Secure Shell",
        "cloud_init_final": r"Cloud-init.*(?:modules:final|finished at)",
        "login": r"\blogin:", "last_wait": r"Job .*start running",
    }
    stages = {name: line[:400] for name, pattern in patterns.items() for line in lines if re.search(pattern, line)}
    notices = [line[:400] for line in lines if re.search(r"failed|error|panic|timed out|emergency", line, re.I)]
    return {"available": True, "bytes": len(data), "stages": stages, "error_or_warning_lines": notices[-6:],
            "scope": "Selected pre-observer OS lines, capped at 400 characters each. Missing markers do not prove a stage was not reached."}


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Fixture interrupted; stopping its owned VM.")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True, help="new private directory on disk-backed storage")
    parser.add_argument("--observer-source", required=True, help="exact source commit, separate from packaged product")
    parser.add_argument("--ssh-port", type=int, default=2222, help="unused outer localhost TCP port")
    args = parser.parse_args()
    if os.uname().machine != "aarch64":
        parser.error("Use the approved native ARM64 hosted runner.")
    if not port_closed(args.ssh_port):
        parser.error("The selected localhost SSH port is already occupied; it was preserved.")
    work = args.work_dir.resolve()
    work.mkdir(mode=0o700)
    reports = work / "reports"
    reports.mkdir()
    report = {"started": stamp(), "observer_source": args.observer_source,
              "image": {"url": IMAGE_URL, "archive_url": IMAGE_ARCHIVE_URL,
                        "sha256": IMAGE_SHA256, "bytes": IMAGE_BYTES},
              "outer": {"uname": list(os.uname()), "uid": os.getuid(),
                        "kvm_present": Path("/dev/kvm").exists()},
              "fixture": {"acceleration": "tcg,thread=multi", "cpu_model": CPU_MODEL,
                          "cpus": 2, "memory_mib": 4096,
                          "disk_gib": 20, "host_mounts": [], "user": "ubuntu", "hostname": HOSTNAME},
              "commands": [], "limits": [
                  "Fixture setup is separate from the two product commands and is not clean-host product time.",
                  "Fixture monotonic times belong to the outer runner; observation.json uses the target VM's clock.",
                  "Software execution affects timings. No hardware-accelerated latency claim.",
                  "No existing vendor account is supplied to this hosted VM. Signed-out startup is not a first task."]}
    output = reports / "fixture.json"

    def save():
        output.write_text(json.dumps(report, indent=2) + "\n")

    def run(command, timeout, *, stdout=subprocess.PIPE, check=True, role="fixture"):
        row = {"role": role, "command": list(map(str, command)), **stamp()}
        report["commands"].append(row)
        save()
        try:
            result = subprocess.run(row["command"], stdin=subprocess.DEVNULL, stdout=stdout,
                                    stderr=subprocess.PIPE, timeout=timeout)
            row["exit"] = result.returncode
            row["stderr"] = result.stderr.decode(errors="replace")[-4096:]
            if check:
                result.check_returncode()
            return result
        except (OSError, subprocess.SubprocessError) as error:
            row["error"] = str(error)
            raise
        finally:
            row["ended"] = stamp()
            save()

    image, overlay, seed = [work / name for name in ["ubuntu.img", "overlay.qcow2", "seed.img"]]
    key = work / "ssh-key"
    ssh = ["ssh", "-i", str(key), "-p", str(args.ssh_port), "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={work / 'known_hosts'}",
           "-o", "ConnectTimeout=5", "ubuntu@127.0.0.1"]
    vm = None
    accessible = False
    save()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        report["diagnostic_guest_preflight"] = verify_diagnostic_guest()
        save()
        run(["curl", "--fail", "--location", "--proto", "=http,https", "--proto-redir", "=http,https",
             "--max-time", "240", "--output", image, IMAGE_ARCHIVE_URL], 250)
        verify_image(image)
        report["image"]["verified"] = stamp()
        print("Pinned stock Ubuntu image verified.", flush=True)
        info = json.loads(run(["qemu-img", "info", "--output=json", image], 10).stdout)
        if info["format"] != "qcow2":
            raise ValueError("Expected the pinned Ubuntu qcow2 disk.")
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, "20G"], 20)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], 10)
        (work / "user-data").write_text("#cloud-config\nhostname: " + HOSTNAME
            + "\nssh_authorized_keys:\n  - " + key.with_suffix(".pub").read_text().strip()
            + "\npackage_update: false\npackage_upgrade: false\n")
        (work / "meta-data").write_text(f"instance-id: {work.name}\nlocal-hostname: {HOSTNAME}\n")
        run(["cloud-localds", seed, work / "user-data", work / "meta-data"], 20)
        report["qemu_version"] = run(["qemu-system-aarch64", "--version"], 10).stdout.decode()
        command = ["qemu-system-aarch64", "-machine", "virt", "-cpu", CPU_MODEL, "-accel", "tcg,thread=multi",
                   "-smp", "2", "-m", "4096", "-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
                   "-nodefaults", "-display", "none", "-monitor", "none", "-no-reboot",
                   "-serial", f"file:{work / 'serial.log'}",
                   "-drive", f"if=virtio,format=qcow2,file={overlay}",
                   "-drive", f"if=virtio,format=raw,file={seed}", "-device", "virtio-rng-pci",
                   "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22",
                   # Boot from the stock disk, without an unused PXE ROM dependency.
                   "-device", "virtio-net-pci,netdev=net0,romfile="]
        with (work / "qemu.stderr").open("wb") as errors:
            vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
        report["vm"] = {"pid": vm.pid, "command": command, "started": stamp()}
        print("Owned software VM started; waiting for the ordinary Ubuntu account.", flush=True)
        save()
        deadline = time.monotonic() + 600
        report["ssh_probe_count"] = 0
        while time.monotonic() < deadline:
            if vm.poll() is not None:
                raise RuntimeError("QEMU exited before the ordinary Ubuntu account became accessible.")
            report["ssh_probe_count"] += 1
            ssh_probe = {"started": stamp()}
            report["last_ssh_probe"] = ssh_probe
            try:
                probe = subprocess.run(ssh + ["true"], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
                ssh_probe.update(exit=probe.returncode, stderr=probe.stderr.decode(errors="replace")[-2048:])
                if probe.returncode == 0:
                    accessible = True
                    break
            except subprocess.TimeoutExpired as error:
                # A slow handshake is a failed readiness sample, not a reason
                # to discard the remaining boot budget or its partial stderr.
                ssh_probe.update(timeout=True, error=str(error), stderr=(error.stderr or b"").decode(errors="replace")[-2048:])
            finally:
                ssh_probe["ended"] = stamp()
                save()
            time.sleep(2)
        if not accessible:
            raise TimeoutError("Stock Ubuntu did not become accessible within the 10-minute boot budget.")
        report["vm"]["ssh_ready"] = stamp()
        report["boot"] = boot_observation(work / "serial.log")
        print("Ordinary Ubuntu account accessible; waiting for cloud-init.", flush=True)
        run(ssh + ["cloud-init status --wait"], 180)
        # Copy only observer source, never product inputs, tools or credentials.
        run(ssh + ["mkdir -p observer/harness"], 20)
        scp = ["scp", "-q", "-i", str(key), "-P", str(args.ssh_port), "-o", "BatchMode=yes",
               "-o", f"UserKnownHostsFile={work / 'known_hosts'}"]
        here = Path(__file__).resolve().parent
        run(scp + [here / "ubuntu_onboarding.py", "ubuntu@127.0.0.1:observer/"], 30)
        run(scp + [here / "harness/process_identity.py", "ubuntu@127.0.0.1:observer/harness/"], 30)
        # The remote deadline ends the observer before SSH recovery starts.
        # Killing only the outer SSH client could leave the observer writing.
        observer = ["timeout", "--signal=INT", "--kill-after=120s", "23m",
                    "python3", "-I", "-B", "observer/ubuntu_onboarding.py", "--host", HOSTNAME,
                    "--platform", "linux-arm64", "--observer-source", args.observer_source,
                    "--observation-dir", "/home/ubuntu/onboarding-observation"]
        report["vm"]["observer_started"] = stamp()
        print("Starting the public bootstrap observer inside Ubuntu.", flush=True)
        with (work / "observer.stdout").open("wb") as log:
            result = run(ssh + [shlex.join(observer)], 1500, stdout=log, check=False, role="observer")
        report["observer_exit"] = result.returncode
        print(f"Public observer returned {result.returncode}; collecting its owned cleanup result.", flush=True)
    except (OSError, ValueError, subprocess.SubprocessError, TimeoutError, RuntimeError) as error:
        report["error"] = str(error)
    finally:
        try:
            if accessible:
                # Recovery is scoped by the observer's own recorded account,
                # hostname, project and process births. Never repeat installation.
                recovery = ["python3", "-I", "-B", "observer/ubuntu_onboarding.py", "--host", HOSTNAME,
                            "--platform", "linux-arm64", "--cleanup-only",
                            "--observation-dir", "/home/ubuntu/onboarding-observation"]
                run(ssh + [shlex.join(recovery)], 100, check=False, role="observer")
                result = run(ssh + ["cat onboarding-observation/result.json"], 15, check=False, role="observer")
                if result.returncode == 0:
                    observed = json.loads(result.stdout)
                    (reports / "observation.json").write_text(json.dumps(observed, indent=2) + "\n")
                run(ssh + ["sudo -n shutdown -h now"], 10, check=False)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report["recovery_error"] = str(error)
        finally:
            if vm is not None:
                report["vm_cleanup"] = stop_vm(vm)
                report["qemu_stderr"] = (work / "qemu.stderr").read_text(errors="replace")[-4096:]
                if not accessible:
                    report["boot"] = boot_observation(work / "serial.log")
            report["ssh_port_closed"] = port_closed(args.ssh_port)
            # All paths are created inside this invocation's new private directory.
            # Keep the small private logs for diagnosis; dispose disks and keys.
            for path in [image, overlay, seed, key, key.with_suffix(".pub"), work / "known_hosts",
                         work / "known_hosts.old", work / "user-data", work / "meta-data"]:
                path.unlink(missing_ok=True)
            report["owned_disks_and_keys_removed"] = True
            report["ended"] = stamp()
            save()
            print("Owned VM teardown recorded.", flush=True)
    return 0 if (report.get("observer_exit") == 0 and report.get("ssh_port_closed")
                 and not report.get("error") and not report.get("recovery_error")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
