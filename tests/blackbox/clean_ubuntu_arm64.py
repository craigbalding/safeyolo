#!/usr/bin/env python3
"""Run the public onboarding observer inside one stock Ubuntu ARM64 VM.

Run on the owned ubuntu-24.04-arm hosted runner, from the repository checkout.
The outer runner needs qemu-system-aarch64, qemu-img, cloud-localds, ARM64 EFI
firmware, curl and OpenSSH. These are fixture tools, not target prerequisites.
The VM uses software execution, its own stock kernel and disk, and no host
mounts. Cloud-init adds only an SSH key and hostname to the normal Ubuntu user.
No product, authentication, helper, package or host preparation is staged there.
Only reports/fixture.json and reports/observation.json may be uploaded.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import shlex
import signal
import socket
import subprocess
import time
from pathlib import Path

IMAGE_URL = "https://cloud-images.ubuntu.com/releases/noble/release-20260705/ubuntu-24.04-server-cloudimg-arm64.img"
# Ubuntu redirects this dated release to its HTTP archive. The trusted task
# supplies the independent digest; unverified disk bytes never reach QEMU.
IMAGE_ARCHIVE_URL = "http://cloud-images-archive.ubuntu.com/releases/noble/release-20260705/ubuntu-24.04-server-cloudimg-arm64.img"
IMAGE_SHA256 = "7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc"
IMAGE_BYTES = 615630848
HOSTNAME = "sy1050-clean-arm64"


def stamp():
    return {"at": dt.datetime.now(dt.UTC).isoformat(), "monotonic": time.monotonic()}


def verify_image(path):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if path.stat().st_size != IMAGE_BYTES or actual != IMAGE_SHA256:
        raise ValueError("Stock Ubuntu image size or SHA256 does not match the pinned public source.")


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


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Fixture interrupted; stopping its owned VM.")

    signal.signal(signal.SIGTERM, interrupted)
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
              "fixture": {"acceleration": "tcg,thread=multi", "cpus": 2, "memory_mib": 4096,
                          "disk_gib": 20, "host_mounts": [], "user": "ubuntu", "hostname": HOSTNAME},
              "commands": [], "limits": [
                  "Fixture setup is separate from the two product commands and is not clean-host product time.",
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
            result = subprocess.run(row["command"], stdout=stdout,
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
    try:
        run(["curl", "--fail", "--location", "--proto", "=http,https", "--proto-redir", "=http,https",
             "--max-time", "240", "--output", image, IMAGE_ARCHIVE_URL], 250)
        verify_image(image)
        report["image"]["verified"] = stamp()
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
        command = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "max", "-accel", "tcg,thread=multi",
                   "-smp", "2", "-m", "4096", "-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
                   "-nodefaults", "-display", "none", "-monitor", "none", "-no-reboot",
                   "-serial", f"file:{work / 'serial.log'}",
                   "-drive", f"if=virtio,format=qcow2,file={overlay}",
                   "-drive", f"if=virtio,format=raw,file={seed}", "-device", "virtio-rng-pci",
                   "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22"]
        with (work / "qemu.stderr").open("wb") as errors:
            vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
        report["vm"] = {"pid": vm.pid, "command": command, "started": stamp()}
        save()
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if vm.poll() is not None:
                raise RuntimeError("QEMU exited before the ordinary Ubuntu account became accessible.")
            probe = subprocess.run(ssh + ["true"], capture_output=True, timeout=15)
            if probe.returncode == 0:
                accessible = True
                break
            time.sleep(2)
        if not accessible:
            report["ssh_error"] = probe.stderr.decode(errors="replace")
            raise TimeoutError("Stock Ubuntu did not become accessible within the 10-minute boot budget.")
        report["vm"]["ssh_ready"] = stamp()
        run(ssh + ["cloud-init status --wait"], 180)
        # Copy only observer source, never product inputs, tools or credentials.
        run(ssh + ["mkdir -p observer/harness"], 20)
        scp = ["scp", "-q", "-i", str(key), "-P", str(args.ssh_port), "-o", "BatchMode=yes",
               "-o", f"UserKnownHostsFile={work / 'known_hosts'}"]
        here = Path(__file__).resolve().parent
        run(scp + [here / "ubuntu_onboarding.py", "ubuntu@127.0.0.1:observer/"], 30)
        run(scp + [here / "harness/process_identity.py", "ubuntu@127.0.0.1:observer/harness/"], 30)
        observer = ["python3", "-I", "-B", "observer/ubuntu_onboarding.py", "--host", HOSTNAME,
                    "--platform", "linux-arm64", "--observer-source", args.observer_source,
                    "--observation-dir", "/home/ubuntu/onboarding-observation"]
        report["vm"]["observer_started"] = stamp()
        with (work / "observer.stdout").open("wb") as log:
            result = run(ssh + [shlex.join(observer)], 1500, stdout=log, check=False, role="observer")
        report["observer_exit"] = result.returncode
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
            report["ssh_port_closed"] = port_closed(args.ssh_port)
            # All paths are created inside this invocation's new private directory.
            # Keep the small private logs for diagnosis; dispose disks and keys.
            for path in [image, overlay, seed, key, key.with_suffix(".pub"), work / "known_hosts",
                         work / "known_hosts.old", work / "user-data", work / "meta-data"]:
                path.unlink(missing_ok=True)
            report["owned_disks_and_keys_removed"] = True
            report["ended"] = stamp()
            save()
    return 0 if (report.get("observer_exit") == 0 and report.get("ssh_port_closed")
                 and not report.get("error") and not report.get("recovery_error")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
