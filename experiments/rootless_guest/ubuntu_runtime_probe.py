#!/usr/bin/env python3
"""Continue #1553 from its retained Ubuntu import, without acquiring a guest.

Sylab runs this as ordinary UID/GID 1000 on sy-1050-connected-8029-amd64.
Use the existing controller's Python environment and this checkout's blackbox
helpers. Only NEW_OUTPUT is created. The retained import and baseline stay
read-only; one disposable systrap agent and its proxy/Coord are stopped finally.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path

if __package__:
    from .import_guest import import_namespace, verify_archive
else:
    from import_guest import import_namespace, verify_archive

ARCHIVE_SHA = "1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe"
PRODUCT = "b6821094322e4ab261f4c149029839037fe43631"
PREPARED = Path("/home/agent/1562-b682-installed")
STAGE = Path("/home/agent/1553-native-import-b/published/extract-5ls7iw5p")
ARCHIVE = Path("/home/agent/1436-operator/guest-store/blobs/sha256") / ARCHIVE_SHA
REPOSITORY = Path(__file__).resolve().parents[2]


def compare_contents(archive, digest, stage, baseline):
    """Compare every regular rootfs payload, including equal-size mutations.

    This reads the archive; it neither extracts nor creates another inventory.
    Run inside the existing import namespace to read private mapped directories.
    Allocation and non-regular metadata are outside this content observation.
    """
    result = {"checked": 0, "bytes": 0, "mismatches": []}
    with archive.open("rb") as stream:
        verify_archive(stream, digest)
        with subprocess.Popen(["zstd", "-dc"], stdin=stream, stdout=subprocess.PIPE) as decoder:
            try:
                with tarfile.open(fileobj=decoder.stdout, mode="r|") as entries:
                    for entry in entries:
                        if not entry.isreg() or not entry.name.startswith("rootfs-tree/"):
                            continue
                        expected = hashlib.file_digest(entries.extractfile(entry), "sha256").hexdigest()
                        for kind, root in (("imported", stage), ("baseline", baseline)):
                            path = root / entry.name
                            if not stat.S_ISREG(path.lstat().st_mode):
                                result["mismatches"].append({"tree": kind, "path": entry.name, "type": "not regular"})
                                continue
                            with path.open("rb") as payload:
                                actual = hashlib.file_digest(payload, "sha256").hexdigest()
                            if actual != expected:
                                result["mismatches"].append({"tree": kind, "path": entry.name,
                                                             "expected": expected, "actual": actual})
                        result["checked"] += 1
                        result["bytes"] += entry.size
                while decoder.stdout.read(1024 * 1024):
                    pass
            finally:
                decoder.stdout.close()
            if decoder.wait() != 0:
                raise RuntimeError("Verified archive content decoding failed")
    return result


def guest_script(guest_root):
    """Exercise actual guest identity, persistent I/O, execution and metadata."""
    expected = 0 if guest_root else 1000
    return f"""set -eu
test "$(id -u)" = {expected}
test "$(id -g)" = {expected}
id
uname -srmo
cat /etc/os-release
for directory in /home/agent /workspace; do
  file=$directory/rootless1553-{expected}
  test ! -e "$file"
  printf '#!/bin/sh\\nprintf rootless1553-ok\\n' > "$file"
  chmod 0700 "$file"
  test "$("$file")" = rootless1553-ok
  stat -c '%n uid=%u gid=%g mode=%a size=%s blocks=%b' "$file"
done
stat -c '%n uid=%u gid=%g mode=%a type=%F' / /var/mail /usr/bin/id
readlink /etc/os-release
getcap /usr/bin/id
printf 'ROOTLESS1553_GUEST_OK uid={expected}\\n'
"""


def qualify(output):
    # Keep the experimental packet on the maintained native instance, command,
    # token-redaction and process-birth helpers. No product helper is duplicated.
    sys.path.insert(0, str(REPOSITORY / "tests/blackbox"))
    import tomlkit
    from guest_exec import guest_command_args
    from installed_host_smoke import _process_start_token
    from installed_linux_update import info, redact, sha
    from installed_sections import copy_prepared_nats, owned_processes, prepare_native_instance, surviving_processes

    assert platform.system() == "Linux" and platform.machine() == "x86_64"
    assert (os.getuid(), os.getgid()) == (1000, 1000)
    assert shutil.disk_usage(output.parent).free >= 5 * 1024**3 + 128 * 1024**2
    os.umask(0o022)  # New runtime directories must be traversable by mapped root.
    output.mkdir(mode=0o755)  # Existing output requires inspection, never replay.
    root, workspace = output / "instance", output / "workspace"
    report_path = output / "result.json"
    report_path.touch(mode=0o600)
    report = {"result": "incomplete", "started": time.time(), "uid": os.getuid(), "gid": os.getgid(),
              "platform": platform.uname()._asdict(), "os_release": Path("/etc/os-release").read_text(),
              "actions": [], "stage": str(STAGE), "cleanup_failures": []}
    tracked = []

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    def run(label, command, *, check=True, timeout=60):
        command = list(map(str, command))
        row = {"label": label, "command": command, "started": time.time()}
        report["actions"].append(row)
        save()
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            row.update(timeout=True, stdout=redact(error.stdout or "", root), stderr=redact(error.stderr or "", root))
            save()
            raise
        row.update(exit=result.returncode, stdout=redact(result.stdout, root), stderr=redact(result.stderr, root),
                   ended=time.time())
        save()
        if check and result.returncode:
            raise RuntimeError(f"{label}: exit {result.returncode}; preserve {report_path}")
        return result

    cli = PREPARED / "bin/safeyolo"

    def native(label, *arguments, **options):
        return run(label, [cli, "--root", root, *arguments], **options)

    try:
        save()
        report["package"] = dict(line.split("=", 1) for line in (PREPARED / "package-info").read_text().splitlines())
        assert report["package"]["source_commit"] == PRODUCT
        mapping = tomlkit.parse((PREPARED / "config.toml").read_text())["linux"]
        assert tuple(mapping[name] for name in ("uid_base", "gid_base", "host_uid", "host_gid")) == (100000, 100000, 1000, 1000)
        report["linux_settings"] = dict(mapping)
        report["prerequisites"] = {name: Path(name).read_text() for name in (
            "/etc/subuid", "/etc/subgid", "/proc/sys/kernel/apparmor_restrict_unprivileged_userns")}
        selected = json.loads((PREPARED / "share/guest-selection.json").read_text())
        assert selected["archive"]["digest"] == "sha256:" + ARCHIVE_SHA
        assert selected["compatibility"] == report["package"]["guest_compatibility"]
        baseline = Path(selected.get("installed_assets") or PREPARED / "share").resolve(strict=True)
        preparation = json.loads((STAGE.parent / "preparation.json").read_text())
        assert preparation["stage"] == str(STAGE) and preparation["archive_sha256"] == ARCHIVE_SHA
        assert preparation["result"].startswith("prepared;")
        report.update(selection=selected, preparation=preparation, imported_root=info(STAGE / "rootfs-tree"),
                      baseline=str(baseline), executables={name: sha(PREPARED / name) for name in (
                          "bin/safeyolo", "bin/safeyolo-proxy", "libexec/runsc", "host/namespace-entry")})
        run("host-filesystem", ["findmnt", "--json", "--target", output])
        # Retain all ordinary host tools except sudo in the candidate's PATH.
        # This does not claim a syscall trace or system-wide sudo revocation.
        commands = output / "commands"
        commands.mkdir()
        for directory in (Path("/usr/bin"), Path("/usr/sbin")):
            for executable in directory.iterdir():
                if executable.name not in {"sudo", "sudoedit"} and executable.is_file():
                    destination = commands / executable.name
                    if not destination.is_symlink():
                        destination.symlink_to(executable)
        os.environ.update(PATH=str(commands), SAFEYOLO_CONFIG_DIR=str(root), SAFEYOLO_LOGS_DIR=str(root / "logs"),
                          SAFEYOLO_COORD_DATA_DIR=str(root / "data/coord"), SAFEYOLO_RUNSC_PLATFORM="systrap",
                          SAFEYOLO_RUNSC_DEBUG="1", SAFEYOLO_NATS_TEST_INSTANCE=output.name, RUST_BACKTRACE="1")
        report["sudo_on_path"] = shutil.which("sudo")
        assert report["sudo_on_path"] is None
        assert f"commit={PRODUCT} profile=production" in run("cli-version", [cli, "--version"]).stdout
        run("runsc-version", [PREPARED / "libexec/runsc", "--version"])
        with import_namespace(PREPARED, 100000, 100000) as (prefix, maps):
            report["content_observer_maps"] = maps
            observed = run("content-comparison", prefix + [sys.executable, Path(__file__).resolve(), "contents",
                           str(ARCHIVE), ARCHIVE_SHA, str(STAGE), str(baseline)], check=False)
            if observed.returncode:
                raise RuntimeError("Content observer failed; retain its exact result before runtime")
        prepare_log = output / "prepare.log"
        prepare_log.touch(mode=0o600)
        with prepare_log.open("w") as log:
            prepare_native_instance(PREPARED, root, log=log)
        copy_prepared_nats(PREPARED, root)
        configuration = tomlkit.parse((root / "config.toml").read_text())
        mapping = configuration["linux"]
        assert dict(mapping) == report["linux_settings"]
        configuration["admin_port"] = 0
        (root / "config.toml").write_text(tomlkit.dumps(configuration))
        # Replace only the disposable instance's borrowed alias. Boot reads
        # installed_assets from the selection, so bind that field explicitly.
        (root / "share").unlink()
        (root / "share").mkdir()
        (root / "share/rootfs-tree").symlink_to(STAGE / "rootfs-tree")
        shutil.copyfile(STAGE / "cache-paths.txt", root / "share/cache-paths.txt")
        selected.update(assets=str(STAGE), installed_assets=str(STAGE))
        (root / "share/guest-selection.json").write_text(json.dumps(selected, indent=2) + "\n")
        workspace.mkdir()
        native("create-agent", "agent", "create", "bbtest", "--workspace", workspace)
        native("start-proxy", "start")
        tracked += owned_processes(root)
        native("start-agent", "agent", "start", "bbtest", "--sandbox-only")
        status = json.loads(native("agent-status", "agent", "status", "bbtest").stdout)
        report["guest_status"] = status
        runtime = json.loads((root / "agents/bbtest/runtime.json").read_text())
        assert status["runtime_state"] == "running"
        assert all(status[key] == runtime[key] for key in ("agent_id", "run_id", "name"))
        for kind in ("holder", "backend"):
            assert runtime[kind + "_token"] and _process_start_token(runtime[kind + "_pid"]) == runtime[kind + "_token"]
            tracked.append({"pid": runtime[kind + "_pid"], "start_token": runtime[kind + "_token"]})
        report["runtime"] = {key: runtime[key] for key in ("run_id", "holder_pid", "holder_token", "backend_pid", "backend_token")}
        spec = json.loads((root / "agents/bbtest/config.json").read_text())
        assert Path(spec["root"]["path"]).resolve() == STAGE / "rootfs-tree"
        for kind in ("uid", "gid"):
            run(kind + "-map", ["cat", f"/proc/{runtime['holder_pid']}/{kind}_map"])
        for guest_root in (False, True):
            run("guest-root" if guest_root else "guest-agent", guest_command_args(
                str(cli), "bbtest", guest_script(guest_root), guest_root=guest_root))
        report["host_files"] = {str(path): info(path) for directory in (workspace, root / "agents/bbtest/home")
                                for path in directory.glob("rootless1553-*")}
        assert len(report["host_files"]) == 4
        for path, details in report["host_files"].items():
            expected = (100000, 100000) if path.endswith("-0") else (1000, 1000)
            assert (details["uid"], details["gid"]) == expected
        report["result"] = "retained import started; guest identity/read-write-execute passed"
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise
    finally:
        if (root / "config.toml").exists():
            try:
                tracked += owned_processes(root)
            except (OSError, ValueError, KeyError) as error:
                # A broken receipt must not skip shutdown of the owned instance.
                report["cleanup_failures"].append(f"process inspection: {error}")
            cleanup = [("cleanup-proxy", ("stop",)), ("cleanup-coord", ("coord", "stop"))]
            if (root / "agents/bbtest").is_dir():
                cleanup.insert(0, ("cleanup-agent", ("agent", "stop", "bbtest")))
            for label, arguments in cleanup:
                try:
                    result = native(label, *arguments, check=False)
                    if result.returncode:
                        report["cleanup_failures"].append(f"{label}: exit {result.returncode}")
                except (OSError, subprocess.SubprocessError) as error:
                    report["cleanup_failures"].append(f"{label}: {error}")
            report["cleanup_failures"] += surviving_processes(tracked)
            report["cleanup_failures"] += [str(path) for pattern in (
                "agents/*/container.pid", "agents/*/userns.pid", "data/ready.json",
                "agents/*/proxy/proxy.sock", "data/sockets/*/proxy.sock", "data/coord/nats/process.json",
            ) for path in root.glob(pattern)]
        if report["cleanup_failures"]:
            report["result"] = "cleanup_failed"
        report["finished"] = time.time()
        save()
        assert not report["cleanup_failures"], report["cleanup_failures"]


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "contents":
        archive, digest, stage, baseline = sys.argv[2:]
        result = compare_contents(Path(archive), digest, Path(stage), Path(baseline))
        print(json.dumps(result, indent=2))
        return int(bool(result["mismatches"]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="absent disk-backed directory; retain original failures")
    qualify(parser.parse_args().output.absolute())
    return 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise InterruptedError(f"Interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
