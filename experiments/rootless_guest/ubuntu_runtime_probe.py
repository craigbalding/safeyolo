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
sys.path.insert(0, str(REPOSITORY / "tests/blackbox"))


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


def observe_cleanup(root, tracked):
    """Distinguish stopped diagnostic files from live owned runtime state."""
    from installed_sections import surviving_processes

    failures = surviving_processes(tracked)
    for line in Path("/proc/net/unix").read_text().splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) == 8 and int(fields[3], 16) & 0x10000 and fields[7].startswith(str(root) + "/"):
            failures.append(f"live Unix listener: {line}")
    failures += [str(path) for pattern in (
        "agents/*/container.pid", "agents/*/userns.pid", "data/ready.json",
    ) for path in root.glob(pattern)]
    return {
        "failures": failures,
        "diagnostic_paths": [str(path) for pattern in (
            "agents/*/proxy/proxy.sock", "data/sockets/*/proxy.sock", "data/coord/nats/process.json",
        ) for path in root.glob(pattern)],
    }


def cancel_published_import(output):
    """Interrupt a real partial import, preserving original output and births."""
    from installed_host_smoke import _process_start_token
    from installed_sections import surviving_processes

    target = output / "external-target"
    target.write_bytes(b"external target must survive\n")
    target.chmod(0o600)
    before = target.stat()
    attempt = output / "cancelled-import"
    command = [sys.executable, str(Path(__file__).with_name("import_guest.py")), "prepare",
               "--archive", str(ARCHIVE), "--sha256", ARCHIVE_SHA, "--output", str(attempt),
               "--host-root", str(PREPARED)]
    result = {"command": command, "signalled": False, "children": []}
    log_path = output / "cancellation.json"
    try:
        with (output / "cancellation.stdout").open("w") as stdout, (output / "cancellation.stderr").open("w") as stderr:
            with subprocess.Popen(command, stdout=stdout, stderr=stderr) as child:
                try:
                    deadline = time.monotonic() + 30
                    while child.poll() is None and time.monotonic() < deadline:
                        stages = list(attempt.glob("extract-*"))
                        children_file = Path(f"/proc/{child.pid}/task/{child.pid}/children")
                        pids = [int(pid) for pid in children_file.read_text().split()]
                        active = [(pid, Path(f"/proc/{pid}/comm")) for pid in pids]
                        # A rootfs plus a live tar is an in-progress extraction,
                        # unlike the older after-child cancellation witness.
                        if stages and (stages[0] / "rootfs-tree").is_dir() and any(
                            path.exists() and path.read_text().strip() == "tar" for _, path in active
                        ):
                            result["stage"] = str(stages[0])
                            result["children"] = [{"pid": pid, "start_token": _process_start_token(pid)} for pid in pids]
                            assert all(item["start_token"] for item in result["children"])
                            (stages[0] / "external-preservation").symlink_to(target)
                            child.terminate()
                            result["signalled"] = True
                            break
                        time.sleep(0.005)
                    if not result["signalled"]:
                        raise RuntimeError("No active extraction observed; preserve reached import without retry")
                    result["exit"] = child.wait(timeout=30)
                finally:
                    if child.poll() is None:
                        # Terminate the exact candidate so its normal cleanup can
                        # run; a failed stop stays an explicit packet failure.
                        child.terminate()
                        try:
                            child.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            result["stop_failed"] = "candidate ignored cleanup deadline; inspect children before retry"
                            child.kill()
                            child.wait(timeout=5)
                            raise
        result["preparation"] = json.loads((attempt / "preparation.json").read_text())
        result["survivors"] = surviving_processes(result["children"])
        after = target.stat()
        result["external_preserved"] = target.read_bytes() == b"external target must survive\n" and (
            before.st_uid, before.st_gid, before.st_mode, before.st_ino
        ) == (after.st_uid, after.st_gid, after.st_mode, after.st_ino)
        assert result["exit"] != 0 and result["external_preserved"] and not result["survivors"]
        assert result["preparation"]["result"] == "failed/cancelled; private stage removed"
        assert not Path(result["preparation"]["stage"]).exists()
    finally:
        log_path.write_text(json.dumps(result, indent=2) + "\n")
    return result


def qualify(output, metadata=None):
    # Keep the experimental packet on the maintained native instance, command,
    # token-redaction and process-birth helpers. No product helper is duplicated.
    import tomlkit
    from guest_exec import guest_command_args
    from installed_host_smoke import _process_start_token
    from installed_linux_update import info, redact, sha
    from installed_sections import copy_prepared_nats, owned_processes, prepare_native_instance

    assert platform.system() == "Linux" and platform.machine() == "x86_64"
    assert (os.getuid(), os.getgid()) == (1000, 1000)
    forecast = (640 if metadata is not None else 128) * 1024**2
    assert shutil.disk_usage(output.parent).free >= 5 * 1024**3 + forecast
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
        if metadata is None:
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
        mounts = []
        if metadata is not None:
            # Reuse the exact canonical stages from 18414. Do not reimport or
            # copy them: copying would itself change the metadata under test.
            prepared = json.loads((metadata / "candidate/canonical/preparation.json").read_text())
            assert prepared["result"].startswith("prepared;")
            fixture = json.loads((metadata / "fixtures.json").read_text())["canonical"]
            assert prepared["archive_sha256"] == fixture["sha256"]
            report["metadata_inputs"] = {
                "candidate": str(Path(prepared["stage"]) / "rootfs-tree"),
                "baseline": str(metadata / "baseline/extract-canonical/rootfs-tree"),
                "fixture": fixture,
            }
            for kind in ("candidate", "baseline"):
                mounts += ["--mount", report["metadata_inputs"][kind] + ":/" + kind]
            shutil.copyfile(Path(__file__).with_name("ubuntu_metadata_guest.sh"), workspace / "metadata.sh")
            (workspace / "metadata.sh").chmod(0o644)
        native("create-agent", "agent", "create", "bbtest", "--workspace", workspace, *mounts)
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
        if metadata is None:
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
        else:
            run("guest-canonical-metadata", guest_command_args(
                str(cli), "bbtest", "exec /bin/bash /workspace/metadata.sh", guest_root=True))
            # Refuse an extraction onto the imported stage while its owned
            # guest is demonstrably usable; the archive is not decompressed.
            preserved = run("existing-usable-stage", [sys.executable, Path(__file__).with_name("import_guest.py"),
                            "prepare", "--archive", ARCHIVE, "--sha256", ARCHIVE_SHA,
                            "--output", STAGE, "--host-root", PREPARED], check=False)
            assert preserved.returncode and "FileExistsError" in preserved.stderr
            report["cancellation"] = cancel_published_import(output)
            run("guest-after-refused-import", guest_command_args(
                str(cli), "bbtest", guest_script(False)))
            report["result"] = "canonical backend observation completed; compare individual results with baseline"
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise
    finally:
        report["guest_result"] = report["result"]
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
            try:
                report["cleanup_observation"] = observe_cleanup(root, tracked)
                report["cleanup_failures"] += report["cleanup_observation"]["failures"]
            except (OSError, ValueError) as error:
                report["cleanup_failures"].append(f"cleanup inspection: {error}")
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
    parser.add_argument("--metadata", type=Path, help="retained native metadata-g5 directory; skips completed contents/I/O proof")
    args = parser.parse_args()
    qualify(args.output.absolute(), args.metadata.absolute() if args.metadata else None)
    return 0


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise InterruptedError(f"Interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
