#!/usr/bin/env python3
"""Qualify native Linux acquisition and storage on an owned prepared host.

Run as the ordinary host account. Supply a verified installed package, its
saved Linux settings, an immutable public guest index and its retained archive.
The probe creates fresh state, uses native acquisition, boots one systrap agent
twice, and stops only that instance. It retains the reports and persistent data.
It does not prepare the host or interrupt WSL or Windows.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import time
import tomllib
import uuid
from pathlib import Path

if __package__:
    from .guest_exec import guest_command_args
    from .installed_ingress_pair import live_guest
    from .installed_linux_update import info, redact, sha
    from .installed_sections import copy_prepared_nats, owned_processes, prepare_native_instance, surviving_processes
else:
    from guest_exec import guest_command_args
    from installed_ingress_pair import live_guest
    from installed_linux_update import info, redact, sha
    from installed_sections import copy_prepared_nats, owned_processes, prepare_native_instance, surviving_processes

REPOSITORY = Path(__file__).resolve().parents[2]


def persistent_files(root: Path, workspace: Path, marker: str) -> dict[str, Path]:
    """Name only this attempt's files in the two selected persistent mounts."""
    return {f"{mount}-{user}": directory / f"{marker}-{user}"
            for mount, directory in (("home", root / "agents/bbtest/home"), ("workspace", workspace))
            for user in ("agent", "root")}


def guest_script(marker: str, *, create: bool, guest_root: bool) -> str:
    """Use guest stdlib only; a restart must lose the root overlay marker."""
    return f'''
import json, os
from pathlib import Path
marker = {marker!r}
create, guest_root = {create!r}, {guest_root!r}
assert os.getuid() == (0 if guest_root else 1000)
overlay = Path('/etc') / marker
assert not overlay.exists(), 'disposable root overlay marker survived'
rows = {{}}
for mount in ('/home/agent', '/workspace'):
    for user in (('root' if guest_root else 'agent',) if create else ('agent', 'root')):
        path = Path(mount) / (marker + '-' + user)
        if create:
            path.write_text(marker)
            path.chmod(0o644)
        assert path.read_text() == marker
        metadata = path.stat()
        assert metadata.st_uid == (0 if user == 'root' else 1000)
        assert metadata.st_gid == (0 if user == 'root' else 1000)
        rows[str(path)] = {{'uid': metadata.st_uid, 'gid': metadata.st_gid,
                           'mode': metadata.st_mode & 0o777}}
if create and guest_root:
    overlay.write_text(marker)
print('STORAGE_OBSERVATION=' + json.dumps({{'uid': os.getuid(), 'files': rows,
    'overlay_present': overlay.exists()}}))
'''


def observation(output: str) -> dict:
    lines = [line.removeprefix("STORAGE_OBSERVATION=") for line in output.splitlines()
             if line.startswith("STORAGE_OBSERVATION=")]
    assert len(lines) == 1, "guest returned no single storage observation"
    return json.loads(lines[0])


def qualify(args: argparse.Namespace) -> None:
    assert platform.system() == "Linux" and os.getuid() != 0
    prepared, output = args.prepared_config.resolve(), args.output.resolve()
    package = dict(line.split("=", 1) for line in (prepared / "package-info").read_text().splitlines())
    assert package["source_commit"] == args.install_commit
    assert sha(args.archive) == args.archive_sha256
    settings = tomllib.loads(args.host_settings.read_text())["linux"]
    assert settings["host_uid"] == os.getuid() and settings["host_gid"] == os.getgid()
    output.mkdir(mode=0o755)  # Exclusive creation: recover an existing attempt instead of replaying.
    root, workspace, store = output / "instance", output / "workspace", output / "guests"
    report_path = output / "observed.json"
    report_path.touch(mode=0o600)
    marker = "storage-" + uuid.uuid4().hex
    env = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(root), SAFEYOLO_LOGS_DIR=str(root / "logs"),
               SAFEYOLO_COORD_DATA_DIR=str(root / "data/coord"), SAFEYOLO_RUNSC_PLATFORM="systrap",
               SAFEYOLO_RUNSC_DEBUG="1", SAFEYOLO_NATS_TEST_INSTANCE=uuid.uuid4().hex)
    report = {"result": "incomplete", "controller_source": subprocess.check_output(
        ["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"], text=True).strip(),
        "package": package, "platform": platform.uname()._asdict(), "uid": os.getuid(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "linux_settings": settings, "archive": {"sha256": args.archive_sha256,
        "bytes": args.archive.stat().st_size}, "marker": marker, "actions": [], "guests": {}}

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    def run(label, command, *, timeout=60, check=True):
        command = list(map(str, command))
        row = {"label": label, "command": command, "started": time.time()}
        report["actions"].append(row)
        save()
        try:
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout,
                                    stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired as error:
            row.update(timeout=True, stdout=redact(error.stdout or "", root),
                       stderr=redact(error.stderr or "", root))
            save()
            raise
        row.update(exit=result.returncode, stdout=redact(result.stdout, root),
                   stderr=redact(result.stderr, root), ended=time.time())
        save()
        if check and result.returncode:
            raise RuntimeError(f"{label}: exit {result.returncode}; see {report_path}")
        return result

    cli = prepared / "bin/safeyolo"

    def native(label, *arguments, **kwargs):
        return run(label, [cli, "--root", root, *arguments], **kwargs)

    tracked = []
    try:
        run("verify-host-package", ["bash", "-c", 'source "$1/native_package.sh"; verify_native_package "$1"',
                                    "verify", prepared])
        report["host_executables"] = {name: sha(prepared / name) for name in (
            "bin/safeyolo", "bin/safeyolo-proxy", "libexec/runsc")}
        run("runsc-version", [prepared / "libexec/runsc", "--version"])
        run("host-filesystem", ["findmnt", "--json", "--target", output])
        run("subuids", ["getsubids", str(os.getuid())])
        run("subgids", ["getsubids", "-g", str(os.getuid())])
        blobs = store / "blobs/sha256"
        blobs.mkdir(parents=True)
        # Copy verified bytes, never hard-link a retained input into mutable state.
        shutil.copyfile(args.archive, blobs / args.archive_sha256)
        common = ["--package-info", prepared / "package-info", "--store", store, "--index", args.index]
        downloaded = run("native-download", [cli, "guest", "download", *common], timeout=180)
        assert downloaded.stdout.strip() == args.index
        selection = output / "selection.json"
        acquired = output / "acquired"
        run("native-acquire", [cli, "--root", acquired, "guest", "acquire", *common,
                              "--host-settings", args.host_settings, "--write-selection", selection], timeout=300)
        selected = json.loads(selection.read_text())
        report["selection"] = selected
        save()
        assert selected["index"]["digest"] == args.index
        assert selected["archive"] == {"digest": "sha256:" + args.archive_sha256,
                                       "size": args.archive.stat().st_size}
        assert selected["platform"] == package["platform"].replace("-", "/", 1)
        assert selected["compatibility"] == package["guest_compatibility"]
        index = json.loads((blobs / args.index.removeprefix("sha256:")).read_text())
        report["guest_annotations"] = index["annotations"]
        assets = Path(selected["assets"])
        tree = assets / "rootfs-tree"
        report["mapped_root"] = info(tree)
        assert (tree.stat().st_uid, tree.stat().st_gid) == (settings["uid_base"], settings["gid_base"])
        assert (tree / "home/agent").stat().st_uid == settings["host_uid"]
        assert (tree / "home/agent").stat().st_gid == settings["host_gid"]
        run("mapped-root-acls", ["getfacl", "-ncp", tree, tree / "home/agent"])
        prepare_log = output / "prepare.log"
        prepare_log.touch(mode=0o600)
        with prepare_log.open("w") as log:
            prepare_native_instance(prepared, root, log=log)
        copy_prepared_nats(prepared, root)
        # Replace only this instance's borrowed share alias with the acquired selection.
        (root / "share").unlink()
        (root / "share").mkdir()
        run("install-acquired-assets", ["bash", "-c",
            'source "$1"; install_platform_assets "$2" "$3"', "install-assets",
            REPOSITORY / "scripts/native_package.sh", assets, root / "share"])
        shutil.copyfile(selection, root / "share/guest-selection.json")
        workspace.mkdir()
        native("create-agent", "agent", "create", "bbtest", "--workspace", workspace)
        native("start-proxy", "start")
        files = persistent_files(root, workspace, marker)
        before = None
        for phase in ("initial", "restart"):
            native(phase + "-start", "agent", "start", "bbtest", "--sandbox-only")
            guest = live_guest(str(cli), root, "bbtest")
            report["guests"][phase] = guest
            tracked += owned_processes(root)
            tracked += [{"pid": guest[key + "_pid"], "start_token": guest[key + "_token"]}
                        for key in ("holder", "backend")]
            report["owned_processes"] = tracked
            save()
            run_record = root / "agents/bbtest"
            spec = json.loads((run_record / "config.json").read_text())
            assert Path(spec["root"]["path"]).resolve() == tree.resolve()
            mounts = {entry["destination"]: entry["source"] for entry in spec["mounts"]}
            assert Path(mounts["/workspace"]).resolve() == workspace
            assert Path(mounts["/home/agent"]).resolve() == root / "agents/bbtest/home"
            report[phase + "-mounts"] = {name: mounts[name] for name in ("/workspace", "/home/agent")}
            run(phase + "-mount-acls", ["getfacl", "-ncp", workspace, root / "agents/bbtest/home"])
            for kind in ("uid", "gid"):
                mapped = run(phase + "-" + kind + "-map", ["cat", f"/proc/{guest['holder_pid']}/{kind}_map"])
                base, host = settings[kind + "_base"], settings["host_" + kind]
                assert [tuple(map(int, line.split())) for line in mapped.stdout.splitlines()] == [
                    (0, base, 1000), (1000, host, 1), (1001, base + 1001, 64535)]
            backend = run(phase + "-backend", ["cat", f"/proc/{guest['backend_pid']}/cmdline"])
            assert "--platform=systrap" in backend.stdout.split("\0")
            assert any(arg.startswith("--overlay2=root:") for arg in backend.stdout.split("\0"))
            for guest_root in (False, True):
                code = guest_script(marker, create=phase == "initial", guest_root=guest_root)
                result = run(phase + ("-root" if guest_root else "-agent"), guest_command_args(
                    str(cli), "bbtest", shlex.join(["python3", "-c", code]), guest_root=guest_root, env=env))
                report[phase + ("-root" if guest_root else "-agent")] = observation(result.stdout)
            current = {name: info(path) for name, path in files.items()}
            report[phase + "-host-files"] = current
            save()
            for name, path in files.items():
                expected = (settings["uid_base"], settings["gid_base"]) if name.endswith("-root") else (os.getuid(), os.getgid())
                assert (path.stat().st_uid, path.stat().st_gid) == expected
                assert path.read_text() == marker
            assert not (tree / "etc" / marker).exists(), "guest wrote into the shared lower tree"
            if before is not None:
                assert current == before, "persistent file identity changed across stop/start"
                assert guest["run_id"] != report["guests"]["initial"]["run_id"]
            before = current
            native(phase + "-stop", "agent", "stop", "bbtest")
        run("workspace-filesystem", ["findmnt", "--json", "--target", workspace])
        run("home-filesystem", ["findmnt", "--json", "--target", root / "agents/bbtest/home"])
        report["result"] = "storage_passed"
    except (OSError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise
    finally:
        failures = []
        if (root / "config.toml").exists():
            for label, command in (("cleanup-agent", ("agent", "cleanup", "bbtest")),
                                   ("cleanup-proxy", ("stop",)), ("cleanup-coord", ("coord", "stop"))):
                try:
                    result = native(label, *command, check=False)
                    if result.returncode:
                        failures.append(f"{label}: exit {result.returncode}")
                except (OSError, subprocess.SubprocessError) as error:
                    failures.append(f"{label}: {error}")
        failures += surviving_processes(tracked)
        failures += [str(path) for pattern in ("agents/*/proxy/proxy.sock", "agents/*/container.pid",
                     "agents/*/userns.pid", "data/ready.json", "data/coord/nats/process.json") for path in root.glob(pattern)]
        report["cleanup_failures"] = failures
        if failures:
            report["result"] = "cleanup_failed"
        save()
        assert not failures, failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("prepared-config", "host-settings", "archive", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("index", "archive-sha256", "install-commit"):
        parser.add_argument("--" + name, required=True)
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
