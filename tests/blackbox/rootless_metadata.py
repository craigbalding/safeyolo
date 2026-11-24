#!/usr/bin/env python3
"""Run the accepted production metadata witness on a prepared Linux AMD64 host.

The retained #1553 specimens and baseline require ordinary UID/GID 1000. Supply
the installed package, matching product source and a new disk-backed output
directory. No host preparation, sudo or guest boot occurs. Native-kernel
effects do not establish gVisor enforcement or whole BB-33 acceptance.
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

BASELINE_HASH = "a7ea2a4b1067a47ae7053390e28005c8db76245055690dbd84a97c4236e0a84a"
FIXTURES = {
    "canonical": "d9aa4fff9f90adde7cf736a0698c09565bc581102d7b1324a988e16e187a8fc3",
    "devices": "a90b8e429bd1de65f497a2a9eecab122ca2ccfc2c987749a33ff18532664ff8d",
    "v2-capability": "8075c6d2545e2c0cf7b3dd3ea54cc12f83cca754fcffe77c68e707f12ebc11c8",
    "raw-acl42": "d58b4624064ca9ead10aa1865390374568fedb7618fdcb6b44f1e229fad0cbb4",
}
FLOOR = 5 * 1024**3
FORECAST = 192 * 1024**2  # Both 64 MiB sparse files counted as fully allocated.


def verified(path, expected):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError(f"Input SHA-256 differs: {path}")
    return actual


def seed_release(archive, store, source, architecture="amd64"):
    """Use tests/test_guest_acquisition.py::release's existing retained-OCI shape."""
    blobs = store / "blobs/sha256"
    blobs.mkdir(parents=True)

    def retain(data, media_type):
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media_type}

    annotations = {
        "org.opencontainers.image.version": "guest-2026-11-15.1554",
        "org.opencontainers.image.source": "https://github.com/craigbalding/safeyolo",
        "org.opencontainers.image.revision": source,
        "dev.safeyolo.guest.compatibility": "v1",
        "dev.safeyolo.guest.profile": "1554-metadata-witness",
    }
    consumer = {"os": "linux", "architecture": architecture}
    config = retain(json.dumps(consumer, separators=(",", ":")).encode(),
                    "application/vnd.safeyolo.guest.platform.v1+json")
    layer = retain(archive.read_bytes(), "application/vnd.safeyolo.guest.v1.tar+zstd")
    child = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
             "artifactType": "application/vnd.safeyolo.guest.v1",
             "annotations": {**annotations, "dev.safeyolo.guest.build-base":
                             "docker.io/library/debian@sha256:" + "b" * 64,
                             "dev.safeyolo.guest.build-inputs": layer["digest"]},
             "config": config, "layers": [layer]}
    descriptor = retain(json.dumps(child).encode(), child["mediaType"])
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "artifactType": "application/vnd.safeyolo.guest.v1", "annotations": annotations,
             "manifests": [{**descriptor, "platform": consumer}]}
    return retain(json.dumps(index).encode(), index["mediaType"])["digest"]


def compare_snapshot(actual, expected):
    # Retained paths, owners, modes, links, content, sparse allocation and decoded
    # ACL/capability bytes are compared. Each independent import has new inodes.
    if actual.keys() != expected.keys():
        raise RuntimeError("Metadata paths differ from the retained canonical baseline")
    for name, row in actual.items():
        fields = {key: value for key, value in row.items() if key != "inode"}
        baseline = {key: value for key, value in expected[name].items() if key != "inode"}
        if fields != baseline:
            raise RuntimeError(f"Metadata differs from retained canonical baseline: {name}")
    if actual["regular"]["inode"] != actual["hardlink"]["inode"]:
        raise RuntimeError("Canonical hardlink no longer shares its regular-file inode")


def status_fields(text):
    wanted = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    return {key: value.split() for line in text.splitlines()
            if ":" in line for key, value in [line.split(":", 1)] if key in wanted}


def compare_access(actual, expected):
    for key in ("uid", "gid", "groups", "operations"):
        if actual[key] != expected[key]:
            raise RuntimeError(f"Native access differs from retained baseline: {key}")
    if status_fields(actual["status"]) != status_fields(expected["status"]):
        raise RuntimeError("Credentials or pre-exec capability masks differ")
    for executable in ("cap-v3", "setid"):
        a, b = actual[executable], expected[executable]
        if (a["exit"], a["stderr"], status_fields(a["stdout"])) != (
                b["exit"], b["stderr"], status_fields(b["stdout"])):
            raise RuntimeError(f"Native capability/set-ID effect differs: {executable}")


def qualify(output, prepared, checkout, baseline_path, specimens):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or (os.getuid(), os.getgid()) != (1000, 1000):
        raise RuntimeError("The retained metadata specimens require Linux AMD64 and ordinary account 1000:1000")
    if output.exists():
        raise RuntimeError("Output exists; inspect the reached result before selecting another attempt")
    package = dict(line.split("=", 1) for line in (prepared / "package-info").read_text().splitlines())
    source = package["source_commit"]
    source_hashes = {}
    for name in ("proxy/src/guest_acquisition.rs", "proxy/src/guest_acquisition/archive.rs",
                 "proxy/src/guest_acquisition/namespace.rs", "proxy/src/linux_host/ownership.rs"):
        expected = hashlib.sha256(subprocess.check_output(["git", "show", f"{source}:{name}"], cwd=checkout)).hexdigest()
        source_hashes[name] = verified(checkout / name, expected)
    cli = prepared / "bin/safeyolo"
    version = subprocess.check_output([str(cli), "--version"], text=True).strip()
    if f"commit={source} profile={package['profile']}" not in version or package["platform"] != "linux-amd64":
        raise RuntimeError("Installed CLI differs from its package source/profile/platform")
    verified(baseline_path, BASELINE_HASH)
    for case, expected in FIXTURES.items():
        verified(specimens / f"{case}.tar.zst", expected)
    free_before = shutil.disk_usage(output.parent).free
    if free_before < FLOOR + FORECAST:
        raise RuntimeError("Witness does not fit above the existing 5 GiB floor")
    baseline = json.loads(baseline_path.read_text())
    old_actions = {row["label"]: row for row in baseline["actions"]}
    expected_before = json.loads(old_actions["baseline/canonical/runtime-metadata"]["stdout"])
    expected_after = json.loads(old_actions["baseline/canonical/runtime-metadata-after-access"]["stdout"])
    output.mkdir(mode=0o700)
    report = {"source": source, "version": version, "started": time.time(), "result": "incomplete",
              "platform": platform.uname()._asdict(), "free_before": free_before,
              "source_hashes": source_hashes, "baseline_sha256": BASELINE_HASH,
              "fixture_sha256": FIXTURES, "actions": [], "maps": {}, "host_files": {},
              "limits": "Synthetic metadata only; native-kernel enforcement. Prior gVisor backend limits carry; no new guest boot or production installation."}

    def save():
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    tools = output / "tools"
    tools.mkdir()
    recorder = tools / "sudo"
    recorder.write_text('#!/bin/sh\nprintf "unexpected host sudo\\n" >> "$SAFEYOLO_TEST_SUDO_ATTEMPTS"\nexit 97\n')
    recorder.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tools}:/usr/sbin:/usr/bin:/sbin:/bin",
                       SAFEYOLO_TEST_SUDO_ATTEMPTS=str(output / "unexpected-host-sudo"), PYTHONDONTWRITEBYTECODE="1")

    def command(label, argv, *, cwd=None, required=True):
        row = {"label": label, "command": list(map(str, argv)), "cwd": str(cwd) if cwd else None}
        report["actions"].append(row)
        save()
        started = time.monotonic()
        try:
            result = subprocess.run(row["command"], cwd=cwd, env=environment,
                                    capture_output=True, text=True, timeout=90, check=False)
        except subprocess.TimeoutExpired as error:
            row.update(timeout=True, stdout=(error.stdout or b"").decode(errors="replace"),
                       stderr=(error.stderr or b"").decode(errors="replace"))
            save()
            raise
        row.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr,
                   seconds=time.monotonic() - started)
        save()
        if required and result.returncode:
            raise RuntimeError(f"{label} failed; preserve original result before retry")
        return result

    from experiments.rootless_guest.import_guest import import_namespace, mapped_namespace

    observer = checkout / "experiments/rootless_guest/ubuntu_metadata_probe.py"
    settings = tomllib.loads((prepared / "config.toml").read_text())["linux"]
    if (settings["host_uid"], settings["host_gid"]) != (1000, 1000):
        raise RuntimeError("Prepared account differs")
    save()
    try:
        for lane, uid_base, gid_base in (("default", 100000, 100000), ("distinct", 231072, 296608)):
            lane_dir = output / lane
            lane_dir.mkdir(mode=0o700)
            selected_settings = dict(settings, uid_base=uid_base, gid_base=gid_base)
            settings_path = lane_dir / "settings.toml"
            settings_path.write_text("[linux]\n" + "".join(
                f"{json.dumps(k)} = {json.dumps(v)}\n" for k, v in selected_settings.items()))
            canonical = None
            for case in FIXTURES:
                case_dir = lane_dir / case
                case_dir.mkdir(mode=0o700)
                store = case_dir / "store"
                index = seed_release(specimens / f"{case}.tar.zst", store, source)
                selection = case_dir / "selection.json"
                acquired = command(f"{lane}/{case}/production-acquire", [cli, "--root", case_dir / "root", "guest", "acquire",
                    "--package-info", prepared / "package-info", "--namespace-root", prepared,
                    "--host-settings", settings_path, "--store", store, "--index", index,
                    "--write-selection", selection], required=False)
                if case == "canonical":
                    if acquired.returncode:
                        raise RuntimeError("Production canonical import/validator failed")
                    record = json.loads(selection.read_text())
                    if record["archive"]["digest"] != "sha256:" + FIXTURES[case] or record["index"]["digest"] != index:
                        raise RuntimeError("Production selection differs from the pinned specimen")
                    canonical = Path(record["assets"]) / "rootfs-tree"
                else:
                    # Current explicit treatment: no silent ACL/capability loss
                    # or device failure can publish a prepared tree.
                    trees = store / "trees/sha256"
                    if acquired.returncode == 0 or selection.exists() or (trees.exists() and list(trees.iterdir())):
                        raise RuntimeError(f"Unsupported {case} was published or its private stage survived")
                    if "no tree was published" not in acquired.stderr and "no guest tree was published" not in acquired.stderr:
                        raise RuntimeError(f"Unsupported {case} lacked the production diagnostic")
                    reason = {"devices": "Cannot mknod", "raw-acl42": "Cannot set POSIX ACL",
                              "v2-capability": "requires a revision-3 capability"}[case]
                    if reason not in acquired.stderr:
                        raise RuntimeError(f"Unsupported {case} failed for another cause; metadata refusal remains unproved")
            expected_owners = {".": (uid_base, gid_base), "private": (1000, 1000),
                               "daemon": (uid_base + 33, gid_base + 33),
                               "boundary": (uid_base + 65535, gid_base + 65535)}
            report["host_files"][lane] = {}
            for name, owner in expected_owners.items():
                info = (canonical / name).stat()
                report["host_files"][lane][name] = {"uid": info.st_uid, "gid": info.st_gid}
                if (info.st_uid, info.st_gid) != owner:
                    raise RuntimeError(f"Other canonical host ownership differs: {lane}/{name}")
            uid_map = [(0, uid_base, 1000), (1000, 1000, 1), (1001, uid_base + 1001, 64535)]
            gid_map = [(0, gid_base, 1000), (1000, 1000, 1), (1001, gid_base + 1001, 64535)]
            with mapped_namespace(prepared, uid_map, gid_map) as (prefix, maps):
                report["maps"][lane] = maps
                if any([tuple(map(int, line.split())) for line in maps[name].splitlines()] != expected
                       for name, expected in (("uid_map", uid_map), ("gid_map", gid_map))):
                    raise RuntimeError("Actual runtime maps differ from the selected independent ranges")
                before = command(lane + "/snapshot-before", prefix + [sys.executable, observer, "snapshot", "."], cwd=canonical)
                compare_snapshot(json.loads(before.stdout), expected_before)
                command(lane + "/inherit", prefix + [sys.executable, "-c",
                    "import os; os.umask(0o077); os.close(os.open('acl-dir/inherited',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o666))"], cwd=canonical)
                for identity in (1000, 33, 65535):
                    access = command(f"{lane}/access-{identity}", prefix + [sys.executable, observer, "access", ".", identity, identity], cwd=canonical)
                    compare_access(json.loads(access.stdout), json.loads(old_actions[f"baseline/canonical/access-{identity}"]["stdout"]))
                after = command(lane + "/snapshot-after", prefix + [sys.executable, observer, "snapshot", "."], cwd=canonical)
                compare_snapshot(json.loads(after.stdout), expected_after)
            if shutil.disk_usage(output).free < FLOOR:
                raise RuntimeError("Backing filesystem crossed existing floor; retain output")
    finally:
        try:
            for lane, uid_base, gid_base in (("default", 100000, 100000), ("distinct", 231072, 296608)):
                trees = sorted((output / lane).glob("*/store/trees"))
                if trees:
                    with import_namespace(prepared, uid_base, gid_base) as (prefix, _maps):
                        command(lane + "/cleanup", prefix + ["rm", "-rf", "--", *trees])
                    if any(tree.exists() for tree in trees):
                        raise RuntimeError("Owned metadata trees survived cleanup")
            if (output / "unexpected-host-sudo").exists():
                raise RuntimeError("Production path attempted host sudo")
            report["cleanup_complete"] = True
        finally:
            report.update(ended=time.time(), free_after=shutil.disk_usage(output).free)
            save()
    report["result"] = "Both production canonical imports, native metadata/access parity and explicit unsupported refusals passed"
    save()
    print(json.dumps({key: report[key] for key in ("result", "started", "ended", "free_before", "free_after")}, indent=2))
