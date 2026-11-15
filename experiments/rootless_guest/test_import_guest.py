"""Focused prototype controls; these do not qualify a native host or backend."""

import contextlib
import hashlib
import io
import json
import os
import signal
import struct
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.rootless_guest.import_guest import (
    ARCHIVE_BASE,
    ID_COUNT,
    extract,
    import_ids,
    inventory,
    prepare,
    verify_archive,
)
from experiments.rootless_guest.make_fixture import create


def translate(mapping, number):
    matches = [outer + number - inner for inner, outer, count in mapping
               if inner <= number < inner + count]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("uid_base,gid_base,uid,gid", [
    (100000, 100000, 1000, 1000), (231072, 400000, 1001, 2001),
])
def test_full_archive_mapping_matches_runtime_owners(uid_base, gid_base, uid, gid):
    for base, operator in [(uid_base, uid), (gid_base, gid)]:
        mapping = import_ids(base, operator)
        outside = {translate(mapping, 0)}
        for guest in range(ID_COUNT):
            actual = translate(mapping, ARCHIVE_BASE + guest)
            assert actual == (operator if guest == 1000 else base + guest)
            assert actual not in outside
            outside.add(actual)
        assert len(outside) == ID_COUNT + 1
        assert 0 not in outside
        assert translate(mapping, 0) == base + 1000


@pytest.mark.parametrize("base,operator", [(0, 1000), (100000, 0),
                                         (100000, 101000), (2**32 - ID_COUNT, 1000)])
def test_invalid_delegation_is_refused_before_entry(base, operator):
    with pytest.raises(ValueError):
        import_ids(base, operator)


def archive_file(tmp_path, members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, payload in members:
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    path = tmp_path / "guest.tar.zst"
    with path.open("wb") as output:
        subprocess.run(["zstd", "-q", "-c"], input=raw.getvalue(), stdout=output, check=True)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_inventory_retains_numeric_owners_acl_capabilities_and_links(tmp_path):
    info = tarfile.TarInfo("rootfs-tree/capability")
    info.uid, info.gid, info.mode = 101000, 165535, 0o6751
    capability = struct.pack("<6I", 0x03000001, 1 << 10, 0, 0, 0, 100000)
    info.pax_headers = {
        "SCHILY.xattr.security.capability": capability.decode("utf-8", "surrogateescape"),
        "SCHILY.xattr.user.safeyolo.fixture": "preserved",
        "SCHILY.acl.access": "user::rwx,user:101000:r--,group::r-x,group:100033:--x,mask::r-x,other::---",
        "SCHILY.acl.default": "user::rwx,user:101000:r--,group::r-x,mask::r-x,other::---",
    }
    link = tarfile.TarInfo("rootfs-tree/hardlink")
    link.type, link.linkname = tarfile.LNKTYPE, info.name
    device = tarfile.TarInfo("rootfs-tree/device")
    device.type, device.devmajor, device.devminor = tarfile.CHRTYPE, 1, 3
    path, digest = archive_file(tmp_path, [(info, b"payload"), (link, b""), (device, b"")])
    with path.open("rb") as stream:
        verify_archive(stream, digest)
        result = inventory(stream)
    first, hardlink, special = result["records"]
    assert (first["uid"], first["gid"], first["mode"]) == (101000, 165535, "0o6751")
    assert first["pax"] == {**info.pax_headers, "hdrcharset": "BINARY"}
    assert first["pax"]["SCHILY.xattr.security.capability"].encode("utf-8", "surrogateescape") == capability
    assert hardlink["link"] == info.name and hardlink["type"] == "1"
    assert special["type"] == "3" and special["device"] == [1, 3]


def test_verified_open_descriptor_survives_path_replacement(tmp_path):
    info = tarfile.TarInfo("Image")
    path, digest = archive_file(tmp_path, [(info, b"verified")])
    with path.open("rb") as stream:
        verify_archive(stream, digest)
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"unverified replacement")
        replacement.replace(path)
        assert inventory(stream)["records"][0]["size"] == len(b"verified")
    with path.open("rb") as stream, pytest.raises(ValueError, match="SHA-256"):
        verify_archive(stream, digest)


def test_linux_cache_list_uses_host_owner_without_changing_rootfs_metadata(tmp_path):
    root = tarfile.TarInfo("rootfs-tree")
    root.type, root.uid, root.gid, root.mode = tarfile.DIRTYPE, os.getuid(), os.getgid(), 0o750
    executable = tarfile.TarInfo("rootfs-tree/executable")
    executable.uid, executable.gid, executable.mode = os.getuid(), os.getgid(), 0o755
    cache = tarfile.TarInfo("cache-paths.txt")
    cache.uid, cache.gid, cache.mode = 1001, 1001, 0o644
    content = b"/var/cache/apt\n/var/lib/apt/lists\n"
    archive, digest = archive_file(tmp_path, [
        (root, b""), (executable, b"#!/bin/sh\nexit 0\n"), (cache, content),
        (tarfile.TarInfo("unselected-host-state"), b"not a backend input"),
    ])
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    with archive.open("rb") as stream:
        verify_archive(stream, digest)
        extract(stream, stage, [], True)
    assert sorted(p.name for p in stage.iterdir()) == ["cache-paths.txt", "rootfs-tree"]
    for path, mode in [(stage / "rootfs-tree", 0o750),
                       (stage / "rootfs-tree/executable", 0o755),
                       (stage / "cache-paths.txt", 0o644)]:
        info = path.lstat()
        assert (info.st_uid, info.st_gid, info.st_mode & 0o7777) == (os.getuid(), os.getgid(), mode)
    assert (stage / "cache-paths.txt").read_bytes() == content
    assert subprocess.run([str(stage / "rootfs-tree/executable")], check=False).returncode == 0


@pytest.mark.parametrize("missing_cache,cancel", [(True, False), (False, True)])
def test_linux_host_cache_failure_and_cancellation_remove_stage(tmp_path, monkeypatch, missing_cache, cancel):
    # Exercise real tar/rm as the worker account; this is not native mapping proof.
    monkeypatch.setattr("experiments.rootless_guest.import_guest.import_namespace",
                        lambda *args: contextlib.nullcontext(([], {})))
    outside = tmp_path / "outside"
    outside.write_bytes(b"unchanged external target")
    before = outside.stat()
    root = tarfile.TarInfo("rootfs-tree")
    root.type, root.uid, root.gid, root.mode = tarfile.DIRTYPE, os.getuid(), os.getgid(), 0o700
    link = tarfile.TarInfo("rootfs-tree/external")
    link.type, link.linkname, link.uid, link.gid = tarfile.SYMTYPE, str(outside), os.getuid(), os.getgid()
    cache = tarfile.TarInfo("cache-paths.txt")
    cache.uid = cache.gid = 1001
    members = [(root, b""), (link, b"")]
    if not missing_cache:
        members.append((cache, b"/var/cache/apt\n"))
    archive, digest = archive_file(tmp_path, members)
    args = SimpleNamespace(platform="linux", output=tmp_path / "attempt", host_root=tmp_path,
                           uid_base=os.getuid(), gid_base=os.getgid(), cancel_after_extract=cancel)
    with archive.open("rb") as stream, pytest.raises((InterruptedError, RuntimeError)):
        prepare(args, stream, digest)
    report = json.loads((args.output / "preparation.json").read_text())
    assert report["result"] == "failed/cancelled; private stage removed"
    assert not Path(report["stage"]).exists()
    assert outside.read_bytes() == b"unchanged external target"
    after = outside.stat()
    assert (before.st_uid, before.st_gid, before.st_mode, before.st_ino) == (
        after.st_uid, after.st_gid, after.st_mode, after.st_ino)


def mac_fixture(tmp_path, external=None):
    members = []
    for name in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4", "unselected-host-state"]:
        info = tarfile.TarInfo(name)
        if name == "Image" and external:
            info.type, info.linkname = tarfile.SYMTYPE, str(external)
        members.append((info, b"" if info.issym() else name.encode()))
    return archive_file(tmp_path, members)


@pytest.mark.parametrize("cancel,external", [(False, False), (True, False), (False, True)])
def test_selected_files_cancellation_and_external_target_preservation(tmp_path, cancel, external):
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside unchanged")
    outside.chmod(0o600)
    before = outside.stat()
    archive, digest = mac_fixture(tmp_path, outside if external else None)
    args = SimpleNamespace(platform="darwin", output=tmp_path / "attempt", cancel_after_extract=cancel)
    with archive.open("rb") as stream:
        verify_archive(stream, digest)
        if cancel or external:
            with pytest.raises((InterruptedError, RuntimeError)):
                prepare(args, stream, digest)
        else:
            prepare(args, stream, digest)
    report = json.loads((args.output / "preparation.json").read_text())
    stage = Path(report["stage"])
    assert (args.output.stat().st_mode & 0o777) == 0o700
    if cancel or external:
        assert not stage.exists()
        assert "removed" in report["result"]
    else:
        assert sorted(p.name for p in stage.iterdir()) == ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]
        assert (stage / "Image").read_bytes() == b"Image"
    after = outside.stat()
    assert outside.read_bytes() == b"outside unchanged"
    assert (before.st_uid, before.st_gid, before.st_mode, before.st_ino) == (
        after.st_uid, after.st_gid, after.st_mode, after.st_ino)


def test_existing_guest_is_preserved(tmp_path):
    archive, digest = mac_fixture(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "Image").write_bytes(b"usable guest")
    args = SimpleNamespace(platform="darwin", output=existing)
    with archive.open("rb") as stream, pytest.raises(FileExistsError):
        prepare(args, stream, digest)
    assert (existing / "Image").read_bytes() == b"usable guest"
    assert len(list(existing.iterdir())) == 1


def test_failed_tar_removes_only_its_private_stage(tmp_path):
    archive, digest = archive_file(tmp_path, [(tarfile.TarInfo("Image"), b"partial")])
    outside = tmp_path / "preserved-install"
    outside.mkdir()
    (outside / "marker").write_bytes(b"preserved")
    args = SimpleNamespace(platform="darwin", output=tmp_path / "failed", cancel_after_extract=False)
    with archive.open("rb") as stream, pytest.raises(RuntimeError, match="Extraction failed"):
        prepare(args, stream, digest)
    report = json.loads((args.output / "preparation.json").read_text())
    assert not Path(report["stage"]).exists()
    assert (outside / "marker").read_bytes() == b"preserved"


def test_inventory_rejects_incomplete_compressed_frame(tmp_path):
    path, _ = archive_file(tmp_path, [(tarfile.TarInfo("Image"), b"payload")])
    path.write_bytes(path.read_bytes()[:-4])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with path.open("rb") as stream:
        verify_archive(stream, digest)
        with pytest.raises((RuntimeError, tarfile.ReadError)):
            inventory(stream)


def test_supplementary_sparse_fixture_is_readable_by_gnu_tar(tmp_path):
    cases = create(tmp_path / "fixtures")
    row = cases["canonical"]
    with Path(row["path"]).open("rb") as stream:
        observed = inventory(stream)
    sparse = next(row for row in observed["records"] if row["name"] == "rootfs-tree/sparse")
    assert sparse["size"] == 64 * 1024**2
    assert sparse["sparse"] == [(0, 4096), (67104768, 4096)]
    with subprocess.Popen(["tar", "--zstd", "-xOf", row["path"], "rootfs-tree/sparse"],
                          stdout=subprocess.PIPE) as child:
        digest = hashlib.file_digest(child.stdout, "sha256").hexdigest()
        assert child.wait() == 0
    assert digest == "c1550f3e6e179b84b5305c572dbc624d3a88e2cf57744c8d516fe867334d69f7"
    with Path(cases["devices"]["path"]).open("rb") as stream:
        devices = inventory(stream)["records"]
    assert [(row["type"], row["device"]) for row in devices[2:]] == [
        ("3", [1, 3]), ("4", [7, 0]),
    ]


@pytest.mark.parametrize("interrupt", [signal.SIGTERM, signal.SIGINT])
def test_signal_during_extraction_reaps_children_before_cleanup(tmp_path, interrupt):
    # Stop real GNU tar after its first block, with zstd blocked on its pipe.
    # The worker account replaces namespace entry only; both children are real.
    import shutil

    outside = tmp_path / "outside"
    outside.write_bytes(b"external target must survive")
    before = outside.stat()
    root = tarfile.TarInfo("rootfs-tree")
    root.type, root.uid, root.gid = tarfile.DIRTYPE, os.getuid(), os.getgid()
    link = tarfile.TarInfo("rootfs-tree/external")
    link.type, link.linkname = tarfile.SYMTYPE, str(outside)
    link.uid, link.gid = os.getuid(), os.getgid()
    payload = tarfile.TarInfo("rootfs-tree/payload")
    payload.uid, payload.gid = os.getuid(), os.getgid()
    archive, digest = archive_file(tmp_path, [(root, b""), (link, b""), (payload, b"x" * 2**20)])
    commands = tmp_path / "commands"
    commands.mkdir()
    for name in ("tar", "zstd"):
        tool = shutil.which(name)
        shim = commands / name
        extra = ["--checkpoint=2", "--checkpoint-action=exec=kill -STOP $PPID"] if name == "tar" else []
        shim.write_text(f"#!{sys.executable}\nimport os\nfrom pathlib import Path\n"
                        "os.setpgid(0, 0)\n"
                        f"pid_path = Path({str(tmp_path / (name + '.pid'))!r})\n"
                        "pid_path.with_suffix('.new').write_text(str(os.getpid()))\n"
                        "pid_path.with_suffix('.new').replace(pid_path)\n"
                        f"os.execv({tool!r}, [{name!r}, *{extra!r}, *os.sys.argv[1:]])\n")
        shim.chmod(0o700)
    output = tmp_path / "attempt"
    driver = """
import contextlib, signal, sys
from pathlib import Path
from types import SimpleNamespace
from experiments.rootless_guest import import_guest as candidate
candidate.import_namespace = lambda *args: contextlib.nullcontext(([], {}))
def interrupted(signum, frame):
    raise InterruptedError(f'Interrupted by signal {signum}')
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, signal.default_int_handler)
args = SimpleNamespace(platform='linux', output=Path(sys.argv[3]), host_root=Path('.'),
                       uid_base=0, gid_base=0, cancel_after_extract=False)
with Path(sys.argv[1]).open('rb') as stream:
    candidate.prepare(args, stream, candidate.verify_archive(stream, sys.argv[2]))
"""
    environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"])
    children = []
    with subprocess.Popen([sys.executable, "-c", driver, str(archive), digest, str(output)],
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          start_new_session=True) as parent:
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if all((tmp_path / (name + ".pid")).exists() for name in ("tar", "zstd")):
                    children = [int((tmp_path / (name + ".pid")).read_text()) for name in ("tar", "zstd")]
                    status = Path(f"/proc/{children[0]}/status")
                    if status.exists() and "State:\tT" in status.read_text():
                        break
                assert parent.poll() is None
                time.sleep(0.01)
            else:
                pytest.fail("real tar did not reach its stopped extraction checkpoint")
            assert list(output.glob("extract-*/rootfs-tree/external"))
            parent.send_signal(interrupt)
            stdout, stderr = parent.communicate(timeout=10)
            assert parent.returncode != 0, (stdout, stderr)
            assert ("InterruptedError" if interrupt == signal.SIGTERM else "KeyboardInterrupt") in stderr, (
                parent.returncode, stdout, stderr, list(output.iterdir()))
            report = json.loads((output / "preparation.json").read_text())
            assert report["result"] == "failed/cancelled; private stage removed"
            assert not Path(report["stage"]).exists()
            assert all(not Path(f"/proc/{pid}").exists() for pid in children)
        finally:
            # A failed control must not leave its deliberately stopped child.
            for pid in children:
                if Path(f"/proc/{pid}").exists():
                    os.kill(pid, signal.SIGKILL)
            if parent.poll() is None:
                parent.kill()
                parent.wait()
    after = outside.stat()
    assert outside.read_bytes() == b"external target must survive"
    assert (before.st_uid, before.st_gid, before.st_mode, before.st_ino) == (
        after.st_uid, after.st_gid, after.st_mode, after.st_ino)
