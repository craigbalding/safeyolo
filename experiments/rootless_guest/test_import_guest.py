"""Focused prototype controls; these do not qualify a native host or backend."""

import hashlib
import io
import json
import struct
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.rootless_guest.import_guest import (
    ARCHIVE_BASE,
    ID_COUNT,
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
