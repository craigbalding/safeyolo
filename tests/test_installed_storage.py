"""Exercise the storage observer's real guest script and replay refusal."""

import argparse
import hashlib
import os
import subprocess
import sys

import pytest

from tests.blackbox import installed_storage as storage


@pytest.mark.parametrize("damage", [None, "missing", "changed", "overlay"])
def test_storage_guest_script_requires_persistence_and_disposable_overlay(tmp_path, damage):
    directories = {name: tmp_path / name for name in ("home", "workspace", "etc")}
    for directory in directories.values():
        directory.mkdir()

    def guest(*, create, guest_root):
        code = storage.guest_script("storage-control", create=create, guest_root=guest_root)
        for original, replacement in (("/home/agent", directories["home"]),
                                       ("/workspace", directories["workspace"]), ("/etc", directories["etc"])):
            code = code.replace(original, str(replacement))
        # The shipped guest uses UID/GID1000. Exercise the same file checks
        # with the source-control account's actual IDs outside a guest.
        code = code.replace("metadata.st_gid == (0 if user == 'root' else 1000)",
                            f"metadata.st_gid == (0 if user == 'root' else {os.getgid()})")
        code = code.replace("else 1000)", f"else {os.getuid()})")
        command = (["sudo", "-n"] if guest_root else []) + [sys.executable, "-c", code]
        return subprocess.run(command, capture_output=True, text=True, timeout=10)

    for guest_root in (False, True):
        created = guest(create=True, guest_root=guest_root)
        assert created.returncode == 0, created.stderr
        row = storage.observation(created.stdout)
        assert row["uid"] == (0 if guest_root else os.getuid())
        assert row["overlay_present"] is guest_root
    if damage != "overlay":
        (directories["etc"] / "storage-control").unlink()
    marker = directories["home"] / "storage-control-agent"
    if damage == "missing":
        marker.unlink()
    elif damage == "changed":
        marker.write_text("lost marker")
    for guest_root in (False, True):
        restarted = guest(create=False, guest_root=guest_root)
        assert (restarted.returncode == 0) == (damage is None), restarted.stderr
        if damage is None:
            row = storage.observation(restarted.stdout)
            assert len(row["files"]) == 4 and row["overlay_present"] is False


def test_storage_refuses_retained_attempt_before_product_effects(tmp_path):
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "package-info").write_text("source_commit=" + "a" * 40 + "\n")
    settings = tmp_path / "settings.toml"
    settings.write_text(f"[linux]\nhost_uid={os.getuid()}\nhost_gid={os.getgid()}\n")
    archive = tmp_path / "guest.tar.zst"
    archive.write_bytes(b"retained archive control")
    output = tmp_path / "retained-attempt"
    output.mkdir()
    saved = output / "original-result"
    saved.write_text("recover this result")
    args = argparse.Namespace(prepared_config=prepared, output=output, install_commit="a" * 40,
                              host_settings=settings, archive=archive,
                              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
    with pytest.raises(FileExistsError):
        storage.qualify(args)
    assert list(output.iterdir()) == [saved]
    assert saved.read_text() == "recover this result"
