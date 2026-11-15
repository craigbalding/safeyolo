"""Exercise the content observer with real compressed archives and trees."""

import hashlib
import io
import json
import subprocess
import sys
import tarfile

import pytest

from experiments.rootless_guest.test_import_guest import archive_file
from experiments.rootless_guest.ubuntu_runtime_probe import __file__ as probe_path
from experiments.rootless_guest.ubuntu_runtime_probe import compare_contents


@pytest.mark.parametrize("mutation", [None, "imported", "baseline"])
def test_content_observer_detects_equal_size_changes_in_either_tree(tmp_path, mutation):
    member = tarfile.TarInfo("rootfs-tree/private/payload")
    archive, digest = archive_file(tmp_path, [(member, b"original")])
    trees = {name: tmp_path / name for name in ("imported", "baseline")}
    for name, root in trees.items():
        directory = root / "rootfs-tree/private"
        directory.mkdir(parents=True, mode=0o700)
        (directory / "payload").write_bytes(b"mutated!" if name == mutation else b"original")
    observed = compare_contents(archive, digest, trees["imported"], trees["baseline"])
    assert (observed["checked"], observed["bytes"]) == (1, 8)
    assert [row["tree"] for row in observed["mismatches"]] == ([] if mutation is None else [mutation])
    command = [sys.executable, probe_path, "contents", str(archive), digest,
               str(trees["imported"]), str(trees["baseline"])]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == int(mutation is not None), result.stderr
    assert json.loads(result.stdout) == observed


def test_content_observer_keeps_decoding_failure_visible(tmp_path):
    """A valid file hash cannot conceal a failed Zstandard frame checksum."""
    member = tarfile.TarInfo("rootfs-tree/payload")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        member.size = 8
        tar.addfile(member, io.BytesIO(b"original"))
    compressed = subprocess.check_output(["zstd", "-q", "-c"], input=raw.getvalue())
    damaged = compressed[:-1] + bytes([compressed[-1] ^ 1])
    archive = tmp_path / "damaged.zst"
    archive.write_bytes(damaged)
    root = tmp_path / "imported"
    (root / "rootfs-tree").mkdir(parents=True)
    (root / member.name).write_bytes(b"original")
    with pytest.raises((RuntimeError, tarfile.ReadError)):
        compare_contents(archive, hashlib.sha256(damaged).hexdigest(), root, root)
