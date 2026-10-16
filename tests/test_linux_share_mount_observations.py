"""Check the Linux share driver's removal assertion against real mountinfo format."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

DRIVER = Path(__file__).parent / "nested-linux/live_mount_backend_proof.py"
assert_mount_removed = runpy.run_path(str(DRIVER))["assert_mount_removed"]

# The installed 02d0f474 run emitted source "none", without the share UUID.
ROOT = "18 1 0:18 / / rw - overlay none rw\n"
SHARE = (
    "36 18 0:38 / /mnt/proof1042live rw,nosuid,nodev - 9p none "
    "rw,trans=fd,rfdno=527,wfdno=527,aname=/,dfltuid=4294967294,"
    "dfltgid=4294967294,dcache=1000,cache=remote_revalidating,directfs\n"
)


def test_removed_mount_requires_a_before_observation_and_actual_disappearance():
    target = "/mnt/proof1042live"
    assert_mount_removed(target, ROOT + SHARE, ROOT)
    with pytest.raises(AssertionError, match="not observed before"):
        assert_mount_removed(target, ROOT, ROOT)
    with pytest.raises(AssertionError, match="survived removal"):
        assert_mount_removed(target, ROOT + SHARE, ROOT + SHARE)
    # A moved mount ID or a replacement at the same target also remains live.
    with pytest.raises(AssertionError, match="survived removal"):
        assert_mount_removed(target, ROOT + SHARE, ROOT + SHARE.replace(target, "/mnt/alias"))
    with pytest.raises(AssertionError, match="survived removal"):
        assert_mount_removed(target, ROOT + SHARE, ROOT + SHARE.replace("36 18", "99 18"))


def test_mountpoint_comparison_preserves_escaped_directory_names():
    target = "/mnt/space tab\tline\nback\\slash\r"
    row = SHARE.replace("/mnt/proof1042live", r"/mnt/space\040tab\011line\012back\134slash" + "\r")
    assert_mount_removed(target, ROOT + row, ROOT)
    with pytest.raises(AssertionError, match="survived removal"):
        assert_mount_removed(target, ROOT + row, ROOT + row)
