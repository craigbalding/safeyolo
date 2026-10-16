"""Check the live-share driver's mount observations and holder release."""

from __future__ import annotations

import json
import runpy
import subprocess
from pathlib import Path

import pytest

DRIVER = Path(__file__).parent / "nested-linux/live_mount_backend_proof.py"
driver = runpy.run_path(str(DRIVER))
assert_mount_removed = driver["assert_mount_removed"]

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


@pytest.mark.parametrize("exit_code", [0, 17])
def test_holder_release_observes_the_command_exit(tmp_path, exit_code):
    script = tmp_path / "holder script.py"
    script.write_text(driver["GUEST_HOLDER"] if exit_code == 0 else "raise SystemExit(17)\n")
    result = tmp_path / "marker's result"
    command = driver["holder_command"](script, "marker", str(tmp_path), result)
    with subprocess.Popen(["sh", "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
        try:
            identity = (json.loads(driver["wait_file"](result.with_suffix(".ready")))
                        if exit_code == 0 else None)
            observation = driver["release_holder"](result)
            stdout, stderr = child.communicate(timeout=5)
            assert child.returncode == observation["exit"] == exit_code, (stdout, stderr)
            if exit_code == 0:
                assert observation["identity"] == identity
                assert observation["accessible"] is True
                assert observation["data"] == "marker survived"
            else:
                assert observation == {"exit": exit_code}
        finally:
            result.with_suffix(".release").touch()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
