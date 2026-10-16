"""Check the live-share driver's mount observations and holder release."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import time
from pathlib import Path

import pytest

DRIVER = Path(__file__).parent / "nested-linux/live_mount_backend_proof.py"
driver = runpy.run_path(str(DRIVER))
assert_mount_removed = driver["assert_mount_removed"]

# This controls only the host command/release contract. The guest keeps its
# Linux process identity, real handles and mount observations in GUEST_HOLDER.
HOST_HOLDER = '''import json, os, sys, time
from pathlib import Path
mode, target, result = sys.argv[1:]
assert mode == "marker"
result = Path(result)
identity = {"pid": os.getpid()}
result.with_suffix(".ready").write_text(json.dumps(identity))
deadline = time.monotonic() + 20
while not result.with_suffix(".release").exists():
    if time.monotonic() > deadline:
        raise TimeoutError("host did not release controlled holder")
    time.sleep(.05)
result.with_suffix(".result").write_text(json.dumps({
    "identity": identity, "accessible": True, "data": "marker survived"}))
'''


def holder_ready(child, path):
    deadline = time.monotonic() + 20
    while not path.exists():
        if child.poll() is not None:
            _, stderr = child.communicate(timeout=5)
            raise RuntimeError(f"holder exited {child.returncode} before ready: {stderr[-2048:]}")
        if time.monotonic() > deadline:
            raise TimeoutError(f"missing probe result: {path}")
        time.sleep(.05)
    return json.loads(path.read_text())

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


@pytest.mark.parametrize(("payload", "exit_code"), [
    (HOST_HOLDER, 0),
    ("raise SystemExit(17)\n", 17),
    # Keep the real Linux guest payload exercised on its actual kernel too.
    *([(driver["GUEST_HOLDER"], 0)] if sys.platform.startswith("linux") else []),
], ids=["host", "exit17", *(["linux-guest"] if sys.platform.startswith("linux") else [])])
def test_holder_release_observes_the_command_exit(tmp_path, payload, exit_code):
    script = tmp_path / "holder script.py"
    script.write_text(payload)
    result = tmp_path / "marker's result"
    command = driver["holder_command"](script, "marker", str(tmp_path), result)
    with subprocess.Popen(["sh", "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
        try:
            identity = (holder_ready(child, result.with_suffix(".ready"))
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


def test_holder_early_exit_reports_bounded_stderr(tmp_path):
    code = "import sys;sys.stderr.write('x' * 4096 + 'holder failure');sys.exit(17)"
    with subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as child:
        with pytest.raises(RuntimeError, match="holder exited 17 before ready") as error:
            holder_ready(child, tmp_path / "absent.ready")
    assert str(error.value).endswith("holder failure")
    assert len(str(error.value)) < 2200
