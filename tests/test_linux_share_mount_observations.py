"""Check the live-share driver's mount observations and holder release."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

DRIVER = Path(__file__).parent / "nested-linux/live_mount_backend_proof.py"
driver = runpy.run_path(str(DRIVER))
assert_mount_removed = driver["assert_mount_removed"]

@pytest.fixture(scope="module")
def mount_holder(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        pytest.skip("the native holder runs on the Linux guest kernel")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("the test-only native holder needs a Linux C compiler")
    binary = tmp_path_factory.mktemp("mount-holder") / "mount-holder"
    source = Path(__file__).parent / "fixtures/live-mount-holder.c"
    built = subprocess.run([compiler, "-std=c11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
                            str(source), "-o", str(binary)], capture_output=True, text=True, timeout=30)
    assert built.returncode == 0, (built.stdout, built.stderr)
    return binary

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


@pytest.mark.parametrize("mode", ["marker", "file", "cwd", "mmap"])
def test_native_holder_retains_real_kernel_state_and_observes_release(tmp_path, mount_holder, mode):
    source = tmp_path / "host.txt"
    source.write_text("before".ljust(4096, "."))
    result = tmp_path / "marker's result"
    # The actual command must work with neither Python nor any other PATH tool.
    command = driver["holder_command"](mount_holder, mode, str(tmp_path), result)
    with subprocess.Popen(["/bin/sh", "-c", command], env=dict(os.environ, PATH=""),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
        try:
            identity = driver["holder_ready"](result)
            process = Path(f"/proc/{identity['pid']}")
            assert identity["start"] == (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
            descriptors = []
            for entry in (process / "fd").iterdir():
                try:
                    descriptors.append(entry.readlink())
                except FileNotFoundError:
                    pass  # The holder can close its temporary heartbeat file during inspection.
            if mode == "file":
                assert source in descriptors
            elif mode == "cwd":
                assert (process / "cwd").readlink() == tmp_path
            elif mode == "mmap":
                assert source not in descriptors
                assert any(str(source) in row and "rw-s" in row for row in (process / "maps").read_text().splitlines())
                assert result.with_suffix(".mapped-before").read_text() == "before".ljust(64, ".")
            with source.open("r+") as changed:
                changed.write('after:"quoted"\\path'.ljust(64, "."))
                changed.flush()
                os.fsync(changed.fileno())
            heartbeat = result.with_suffix(".heartbeat").read_text()
            deadline = time.monotonic() + 5
            while result.with_suffix(".heartbeat").read_text() == heartbeat:
                assert time.monotonic() < deadline
                time.sleep(.05)
            observation = driver["release_holder"](result)
            stdout, stderr = child.communicate(timeout=5)
            assert child.returncode == observation["exit"] == 0, (stdout, stderr)
            assert observation["identity"] == identity
            assert observation["accessible"] is True
            if mode == "marker":
                assert observation["data"] == "marker survived"
            else:
                assert observation["data"] == 'after:"quoted"\\path'.ljust(64, ".")
            if mode in ("file", "mmap"):
                assert source.read_bytes()[128:151] == b"guest-open-handle-write"
            elif mode == "cwd":
                assert (tmp_path / "guest-cwd-write").read_text() == "guest-cwd-write"
            assert json.loads(result.with_suffix(".read-result").read_text())["data"] == observation["data"]
        finally:
            result.with_suffix(".release").touch()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)


@pytest.mark.parametrize("exit_code", [17, 127])
def test_holder_early_exit_keeps_actual_exit_and_bounded_stderr(tmp_path, exit_code):
    script = tmp_path / "failing holder"
    if exit_code == 17:
        script.write_text("#!/bin/sh\nprintf '%4096s' x >&2\nprintf 'holder failure' >&2\nexit 17\n")
        script.chmod(0o755)
    result = tmp_path / "absent"
    command = driver["holder_command"](script, "marker", str(tmp_path), result)
    with subprocess.Popen(["/bin/sh", "-c", command]) as child:
        with pytest.raises(RuntimeError, match=f"holder exited {exit_code} before ready") as error:
            driver["holder_ready"](result)
        assert driver["release_holder"](result) == {"exit": exit_code}
        assert child.wait(timeout=5) == exit_code
    if exit_code == 17:
        assert str(error.value).endswith("holder failure")
        assert len(result.with_suffix(".log").read_text()) > 4096
    else:
        assert str(script) in str(error.value)
    assert len(str(error.value)) < 2200


@pytest.mark.parametrize("mode", ["file", "cwd", "mmap"])
def test_native_holder_setup_failure_cannot_become_ready(tmp_path, mount_holder, mode):
    result = tmp_path / "failed"
    command = driver["holder_command"](mount_holder, mode, str(tmp_path / "missing"), result)
    with subprocess.Popen(["/bin/sh", "-c", command]) as child:
        with pytest.raises(RuntimeError, match="holder exited 1 before ready"):
            driver["holder_ready"](result)
        assert child.wait(timeout=5) == 1
    assert not result.with_suffix(".ready").exists()
    assert not result.with_suffix(".result").exists()
    assert "No such file" in result.with_suffix(".log").read_text()


def test_native_cwd_holder_preserves_failed_access_after_release(tmp_path, mount_holder):
    source = tmp_path / "host.txt"
    source.write_text("before".ljust(4096, "."))
    result = tmp_path / "failed-access"
    command = driver["holder_command"](mount_holder, "cwd", str(tmp_path), result)
    with subprocess.Popen(["/bin/sh", "-c", command]) as child:
        try:
            identity = driver["holder_ready"](result)
            source.unlink()
            observation = driver["release_holder"](result)
            assert child.wait(timeout=5) == 0
            assert observation["identity"] == identity
            assert observation["accessible"] is False and observation["errno"] == 2
            assert not result.with_suffix(".read-result").exists()
            assert "held access after release" in result.with_suffix(".log").read_text()
        finally:
            result.with_suffix(".release").touch()
            child.wait(timeout=5)


def test_native_mmap_holder_refuses_a_short_file_before_ready(tmp_path, mount_holder):
    (tmp_path / "host.txt").write_text("short")
    result = tmp_path / "short-map"
    command = driver["holder_command"](mount_holder, "mmap", str(tmp_path), result)
    with subprocess.Popen(["/bin/sh", "-c", command]) as child:
        with pytest.raises(RuntimeError, match="at least 4096 bytes"):
            driver["holder_ready"](result)
        assert child.wait(timeout=5) == 1
    assert not result.with_suffix(".ready").exists()


@pytest.mark.parametrize("supplied", [False, True])
def test_linux_driver_prepares_native_holder_and_keeps_failed_startup(tmp_path, mount_holder, supplied):
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    cli = root / "bin/safeyolo"
    cli.write_text("#!/bin/sh\necho 'controlled unavailable product' >&2\nexit 17\n")
    cli.chmod(0o755)
    base = tmp_path / "result"
    with pytest.raises(RuntimeError, match="owned instance cleanup failed"):
        driver["run_proof"](root, base, holder_probe=mount_holder if supplied else None)
    report = json.loads((base / "observed.json").read_text())
    binary = base / "workspace/mount-holder"
    assert binary.is_file() and os.access(binary, os.X_OK)
    assert report["holder_probe"]["sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert report["holder_probe"]["supplied"] == (str(mount_holder) if supplied else None)
    builds = [row for row in report["commands"] if row["argv"][0] == "cc"]
    assert bool(builds) != supplied
    assert all(row["exit"] == 0 for row in builds)
    failed = [row for row in report["commands"] if row["argv"][0] == str(cli)]
    assert failed and all(row["exit"] == 17 and "controlled unavailable product" in row["stderr"] for row in failed)
    assert report["cleanup_failures"]
    assert not json.loads((base / "procedure.json").read_text())["finished"]


def test_mac_missing_probe_is_refused_before_creating_mount_fixture(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    base = tmp_path / "result"
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(ValueError, match="requires --holder-probe"):
        driver["run_proof"](root, base)
    assert not base.exists()
