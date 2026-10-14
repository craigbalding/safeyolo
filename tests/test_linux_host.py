"""Check Linux preparation through the native CLI and real guest filesystem.

Tiny extraction stages use /tmp because the nested host mounts cannot change
numeric ownership or ACLs. These controls do not prove fresh Ubuntu startup.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests import test_guest_acquisition as acquisition
from tests.test_host_packages import executable

native_cli = acquisition.native_cli
package_info = acquisition.package_info

FILES = ("runsc", "gvisor-bin/checkpointgofer",
         "gvisor-bin/gvisor-sentry-prewarmer", "gvisor-bin/gvisor_sentry",
         "gvisor-bin/runsc-fd-parking", "gvisor-bin/runsc-metric-server")


def command(binary, *arguments, **kwargs):
    return subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                          text=True, timeout=30, **kwargs)


@pytest.fixture
def owned_stage():
    parent = Path(tempfile.mkdtemp(prefix="linux-preparation-"))
    try:
        stage = parent / "extract-owned"
        stage.mkdir(mode=0o700)
        yield parent, stage
    finally:
        subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(parent)], check=True)


def own(path, uid, gid):
    subprocess.run(["sudo", "-n", "chown", "-h", f"{uid}:{gid}", str(path)], check=True)


def payload(path):
    (path / "gvisor-bin").mkdir(parents=True)
    executable(path / "runsc", "runsc version release-20261005.0")
    for name in FILES[1:]:
        shutil.copy2(path / "runsc", path / name)
    return path / "runsc"


@pytest.mark.parametrize("fault", ["missing", "architecture", "version", "truncated"])
def test_runtime_input_fails_before_host_changes(native_cli, tmp_path, fault):
    runtime = payload(tmp_path / "runtime")
    sidecar = runtime.parent / "gvisor-bin/gvisor_sentry"
    if fault == "missing":
        sidecar.unlink()
    elif fault == "architecture":
        data = bytearray(sidecar.read_bytes())
        data[18:20] = (62 if os.uname().machine in ("arm64", "aarch64") else 183).to_bytes(2, "little")
        sidecar.write_bytes(data)
    elif fault == "truncated":
        sidecar.write_bytes(b"broken")
    else:
        executable(runtime, "runsc version release-19000101.0")
    settings = tmp_path / "prepared.toml"
    result = command(native_cli, "--root", tmp_path / "fresh", "host", "prepare",
                     "--system-runsc", runtime, "--write-settings", settings)
    assert result.returncode != 0
    assert {"missing": "incomplete", "architecture": "another architecture", "version": "incompatible", "truncated": "corrupt"}[fault] in result.stderr
    assert "Host changes and attempted operations: none" in result.stderr
    assert not settings.exists() and not (tmp_path / "fresh").exists()


@pytest.mark.parametrize("uid_base,gid_base", [(300000, 500000), (100000, 100000)])
def test_mapping_remap_keeps_modes_links_and_guest_user_ids(native_cli, owned_stage, uid_base, gid_base):
    parent, stage = owned_stage
    tree = stage / "rootfs-tree"
    tree.mkdir()
    root_file = tree / "root"
    root_file.write_bytes(b"root bytes")
    (tree / "hard").hardlink_to(root_file)
    os.setxattr(root_file, "user.safeyolo-test", b"kept attribute")
    subprocess.run(["setfacl", "-m", "u:101000:r-x", str(root_file)], check=True)
    own(root_file, 100000, 100000)
    subprocess.run(["sudo", "-n", "chmod", "6751", str(root_file)], check=True)
    (tree / "symbolic").symlink_to("root")
    own(tree / "symbolic", 100000, 100000)
    for name, uid in (("agent", 101000), ("other", 101001), ("last", 165535)):
        path = tree / name
        path.write_bytes(name.encode())
        own(path, uid, uid)
    own(tree, 100000, 100000)
    unrelated = parent / "other-install"
    unrelated.mkdir()
    own(unrelated, 100000, 100000)
    inode = root_file.stat().st_ino
    result = command("sudo", "-n", native_cli, "host", "remap-rootfs", tree,
                     uid_base, gid_base, os.getuid(), os.getgid())
    assert result.returncode == 0, result.stderr
    assert (tree.stat().st_uid, tree.stat().st_gid) == (uid_base, gid_base)
    assert (root_file.stat().st_uid, root_file.stat().st_gid) == (uid_base, gid_base)
    assert stat.S_IMODE(root_file.stat().st_mode) == 0o6751
    assert root_file.stat().st_ino == (tree / "hard").stat().st_ino == inode
    assert (tree / "symbolic").readlink() == Path("root")
    assert ((tree / "symbolic").lstat().st_uid, (tree / "symbolic").lstat().st_gid) == (uid_base, gid_base)
    assert ((tree / "agent").stat().st_uid, (tree / "agent").stat().st_gid) == (os.getuid(), os.getgid())
    assert ((tree / "other").stat().st_uid, (tree / "other").stat().st_gid) == (uid_base + 1001, gid_base + 1001)
    assert ((tree / "last").stat().st_uid, (tree / "last").stat().st_gid) == (uid_base + 65535, gid_base + 65535)
    attribute = command("sudo", "-n", "/usr/bin/python3", "-c",
                        "import os,sys;sys.stdout.buffer.write(os.getxattr(sys.argv[1], 'user.safeyolo-test'))", root_file)
    assert attribute.returncode == 0 and attribute.stdout == "kept attribute"
    acl = command("getfacl", "-ncp", root_file)
    assert f"user:{os.getuid()}:r-x" in acl.stdout
    assert (unrelated.stat().st_uid, unrelated.stat().st_gid) == (100000, 100000)


@pytest.mark.parametrize("fault", ["shared", "outside-owner", "outside-link"])
def test_remap_refuses_live_tree_and_bad_owner_before_changing_files(native_cli, owned_stage, fault):
    parent, stage = owned_stage
    tree = (parent if fault == "shared" else stage) / "rootfs-tree"
    tree.mkdir()
    child = tree / "file"
    child.write_bytes(b"preserved")
    own(child, 0 if fault == "outside-owner" else 100000, 100000)
    own(tree, 100000, 100000)
    if fault == "outside-link":
        subprocess.run(["sudo", "-n", "ln", str(child), str(parent / "outside")], check=True)
    result = command("sudo", "-n", native_cli, "host", "remap-rootfs", tree,
                     300000, 500000, os.getuid(), os.getgid())
    assert result.returncode != 0
    assert {"shared": "private extract-", "outside-owner": "outside the published",
            "outside-link": "hard link outside"}[fault] in result.stderr
    assert tree.stat().st_uid == tree.stat().st_gid == 100000
    assert child.read_bytes() == b"preserved"
    assert child.stat().st_uid == (0 if fault == "outside-owner" else 100000)


def test_denied_runtime_permission_reports_changes_and_retry_is_idempotent(native_cli, owned_stage):
    parent, _stage = owned_stage
    private = parent / "private"
    runtime = payload(private / "runtime")
    own(private, 0, os.getgid())
    subprocess.run(["sudo", "-n", "chmod", "0710", str(private)], check=True)
    # The operator can traverse this directory through its group. Mapped
    # sandbox root needs the separate, explained ACL operation.
    tools = parent / "tools"
    tools.mkdir()
    (tools / "sudo").write_text("#!/bin/sh\necho 'fixture sudo denied' >&2\nexit 77\n")
    (tools / "sudo").chmod(0o755)
    settings = parent / "prepared.toml"
    arguments = ("--root", parent / "instance", "host", "prepare", "--yes",
                 "--system-runsc", runtime, "--write-settings", settings)
    declined = command(native_cli, *(arg for arg in arguments if arg != "--yes"), input="n\n")
    assert declined.returncode != 0 and "declined" in declined.stderr
    assert "Host changes and attempted operations: none" in declined.stderr and not settings.exists()
    denied = command(native_cli, *arguments, env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"})
    assert denied.returncode != 0 and "fixture sudo denied" in denied.stderr
    assert "attempted allow UID" in denied.stderr
    assert denied.stderr.index("SafeYolo needs these host changes") < denied.stderr.index("fixture sudo denied")
    assert "Host changes and attempted operations:" in denied.stderr and not settings.exists()
    retry = command(native_cli, *arguments)
    assert retry.returncode == 0, retry.stderr
    assert json.loads(retry.stdout)["linux"]["runsc_origin"] == "system"
    settings.unlink()
    before = command("getfacl", "-ncp", private).stdout
    repeated = command(native_cli, *arguments)
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout)["applied"] == []
    assert "SafeYolo needs these host changes" not in repeated.stderr
    assert command("getfacl", "-ncp", private).stdout == before

    # Activation also grants access to a newly created private install root.
    # Its narrow operation must retain the same partial-failure diagnosis.
    root = parent / "instance"
    initialized = command(native_cli, "--root", root, "init")
    assert initialized.returncode == 0, initialized.stderr
    with (root / "config.toml").open("a") as config:
        config.write(settings.read_text())
    base = json.loads(repeated.stdout)["linux"]["uid_base"]
    subprocess.run(["sudo", "-n", "setfacl", "-x", f"u:{base}", str(private)], check=True)
    activation = command(native_cli, "--root", root, "host", "grant-runtime-access",
                         env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"})
    assert activation.returncode != 0 and "fixture sudo denied" in activation.stderr
    assert "Host changes and attempted operations: attempted allow UID" in activation.stderr
    assert "retry the installer" in activation.stderr
    recovery = command(native_cli, "--root", root, "host", "grant-runtime-access")
    assert recovery.returncode == 0, recovery.stderr


def test_doctor_keeps_selected_system_identity_when_runtime_disappears(native_cli, owned_stage):
    parent, _stage = owned_stage
    runtime = payload(parent / "runtime")
    root = parent / "instance"
    initialized = command(native_cli, "--root", root, "init")
    assert initialized.returncode == 0, initialized.stderr
    prepared = command(native_cli, "--root", root, "host", "prepare", "--yes", "--system-runsc", runtime)
    assert prepared.returncode == 0, prepared.stderr
    first = command(native_cli, "--root", root, "doctor")
    assert first.returncode == 0, first.stderr
    observed = json.loads(first.stdout)["linux"]
    assert observed["path"] == str(runtime) and observed["origin"] == "system"
    assert observed["version"] == "release-20261005.0"
    runtime.unlink()
    missing = command(native_cli, "--root", root, "doctor")
    assert missing.returncode == 0, missing.stderr
    observed = json.loads(missing.stdout)["linux"]
    assert observed["state"] == "unavailable" and observed["path"] == str(runtime)
    assert observed["origin"] == "system" and "no other runtime" in observed["error"]


def test_profile_load_failure_retains_only_its_complete_profile(native_cli, owned_stage):
    parent, _stage = owned_stage
    runtime = parent / 'runtime with "quotes"'
    name = "safeyolo-runsc-" + hashlib.sha256(os.fsencode(runtime)).hexdigest()[:16]
    profile = Path("/etc/apparmor.d") / name
    assert not profile.exists()
    tools = parent / "tools"
    tools.mkdir()
    parser = tools / "apparmor_parser"
    parser.write_text("#!/bin/sh\necho 'fixture profile load refused' >&2\nexit 77\n")
    parser.chmod(0o755)
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(profile.parent)], check=True)
    try:
        arguments = ("-n", "env", f"PATH={tools}:{os.environ['PATH']}", native_cli,
                     "host", "load-profile", runtime)
        result = command("sudo", *arguments)
        assert result.returncode != 0 and "profile file remains" in result.stderr
        original = profile.read_bytes()
        assert b'\\"quotes\\"' in original
        assert b"userns," in original and b"flags=(unconfined)" in original
        parser.write_text("#!/bin/sh\nexit 0\n")
        retry = command("sudo", *arguments)
        assert retry.returncode == 0, retry.stderr
        assert profile.read_bytes() == original
    finally:
        subprocess.run(["sudo", "-n", "rm", "-f", "--", str(profile)], check=True)
