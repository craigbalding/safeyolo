"""Check Linux preparation through the native CLI and real guest filesystem.

Tiny extraction stages use /tmp because the nested host mounts cannot change
numeric ownership or ACLs. These controls do not prove fresh Ubuntu startup.
"""

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests import test_guest_acquisition as acquisition
from tests.blackbox import retained_inputs
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


@pytest.mark.parametrize("bases", [(231072, 400000), (100000, 100000), None],
                         ids=["alternate", "fixed-preferred", "missing"])
def test_retained_systrap_caller_remaps_only_its_private_copy(native_cli, owned_stage, bases, monkeypatch):
    parent, _ = owned_stage
    source = parent / "blackbox-platform"
    tree = source / "rootfs-tree"
    tree.mkdir(parents=True)
    (tree / "root").write_bytes(b"published root")
    (tree / "hard").hardlink_to(tree / "root")
    (tree / "symbolic").symlink_to("root")
    (tree / "agent").write_bytes(b"guest user")
    for path in (tree / "root", tree / "symbolic", tree):
        own(path, 100000, 100000)
    own(tree / "agent", 101000, 101000)
    (source / "cache-paths.txt").write_text("/var/cache/apt\n")
    archive = parent / "guest.tar.zst"
    tar_bytes = subprocess.check_output(["sudo", "-n", "tar", "--format=pax", "--numeric-owner", "-C", str(source),
                                         "-cf", "-", "rootfs-tree", "cache-paths.txt"])
    with archive.open("wb") as stream:
        subprocess.run(["zstd", "-q", "-c"], input=tar_bytes, stdout=stream, check=True)
    original_archive = hashlib.sha256(archive.read_bytes()).hexdigest()
    descriptor = {"digest": "sha256:" + original_archive, "size": archive.stat().st_size}
    selection = parent / "selection.json"
    selection.write_text(json.dumps({"schema": "safeyolo.blackbox-inputs/v1", "status": "selected",
        "platform": "linux-arm64" if os.uname().machine in {"arm64", "aarch64"} else "linux-amd64",
        "guest": {"version": "guest-2026-10-17.1", "compatibility": "v1", "archive": descriptor,
                  "index": {"digest": "sha256:" + "a" * 64, "size": 10},
                  "child": {"digest": "sha256:" + "b" * 64, "size": 10}}}))
    bundle = parent / "bundle"
    (bundle / "bin").mkdir(parents=True)
    (bundle / "bin/safeyolo").symlink_to(native_cli)
    root = parent / "installed"
    directory = parent / "private-guest"
    prepare_calls = []
    actual_run = subprocess.run

    def prepared_host(arguments, **kwargs):
        if arguments[:6] == [str(bundle / "bin/safeyolo"), "--root", str(root), "host", "prepare", "--package-root"]:
            prepare_calls.append(arguments)
            assert arguments[6:] == [str(bundle), "--installed-root", str(bundle), "--write-settings",
                                     str(directory / "linux-settings.toml"), *(["--yes"] if bases else [])]
            # Range allocation belongs to native host prepare. Control that
            # host prerequisite here; extraction and native remapping stay real.
            # Missing ranges without --yes must stop, rather than reuse fixed IDs.
            if bases is None:
                raise subprocess.CalledProcessError(1, arguments, stderr="host preparation was not approved")
            (directory / "linux-settings.toml").write_text(
                f"[linux]\nuid_base={bases[0]}\ngid_base={bases[1]}\nhost_uid={os.getuid()}\nhost_gid={os.getgid()}\n")
            return subprocess.CompletedProcess(arguments, 0)
        return actual_run(arguments, **kwargs)

    monkeypatch.setattr(retained_inputs.subprocess, "run", prepared_host)
    if bases is None:
        with pytest.raises(subprocess.CalledProcessError):
            retained_inputs.prepare_guest(selection, archive, bundle, root, directory, yes=False)
        assets = directory / "extract-guest"
        assert not (root / "share/guest-selection.json").exists()
        assert (assets / "rootfs-tree").stat().st_uid == 100000
        assert not (directory / "guest.tar").exists()
    else:
        assets = retained_inputs.prepare_guest(selection, archive, bundle, root, directory, yes=True)
        assert (assets / "rootfs-tree").stat().st_uid == bases[0]
        assert (assets / "rootfs-tree").stat().st_gid == bases[1]
        assert (assets / "rootfs-tree/agent").stat().st_uid == os.getuid()
        frozen = json.loads((root / "share/guest-selection.json").read_bytes())
        assert frozen["archive"] == descriptor
    assert len(prepare_calls) == 1
    assert (tree.stat().st_uid, tree.stat().st_gid) == (100000, 100000)
    assert (tree / "agent").stat().st_uid == 101000
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == original_archive
    # The package runner owns a mktemp parent with mode 0700. Its independent
    # extraction stays inside that private parent, including on a failed prepare.
    assert parent.stat().st_uid == os.getuid() and stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert assets.stat().st_uid == os.getuid() and stat.S_IMODE(assets.stat().st_mode) == 0o700
    copied = assets / "rootfs-tree/root"
    assert copied.read_bytes() == b"published root"
    assert copied.stat().st_ino != (tree / "root").stat().st_ino
    assert copied.stat().st_ino == (assets / "rootfs-tree/hard").stat().st_ino
    assert (assets / "rootfs-tree/symbolic").readlink() == Path("root")
    assert (assets / "cache-paths.txt").read_bytes() == (source / "cache-paths.txt").read_bytes()


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


def test_relative_package_directory_selects_its_bundled_payload(native_cli, owned_stage):
    parent, _stage = owned_stage
    bundle = parent / "bundle"
    payload(bundle / "libexec")
    (bundle / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256((bundle / 'libexec' / name).read_bytes()).hexdigest()}  ./libexec/{name}\n"
        for name in FILES
    ))
    root = parent / "instance"
    result = command(native_cli, "--root", root, "host", "prepare", "--yes",
                     "--package-root", "bundle", "--installed-root", root,
                     "--write-settings", parent / "prepared.toml", cwd=parent)
    assert result.returncode == 0, result.stderr
    selected = json.loads(result.stdout)["linux"]
    assert selected["runsc"] == str(root / "libexec/runsc")
    assert selected["runsc_origin"] == "bundled"


@pytest.mark.parametrize("namespace_status,audit_status", [(0, 0), (77, 0), (77, 61)])
def test_namespace_failure_keeps_original_result_and_observes_only_its_audit(
    native_cli, owned_stage, namespace_status, audit_status,
):
    parent, _stage = owned_stage
    runtime = payload(parent / "runtime")
    tools = parent / "tools"
    tools.mkdir()
    probe_record = parent / "probe"
    audit_record = parent / "audit"
    original_stderr = "fixture namespace denial " + "x" * 2300
    unshare = tools / "unshare"
    unshare.write_text(
        '#!/bin/sh\n[ "$1" = --kill-child=SIGKILL ] && exit 0\n'
        'printf "%s\\n" "$$" "$*" > "$PROBE_RECORD"\n'
        'if IFS= read -r unexpected; then echo "probe inherited caller input" >&2; exit 88; fi\n'
        f"printf '%s\\n' '{original_stderr}' >&2\nexit {namespace_status}\n"
    )
    unshare.chmod(0o755)
    journal = tools / "journalctl"
    journal.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$AUDIT_RECORD"\n'
        + ('echo \'fixture audit access refused\' >&2\n' if audit_status else
           'echo \'apparmor="DENIED" fixture audit record\'\n')
        + f"exit {audit_status}\n"
    )
    journal.chmod(0o755)
    settings = parent / "prepared.toml"
    result = command(native_cli, "--root", parent / "instance", "host", "prepare", "--yes",
                     "--system-runsc", runtime, "--write-settings", settings,
                     input="operator input must stay outside the namespace probe\n",
                     env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                          "PROBE_RECORD": str(probe_record), "AUDIT_RECORD": str(audit_record)})
    pid, arguments = probe_record.read_text().splitlines()
    assert arguments == "-Urn true"
    if namespace_status == 0:
        assert result.returncode == 0, result.stderr
        assert settings.exists() and not audit_record.exists()
        assert "namespace probe" not in result.stderr
        return
    assert result.returncode != 0 and not settings.exists()
    assert original_stderr in result.stderr
    assert f"namespace probe pid={pid} status=exit status: 77" in result.stderr
    assert "started=" in result.stderr and "finished=" in result.stderr and "source=" in result.stderr
    for name in ("apparmor_restrict_unprivileged_userns", "apparmor_restrict_unprivileged_unconfined"):
        assert f"kernel.{name}=" in result.stderr
    assert "AppArmor label command=" in result.stderr and "/proc/self/attr/current" in result.stderr
    assert "AppArmor label status=" in result.stderr or "AppArmor label read failed:" in result.stderr
    audit_arguments = audit_record.read_text().splitlines()
    assert audit_arguments[:3] == ["--dmesg", "--no-pager", "--output=short-iso-precise"]
    assert audit_arguments[3] == "--since" and audit_arguments[5] == "--until"
    assert int(audit_arguments[4][1:]) < int(audit_arguments[6][1:])
    assert audit_arguments[7:] == ["--grep", f'apparmor="DENIED".* pid={pid}( |$)']
    assert f"AppArmor audit status=exit status: {audit_status}" in result.stderr
    assert ("fixture audit access refused" if audit_status else 'apparmor="DENIED" fixture audit record') in result.stderr


@pytest.mark.parametrize("world_access", [False, True])
def test_runtime_access_preserves_other_acl_rights_and_honors_named_denial(native_cli, owned_stage, world_access):
    parent, _stage = owned_stage
    runtime = payload(parent / "runtime")
    (runtime.parent / "gvisor-bin").chmod(0o700)
    settings = parent / "prepared.toml"
    arguments = ("--root", parent / "instance", "host", "prepare", "--yes",
                 "--system-runsc", runtime, "--write-settings", settings)
    first = command(native_cli, *arguments)
    assert first.returncode == 0, first.stderr
    mapping = json.loads(first.stdout)["linux"]
    base = mapping["uid_base"]
    access = command("sudo", "-n", "setpriv", f"--reuid={base}",
                     f"--regid={mapping['gid_base']}", "--clear-groups",
                     "/usr/bin/test", "-x", runtime.parent / "gvisor-bin/gvisor_sentry")
    assert access.returncode == 0, access.stderr
    settings.unlink()
    # An explicit user entry wins over other:: permissions. Widening the
    # mask must not expose another entry's previously masked permissions.
    subprocess.run(["setfacl", "-m", f"u:42:rwx,u:{base}:---,g::rwx,g:43:rw-,m::---,o::{ '--x' if world_access else '---'}",
                    str(parent)], check=True)
    result = command(native_cli, *arguments)
    assert result.returncode == 0, result.stderr
    acl = command("getfacl", "-ncp", parent).stdout
    assert "user:42:---" in acl
    assert "group::---" in acl and "group:43:rw-\t#effective:---" in acl
    assert f"user:{base}:--x" in acl and "mask::--x" in acl
    settings.unlink()
    repeat = command(native_cli, *arguments)
    assert repeat.returncode == 0, repeat.stderr
    assert json.loads(repeat.stdout)["applied"] == []
    assert command("getfacl", "-ncp", parent).stdout == acl


@pytest.mark.parametrize("prior_access", ["other", "group"])
def test_runtime_access_keeps_mapped_uid_read_access_before_after_and_repeat(native_cli, owned_stage, prior_access):
    parent, _stage = owned_stage
    runtime = payload(parent / "runtime")
    root = parent / "instance"
    initialized = command(native_cli, "--root", root, "init")
    assert initialized.returncode == 0, initialized.stderr
    prepared = command(native_cli, "--root", root, "host", "prepare", "--yes", "--system-runsc", runtime)
    assert prepared.returncode == 0, prepared.stderr
    mapping = json.loads(prepared.stdout)["linux"]
    if prior_access == "group":
        own(parent, os.getuid(), mapping["gid_base"])
    # other:: is outside the ACL mask. A new named entry must retain those
    # rights under its mask. Matching group rights must also be preserved.
    acl = ("u::rwx,u:42:rwx,g::---,m::---,o::r--" if prior_access == "other" else
           "u::rwx,u:42:rwx,g::r--,m::r--,o::---")
    subprocess.run(["setfacl", "--set", acl, str(parent)], check=True)
    listing = ("-n", "setpriv", f"--reuid={mapping['uid_base']}",
               f"--regid={mapping['gid_base']}", "--clear-groups", "/usr/bin/python3",
               "-c", "import os,sys; print(sorted(os.listdir(sys.argv[1])))", parent)
    before = command("sudo", *listing)
    assert before.returncode == 0, before.stderr
    grant = command(native_cli, "--root", root, "host", "grant-runtime-access")
    assert grant.returncode == 0, grant.stderr
    after = command("sudo", *listing)
    assert after.returncode == 0 and after.stdout == before.stdout, after.stderr
    selected_acl = command("getfacl", "-ncp", parent).stdout
    assert f"user:{mapping['uid_base']}:r-x" in selected_acl and "mask::r-x" in selected_acl
    assert ("user:42:---" if prior_access == "other" else "user:42:r--") in selected_acl
    repeat = command(native_cli, "--root", root, "host", "grant-runtime-access")
    assert repeat.returncode == 0, repeat.stderr
    assert command("getfacl", "-ncp", parent).stdout == selected_acl
    repeated_listing = command("sudo", *listing)
    assert repeated_listing.returncode == 0 and repeated_listing.stdout == before.stdout


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
    capability = command("sudo", "-n", "setcap", "-n", "100000", "cap_net_raw=ep", root_file)
    assert capability.returncode == 0, capability.stderr
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
    capability = command("getcap", "-n", root_file)
    assert "cap_net_raw=ep" in capability.stdout and f"[rootid={uid_base}]" in capability.stdout
    assert (unrelated.stat().st_uid, unrelated.stat().st_gid) == (100000, 100000)


def test_remap_preserves_unchanged_inode_metadata(native_cli, owned_stage):
    _parent, stage = owned_stage
    tree = stage / "rootfs-tree"
    tree.mkdir()
    plain, attributed, agent = (tree / name for name in ("plain", "attributed", "agent"))
    for path in (plain, attributed, agent):
        path.write_bytes(b"guest bytes")
    os.setxattr(attributed, "user.safeyolo-test", b"unchanged")
    subprocess.run(["setfacl", "-m", "u:42:r-x", str(attributed)], check=True)
    for path in (tree, plain, attributed):
        own(path, 100000, 100000)
    own(agent, 101000, 101000)
    before = {path: path.stat() for path in (tree, plain, attributed)}
    result = command("sudo", "-n", native_cli, "host", "remap-rootfs", tree,
                     100000, 100000, os.getuid(), os.getgid())
    assert result.returncode == 0, result.stderr
    for path, metadata in before.items():
        after = path.stat()
        assert (after.st_ino, after.st_mode, after.st_ctime_ns) == (
            metadata.st_ino, metadata.st_mode, metadata.st_ctime_ns)
    assert (agent.stat().st_uid, agent.stat().st_gid) == (os.getuid(), os.getgid())
    assert "user:42:r-x" in command("getfacl", "-ncp", attributed).stdout


@pytest.mark.parametrize("uid_base,gid_base", [(100000, 100000), (300000, 500000)])
def test_remap_nested_attributes_and_links_preserve_external_target(native_cli, owned_stage, uid_base, gid_base):
    parent, stage = owned_stage
    tree = stage / "rootfs-tree"
    nested = tree / "nested/deeper"
    nested.mkdir(parents=True)
    attributed = nested / "attributed"
    attributed.write_bytes(b"guest bytes")
    subprocess.run(["setfacl", "-m", "u:101000:r-x,g:101000:r--", str(attributed)], check=True)
    subprocess.run(["setfacl", "-m", "d:u:101000:r-x,d:g:101000:r--", str(nested)], check=True)
    (tree / "hard").hardlink_to(attributed)
    external = parent / "external"
    external.write_bytes(b"outside bytes")
    (nested / "outside").symlink_to(external)
    paths = (tree, tree / "nested", nested, attributed, nested / "outside")
    for path in paths:
        own(path, 100000, 100000)
    before = external.stat()
    result = command("sudo", "-n", native_cli, "host", "remap-rootfs", tree,
                     uid_base, gid_base, os.getuid(), os.getgid())
    assert result.returncode == 0, result.stderr
    assert attributed.stat().st_ino == (tree / "hard").stat().st_ino
    for path in paths:
        assert (path.lstat().st_uid, path.lstat().st_gid) == (uid_base, gid_base)
    acl = command("getfacl", "-ncp", attributed).stdout
    assert f"user:{os.getuid()}:r-x" in acl and f"group:{os.getgid()}:r--" in acl
    default_acl = command("getfacl", "-ncp", nested).stdout
    assert f"default:user:{os.getuid()}:r-x" in default_acl
    assert f"default:group:{os.getgid()}:r--" in default_acl
    assert external.read_bytes() == b"outside bytes"
    after = external.stat()
    assert (after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_ctime_ns) == (
        before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_ctime_ns)


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
    assert not (parent / "instance/host").exists()
    denied = command(native_cli, *arguments, env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"})
    assert denied.returncode != 0 and "fixture sudo denied" in denied.stderr
    first_change = declined.stderr.split("SafeYolo needs these host changes:\n", 1)[1].splitlines()[0].strip()
    if first_change.startswith("prepare namespace entry"):
        assert "attempted load this installation's namespace AppArmor profile" in denied.stderr
    elif "AppArmor profile" in first_change:
        assert "attempted load this runtime's AppArmor profile" in denied.stderr
    else:
        assert first_change.startswith("allow the selected sandbox-root UID")
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
    tools = parent / "tools"
    tools.mkdir()
    (tools / "getent").symlink_to(shutil.which("getent"))
    unavailable = command(native_cli, "--root", root, "doctor",
                          env={**os.environ, "PATH": str(tools)})
    observed = json.loads(unavailable.stdout)["linux"]
    assert observed["state"] == "unavailable"
    assert "newuidmap" in observed["error"] and "newgidmap" in observed["error"]
    assert "zstd" not in observed["error"]
    assert observed["path"] == str(runtime) and observed["origin"] == "system"
    assert observed["version"] == "release-20261005.0"
    for name in ("newuidmap", "newgidmap", "setfacl", "getfacl", "unshare",
                 "nsenter", "ip", "ssh", "curl", "tar", "true", "aa-exec"):
        path = shutil.which(name)
        if path:
            (tools / name).symlink_to(path)
    assert shutil.which("zstd", path=str(tools)) is None
    ready = command(native_cli, "--root", root, "doctor",
                    env={**os.environ, "PATH": str(tools)})
    observed = json.loads(ready.stdout)["linux"]
    assert observed["state"] == "ready", observed
    if not Path("/dev/kvm").exists():
        kvm = command(native_cli, "--root", root, "doctor",
                      env={**os.environ, "SAFEYOLO_RUNSC_PLATFORM": "kvm"})
        observed = json.loads(kvm.stdout)["linux"]
        assert observed["state"] == "unavailable", observed
        assert "/dev/kvm" in observed["error"] and "host prepare" in observed["error"]
        assert observed["path"] == str(runtime) and observed["origin"] == "system"
        for backend in ("auto", "systrap"):
            available = command(native_cli, "--root", root, "doctor",
                                env={**os.environ, "SAFEYOLO_RUNSC_PLATFORM": backend})
            assert json.loads(available.stdout)["linux"]["state"] == "ready", available.stdout
    runtime.unlink()
    missing = command(native_cli, "--root", root, "doctor")
    assert missing.returncode == 0, missing.stderr
    observed = json.loads(missing.stdout)["linux"]
    assert observed["state"] == "unavailable" and observed["path"] == str(runtime)
    assert observed["origin"] == "system" and "no other runtime" in observed["error"]


@pytest.mark.parametrize("operation,prefix", [("load-profile", "safeyolo-runsc"),
                                               ("load-namespace-profile", "safeyolo-userns")])
def test_profile_load_failure_retains_only_its_complete_profile(native_cli, owned_stage, operation, prefix):
    parent, _stage = owned_stage
    runtime = parent / 'runtime with "quotes"'
    name = prefix + "-" + hashlib.sha256(os.fsencode(runtime)).hexdigest()[:16]
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
                     "host", operation, runtime)
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


@pytest.mark.parametrize("prepared_entry", [False, True], ids=["missing-entry", "working-entry"])
def test_host_prepare_retries_retained_runtime_profile(native_cli, owned_stage, prepared_entry):
    # Control AppArmor availability and parser failures, while executing the
    # actual preparation/privileged profile-writing caller. Kernel namespace
    # creation under both restrictions is covered by the separate host test.
    parent, _stage = owned_stage
    runtime = payload(parent / "runtime")
    root = parent / "instance"
    entry = root / "host/namespace-entry"
    profiles = [Path("/etc/apparmor.d") / (prefix + "-" + hashlib.sha256(os.fsencode(path)).hexdigest()[:16])
                for prefix, path in (("safeyolo-runsc", runtime), ("safeyolo-userns", entry))]
    tools = parent / "tools"
    tools.mkdir()
    loaded = parent / "loaded"
    loaded.mkdir()
    refused = parent / "refused"
    calls = parent / "parser-calls"
    restriction = parent / "restriction"
    restriction.write_text("1\n")
    shim = parent / "restriction.so"
    source = "#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <fcntl.h>\n#include <stdarg.h>\n#include <stdlib.h>\n#include <string.h>\n"
    for name in ("open", "open64"):
        source += f"""
int {name}(const char *path, int flags, ...) {{
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {{
        va_list args; va_start(args, flags); mode = va_arg(args, unsigned int); va_end(args);
    }}
    if (strcmp(path, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == 0)
        path = getenv("SAFEYOLO_FIXTURE_RESTRICTION");
    int (*original)(const char *, int, ...) = dlsym(RTLD_NEXT, "{name}");
    return original(path, flags, mode);
}}
"""
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Werror", "-x", "c", "-", "-ldl", "-o", str(shim)],
                   input=source, text=True, check=True, timeout=15)
    (tools / "apparmor_parser").write_text(
        '#!/bin/sh\nset -eu\n[ "$1" = -r ]\n'
        f'printf "%s\\n" "$2" >> {shlex.quote(str(calls))}\n'
        f'if [ "$2" = {shlex.quote(str(profiles[0]))} ] && [ -e {shlex.quote(str(refused))} ]; then\n'
        "echo 'fixture profile load refused' >&2\nexit 77\nfi\n"
        f': > {shlex.quote(str(loaded))}/"$(basename "$2")"\n')
    (tools / "aa-exec").write_text(
        '#!/bin/sh\nset -eu\n[ "$1" = -p ] && [ "$3" = -- ] && [ "$4" = true ]\n'
        f'test -e {shlex.quote(str(loaded))}/"$2"\n')
    (tools / "unshare").write_text("#!/bin/sh\nexit 0\n")
    # Keep the controlled parser on PATH across real sudo's environment reset.
    (tools / "sudo").write_text(
        '#!/bin/sh\n[ "$1" = -- ] || exit 99\nshift\n'
        f'exec {shlex.quote(shutil.which("sudo"))} -n -- env '
        f'{shlex.quote("PATH=" + str(tools) + ":" + os.environ["PATH"])} "$@"\n')
    for tool in tools.iterdir():
        tool.chmod(0o755)
    environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "LD_PRELOAD": str(shim),
                   "SAFEYOLO_FIXTURE_RESTRICTION": str(restriction)}
    settings = parent / "prepared.toml"
    arguments = (native_cli, "--root", root, "host", "prepare", "--yes",
                 "--system-runsc", runtime, "--write-settings", settings)
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(profiles[0].parent)], check=True)
    try:
        if prepared_entry:
            seeded = command(*arguments, env=environment)
            assert seeded.returncode == 0, seeded.stderr
            (loaded / profiles[0].name).unlink()
            entry.chmod(0o700)
            settings.unlink()
        refused.touch()
        failed = command(*arguments, env=environment)
        assert failed.returncode != 0 and "fixture profile load refused" in failed.stderr, failed.stderr
        assert "profile file remains" in failed.stderr and not settings.exists()
        original = profiles[0].read_bytes()
        assert b"userns," in original and b"flags=(unconfined)" in original
        assert entry.exists() == prepared_entry
        refused.unlink()
        # A retained runtime file must not hide an unloaded profile, including
        # when the independent namespace-entry probe already succeeds.
        subprocess.run(["sudo", "-n", "rm", "-f", "--", str(calls)], check=True)
        retried = command(*arguments, env=environment)
        assert retried.returncode == 0, retried.stderr
        assert json.loads(retried.stdout)["state"] == "prepared"
        assert json.loads(retried.stdout)["linux"]["apparmor_profile"] == profiles[0].name
        assert calls.read_text().splitlines() == list(map(str, profiles[:1] if prepared_entry else profiles))
        assert profiles[0].read_bytes() == original
        assert stat.S_IMODE(entry.stat().st_mode) == (0o700 if prepared_entry else 0o755)
        calls_before_repeat = calls.read_bytes()
        settings.unlink()
        repeated = command(*arguments, env=environment)
        assert repeated.returncode == 0, repeated.stderr
        assert json.loads(repeated.stdout)["applied"] == []
        assert calls.read_bytes() == calls_before_repeat
    finally:
        subprocess.run(["sudo", "-n", "rm", "-f", "--", *map(str, profiles)], check=True)


def test_scoped_namespace_entry_with_both_apparmor_restrictions(native_cli, owned_stage):
    restrictions = [Path("/proc/sys/kernel") / name for name in (
        "apparmor_restrict_unprivileged_userns", "apparmor_restrict_unprivileged_unconfined")]
    if not all(path.exists() and path.read_text().strip() == "1" for path in restrictions):
        pytest.skip("requires a host with both AppArmor restrictions enabled")
    parent, _stage = owned_stage
    root = parent / "instance"
    runtime = payload(parent / "runtime")
    entry = root / "host/namespace-entry"
    profiles = [Path("/etc/apparmor.d") / (prefix + "-" + hashlib.sha256(os.fsencode(path)).hexdigest()[:16])
                for prefix, path in (("safeyolo-runsc", runtime), ("safeyolo-userns", entry))]
    try:
        prepared = command(native_cli, "--root", root, "host", "prepare", "--yes",
                           "--system-runsc", runtime, "--write-settings", parent / "prepared.toml")
        assert prepared.returncode == 0, prepared.stderr
        observe = ("import json,os; from pathlib import Path; print(json.dumps({"
                   "'user':os.readlink('/proc/self/ns/user'),'net':os.readlink('/proc/self/ns/net'),"
                   "'uid':os.getuid(),'uid_map':Path('/proc/self/uid_map').read_text(),"
                   "'label':Path('/proc/self/attr/current').read_text()}))")
        entered = command(entry, "unshare", "-Urn", sys.executable, "-c", observe)
        assert entered.returncode == 0, entered.stderr
        observed = json.loads(entered.stdout)
        assert observed["user"] != os.readlink("/proc/self/ns/user"), observed
        assert observed["net"] != os.readlink("/proc/self/ns/net"), observed
        assert observed["uid"] == 0 and list(map(int, observed["uid_map"].split())) == [0, os.getuid(), 1]
        assert profiles[1].name in observed["label"] and "//&unconfined" not in observed["label"], observed
        repeated = command(native_cli, "--root", root, "host", "prepare", "--yes",
                           "--system-runsc", runtime, "--write-settings", parent / "repeated.toml")
        assert repeated.returncode == 0, repeated.stderr
        assert json.loads(repeated.stdout)["applied"] == []
        subprocess.run(["sudo", "-n", "apparmor_parser", "-R", str(profiles[0])], check=True)
        runtime_repaired = command(native_cli, "--root", root, "host", "prepare", "--yes",
                                   "--system-runsc", runtime, "--write-settings", parent / "runtime-repaired.toml")
        assert runtime_repaired.returncode == 0, runtime_repaired.stderr
        assert json.loads(runtime_repaired.stdout)["applied"] == [
            f"profile setup was requested; {profiles[0]} remains if the profile load fails",
            "load this runtime's AppArmor profile",
        ]
        entry.chmod(0o700)
        subprocess.run(["sudo", "-n", "apparmor_parser", "-R", str(profiles[1])], check=True)
        repaired = command(native_cli, "--root", root, "host", "prepare", "--yes",
                           "--system-runsc", runtime, "--write-settings", parent / "repaired.toml")
        assert repaired.returncode == 0, repaired.stderr
        assert stat.S_IMODE(entry.stat().st_mode) == 0o700
        assert all(path.read_text().strip() == "1" for path in restrictions)
    finally:
        for profile in profiles:
            if profile.exists():
                subprocess.run(["sudo", "-n", "apparmor_parser", "-R", str(profile)], check=True)
                subprocess.run(["sudo", "-n", "rm", "--", str(profile)], check=True)
