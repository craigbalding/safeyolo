"""Run the staged shell/cache boundary without downloading a distribution."""

import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "guest/build_profile.py"
SCRIPT = """#!/bin/bash
set -euo pipefail
echo build >> "$BUILD_LOG"
test "$0" != "$ORIGINAL_SCRIPT"
if [[ ${WAIT_FOR_SIGNAL:-0} == 1 ]]; then
    trap 'echo cleaned > "$SIGNAL_CLEANED"; exit 143' TERM
    echo ready > "$SIGNAL_READY"
    # Reading a FIFO is interrupted by TERM; no child sleeps outlive this test.
    read -r _ < "$SIGNAL_FIFO"
fi
if [[ -n ${SAFEYOLO_ROOTFS_OUT_TREE:-} ]]; then
    mkdir -p "$SAFEYOLO_ROOTFS_OUT_TREE/etc"
    cat "$(dirname "$0")/helper" > "$SAFEYOLO_ROOTFS_OUT_TREE/etc/result"
else
    echo image > "$SAFEYOLO_ROOTFS_OUT_EXT4"
fi
echo /var/cache/apt > "$SAFEYOLO_ROOTFS_OUT_CACHE_PATHS"
exit "${BUILD_EXIT:-0}"
"""


@pytest.fixture
def profile(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    script = source / "build.sh"
    script.write_text(SCRIPT)
    (source / "helper").write_text("staged helper\n")
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({
        "name": "test", "script": "build.sh", "base": "registry.example/distro@sha256:" + "a" * 64,
        "files": ["build.sh", "helper"],
        "environment": {"BUILD_LOG": str(tmp_path / "calls"), "ORIGINAL_SCRIPT": str(script)},
    }))
    return path, source, tmp_path / "cache"


def command(profile, *extra):
    path, source, cache = profile
    return [sys.executable, str(RUNNER), "--profile", str(path), "--source", str(source),
            "--cache", str(cache), "--architecture", "amd64", *extra]


def build(profile, *extra, env=None):
    result = subprocess.run(command(profile, *extra), capture_output=True, text=True, env=env, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_reuses_completed_output_and_force_selects_fresh_output(profile):
    first = build(profile)
    second = build(profile)
    assert second == {**first, "cache_hit": True}
    calls = profile[0].parent / "calls"
    assert calls.read_text().splitlines() == ["build"]
    forced = build(profile, "--force")
    assert forced["key"] == first["key"] and forced["assets"] != first["assets"]
    assert calls.read_text().splitlines() == ["build", "build"]
    assert build(profile) == {**forced, "cache_hit": True}
    assert (Path(first["assets"]) / "rootfs-tree/etc/result").read_text() == "staged helper\n"


@pytest.mark.parametrize("changed", ["script", "helper", "mode", "base", "architecture", "output-kind", "frozen"])
def test_each_declared_input_invalidates(profile, changed):
    frozen = profile[0].parent / "frozen.json"
    frozen.write_text('{"tools":{"mise":{"version":"1"}}}')
    options = ["--guest-inputs", str(frozen)]
    first = build(profile, *options)
    if changed in {"script", "helper"}:
        path = profile[1] / ("build.sh" if changed == "script" else "helper")
        with path.open("a") as stream:
            stream.write("\n# changed\n")
    elif changed == "mode":
        (profile[1] / "helper").chmod(0o700)
    elif changed == "base":
        value = json.loads(profile[0].read_text())
        value["base"] = value["base"].replace("a" * 64, "b" * 64)
        profile[0].write_text(json.dumps(value))
    elif changed == "frozen":
        frozen.write_text('{"tools":{"mise":{"version":"2"}}}')
    else:
        options += ["--" + changed, "arm64" if changed == "architecture" else "ext4"]
    second = build(profile, *options)
    assert second["key"] != first["key"] and not second["cache_hit"]
    assert Path(first["assets"]).is_dir() and Path(second["assets"]).is_dir()


def test_failure_and_failed_force_never_replace_completed_output(profile):
    first = build(profile)
    result = subprocess.run(command(profile, "--force"), capture_output=True, text=True,
                            env={**os.environ, "BUILD_EXIT": "73"}, timeout=15)
    assert result.returncode != 0 and "retained at" in result.stderr
    assert build(profile) == {**first, "cache_hit": True}
    assert len(list(profile[2].glob("*.json"))) == 1


def test_unfinished_output_is_not_a_cache_hit(profile):
    first = build(profile)
    (Path(first["assets"]) / "rootfs-tree/etc/result").unlink()
    (Path(first["assets"]) / "rootfs-tree/etc").rmdir()
    result = subprocess.run(command(profile), capture_output=True, text=True, timeout=15)
    assert result.returncode != 0 and "missing its completed rootfs" in result.stderr


def test_shared_script_open_for_writing_is_staged_before_execution(profile):
    # Executing this inode directly can fail ETXTBSY on shared filesystems.
    # The runner executes its staged copy and reads only the staged helper.
    with (profile[1] / "build.sh").open("a"):
        result = build(profile)
    assert (Path(result["assets"]) / "rootfs-tree/etc/result").read_text() == "staged helper\n"


def test_relative_builder_reads_use_the_staged_source_directory(profile):
    script = profile[1] / "build.sh"
    script.write_text(script.read_text().replace('"$(dirname "$0")/helper"', 'helper'))
    result = build(profile)
    assert (Path(result["assets"]) / "rootfs-tree/etc/result").read_text() == "staged helper\n"


def test_implicit_source_parents_do_not_change_identity_with_caller_umask(profile):
    (profile[1] / "nested").mkdir()
    (profile[1] / "nested/input").write_text("input")
    record = json.loads(profile[0].read_text())
    record["files"].append("nested/input")
    profile[0].write_text(json.dumps(record))
    results = []
    for mask in ("077", "022"):
        result = subprocess.run(["bash", "-c", 'umask "$1"; shift; exec "$@"',
                                 "profile-umask", mask, *command(profile)],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        results.append(json.loads(result.stdout))
    assert results[1] == {**results[0], "cache_hit": True}


def test_builder_cannot_admit_a_link_to_an_unfinished_external_tree(profile):
    # Remove the fixture's terminal exit so this output replacement runs.
    source = (profile[1] / "build.sh").read_text().replace('exit "${BUILD_EXIT:-0}"', '''
mkdir -p "$SAFEYOLO_ROOTFS_WORK_DIR/other/etc"
rm -rf -- "$SAFEYOLO_ROOTFS_OUT_TREE"
ln -s "$SAFEYOLO_ROOTFS_WORK_DIR/other" "$SAFEYOLO_ROOTFS_OUT_TREE"
''')
    (profile[1] / "build.sh").write_text(source)
    result = subprocess.run(command(profile), capture_output=True, text=True, timeout=15)
    assert result.returncode != 0 and "missing its completed rootfs tree" in result.stderr
    assert not list(profile[2].glob("*.json"))


@pytest.mark.parametrize("local", [False, True])
def test_raw_tree_export_preserves_metadata_and_uses_selected_mapping(local):
    binary = os.environ.get("SAFEYOLO_NATIVE_CLI")
    if not binary:
        pytest.skip("set SAFEYOLO_NATIVE_CLI to the candidate CLI for raw-tree export proof")
    assert Path(binary).is_file()
    with tempfile.TemporaryDirectory(prefix="kali-profile-metadata-") as temporary:
        directory = Path(temporary)
        try:
            built = directory / "built"
            tree = built / "rootfs-tree"
            tree.mkdir(parents=True)
            (tree / "command").write_text("guest executable\n")
            (tree / "command").chmod(0o751)
            os.link(tree / "command", tree / "hard")
            (tree / "symbolic").symlink_to("command")
            os.setxattr(tree / "command", "user.safeyolo.fixture", b"metadata")
            acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in [
                (1, 7, 0xFFFFFFFF), (2, 4, 33), (4, 5, 0xFFFFFFFF),
                (16, 5, 0xFFFFFFFF), (32, 1, 0xFFFFFFFF),
            ])
            os.setxattr(tree / "command", "system.posix_acl_access", acl)
            subprocess.run(["sudo", "-n", "chown", "-Rh", "0:0", str(tree)], check=True)
            subprocess.run(["sudo", "-n", "chown", "1000:33", str(tree / "command")], check=True)
            architecture = "amd64" if os.uname().machine == "x86_64" else "arm64"
            (built / "build-inputs.json").write_text(json.dumps({"architecture": architecture, "output_kind": "tree"}))
            (built / "build-base.txt").write_text("docker.io/kalilinux/kali-rolling@sha256:" + "a" * 64)
            (built / "cache-paths.txt").write_text("/var/cache/apt\n")
            output = directory / "exported"
            arguments = [str(ROOT / "guest/export-profile.sh"), "--build", str(built),
                         "--platform", "linux/" + architecture, "--output", str(output),
                         "--native-cli", str(Path(binary).resolve())]
            if local:
                settings = directory / "host-settings.toml"
                settings.write_text(f"[linux]\nuid_base=231072\ngid_base=400000\nhost_uid={os.getuid()}\nhost_gid={os.getgid()}\n")
                arguments += ["--host-settings", str(settings)]
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            exported = output / "rootfs-tree"
            assert (exported.stat().st_uid, exported.stat().st_gid) == ((231072, 400000) if local else (100000, 100000))
            assert (exported / "command").stat().st_uid == (os.getuid() if local else 101000)
            assert (exported / "command").stat().st_gid == (400033 if local else 100033)
            assert (exported / "command").stat().st_mode & 0o777 == 0o751
            assert (exported / "command").stat().st_ino == (exported / "hard").stat().st_ino
            assert (exported / "symbolic").readlink() == Path("command")
            attributes = subprocess.check_output(["sudo", "-n", sys.executable, "-c",
                'import json,os,sys; print(json.dumps([os.getxattr(sys.argv[1], name).hex() for name in ("user.safeyolo.fixture", "system.posix_acl_access")]))',
                str(exported / "command")], text=True)
            expected_acl = bytearray(acl)
            expected_acl[16:20] = (231105 if local else 100033).to_bytes(4, "little")
            assert json.loads(attributes) == [b"metadata".hex(), expected_acl.hex()]
            assert tree.stat().st_uid == 0 and (tree / "command").stat().st_uid == 1000
        finally:
            subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(directory)], check=True)


def test_signal_waits_for_builder_cleanup_without_admitting_output(profile, tmp_path):
    ready, cleaned, fifo = (tmp_path / name for name in ("ready", "cleaned", "fifo"))
    os.mkfifo(fifo)
    environment = {**os.environ, "WAIT_FOR_SIGNAL": "1", "SIGNAL_READY": str(ready),
                   "SIGNAL_CLEANED": str(cleaned), "SIGNAL_FIFO": str(fifo)}
    child = subprocess.Popen(command(profile), env=environment, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        # A real FIFO rendezvous shows the builder reached its trap setup.
        descriptor = os.open(fifo, os.O_RDWR)
        import time
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert child.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        child.send_signal(signal.SIGTERM)
        _, errors = child.communicate(timeout=10)
        assert child.returncode == 143, errors
        assert cleaned.read_text() == "cleaned\n"
        assert not list(profile[2].glob("*.json"))
    finally:
        os.close(descriptor)
        if child.poll() is None:
            child.kill()
            child.wait()
