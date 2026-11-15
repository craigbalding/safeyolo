"""Exercise content and cleanup observers with real archives, processes and sockets."""

import hashlib
import io
import json
import socket
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from experiments.rootless_guest import ubuntu_runtime_probe as probe
from experiments.rootless_guest.test_import_guest import archive_file
from experiments.rootless_guest.ubuntu_runtime_probe import __file__ as probe_path
from experiments.rootless_guest.ubuntu_runtime_probe import compare_contents, observe_cleanup


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


@pytest.mark.parametrize("case", [
    "clean", "inert-socket", "stopped-record", "live-child", "live-listener", "foreign-listener",
    "container", "userns", "ready",
])
def test_cleanup_observer(tmp_path, case):
    from installed_host_smoke import _process_start_token

    root = tmp_path / "i"
    root.mkdir()
    path = root / "agents/a/proxy/proxy.sock"
    tracked = []
    child = None
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if case in {"inert-socket", "live-listener", "foreign-listener"}:
            if case == "foreign-listener":
                path = tmp_path / "foreign.sock"
            path.parent.mkdir(parents=True, exist_ok=True)
            listener.bind(str(path))
            listener.listen()
            if case == "inert-socket":
                listener.close()
        elif case in {"stopped-record", "live-child"}:
            child = subprocess.Popen([sys.executable, "-c", "import signal; signal.pause()"])
            token = _process_start_token(child.pid)
            assert token is not None
            tracked.append({"pid": child.pid, "start_token": token})
            path = root / "data/coord/nats/process.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"pid": child.pid, "start_token": token}))
            if case == "stopped-record":
                child.terminate()
                child.wait(timeout=5)
        elif case in {"container", "userns", "ready"}:
            path = root / ("data/ready.json" if case == "ready" else f"agents/a/{case}.pid")
            path.parent.mkdir(parents=True)
            path.write_text("1")

        observed = observe_cleanup(root, tracked)
        assert bool(observed["failures"]) == (case in {"live-child", "live-listener", "container", "userns", "ready"})
        if case == "live-child":
            assert observed["failures"] == [f"owned process {child.pid} is still live"]
        elif case == "live-listener":
            assert len(observed["failures"]) == 1
            assert observed["failures"][0].startswith("live Unix listener: ")
            assert str(path) in observed["failures"][0]
        elif case in {"container", "userns", "ready"}:
            assert observed["failures"] == [str(path)]
        assert observed["diagnostic_paths"] == (
            [str(path)] if case in {"inert-socket", "live-listener", "stopped-record", "live-child"} else [])
        if case != "clean":
            assert path.exists(), "Observation must preserve diagnostic and runtime state"
    finally:
        listener.close()
        if child is not None and child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


def test_cleanup_observer_keeps_inspection_failure_visible(tmp_path, monkeypatch):
    read_text = Path.read_text

    def denied_unix_table(path, *args, **kwargs):
        if path == Path("/proc/net/unix"):
            raise PermissionError("cannot inspect listeners")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied_unix_table)
    with pytest.raises(PermissionError, match="cannot inspect listeners"):
        observe_cleanup(tmp_path, [])


@pytest.mark.parametrize("exit_code", [0, 7])
def test_cancellation_observer_does_not_accept_completion_before_signal(tmp_path, monkeypatch, exit_code):
    popen = subprocess.Popen

    def completed_before_extraction(command, **options):
        return popen([sys.executable, "-c", f"print('before extraction'); raise SystemExit({exit_code})"], **options)

    monkeypatch.setattr(subprocess, "Popen", completed_before_extraction)
    with pytest.raises(RuntimeError, match="No active extraction observed"):
        probe.cancel_published_import(tmp_path)
    result = json.loads((tmp_path / "cancellation.json").read_text())
    assert result["signalled"] is False
    assert result["children"] == []
    assert (tmp_path / "cancellation.stdout").read_text() == "before extraction\n"
    assert (tmp_path / "external-target").read_bytes() == b"external target must survive\n"
