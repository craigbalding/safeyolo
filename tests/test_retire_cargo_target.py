"""Focused executable checks for Cargo target retirement."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import runpy
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "retire_cargo_target.py"


def _commit() -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    target = tmp_path / "target-623 parser"
    debug = target / "debug"
    debug.mkdir(parents=True)
    binary = debug / "candidate-proxy"
    binary.write_bytes(b"candidate binary\n")
    binary.chmod(0o755)
    receipt = tmp_path / "sol-receipt.md"
    commit = _commit()
    receipt.write_text(f"accepted candidate commit: {commit}\n")
    record = tmp_path / "retirements.jsonl"
    return target, receipt, record, commit


def _run(
    target: Path, receipt: Path, record: Path, commit: str, *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--target",
            str(target),
            "--receipt",
            str(receipt),
            "--commit",
            commit,
            "--record",
            str(record),
        ],
        text=True,
        capture_output=True,
        check=False,
        cwd=cwd,
    )


def test_external_target_retirement_preserves_receipt_hash_evidence(tmp_path: Path) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    receipt_hash = hashlib.sha256(receipt.read_bytes()).hexdigest()

    result = _run(target, receipt, record, commit)

    assert result.returncode == 0, result.stderr
    event = json.loads(result.stdout)
    assert event["candidate_commit"] == commit
    assert event["acceptance_receipt_sha256"] == receipt_hash
    assert event["top_level_debug_binaries"]["candidate-proxy"] == hashlib.sha256(
        b"candidate binary\n"
    ).hexdigest()
    assert record.read_text().splitlines() == [json.dumps(event, sort_keys=True)]
    assert receipt.read_bytes() == f"accepted candidate commit: {commit}\n".encode()
    assert not target.exists()


@pytest.mark.parametrize("nested_option", ["receipt", "record"])
def test_evidence_paths_inside_target_are_refused(
    tmp_path: Path, nested_option: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    if nested_option == "receipt":
        receipt = target / "sol-receipt.md"
        receipt.write_text(f"accepted candidate commit: {commit}\n")
    else:
        record = target / "retirements.jsonl"

    result = _run(target, receipt, record, commit)

    assert result.returncode != 0
    assert f"--{nested_option} must be outside --target" in result.stderr
    assert target.is_dir()


def test_ancestor_cwd_is_live_owner(tmp_path: Path) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    original_cwd = Path.cwd()
    try:
        os.chdir(target)
        result = _run(target, receipt, record, commit, cwd=ROOT)
    finally:
        os.chdir(original_cwd)

    assert result.returncode != 0
    assert f"target is still referenced by live process {os.getpid()}" in result.stderr
    assert target.is_dir()


def _start_owner(target: Path, owner_kind: str) -> subprocess.Popen[bytes]:
    environment = os.environ.copy()
    environment.pop("CARGO_TARGET_DIR", None)
    environment["PWD"] = "/"
    options: dict[str, object] = {"env": environment, "cwd": "/"}
    arguments = [sys.executable, "-c", "import time; time.sleep(60)"]
    if owner_kind == "env":
        environment["CARGO_TARGET_DIR"] = str(target)
    elif owner_kind == "relative-env":
        environment["CARGO_TARGET_DIR"] = target.name
        options["cwd"] = target.parent
    elif owner_kind == "prefix-env":
        other = target.with_name(f"{target.name}-other")
        other.mkdir()
        environment["CARGO_TARGET_DIR"] = str(other)
    elif owner_kind == "cwd":
        options["cwd"] = target
    elif owner_kind in ("argv", "relative-argv", "equals-argv"):
        value = str(target)
        if owner_kind == "relative-argv":
            value = target.name
            options["cwd"] = target.parent
        arguments.extend(
            [f"--target-dir={value}"] if owner_kind == "equals-argv"
            else ["--target-dir", value]
        )
    else:
        held = target / "held-open"
        held.write_bytes(b"held")
        descriptor = os.open(held, os.O_RDONLY)
        options["pass_fds"] = (descriptor,)
    owner = subprocess.Popen(
        arguments,
        **options,
    )
    if owner_kind == "open-fd":
        os.close(descriptor)
    return owner


@pytest.mark.parametrize("owner_kind", [
    "env", "relative-env", "cwd", "open-fd", "argv", "relative-argv", "equals-argv",
])
def test_external_target_refuses_live_owner_from_env_cwd_or_fd(
    tmp_path: Path, owner_kind: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    owner = _start_owner(target, owner_kind)
    try:
        deadline = time.monotonic() + 2
        while owner.poll() is None and time.monotonic() < deadline:
            result = _run(target, receipt, record, commit)
            if result.returncode != 0:
                break
            time.sleep(0.05)
        else:
            pytest.fail("live owner fixture did not remain running")

        assert result.returncode != 0
        assert f"target is still referenced by live process {owner.pid}" in result.stderr
        assert target.is_dir()
        assert not record.exists()
    finally:
        owner.terminate()
        owner.wait(timeout=5)


def test_prefix_env_does_not_claim_target(tmp_path: Path) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    owner = _start_owner(target, "prefix-env")
    try:
        result = _run(target, receipt, record, commit)
        assert result.returncode == 0, result.stderr
        assert not target.exists()
    finally:
        owner.terminate()
        owner.wait(timeout=5)


@pytest.mark.parametrize("owner_kind", ["cwd", "open-fd"])
@pytest.mark.parametrize("suffix", ["real\ttab", "real\nnewline", r"literal\ttab", r"literal\nnewline", "control\x01byte", "literal^Abyte"])
def test_live_file_owner_preserves_exact_path_bytes(
    tmp_path: Path, owner_kind: str, suffix: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    target = target.rename(target.with_name(f"target-{suffix}"))
    owner = _start_owner(target, owner_kind)
    try:
        result = _run(target, receipt, record, commit)
        assert owner.poll() is None
        assert result.returncode != 0
        assert f"target is still referenced by live process {owner.pid}" in result.stderr
        assert target.is_dir()
        assert not record.exists()
    finally:
        owner.terminate()
        owner.wait(timeout=5)


@pytest.mark.parametrize("owner_kind", ["env", "relative-env", "argv", "relative-argv"])
def test_live_argument_owner_preserves_trailing_whitespace(
    tmp_path: Path, owner_kind: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    target = target.rename(target.with_name("target-trailing \t"))
    owner = _start_owner(target, owner_kind)
    try:
        result = _run(target, receipt, record, commit)
        assert owner.poll() is None
        assert result.returncode != 0
        assert f"target is still referenced by live process {owner.pid}" in result.stderr
        assert target.is_dir()
        assert not record.exists()
    finally:
        owner.terminate()
        owner.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "darwin", reason="Mac native image inspection")
@pytest.mark.parametrize("owner_kind", ["executable", "closed-fd-mapping"])
@pytest.mark.parametrize("suffix", ["plain", "raw\tname\n"])
def test_mac_live_image_without_open_descriptor_is_preserved(
    tmp_path: Path, owner_kind: str, suffix: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    target = target.rename(target.with_name(f"target-{suffix}"))
    environment = os.environ.copy()
    environment.pop("CARGO_TARGET_DIR", None)
    if owner_kind == "executable":
        executable = target / "debug" / "running-cat"
        shutil.copy("/bin/cat", executable)
        arguments = [str(executable)]
    else:
        mapped = target / "mapped-data"
        mapped.write_bytes(b"retained mapping\n")
        arguments = [sys.executable, "-c", """
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
libc.mmap.restype = ctypes.c_void_p
fd = os.open(sys.argv[1], os.O_RDONLY)
address = libc.mmap(None, 4096, 1, 2, fd, 0)  # PROT_READ, MAP_PRIVATE
os.close(fd)
if address == ctypes.c_void_p(-1).value:
    raise OSError(ctypes.get_errno(), 'mmap failed')
print('ready', flush=True)
sys.stdin.readline()
print(ctypes.string_at(address, 16).decode().strip(), flush=True)
""", str(mapped)]
    owner = subprocess.Popen(
        arguments, cwd="/", env=environment, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert owner.stdin is not None and owner.stdout is not None
        if owner_kind == "executable":
            owner.stdin.write("ready\n")
            owner.stdin.flush()
        assert select.select([owner.stdout], [], [], 5)[0], "owner failed to start"
        assert owner.stdout.readline() == "ready\n"
        result = _run(target, receipt, record, commit)
        assert owner.poll() is None
        assert result.returncode != 0, result.stdout
        assert f"target is still referenced by live process {owner.pid}" in result.stderr
        assert target.is_dir() and not record.exists()
        owner.stdin.write("still live\n")
        owner.stdin.flush()
        assert select.select([owner.stdout], [], [], 5)[0], "owner stopped responding"
        expected = "still live\n" if owner_kind == "executable" else "retained mapping\n"
        assert owner.stdout.readline() == expected
    finally:
        if owner.poll() is None:
            owner.terminate()
        owner.wait(timeout=5)
    result = _run(target, receipt, record, commit)
    assert result.returncode == 0, result.stderr
    assert not target.exists() and record.is_file()


@pytest.mark.parametrize("failure", ["executable-truncated", "region-short", "region-no-progress"])
def test_mac_native_image_inspection_failure_retains_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    namespace = runpy.run_path(str(SCRIPT))
    globals_ = namespace["main"].__globals__
    ctypes = globals_["ctypes"]

    def executable(pid: int, buffer: object, size: int) -> int:
        name = b"/usr/bin/unrelated"
        ctypes.memmove(buffer, name, len(name))
        return size if failure == "executable-truncated" else len(name)

    def region(pid: int, flavor: int, address: int, buffer: object, size: int) -> int:
        return size - 1 if failure == "region-short" else size

    library = SimpleNamespace(proc_pidpath=executable, proc_pidinfo=region,
                              proc_pidfdinfo=lambda *args: 0)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: library)
    monkeypatch.setitem(globals_, "darwin_process_files", lambda *args: (Path("/"), []))
    monkeypatch.setitem(globals_, "darwin_process_arguments", lambda pid: ([], []))
    monkeypatch.setitem(globals_, "active_owner", namespace["darwin_active_owner"])
    original = subprocess.check_output
    monkeypatch.setattr(subprocess, "check_output", lambda args, **kwargs:
                        "999999\n" if args == ["ps", "-axo", "pid="] else original(args, **kwargs))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--target", str(target),
                                     "--receipt", str(receipt), "--commit", commit,
                                     "--record", str(record)])
    with pytest.raises(SystemExit, match="target retained"):
        namespace["main"]()
    assert target.is_dir() and not record.exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="Mac native image inspection")
def test_mac_retirement_refuses_its_own_closed_descriptor_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, receipt, record, commit = _fixture(tmp_path)
    mapped = target / "mapped-data"
    mapped.write_bytes(b"retained mapping\n")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    fd = os.open(mapped, os.O_RDONLY)
    try:
        address = libc.mmap(None, 4096, 1, 2, fd, 0)  # PROT_READ, MAP_PRIVATE
    finally:
        os.close(fd)
    assert address != ctypes.c_void_p(-1).value
    namespace = runpy.run_path(str(SCRIPT))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--target", str(target),
                                     "--receipt", str(receipt), "--commit", commit,
                                     "--record", str(record)])
    try:
        with pytest.raises(SystemExit, match=f"target is still referenced by live process {os.getpid()}"):
            namespace["main"]()
        assert target.is_dir() and not record.exists()
        assert ctypes.string_at(address, 17) == b"retained mapping\n"
    finally:
        assert libc.munmap(address, 4096) == 0
    assert namespace["main"]() == 0
    assert not target.exists() and record.is_file()
