"""Focused executable checks for the guarded Cargo wrapper."""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "cargo_with_space.sh"
sys.path.insert(0, str(ROOT / "scripts"))
import validate_rust_dependencies as dependency_validator  # noqa: E402


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _linux_running_group_members(pgid: int) -> list[int]:
    members = []
    for stat_file in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat_file.read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            continue  # The process exited during the scan.
        # An adopted zombie cannot run or hold a compiler's output pipes open.
        if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
            members.append(int(stat_file.parent.name))
    return members


@pytest.fixture
def linux_child_subreaper() -> Iterator[None]:
    if not sys.platform.startswith("linux"):
        pytest.skip("controlling orphan adoption requires Linux prctl")
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    # Keep adoption local to this test process; restore the caller's setting.
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0, os.strerror(ctypes.get_errno())
    assert libc.prctl(36, 1, 0, 0, 0) == 0, os.strerror(ctypes.get_errno())
    try:
        yield
    finally:
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0, os.strerror(ctypes.get_errno())


def _fixture(tmp_path: Path, *, darwin: bool, with_setsid: bool) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "bash", "#!/bin/sh\nexec /bin/bash \"$@\"\n")
    _write_executable(bin_dir / "sh", "#!/bin/sh\nexec /bin/sh \"$@\"\n")
    (bin_dir / "awk").symlink_to("/usr/bin/awk")
    (bin_dir / "ps").symlink_to(shutil.which("ps"))
    _write_executable(
        bin_dir / "dirname",
        "#!/bin/sh\nif [ \"$DF_EXPECT_BSD\" = 1 ] && [ \"$1\" = -- ]; then exit 2; fi\nif [ \"$DF_EXPECT_GNU\" = 1 ] && [ \"$1\" != -- ]; then exit 2; fi\nexec /usr/bin/dirname \"$@\"\n",
    )
    _write_executable(
        bin_dir / "stat",
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "expected = ['-f', '%d:%i'] if os.environ['DF_EXPECT_BSD'] == '1' else ['-c', '%d:%i', '--']\n"
        "if sys.argv[1:-1] != expected:\n"
        "    sys.exit(2)\n"
        "value = os.stat(sys.argv[-1])\n"
        "print(f'{value.st_dev}:{value.st_ino}')\n",
    )
    (bin_dir / "sleep").symlink_to(shutil.which("sleep"))
    if with_setsid:
        _write_executable(
            bin_dir / "setsid",
            "#!/bin/sh\nprintf '%s\\n' 'setsid-invoked' >> \"$CARGO_FAKE_LOG\"\nexec \"$@\"\n",
        )
    platform = "Darwin" if darwin else "Linux"
    _write_executable(bin_dir / "uname", f"#!/bin/sh\nprintf '%s\\n' '{platform}'\n")
    log = tmp_path / "cargo.log"
    _write_executable(
        bin_dir / "cargo",
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CARGO_FAKE_LOG\"\n",
    )
    _write_executable(
        bin_dir / "df",
        "#!/bin/sh\nif [ \"$DF_EXPECT_BSD\" = 1 ] && [ \"$2\" = -- ]; then exit 2; fi\nif [ \"$DF_EXPECT_GNU\" = 1 ] && [ \"$2\" != -- ]; then exit 2; fi\nprintf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'\nprintf '%s\\n' '/dev/fake 100000000 1 99999999 1% /'\n",
    )
    return bin_dir, log


def _run_wrapper(
    tmp_path: Path,
    *,
    darwin: bool,
    with_setsid: bool,
    source_root: Path | None = None,
    target_dir: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_dir, log = _fixture(tmp_path, darwin=darwin, with_setsid=with_setsid)
    (bin_dir / "mkdir").symlink_to(shutil.which("mkdir"))
    env = {
        "PATH": str(bin_dir),
        "CARGO_FAKE_LOG": str(log),
        "CARGO_TARGET_DIR": str(target_dir or tmp_path / "missing" / "target"),
        "SAFEYOLO_CARGO_RESERVE_GIB": "0",
        "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
        "DF_EXPECT_BSD": "1" if darwin else "0",
        "DF_EXPECT_GNU": "0" if darwin else "1",
    }
    cwd = None
    if source_root is not None:
        source_root.mkdir(parents=True, exist_ok=True)
        cwd = source_root
        env["SAFEYOLO_CARGO_SOURCE_BATCH"] = "review-mutants"
        env["SAFEYOLO_CARGO_SOURCE_ROOT"] = str(source_root)
    return subprocess.run(
        [str(WRAPPER), "build", "--locked"],
        env=env,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_dependency_target_root_defaults_to_checkout_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(dependency_validator.DEPENDENCY_TARGET_ROOT_ENV, raising=False)

    root = dependency_validator._dependency_target_root()

    assert root == dependency_validator.DEFAULT_DEPENDENCY_TARGET_ROOT.resolve()
    assert root != Path(tempfile.gettempdir())
    assert root.parent == ROOT.parent.resolve()


def test_dependency_target_root_honours_configuration_and_cleans_only_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configured_root = tmp_path / "build-targets"
    source = tmp_path / "source-evidence.txt"
    source.write_text("retain me\n")
    monkeypatch.setenv(
        dependency_validator.DEPENDENCY_TARGET_ROOT_ENV, str(configured_root)
    )

    root = dependency_validator._dependency_target_root()
    context, target_directory = dependency_validator._create_dependency_target(root)
    try:
        assert root == configured_root.resolve()
        assert target_directory.parent == root
        assert target_directory.name.startswith(
            dependency_validator.DEPENDENCY_TARGET_PREFIX
        )
        assert target_directory.is_dir()
        (target_directory / "generated-cargo-artifact").write_text("generated\n")
    finally:
        context.cleanup()

    assert configured_root.is_dir()
    assert not target_directory.exists()
    assert source.read_text() == "retain me\n"


def test_linux_invokes_setsid_when_available(tmp_path: Path) -> None:
    result = _run_wrapper(tmp_path, darwin=False, with_setsid=True)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "cargo.log").read_text() == "setsid-invoked\nbuild --locked\n"
    assert "setsid unavailable" not in result.stderr


def test_cargo_failure_status_is_preserved(tmp_path: Path) -> None:
    bin_dir, _ = _fixture(tmp_path, darwin=False, with_setsid=False)
    _write_executable(bin_dir / "cargo", "#!/bin/sh\nexit 23\n")

    result = subprocess.run(
        [str(WRAPPER), "build"],
        env={
            "PATH": str(bin_dir),
            "SAFEYOLO_CARGO_RESERVE_GIB": "0",
            "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
        },
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 23, result.stderr


@pytest.mark.parametrize("cargo_status", [0, 23])
@pytest.mark.parametrize("query_fails", [False, True])
def test_linux_finishes_with_unreaped_zombie_after_live_descendant(
    tmp_path: Path, linux_child_subreaper: None, cargo_status: int, query_fails: bool
) -> None:
    real_setsid = shutil.which("setsid")
    if real_setsid is None:
        pytest.skip("setsid is required for the process-group regression")
    bin_dir, _ = _fixture(tmp_path, darwin=False, with_setsid=False)
    (bin_dir / "setsid").symlink_to(real_setsid)
    cargo_file = tmp_path / "cargo-pids"
    release_child = tmp_path / "release-child"
    samples = tmp_path / "df-samples"
    query_failure = tmp_path / "ps-failed"
    if query_fails:
        (bin_dir / "ps").unlink()
        _write_executable(
            bin_dir / "ps",
            f"#!{sys.executable}\n"
            "import os, sys\n"
            f"if not os.path.exists({str(release_child)!r}):\n"
            f"    open({str(query_failure)!r}, 'w').close()\n"
            "    sys.exit(1)\n"
            f"os.execv({shutil.which('ps')!r}, [{shutil.which('ps')!r}, *sys.argv[1:]])\n",
        )
    _write_executable(
        bin_dir / "cargo",
        f"#!{sys.executable}\n"
        "import os, time\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        f"    while not os.path.exists({str(release_child)!r}): time.sleep(0.01)\n"
        "    os._exit(0)\n"
        f"with open({str(cargo_file) + '.tmp'!r}, 'w') as log: log.write(f'{{os.getpid()}}\\n{{child}}\\n')\n"
        f"os.replace({str(cargo_file) + '.tmp'!r}, {str(cargo_file)!r})\n"
        f"os._exit({cargo_status})\n",
    )
    _write_executable(
        bin_dir / "df",
        f"#!{sys.executable}\n"
        f"with open({str(samples)!r}, 'a') as log: log.write('sample\\n')\n"
        "print('Filesystem 1024-blocks Used Available Capacity Mounted on')\n"
        f"print('/dev/fake 100000000 1 {11 * 1024 * 1024} 1% /')\n",
    )
    sentinel = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    cargo_pid = child_pid = 0
    stdout_file = tmp_path / "stdout"
    stderr_file = tmp_path / "stderr"
    with stdout_file.open("w") as stdout, stderr_file.open("w") as stderr:
        process = subprocess.Popen(
            [str(WRAPPER), "build"],
            env={
                "PATH": str(bin_dir),
                "CARGO_TARGET_DIR": str(tmp_path),
                "SAFEYOLO_CARGO_RESERVE_GIB": "10",
                "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
                "SAFEYOLO_CARGO_HARD_STOP": "1",
            },
            start_new_session=True,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            deadline = time.monotonic() + 5
            while not cargo_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            cargo_pid, child_pid = map(int, cargo_file.read_text().splitlines())
            deadline = time.monotonic() + 5
            while _pid_exists(cargo_pid) and time.monotonic() < deadline:
                time.sleep(0.01)
            assert not _pid_exists(cargo_pid), "Cargo leader was not reaped"
            assert _linux_running_group_members(cargo_pid) == [child_pid]
            child_stat = Path(f"/proc/{child_pid}/stat")
            assert int(child_stat.read_text().rsplit(")", 1)[1].split()[1]) == os.getpid()

            # Two further samples prove monitoring continues after leader exit.
            sample_count = len(samples.read_text().splitlines())
            deadline = time.monotonic() + 5
            while len(samples.read_text().splitlines()) < sample_count + 2 and time.monotonic() < deadline:
                assert process.poll() is None, "wrapper abandoned its live descendant"
                time.sleep(0.02)
            assert len(samples.read_text().splitlines()) >= sample_count + 2
            assert _linux_running_group_members(cargo_pid) == [child_pid]
            assert process.poll() is None
            assert query_failure.exists() == query_fails

            release_child.touch()
            deadline = time.monotonic() + 5
            while child_stat.read_text().rsplit(")", 1)[1].split()[0] != "Z" and time.monotonic() < deadline:
                time.sleep(0.01)
            assert child_stat.read_text().rsplit(")", 1)[1].split()[0] == "Z"
            os.killpg(cargo_pid, 0)  # Presence alone still reports the dead group.
            assert process.wait(timeout=4) == cargo_status, stderr_file.read_text()
            assert child_stat.read_text().rsplit(")", 1)[1].split()[0] == "Z", "zombie was reaped early"
            assert sentinel.poll() is None, "unrelated sentinel was signalled"
            assert stdout_file.read_text() == ""
            assert stderr_file.read_text() == ""
        finally:
            if cargo_pid == 0 and cargo_file.exists():
                cargo_pid, child_pid = map(int, cargo_file.read_text().splitlines())
            for pgid in (cargo_pid, process.pid):
                if pgid:
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # This fixture group has already exited.
            process.wait(timeout=5)
            if child_pid:
                assert os.waitpid(child_pid, 0)[0] == child_pid
            sentinel.terminate()
            sentinel.wait(timeout=5)


@pytest.mark.parametrize("hard_stop", ["0", "1"])
def test_linux_monitors_reserve_before_setsid_creates_group(
    tmp_path: Path, hard_stop: str
) -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("the regression exercises Linux process-group semantics")
    real_setsid = shutil.which("setsid")
    if real_setsid is None:
        pytest.skip("setsid is required for the startup regression")

    bin_dir, _ = _fixture(tmp_path, darwin=False, with_setsid=False)
    start_gate = tmp_path / "start-session"
    cargo_ready = tmp_path / "cargo-ready"
    os.mkfifo(start_gate)
    os.mkfifo(cargo_ready)
    launcher_file = tmp_path / "launcher-pid"
    cargo_file = tmp_path / "cargo-pids"
    samples = tmp_path / "df-samples"
    interrupted = tmp_path / "interrupted"
    finished = tmp_path / "finished"
    _write_executable(
        bin_dir / "setsid",
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"open({str(launcher_file)!r}, 'w').write(str(os.getpid()))\n"
        # Only a monitoring df invocation can release this launcher. The
        # preflight df has completed, but no Cargo session can exist yet.
        f"with open({str(start_gate)!r}) as gate: gate.read()\n"
        f"os.execv({real_setsid!r}, [{real_setsid!r}, *sys.argv[1:]])\n",
    )
    _write_executable(
        bin_dir / "cargo",
        f"#!{sys.executable}\n"
        "import os, signal, time\n"
        "def interrupt(signum, frame):\n"
        f"    open({str(interrupted)!r}, 'w').write('INT')\n"
        "    raise SystemExit(130)\n"
        "signal.signal(signal.SIGINT, interrupt)\n"
        f"open({str(cargo_file)!r}, 'w').write(f'{{os.getpid()}}\\n{{os.getpgrp()}}\\n{{os.getsid(0)}}\\n')\n"
        f"with open({str(cargo_ready)!r}, 'w') as ready: ready.write('ready')\n"
        "time.sleep(1)\n"
        f"open({str(finished)!r}, 'w').write('finished')\n",
    )
    _write_executable(
        bin_dir / "df",
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        f"samples = Path({str(samples)!r})\n"
        "available = 11 * 1024 * 1024\n"
        "if samples.exists():\n"
        f"    with open({str(start_gate)!r}, 'w'): pass\n"
        f"    with open({str(cargo_ready)!r}) as ready: ready.read()\n"
        "    available = 9 * 1024 * 1024\n"
        "with samples.open('a') as log: log.write(f'{available}\\n')\n"
        "print('Filesystem 1024-blocks Used Available Capacity Mounted on')\n"
        "print(f'/dev/fake 100000000 1 {available} 1% /')\n",
    )
    process = subprocess.Popen(
        [str(WRAPPER), "build"],
        env={
            "PATH": str(bin_dir),
            "CARGO_TARGET_DIR": str(tmp_path),
            "SAFEYOLO_CARGO_RESERVE_GIB": "10",
            "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
            "SAFEYOLO_CARGO_HARD_STOP": hard_stop,
        },
        start_new_session=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(timeout=8)
        assert stdout == ""
        assert process.returncode == 75, stderr
        assert samples.read_text().splitlines() == [str(11 * 1024 * 1024), str(9 * 1024 * 1024)]
        cargo_pid, pgid, sid = map(int, cargo_file.read_text().splitlines())
        assert cargo_pid == pgid == sid, "fake Cargo did not enter the real setsid session"
        assert not _pid_exists(cargo_pid), "Cargo was not reaped"
        assert interrupted.exists() == (hard_stop == "1")
        assert finished.exists() == (hard_stop == "0")
    finally:
        groups = [process.pid]
        if launcher_file.exists():
            groups.append(int(launcher_file.read_text()))
        for pgid in groups:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # This fixture group has already exited.
        process.wait()


def test_macos_runs_without_setsid_and_reports_stop_limitation(tmp_path: Path) -> None:
    result = _run_wrapper(tmp_path, darwin=True, with_setsid=False)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "cargo.log").read_text() == "build --locked\n"
    assert "setsid unavailable" in result.stderr
    assert "signals Cargo only" in result.stderr


def test_default_reserve_refuses_to_start_cargo(tmp_path: Path) -> None:
    bin_dir, log = _fixture(tmp_path, darwin=False, with_setsid=True)
    _write_executable(
        bin_dir / "df",
        "#!/bin/sh\n"
        "printf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n"
        "printf '%s\\n' '/dev/fake 100000000 1 8082004 1% /'\n",
    )

    result = subprocess.run(
        [str(WRAPPER), "build", "--locked"],
        env={
            "PATH": str(bin_dir),
            "CARGO_FAKE_LOG": str(log),
            "CARGO_TARGET_DIR": str(tmp_path),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 75
    assert "8082004 KiB free" in result.stderr
    assert "below 20 GiB reserve" in result.stderr
    assert not log.exists(), "Cargo started below the default reserve"


def test_source_batch_reuses_one_target_from_one_stable_source(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = tmp_path / "scratch"
    source.mkdir()
    source_marker = source / "candidate-or-mutant.txt"
    source_marker.write_text("candidate\n")

    first = _run_wrapper(
        tmp_path / "first",
        darwin=False,
        with_setsid=True,
        source_root=source,
        target_dir=target,
    )
    source_marker.write_text("mutant\n")
    second = _run_wrapper(
        tmp_path / "second",
        darwin=False,
        with_setsid=True,
        source_root=source,
        target_dir=target,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert (target / ".safeyolo-cargo-source-batch").read_text().splitlines() == [
        "review-mutants",
        str(source.resolve()),
        f"{source.stat().st_dev}:{source.stat().st_ino}",
    ]


def test_source_batch_uses_the_macos_directory_identity_format(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = tmp_path / "scratch"
    result = _run_wrapper(
        tmp_path / "run",
        darwin=True,
        with_setsid=False,
        source_root=source,
        target_dir=target,
    )

    assert result.returncode == 0, result.stderr
    assert (target / ".safeyolo-cargo-source-batch").read_text().splitlines() == [
        "review-mutants",
        str(source.resolve()),
        f"{source.stat().st_dev}:{source.stat().st_ino}",
    ]


def test_source_batch_rejects_target_reuse_from_another_source(tmp_path: Path) -> None:
    target = tmp_path / "target"
    first = _run_wrapper(
        tmp_path / "first",
        darwin=False,
        with_setsid=True,
        source_root=tmp_path / "scratch-a",
        target_dir=target,
    )
    retained = target / "retain-me"
    retained.write_text("keep\n")
    second = _run_wrapper(
        tmp_path / "second",
        darwin=False,
        with_setsid=True,
        source_root=tmp_path / "scratch-b",
        target_dir=target,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 64
    assert "belongs to another source batch or source tree" in second.stderr
    assert str(target) not in second.stderr
    assert str(tmp_path / "scratch-b") not in second.stderr
    assert not (tmp_path / "second" / "cargo.log").exists()
    assert retained.read_text() == "keep\n"


def test_source_batch_rejects_recreated_source_at_the_same_path(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = tmp_path / "scratch"
    source.mkdir()
    (source / "candidate.txt").write_text("candidate\n")
    first = _run_wrapper(
        tmp_path / "first",
        darwin=False,
        with_setsid=True,
        source_root=source,
        target_dir=target,
    )
    original_identity = f"{source.stat().st_dev}:{source.stat().st_ino}"
    source.rename(tmp_path / "replaced-scratch")
    source.mkdir()
    (source / "mutant.txt").write_text("mutant\n")
    replacement_identity = f"{source.stat().st_dev}:{source.stat().st_ino}"
    second = _run_wrapper(
        tmp_path / "second",
        darwin=False,
        with_setsid=True,
        source_root=source,
        target_dir=target,
    )

    assert first.returncode == 0, first.stderr
    assert original_identity != replacement_identity
    assert second.returncode == 64
    assert "belongs to another source batch or source tree" in second.stderr
    assert str(target) not in second.stderr
    assert str(source) not in second.stderr
    assert not (tmp_path / "second" / "cargo.log").exists()


def test_source_batch_rejects_stale_metadata_without_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    source = tmp_path / "scratch"
    source.mkdir()
    metadata = target / ".safeyolo-cargo-source-batch"
    metadata.write_text(f"review-mutants\n{source.resolve()}\n")
    retained = target / "retain-me"
    retained.write_text("keep\n")
    result = _run_wrapper(
        tmp_path / "run",
        darwin=False,
        with_setsid=True,
        source_root=source,
        target_dir=target,
    )

    assert result.returncode == 64
    assert "belongs to another source batch or source tree" in result.stderr
    assert str(target) not in result.stderr
    assert not (tmp_path / "run" / "cargo.log").exists()
    assert metadata.read_text() == f"review-mutants\n{source.resolve()}\n"
    assert retained.read_text() == "keep\n"


def test_source_batch_rejects_malformed_metadata_without_cleanup(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    metadata = target / ".safeyolo-cargo-source-batch"
    metadata.mkdir()
    retained = target / "retain-me"
    retained.write_text("keep\n")
    result = _run_wrapper(
        tmp_path / "run",
        darwin=False,
        with_setsid=True,
        source_root=tmp_path / "scratch",
        target_dir=target,
    )

    assert result.returncode == 64
    assert "has malformed source-batch metadata" in result.stderr
    assert str(target) not in result.stderr
    assert not (tmp_path / "run" / "cargo.log").exists()
    assert metadata.is_dir()
    assert retained.read_text() == "keep\n"


def test_non_scratch_builds_ignore_source_batch_metadata(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    metadata = target / ".safeyolo-cargo-source-batch"
    metadata.write_text("malformed metadata\n")
    retained = target / "retain-me"
    retained.write_text("keep\n")

    first = _run_wrapper(
        tmp_path / "first",
        darwin=False,
        with_setsid=True,
        target_dir=target,
    )
    second = _run_wrapper(
        tmp_path / "second",
        darwin=False,
        with_setsid=True,
        target_dir=target,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert metadata.read_text() == "malformed metadata\n"
    assert retained.read_text() == "keep\n"


def test_macos_hard_stop_interrupts_cargo_but_leaves_child(tmp_path: Path) -> None:
    bin_dir, _ = _fixture(tmp_path, darwin=True, with_setsid=False)
    (bin_dir / "python3").symlink_to(sys.executable)
    _write_executable(
        bin_dir / "cargo",
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import signal\n"
        "import subprocess\n"
        "import time\n"
        "signal.signal(signal.SIGINT, signal.default_int_handler)\n"
        "child = subprocess.Popen(['/bin/sleep', '30'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "with open(os.environ['CARGO_PID_FILE'], 'w') as f:\n"
        "    f.write(f'{os.getpid()}\\n{child.pid}\\n')\n"
        "try:\n"
        "    signal.pause()\n"
        "except KeyboardInterrupt:\n"
        "    raise SystemExit(130)\n"
        "time.sleep(30)\n",
    )
    _write_executable(
        bin_dir / "df",
        "#!/bin/sh\n"
        "if [ ! -e \"$DF_STATE\" ]; then : > \"$DF_STATE\"; available=99999999; "
        "elif [ ! -e \"$CARGO_PID_FILE\" ]; then sleep 0.2; available=99999999; "
        "else available=1; fi\n"
        "printf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n"
        "printf '/dev/fake 100000000 1 %s 1%% /\\n' \"$available\"\n",
    )
    pid_file = tmp_path / "cargo-pids"
    env = {
        "PATH": str(bin_dir),
        "CARGO_TARGET_DIR": str(tmp_path / "missing" / "target"),
        "SAFEYOLO_CARGO_RESERVE_GIB": "20",
        "SAFEYOLO_CARGO_HARD_STOP": "1",
        "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
        "DF_STATE": str(tmp_path / "df-state"),
        "CARGO_PID_FILE": str(pid_file),
    }
    process = subprocess.Popen(
        [str(WRAPPER), "build"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cargo_pid = 0
    child_pid = 0
    try:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pid_file.exists(), "live Cargo fixture did not start"
        cargo_pid, child_pid = (int(value) for value in pid_file.read_text().splitlines())
        stdout, stderr = process.communicate(timeout=5)
        assert stdout == ""
        assert process.returncode == 75, stderr
        assert "Cargo interrupted by explicit emergency disk-space stop" in stderr
        assert "setsid unavailable" in stderr
        assert not _pid_exists(cargo_pid), "Cargo survived the hard stop"
        assert _pid_exists(child_pid), "child unexpectedly received Cargo-only signal"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        try:
            cargo_pid, child_pid = (int(value) for value in pid_file.read_text().splitlines())
        except (FileNotFoundError, ValueError, IndexError):
            pass
        for pid in (cargo_pid, child_pid):
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


def test_linux_validator_timeout_kills_real_setsid_group_only(tmp_path: Path) -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("the regression exercises Linux process-group semantics")
    real_setsid = shutil.which("setsid")
    if real_setsid is None:
        pytest.skip("setsid is required for the process-group regression")

    bin_dir, _ = _fixture(tmp_path, darwin=False, with_setsid=False)
    (bin_dir / "setsid").symlink_to(real_setsid)
    cargo_pid_file = tmp_path / "cargo-pids"
    child_pid_file = tmp_path / "child-pid"
    child_code = (
        "import os, signal, time\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(child_pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)\n"
    )
    _write_executable(
        bin_dir / "cargo",
        f"#!{sys.executable}\n"
        "import os\n"
        "import signal\n"
        "import subprocess\n"
        "import time\n"
        f"child = subprocess.Popen([{sys.executable!r}, '-c', {child_code!r}])\n"
        f"while not os.path.exists({str(child_pid_file)!r}):\n"
        "    time.sleep(0.01)\n"
        f"open({str(cargo_pid_file)!r}, 'w').write(f'{{os.getpid()}}\\n{{child.pid}}\\n')\n"
        "def interrupt(signum, frame):\n"
        "    raise SystemExit(130)\n"
        "signal.signal(signal.SIGINT, interrupt)\n"
        "signal.pause()\n",
    )

    sentinel = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    cargo_pid = 0
    try:
        report: dict[str, object] = {"commands": []}
        runner = dependency_validator.Runner(
            report,
            offline=True,
            report_path=tmp_path / "report.json",
            target_dir=tmp_path / "target",
        )
        result, _ = runner.command(
            "real-setsid-timeout",
            ["cargo", "build"],
            kind="regression",
            environment={
                "PATH": str(bin_dir),
                # Runner copies the environment. A shell startup hook must not
                # prepend tool shims ahead of these controlled fake commands.
                "BASH_ENV": "__UNSET__",
                "CARGO_TARGET_DIR": str(tmp_path / "missing" / "target"),
                "SAFEYOLO_CARGO_RESERVE_GIB": "0",
                "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
                "CARGO_PID_FILE": str(cargo_pid_file),
            },
            expect_failure=True,
            timeout=0.1,
            print_output=False,
        )
        assert result.returncode == 124
        assert report["commands"][0]["timed_out"] is True  # type: ignore[index]
        cargo_pid, _ = (
            int(value) for value in cargo_pid_file.read_text().splitlines()
        )
        assert sentinel.poll() is None, "outer sentinel was signalled"
        deadline = time.monotonic() + 2
        while _linux_running_group_members(cargo_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        members = _linux_running_group_members(cargo_pid)
        assert not members, f"Cargo group retains running processes: {members}"
        assert not _pid_exists(cargo_pid), "Cargo leader was not reaped"
    finally:
        if cargo_pid:
            try:
                os.killpg(cargo_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if sentinel.poll() is None:
            sentinel.terminate()
            sentinel.wait()
