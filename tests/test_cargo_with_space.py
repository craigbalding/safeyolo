"""Focused executable checks for the guarded Cargo wrapper."""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import sys
import time
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


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def _fixture(tmp_path: Path, *, darwin: bool, with_setsid: bool) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "bash", "#!/bin/sh\nexec /bin/bash \"$@\"\n")
    _write_executable(bin_dir / "sh", "#!/bin/sh\nexec /bin/sh \"$@\"\n")
    (bin_dir / "awk").symlink_to("/usr/bin/awk")
    _write_executable(
        bin_dir / "dirname",
        "#!/bin/sh\nif [ \"$DF_EXPECT_BSD\" = 1 ] && [ \"$1\" = -- ]; then exit 2; fi\nif [ \"$DF_EXPECT_GNU\" = 1 ] && [ \"$1\" != -- ]; then exit 2; fi\nexec /usr/bin/dirname \"$@\"\n",
    )
    (bin_dir / "sleep").symlink_to("/usr/bin/sleep")
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
    tmp_path: Path, *, darwin: bool, with_setsid: bool
) -> subprocess.CompletedProcess[str]:
    bin_dir, log = _fixture(tmp_path, darwin=darwin, with_setsid=with_setsid)
    env = {
        "PATH": str(bin_dir),
        "CARGO_FAKE_LOG": str(log),
        "CARGO_TARGET_DIR": str(tmp_path / "missing" / "target"),
        "SAFEYOLO_CARGO_RESERVE_GIB": "0",
        "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
        "DF_EXPECT_BSD": "1" if darwin else "0",
        "DF_EXPECT_GNU": "0" if darwin else "1",
    }
    return subprocess.run(
        [str(WRAPPER), "build", "--locked"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_linux_uses_dedicated_process_group_when_setsid_exists(tmp_path: Path) -> None:
    result = _run_wrapper(tmp_path, darwin=False, with_setsid=True)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "cargo.log").read_text() == "setsid-invoked\nbuild --locked\n"
    assert "setsid unavailable" not in result.stderr


def test_macos_runs_without_setsid_and_reports_stop_limitation(tmp_path: Path) -> None:
    result = _run_wrapper(tmp_path, darwin=True, with_setsid=False)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "cargo.log").read_text() == "build --locked\n"
    assert "setsid unavailable" in result.stderr
    assert "signals Cargo only" in result.stderr


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
        cargo_pid, child_pid = (
            int(value) for value in cargo_pid_file.read_text().splitlines()
        )
        assert sentinel.poll() is None, "outer sentinel was signalled"
        deadline = time.monotonic() + 2
        while _process_group_exists(cargo_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _process_group_exists(cargo_pid), "Cargo process group survived"
        assert not _pid_exists(child_pid), "interrupt-ignoring child survived"
    finally:
        if cargo_pid:
            try:
                os.killpg(cargo_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if sentinel.poll() is None:
            sentinel.terminate()
            sentinel.wait()
