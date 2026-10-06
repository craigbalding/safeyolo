"""The real-platform acceptance driver must behave like a reading terminal."""

import importlib.util
import os
import pty
import subprocess
import sys
from pathlib import Path

import pytest

probe_path = Path(__file__).resolve().parents[2] / "tests/nested-linux/launcher_acceptance.py"
spec = importlib.util.spec_from_file_location("launcher_acceptance", probe_path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@pytest.mark.parametrize("output_size", [32, 256 * 1024])
def test_wait_drains_output_and_preserves_exit_code(tmp_path, output_size):
    master, slave = pty.openpty()
    marker = tmp_path / "drained"
    child = """
import sys, termios
from pathlib import Path
sys.stdout.write('x' * int(sys.argv[1]))
sys.stdout.flush()
termios.tcsetattr(0, termios.TCSADRAIN, termios.tcgetattr(0))
Path(sys.argv[2]).touch()
sys.exit(7)
"""
    process = subprocess.Popen([sys.executable, "-c", child, str(output_size), str(marker)],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    screen = bytearray()
    try:
        assert probe.wait_terminal_exit(process, master, screen, timeout=5) == 7
        assert screen == b"x" * output_size
        assert marker.is_file()
    finally:
        os.close(master)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_wait_does_not_mistake_output_for_exit():
    master, slave = pty.openpty()
    process = subprocess.Popen([sys.executable, "-c", "print('still running', flush=True); input()"],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    screen = bytearray()
    try:
        assert probe.read_terminal(master, screen, timeout=5)
        with pytest.raises(subprocess.TimeoutExpired):
            probe.wait_terminal_exit(process, master, screen, timeout=0.2)
        assert b"still running" in screen
        assert process.poll() is None
    finally:
        os.close(master)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def test_probe_rejects_the_wrong_native_source_before_configuration_changes(native_agent):
    """A retained executable cannot be reported as a new journey candidate."""
    root = native_agent["root"]
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(native_agent["cli"].resolve())
    before = {path: path.read_bytes() for path in (root / "config.toml", root / "policy.toml")}
    result = subprocess.run(
        [sys.executable, str(probe_path), "--root", str(root), "--fixture-parent", str(root),
         "--commit", "0" * 40],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0 and "wrong installed source: bin/safeyolo" in result.stderr
    assert {path: path.read_bytes() for path in before} == before
    assert not list(root.glob("native-terminal-*"))
    assert not (root / "data/proxy-process.json").exists()


@pytest.mark.parametrize("different_profile", ["bin/safeyolo-proxy", "assets/guest/safeyolo-guest"])
def test_probe_rejects_mixed_installed_profiles_before_starting_an_agent(native_agent, different_profile):
    """Matching commits with different host/guest profiles are not one input."""
    root = native_agent["root"]
    cli = native_agent["cli"].resolve()
    version = subprocess.check_output([str(cli), "--version"], text=True).strip()
    identity = version.partition(" commit=")[2]
    commit = identity.split()[0]
    alternate = "production" if identity.endswith("profile=debug") else "debug"
    for relative in ("bin/safeyolo", "bin/safeyolo-proxy", "bin/safeyolo-coord",
                     "assets/guest/safeyolo-guest", "assets/guest/safeyolo-coord"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "bin/safeyolo":
            path.symlink_to(cli)
            continue
        selected = f"{commit} profile={alternate}" if relative == different_profile else identity
        observed = f"{path.name} 0.1.0 commit={selected}"
        # Controlled version output tests the driver's input relationship;
        # no fake runtime is used as lifecycle acceptance.
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{observed}'\n")
        path.chmod(0o755)
        path.with_suffix(".version").write_text(observed + "\n")
    before = {path: path.read_bytes() for path in (root / "config.toml", root / "policy.toml")}
    result = subprocess.run(
        [sys.executable, str(probe_path), "--root", str(root), "--fixture-parent", str(root), "--commit", commit],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0 and f"installed source/profile differs: {different_profile}" in result.stderr
    assert {path: path.read_bytes() for path in before} == before
    assert not list(root.glob("native-terminal-*"))
    assert not (root / "data/proxy-process.json").exists()
