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
