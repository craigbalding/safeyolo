"""Private terminal-session lifecycle for the shared traffic master."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .config import get_config_dir, get_data_dir

SESSION_NAME = "safeyolo-traffic"


def find_private_tmux() -> Path:
    """Find SafeYolo's bundled tmux, with a system binary as a dev fallback."""
    explicit = os.environ.get("SAFEYOLO_TMUX_BIN")
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        raise RuntimeError(f"SAFEYOLO_TMUX_BIN is not executable: {candidate}")

    candidates = (
        get_config_dir() / "bin" / "safeyolo-tmux",
        Path(sys.executable).parent / "safeyolo-tmux",
        Path(__file__).resolve().parent / "runtime" / "bin" / "safeyolo-tmux",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    system_tmux = shutil.which("tmux")
    if system_tmux:
        return Path(system_tmux)
    raise RuntimeError("SafeYolo's private tmux runtime is missing; reinstall the host artifact")


def socket_path() -> Path:
    return get_data_dir() / "traffic-tmux.sock"


def _base_command(tmux: Path | None = None) -> list[str]:
    binary = find_private_tmux() if tmux is None else tmux
    return [str(binary), "-S", str(socket_path()), "-f", "/dev/null"]


def session_exists(tmux: Path | None = None) -> bool:
    result = subprocess.run(
        [*_base_command(tmux), "has-session", "-t", SESSION_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def session_process_alive(tmux: Path | None = None) -> bool:
    if not session_exists(tmux):
        return False
    result = subprocess.run(
        [
            *_base_command(tmux),
            "display-message",
            "-p",
            "-t",
            f"{SESSION_NAME}:0.0",
            "#{pane_dead}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "0"


def start_session(
    command: list[str],
    tmux: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    """Create the private server and launch one command in its PTY."""
    data_dir = get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    data_dir.chmod(0o700)
    base = _base_command(tmux)
    if session_exists(tmux):
        raise RuntimeError("SafeYolo traffic session is already running")
    subprocess.run(
        [*base, "new-session", "-d", "-s", SESSION_NAME],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    try:
        subprocess.run(
            [
                *base,
                "set-window-option",
                "-t",
                f"{SESSION_NAME}:0",
                "remain-on-exit",
                "on",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        subprocess.run(
            [
                *base,
                "respawn-pane",
                "-k",
                "-t",
                f"{SESSION_NAME}:0.0",
                shlex.join(command),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
    except Exception:
        stop_session(tmux)
        raise


def capture_session(tmux: Path | None = None) -> str:
    result = subprocess.run(
        [*_base_command(tmux), "capture-pane", "-p", "-S", "-200", "-t", f"{SESSION_NAME}:0.0"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def attach_session(tmux: Path | None = None) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("the shared traffic console requires an interactive terminal")
    return subprocess.call([*_base_command(tmux), "attach-session", "-t", SESSION_NAME])


def stop_session(tmux: Path | None = None) -> None:
    subprocess.run(
        [*_base_command(tmux), "kill-session", "-t", SESSION_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
