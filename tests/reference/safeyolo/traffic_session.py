"""Private terminal-session lifecycle for the shared traffic master."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .config import get_config_dir, get_data_dir
from .runtime_identity import process_start_token

SESSION_NAME = "safeyolo-traffic"
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def find_private_tmux() -> Path:  # DOC: README.md, cli/README.md
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


def session_process_id(tmux: Path | None = None) -> int | None:
    """Read the live pane's PID; exec-owned commands use it as their process ID."""
    command = [
        *_base_command(tmux),
        "display-message",
        "-p",
        "-t",
        f"{SESSION_NAME}:0.0",
        "#{pane_dead} #{pane_pid}",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError:
        # A failed tmux query cannot establish ownership of a live process.
        return None
    if result.returncode != 0:
        return None
    fields = result.stdout.split()
    if len(fields) != 2 or fields[0] != "0":
        return None
    return _parse_pane_pid(fields[1])


def interrupt_session_process(process_id: int, start_token: str, tmux: Path | None = None) -> None:
    """Interrupt the identified pane through its tmux server when direct signals are denied."""
    base = _base_command(tmux)
    result = subprocess.run(
        [*base, "display-message", "-p", "-t", f"{SESSION_NAME}:0.0",
         "#{pane_dead} #{pane_pid} #{pane_id}"],
        capture_output=True, text=True, check=True,
    )
    fields = result.stdout.split()
    if (
        len(fields) != 3 or fields[0] != "0"
        or _parse_pane_pid(fields[1]) != process_id
        or not fields[2].startswith("%")
        or not fields[2][1:].isascii() or not fields[2][1:].isdecimal()
        or process_start_token(process_id) != start_token
    ):
        raise RuntimeError("Cannot verify Rust proxy tmux pane identity; lifetime state has been retained")
    # The server still has the sandbox identity that launched this pane. A
    # terminal interrupt reaches that pane even if a later SSH session cannot
    # signal its process directly under the macOS seatbelt.
    subprocess.run(
        [*base, "send-keys", "-t", fields[2], "C-c"],
        capture_output=True, text=True, check=True,
    )


def _parse_pane_pid(raw_pid: str) -> int | None:
    if not raw_pid.isascii() or not raw_pid.isdecimal():
        return None
    try:
        pid = int(raw_pid)
    except ValueError:
        # Decimal output can still exceed Python's integer-conversion limit.
        return None
    return pid if pid > 1 else None


def _create_traffic_tmux_session(base: list[str], tmux: Path | None, env: dict[str, str] | None) -> None:
    # A tmux client does not pass arbitrary environment variables to a pane
    # when its private server already exists. Temporarily include the client's
    # variable names in update-environment; tmux transfers the values through
    # its client protocol, without putting credentials in command arguments.
    previous_update = None
    if env is not None:
        option = subprocess.run(
            [*base, "show-options", "-gqv", "update-environment"],
            capture_output=True, text=True, check=False, env=env,
        )
        if option.returncode == 0:
            server_env = subprocess.run(
                [*base, "show-environment", "-g"],
                capture_output=True, text=True, check=True, env=env,
            )
            server_names = {
                line.lstrip("-").split("=", 1)[0]
                for line in server_env.stdout.splitlines()
            }
            names = {name for name in env.keys() | server_names if _ENV_NAME.fullmatch(name)}
            previous_update = option.stdout.rstrip("\n")
            subprocess.run(
                [*base, "set-option", "-g", "update-environment", " ".join(sorted(names))],
                check=True, capture_output=True, text=True, env=env,
            )
    created = False
    try:
        subprocess.run(
            [*base, "new-session", "-d", "-s", SESSION_NAME],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        created = True
    finally:
        if previous_update is not None:
            try:
                subprocess.run(
                    [*base, "set-option", "-g", "update-environment", previous_update],
                    check=True, capture_output=True, text=True, env=env,
                )
            except Exception:
                if created:
                    stop_session(tmux)
                raise


def start_session(
    command: list[str],
    tmux: Path | None = None,
    env: dict[str, str] | None = None,
    exec_command: bool = False,
    cwd: Path | None = None,
) -> int | None:
    """Launch one command in the PTY, optionally replacing its pane shell."""
    data_dir = get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    data_dir.chmod(0o700)
    base = _base_command(tmux)
    if session_exists(tmux):
        if session_process_alive(tmux):
            raise RuntimeError("SafeYolo traffic session is already running")
        # remain-on-exit deliberately preserves the console after a crash.
        # Reap that dead pane before retrying startup.
        stop_session(tmux)
    _create_traffic_tmux_session(base, tmux, env)
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
                *(["-c", str(cwd)] if cwd is not None else []),
                ("exec " if exec_command else "") + shlex.join(command),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
    except Exception:
        stop_session(tmux)
        raise
    if exec_command:
        # Observation failures after successful respawn do not own cleanup.
        # The launcher retains pending lifetime state when the PID is unknown.
        try:
            result = subprocess.run(
                [*base, "display-message", "-p", "-t", f"{SESSION_NAME}:0.0", "#{pane_pid}"],
                capture_output=True, text=True, check=False,
            )
        except OSError:
            return None
        if result.returncode == 0:
            return _parse_pane_pid(result.stdout.strip())
    return None


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
