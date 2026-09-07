"""Host tmux sessions for independent operator shells, not coding-agent launches."""

import hashlib
import os
import shutil
import subprocess
import sys

from .agents_store import get_or_mint_agent_id
from .config import get_config_dir, get_logs_dir


def _session_target(name: str, *, root: bool) -> tuple[list[str], str]:
    # A dedicated server makes reconnect independent of the caller's tmux
    # server. Agent identity prevents a reused name from selecting an old shell.
    config_id = hashlib.sha256(os.fsencode(get_config_dir().resolve())).hexdigest()[:16]
    agent_id = get_or_mint_agent_id(name)
    session = f"shell-{name}-{agent_id}-{'root' if root else 'agent'}"
    return ["tmux", "-L", f"safeyolo-shells-{config_id}"], session


def _shell_command(name: str, *, root: bool) -> list[str]:
    # Pass the installation and instance explicitly; an existing tmux server
    # can have an older environment. Do not resolve the Python venv symlink.
    return [
        "env", f"SAFEYOLO_CONFIG_DIR={get_config_dir().resolve()}",
        f"SAFEYOLO_LOGS_DIR={get_logs_dir().resolve()}",
        sys.executable, "-m", "safeyolo.cli", "agent", "shell",
        *(["--root"] if root else []), "--", name,
    ]


def _ensure_session(tmux: list[str], session: str, command: list[str], env: dict[str, str]) -> None:
    target = f"={session}"
    present = subprocess.run([*tmux, "has-session", "-t", target], env=env, capture_output=True)
    if present.returncode == 0:
        return
    created = subprocess.run([
        *tmux, "new-session", "-d", "-s", session, "-n", "sandbox-shell", *command,
        ";", "set-option", "-t", session, "destroy-unattached", "off",
        ";", "set-window-option", "-t", session, "remain-on-exit", "off",
    ], env=env, capture_output=True, text=True)
    if created.returncode:
        # A concurrent opener may have created this exact session. Accept
        # that race only after observing the session, not merely an error code.
        present = subprocess.run([*tmux, "has-session", "-t", target], env=env, capture_output=True)
        if present.returncode or not created.stderr.startswith("duplicate session:"):
            raise RuntimeError(f"Cannot create persistent sandbox shell: {created.stderr.strip()}")


def open_persistent_shell(name: str, *, root: bool = False) -> int:
    """Create or reattach an operator shell that survives viewer disconnection."""
    if shutil.which("tmux") is None:
        raise RuntimeError("Persistent sandbox shells require tmux on the SafeYolo host. Install tmux there and retry.")
    tmux, session = _session_target(name, root=root)
    env = dict(os.environ)
    current_socket = env.pop("TMUX", "").rsplit(",", 2)[0]
    env.pop("TMUX_PANE", None)
    # Use tmux's private per-uid directory under /tmp consistently, including
    # when SSH and local clients have different TMUX_TMPDIR settings.
    env["TMUX_TMPDIR"] = "/tmp"
    _ensure_session(tmux, session, _shell_command(name, root=root), env)
    target = f"={session}"
    located = subprocess.run(
        [*tmux, "display-message", "-p", "-t", target, "#{socket_path}"],
        env=env, capture_output=True, text=True,
    )
    if located.returncode:
        raise RuntimeError(f"Cannot locate persistent sandbox shell: {located.stderr.strip()}")
    action = "switch-client" if current_socket == located.stdout.strip() else "attach-session"
    return subprocess.run([*tmux, action, "-t", target], env=env, check=False).returncode
