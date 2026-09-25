"""Persistent agent API token shared by the Python and Rust proxy launchers."""

import secrets
from pathlib import Path

from .agent_command_supervisor import _write_text


def ensure_agent_token(data_dir: Path) -> str:
    """Reuse a configured token, or replace an absent or empty token privately."""
    token_path = data_dir / "agent_token"
    try:
        token = token_path.read_text().strip()
    except FileNotFoundError:
        token = ""
    if token:
        return token
    token = secrets.token_hex(32)
    _write_text(token_path, token, mode=0o600)
    return token
