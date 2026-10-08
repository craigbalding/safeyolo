"""Persistent agent API token shared by the Python and Rust proxy launchers."""

import os
import secrets
import uuid
from pathlib import Path


def _write_text(path: Path, value: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            if mode is not None:
                os.fchmod(handle.fileno(), mode)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


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
