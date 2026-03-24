"""
tokens.py - Agent token utilities for relay access

Simple opaque token model: proxy generates a random token on startup,
writes it to disk, agent containers read it from a bind mount.
No HMAC, no expiry, no CLI involvement.
"""

from pathlib import Path


def read_active_token(token_path: Path) -> str | None:
    """Read the active token from disk.

    Returns None if the file doesn't exist or is empty.
    Reads directly without exists() check to avoid TOCTOU race.
    """
    try:
        content = token_path.read_text().strip()
        return content if content else None
    except FileNotFoundError:
        return None
    except OSError:
        return None
