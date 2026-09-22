"""Host mount protection lookup helpers."""

from pathlib import Path

from .config import load_config


def get_protected_paths() -> list[str]:
    """Load protected paths from config."""
    config = load_config()
    return config.get("protected_paths", [])


def is_path_protected(host_path: str, protected_paths: list[str] | None = None) -> str | None:
    """Return the protected parent of a host path, if one exists."""
    if protected_paths is None:
        protected_paths = get_protected_paths()

    check = Path(host_path).resolve()
    for protected_path in protected_paths:
        protected = Path(protected_path).resolve()
        if check == protected or protected in check.parents:
            return str(protected)
    return None
