"""Shared service definition loading for CLI commands."""

from pathlib import Path

import yaml


def _get_services_dirs() -> list[Path]:
    """Get service definition directories (user + builtin)."""
    from ..config import _get_config_dir_path

    user_dir = _get_config_dir_path() / "services"
    builtin_dir = Path(__file__).parent.parent.parent.parent.parent / "config" / "services"
    return [builtin_dir, user_dir]


def _load_service_files() -> list[dict]:
    """Load all service definition YAML files.

    User directory takes priority over builtins (same name → user wins).
    """
    services = {}
    for directory in _get_services_dirs():
        if not directory.exists():
            continue
        for yaml_file in sorted(directory.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text())
                if raw and isinstance(raw, dict) and "name" in raw:
                    services[raw["name"]] = raw
            except (OSError, yaml.YAMLError):
                continue
    return list(services.values())


def find_service(name: str) -> dict | None:
    """Find a single service definition by name. Returns None if not found."""
    for svc in _load_service_files():
        if svc["name"] == name:
            return svc
    return None
