"""Configuration loading and path management."""

from pathlib import Path
from typing import Any

import yaml

# Config directory names
PROJECT_DIR_NAME = "safeyolo"
GLOBAL_DIR_NAME = ".safeyolo"

# Default config values
DEFAULT_CONFIG = {
    "version": 1,
    "proxy": {
        "port": 8080,
        "admin_port": 9090,
        "image": "safeyolo:latest",
        "container_name": "safeyolo",
    },
    "modes": {
        "credential_guard": "block",
        "rate_limiter": "block",
        "pattern_scanner": "warn",
    },
    "notifications": {
        "method": "none",
    },
}


def find_config_dir() -> Path | None:
    """Find the safeyolo config directory.

    Search order:
    1. ./safeyolo/ (project-specific)
    2. ~/.safeyolo/ (global)

    Returns None if no config directory exists.
    """
    # Check project-specific first
    project_dir = Path.cwd() / PROJECT_DIR_NAME
    if project_dir.is_dir():
        return project_dir

    # Check global
    global_dir = Path.home() / GLOBAL_DIR_NAME
    if global_dir.is_dir():
        return global_dir

    return None


def get_config_dir(create: bool = False) -> Path:
    """Get the config directory, optionally creating it.

    Prefers project-specific directory if it exists, otherwise global.
    """
    existing = find_config_dir()
    if existing:
        return existing

    # Default to project-specific for new configs
    project_dir = Path.cwd() / PROJECT_DIR_NAME
    if create:
        project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


def get_config_path() -> Path:
    """Get path to config.yaml."""
    return get_config_dir() / "config.yaml"


def get_rules_path() -> Path:
    """Get path to rules.json."""
    return get_config_dir() / "rules.json"


def get_logs_dir() -> Path:
    """Get path to logs directory."""
    return get_config_dir() / "logs"


def get_certs_dir() -> Path:
    """Get path to certs directory."""
    return get_config_dir() / "certs"


def get_policies_dir() -> Path:
    """Get path to policies directory."""
    return get_config_dir() / "policies"


def get_data_dir() -> Path:
    """Get path to data directory."""
    return get_config_dir() / "data"


def get_admin_token_path() -> Path:
    """Get path to admin token file."""
    return get_data_dir() / "admin_token"


def load_config() -> dict[str, Any]:
    """Load configuration from config.yaml.

    Returns DEFAULT_CONFIG if no config file exists.
    """
    config_path = get_config_path()
    if not config_path.exists():
        return DEFAULT_CONFIG.copy()

    with open(config_path) as f:
        user_config = yaml.safe_load(f) or {}

    # Merge with defaults
    config = DEFAULT_CONFIG.copy()
    _deep_merge(config, user_config)
    return config


def save_config(config: dict[str, Any]) -> None:
    """Save configuration to config.yaml."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _deep_merge(base: dict, override: dict) -> None:
    """Deep merge override into base dict (mutates base)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def get_admin_token() -> str | None:
    """Get admin API token from file or environment."""
    import os

    # Check environment first
    token = os.environ.get("SAFEYOLO_ADMIN_TOKEN")
    if token:
        return token

    # Check file
    token_path = get_admin_token_path()
    if token_path.exists():
        return token_path.read_text().strip()

    return None


def ensure_directories() -> None:
    """Ensure all required directories exist."""
    config_dir = get_config_dir(create=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)
