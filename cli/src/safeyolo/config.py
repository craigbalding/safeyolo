"""Configuration loading and path management."""

import os
from pathlib import Path
from typing import Any

import yaml

# Environment variable names for path overrides (useful for testing and custom setups)
_CONFIG_DIR_ENV = "SAFEYOLO_CONFIG_DIR"
_LOGS_DIR_ENV = "SAFEYOLO_LOGS_DIR"


def _get_config_dir_path() -> Path:
    """Get config directory path, checking env var override."""
    override = os.environ.get(_CONFIG_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".safeyolo"


# Default config values
DEFAULT_CONFIG = {
    "version": 1,
    "sandbox": True,  # Sandbox mode with network isolation (secure default)
    "proxy": {
        "port": 8080,
        "admin_port": 9090,
        "image": "safeyolo:latest",
        "container_name": "safeyolo",
    },
    "modes": {
        "credential_guard": "block",
        "network_guard": "block",
        "pattern_scanner": "warn",
    },
    "notifications": {
        "method": "none",
    },
    "test": {
        "enabled": False,
        # Sinkhole routing: redirect upstream to local test sinkhole
        "sinkhole_router": "",  # path to sinkhole_router.py addon
        "sinkhole_host": "127.0.0.1",
        "sinkhole_http_port": 18080,
        "sinkhole_https_port": 18443,
        # Upstream CA: trust test CA for sinkhole TLS verification
        "ca_cert": "",  # path to test CA cert
    },
}


def find_config_dir() -> Path | None:
    """Check if config directory exists.

    Returns ~/.safeyolo/ if it exists, None otherwise.
    Used to check if SafeYolo is initialized.
    """
    config_dir = _get_config_dir_path()
    if config_dir.is_dir():
        return config_dir
    return None


def get_config_dir(create: bool = False) -> Path:
    """Get the config directory (~/.safeyolo/)."""
    config_dir = _get_config_dir_path()
    if create:
        config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_logs_dir(create: bool = False) -> Path:
    """Get the logs directory ($SAFEYOLO_LOGS_DIR or $XDG_STATE_HOME/safeyolo/)."""
    override = os.environ.get(_LOGS_DIR_ENV)
    if override:
        logs_dir = Path(override)
    else:
        xdg_state = os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")
        logs_dir = Path(xdg_state) / "safeyolo"
    if create:
        logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def get_config_path() -> Path:
    """Get path to config.yaml."""
    return get_config_dir() / "config.yaml"


def get_certs_dir() -> Path:
    """Get path to certs directory."""
    return get_config_dir() / "certs"


def get_policies_dir() -> Path:
    """Get path to policies directory."""
    return get_config_dir() / "policies"


def get_data_dir() -> Path:
    """Get path to data directory."""
    return get_config_dir() / "data"


def get_agents_dir() -> Path:
    """Get path to agents directory."""
    return get_config_dir() / "agents"


def get_policy_toml_path() -> Path:
    """Get path to policy.toml (single policy file)."""
    return get_config_dir() / "policy.toml"


def get_admin_token_path() -> Path:
    """Get path to admin token file."""
    return get_data_dir() / "admin_token"


def get_agent_token_path() -> Path:
    """Get path to agent API token file."""
    return get_data_dir() / "agent_token"


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


def get_share_dir() -> Path:
    """Get path to shared VM assets (kernel, initramfs, base rootfs)."""
    return get_config_dir() / "share"


def get_vm_helper_path() -> Path:
    """Get path to the safeyolo-vm binary."""
    return get_config_dir() / "bin" / "safeyolo-vm"


def get_ssh_key_path() -> Path:
    """Get path to the VM SSH private key."""
    return get_data_dir() / "vm_ssh_key"


def get_agent_map_path() -> Path:
    """Get path to the agent-IP map file (read by service_discovery addon)."""
    return get_data_dir() / "agent_map.json"


def get_bridge_sockets_dir() -> Path:
    """Per-agent proxy_bridge listener sockets live here."""
    return get_data_dir() / "sockets"


def get_proxy_pid_path() -> Path:
    """Get path to the mitmproxy PID file."""
    return get_data_dir() / "proxy.pid"


def ensure_directories() -> None:
    """Ensure all required directories exist."""
    config_dir = get_config_dir(create=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "share").mkdir(exist_ok=True)
    (config_dir / "bin").mkdir(exist_ok=True)
