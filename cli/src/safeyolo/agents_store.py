"""Centralized read/write for agents.yaml with file locking."""

import fcntl
import json
import logging
from pathlib import Path

import yaml

from .config import get_agents_dir, get_config_dir

log = logging.getLogger("safeyolo.agents-store")


def _agents_yaml_path() -> Path:
    """Path to ~/.safeyolo/agents.yaml."""
    return get_config_dir() / "agents.yaml"


def _lock_path() -> Path:
    """Path to lock file sibling."""
    return get_config_dir() / ".agents.yaml.lock"


def load_all_agents() -> dict[str, dict]:
    """Read all agent entries. Returns {} if file missing."""
    path = _agents_yaml_path()
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            return {}
        return data
    except Exception as e:
        log.warning(f"Failed to read {path}: {e}")
        return {}


def load_agent(name: str) -> dict:
    """Read a single agent entry. Returns {} if not found."""
    return load_all_agents().get(name, {})


def save_agent(name: str, metadata: dict) -> None:
    """Write a single agent entry (lock + read-modify-write)."""
    path = _agents_yaml_path()
    lock = _lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    lock.touch()
    with open(lock) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            all_agents = load_all_agents()
            all_agents[name] = metadata
            path.write_text(yaml.dump(all_agents, default_flow_style=False, sort_keys=False))
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def remove_agent(name: str) -> bool:
    """Delete an agent entry. Returns True if it existed."""
    path = _agents_yaml_path()
    lock = _lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    lock.touch()
    with open(lock) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            all_agents = load_all_agents()
            if name not in all_agents:
                return False
            del all_agents[name]
            if all_agents:
                path.write_text(yaml.dump(all_agents, default_flow_style=False, sort_keys=False))
            elif path.exists():
                path.write_text("{}\n")
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def migrate_from_json(name: str, agent_dir: Path | None = None) -> dict:
    """Read .safeyolo.json, write to agents.yaml, delete JSON. Returns metadata."""
    if agent_dir is None:
        agent_dir = get_agents_dir() / name
    json_file = agent_dir / ".safeyolo.json"
    if not json_file.exists():
        return {}
    try:
        metadata = json.loads(json_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    save_agent(name, metadata)
    json_file.unlink()
    log.info(f"Migrated {name} from .safeyolo.json to agents.yaml")
    return metadata
