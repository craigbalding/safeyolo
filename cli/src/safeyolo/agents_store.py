"""Centralized read/write for agent config in policy.toml [agents] section."""

import fcntl
import logging
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import tomlkit

from .config import get_config_dir

log = logging.getLogger("safeyolo.agents-store")


def _policy_toml_path() -> Path:
    """Path to ~/.safeyolo/policy.toml."""
    return get_config_dir() / "policy.toml"


def _lock_path() -> Path:
    """Path to lock file sibling."""
    return get_config_dir() / ".policy.toml.lock"


def _load_doc() -> tomlkit.TOMLDocument:
    """Load policy.toml as a TOMLDocument. Returns empty doc if missing."""
    path = _policy_toml_path()
    if not path.exists():
        return tomlkit.document()
    try:
        return tomlkit.parse(path.read_text())
    except (OSError, tomlkit.exceptions.TOMLKitError) as e:
        log.warning("Failed to parse %s: %s", path, type(e).__name__)
        return tomlkit.document()


def _save_doc(doc: tomlkit.TOMLDocument) -> None:
    """Atomic write of TOMLDocument back to policy.toml."""
    path = _policy_toml_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = tomlkit.dumps(doc)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".toml", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    shutil.move(tmp_path, path)


def _locked_mutate(mutate_fn: Callable[[tomlkit.TOMLDocument], Any]) -> Any:
    """Read-modify-write policy.toml under exclusive file lock."""
    lock = _lock_path()
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch()
    with open(lock) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            doc = _load_doc()
            result = mutate_fn(doc)
            _save_doc(doc)
            return result
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _get_agents(doc: tomlkit.TOMLDocument) -> dict:
    """Extract [agents] section as plain dict."""
    agents = doc.get("agents")
    if agents is None:
        return {}
    if hasattr(agents, "unwrap"):
        return agents.unwrap()
    return dict(agents)


def _ensure_agents_table(doc: tomlkit.TOMLDocument):
    """Get or create the [agents] table."""
    if "agents" not in doc:
        doc.add("agents", tomlkit.table())
    return doc["agents"]


def _dict_to_toml_table(metadata: dict) -> tomlkit.items.Table:
    """Convert a metadata dict to a tomlkit Table with proper nesting."""
    agent_table = tomlkit.table()
    for key, value in metadata.items():
        if key == "services" and isinstance(value, dict):
            svc_table = tomlkit.table()
            for svc_name, svc_config in value.items():
                svc_entry = tomlkit.table()
                if isinstance(svc_config, dict):
                    for sk, sv in svc_config.items():
                        svc_entry.add(sk, sv)
                else:
                    svc_entry.add("capability", svc_config)
                svc_table.add(svc_name, svc_entry)
            agent_table.add("services", svc_table)
        elif key in ("contract_bindings", "grants") and isinstance(value, list):
            aot = tomlkit.aot()
            for item in value:
                entry = tomlkit.table()
                for ik, iv in item.items():
                    if isinstance(iv, dict):
                        sub = tomlkit.table()
                        for dk, dv in iv.items():
                            sub.add(dk, dv)
                        entry.add(ik, sub)
                    else:
                        entry.add(ik, iv)
                aot.append(entry)
            agent_table.add(key, aot)
        else:
            agent_table.add(key, value)
    return agent_table


def load_all_agents() -> dict[str, dict]:
    """Read all agent entries from policy.toml [agents]. Returns {} if missing."""
    doc = _load_doc()
    return _get_agents(doc)


def load_agent(name: str) -> dict:
    """Read a single agent entry. Returns {} if not found."""
    return load_all_agents().get(name, {})


def save_agent(name: str, metadata: dict) -> None:
    """Write a single agent entry (lock + read-modify-write)."""
    def mutate(doc):
        agents = _ensure_agents_table(doc)
        if name in agents:
            del agents[name]
        agents.add(name, _dict_to_toml_table(metadata))

    _locked_mutate(mutate)


def remove_agent(name: str) -> bool:
    """Delete an agent entry. Returns True if it existed."""
    def mutate(doc):
        agents = doc.get("agents")
        if agents is None or name not in agents:
            return False
        del agents[name]
        return True

    return _locked_mutate(mutate)
