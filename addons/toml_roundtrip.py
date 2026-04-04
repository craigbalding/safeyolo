"""
toml_roundtrip.py - TOML round-trip load/save with comment preservation.

Uses tomlkit to load and save TOML files while preserving comments,
formatting, and key ordering. Mirrors yaml_roundtrip.py for the TOML
policy format.
"""

import fcntl
import logging
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import tomlkit
from toml_normalize import normalize
from tomlkit.items import InlineTable, Table

log = logging.getLogger("safeyolo.toml-roundtrip")


def load_roundtrip(path: Path) -> tomlkit.TOMLDocument:
    """Load a TOML file preserving comments and formatting.

    Args:
        path: Path to the TOML file

    Returns:
        TOMLDocument with comments preserved

    Raises:
        FileNotFoundError: If the file doesn't exist
        Exception: On parse errors
    """
    return tomlkit.parse(path.read_text())


def save_roundtrip(path: Path, doc: tomlkit.TOMLDocument) -> None:
    """Atomic write of a TOMLDocument back to TOML, preserving comments.

    Uses tempfile + move for atomic writes.

    Args:
        path: Destination file path
        doc: TOMLDocument to serialize
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    content = tomlkit.dumps(doc)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".toml", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    shutil.move(tmp_path, path)
    log.info(f"Saved TOML (round-trip) to {path}")


def load_as_internal(path: Path) -> dict:
    """Load TOML and normalize to internal field names.

    Convenience: load + unwrap + normalize. The output dict is identical
    to what PyYAML produces from the current policy.yaml format, so
    policy_compiler.py works unmodified.

    Args:
        path: Path to the TOML policy file

    Returns:
        Dict with internal field names, ready for policy_compiler
    """
    doc = load_roundtrip(path)
    raw = _unwrap(doc)
    return normalize(raw)


def _unwrap(doc: tomlkit.TOMLDocument) -> dict:
    """Convert TOMLDocument to plain dict (recursive)."""
    return doc.unwrap()


def add_host_credential(doc: tomlkit.TOMLDocument, host: str, cred_ids: list[str]) -> None:
    """Add credential IDs to a host entry in the [hosts] table.

    Operates on the TOMLDocument using TOML field names (allow, rate).
    Creates the host entry if it doesn't exist.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        host: Host pattern (e.g., "api.example.com")
        cred_ids: Credential identifiers to add (e.g., ["hmac:a1b2c3"])
    """
    hosts = doc.get("hosts")
    if hosts is None:
        hosts = tomlkit.table()
        doc.add("hosts", hosts)

    if host in hosts:
        host_config = hosts[host]
        if isinstance(host_config, (dict, Table, InlineTable)):
            existing = host_config.get("allow")
            if existing is None:
                host_config["allow"] = cred_ids
            else:
                for cred in cred_ids:
                    if cred not in existing:
                        existing.append(cred)
        else:
            # Scalar or unexpected — replace with inline table
            it = tomlkit.inline_table()
            it.append("allow", cred_ids)
            hosts[host] = it
    else:
        # New host entry
        it = tomlkit.inline_table()
        it.append("allow", cred_ids)
        hosts[host] = it


def update_host_field(doc: tomlkit.TOMLDocument, host: str, key: str, value: Any) -> None:
    """Update a single field on a host entry.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        host: Host pattern
        key: TOML field name (allow, rate, bypass, unknown_creds, etc.)
        value: New value
    """
    hosts = doc.get("hosts")
    if hosts is None:
        hosts = tomlkit.table()
        doc.add("hosts", hosts)

    if host in hosts:
        host_config = hosts[host]
        if isinstance(host_config, (dict, Table, InlineTable)):
            host_config[key] = value
        else:
            it = tomlkit.inline_table()
            it.append(key, value)
            hosts[host] = it
    else:
        it = tomlkit.inline_table()
        it.append(key, value)
        hosts[host] = it


def add_host(doc: tomlkit.TOMLDocument, host: str, config: dict) -> None:
    """Add a new host entry with multiple fields.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        host: Host pattern
        config: Dict of TOML field names and values
    """
    hosts = doc.get("hosts")
    if hosts is None:
        hosts = tomlkit.table()
        doc.add("hosts", hosts)

    it = tomlkit.inline_table()
    for k, v in config.items():
        it.append(k, v)
    hosts[host] = it


# =========================================================================
# Agent helpers — read/write [agents] section
# =========================================================================


def _ensure_agents_table(doc: tomlkit.TOMLDocument) -> tomlkit.items.Table:
    """Get or create the [agents] table in a TOMLDocument."""
    if "agents" not in doc:
        doc.add("agents", tomlkit.table())
    return doc["agents"]


def load_agents(doc: tomlkit.TOMLDocument) -> dict:
    """Extract all agents from the [agents] section as plain dicts.

    Returns:
        Dict of agent_name -> agent_metadata (unwrapped to plain dicts).
        Empty dict if no [agents] section.
    """
    agents = doc.get("agents")
    if agents is None:
        return {}
    # Unwrap tomlkit items to plain Python types
    if hasattr(agents, "unwrap"):
        return agents.unwrap()
    return dict(agents)


def upsert_agent(doc: tomlkit.TOMLDocument, name: str, metadata: dict) -> None:
    """Insert or replace an agent entry under [agents].

    Converts the metadata dict into tomlkit tables/arrays-of-tables
    so the output is well-structured TOML with proper section headers.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        name: Agent name (e.g., "boris")
        metadata: Agent config dict (template, folder, services, grants, etc.)
    """
    agents = _ensure_agents_table(doc)

    agent_table = tomlkit.table()

    for key, value in metadata.items():
        if key == "services" and isinstance(value, dict):
            # services -> nested sub-tables: [agents.name.services.gmail]
            svc_table = tomlkit.table()
            for svc_name, svc_config in value.items():
                svc_entry = tomlkit.table()
                if isinstance(svc_config, dict):
                    for sk, sv in svc_config.items():
                        svc_entry.add(sk, sv)
                else:
                    # Legacy string format: service_name: capability
                    svc_entry.add("capability", svc_config)
                svc_table.add(svc_name, svc_entry)
            agent_table.add("services", svc_table)

        elif key in ("contract_bindings", "grants") and isinstance(value, list):
            # Array of tables: [[agents.name.grants]]
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

    # Replace or add
    if name in agents:
        del agents[name]
    agents.add(name, agent_table)


def remove_agent(doc: tomlkit.TOMLDocument, name: str) -> bool:
    """Remove an agent entry from [agents].

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        name: Agent name to remove

    Returns:
        True if the agent existed and was removed, False otherwise.
    """
    agents = doc.get("agents")
    if agents is None or name not in agents:
        return False
    del agents[name]
    return True


# =========================================================================
# Unified file locking
# =========================================================================


def _lock_path(policy_path: Path) -> Path:
    """Lock file path for a policy.toml file."""
    return policy_path.parent / ".policy.toml.lock"


def locked_policy_mutate(
    policy_path: Path,
    mutate_fn: Callable[[tomlkit.TOMLDocument], Any],
) -> Any:
    """Read-modify-write policy.toml under an exclusive file lock.

    Args:
        policy_path: Path to policy.toml
        mutate_fn: Called with the loaded TOMLDocument. May modify it in place.
                   Return value is passed through to the caller.

    Returns:
        Whatever mutate_fn returns.
    """
    lock = _lock_path(policy_path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch()

    with open(lock) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            doc = load_roundtrip(policy_path)
            result = mutate_fn(doc)
            save_roundtrip(policy_path, doc)
            return result
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def policy_path_for_loader(loader: Any) -> Path | None:
    """Extract the baseline policy path from a PolicyLoader instance.

    Replaces the getattr(loader, "_agents_path", ...)() pattern.
    """
    path = getattr(loader, "_baseline_path", None)
    if path and isinstance(path, Path) and path.exists():
        return path
    return None
