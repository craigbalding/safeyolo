"""
toml_roundtrip.py - TOML round-trip load/save with comment preservation.

Uses tomlkit to load and save TOML files while preserving comments,
formatting, and key ordering.

All mutation helpers fail-closed: they raise ValueError with a clear
message rather than silently rewriting hand-edited malformed values.
Atomic writes fsync the tempfile and clean up on failure so a crash
mid-write cannot leave a zero-length policy file visible.
"""

import fcntl
import logging
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import tomlkit
from toml_normalize import normalize
from tomlkit.items import InlineTable, Table

log = logging.getLogger("safeyolo.toml-roundtrip")


# =========================================================================
# Load / save
# =========================================================================


def load_roundtrip(path: Path) -> tomlkit.TOMLDocument:
    """Load a TOML file preserving comments and formatting.

    Args:
        path: Path to the TOML file

    Returns:
        TOMLDocument with comments preserved

    Raises:
        FileNotFoundError: If the file doesn't exist
        tomlkit.exceptions.TOMLKitError: On parse errors
    """
    return tomlkit.parse(path.read_text())


def save_roundtrip(path: Path, doc: tomlkit.TOMLDocument) -> None:
    """Atomic write of a TOMLDocument back to TOML, preserving comments.

    Uses tempfile + fsync + rename for atomicity. Cleans up the temp file
    on failure so no leftover droppings accumulate in the target directory.

    Args:
        path: Destination file path
        doc: TOMLDocument to serialize

    Raises:
        OSError: On write or rename failure (temp file is cleaned up).
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    content = tomlkit.dumps(doc)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".toml", dir=path.parent, delete=False
        ) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name

        shutil.move(tmp_path, path)
        tmp_path = None  # moved successfully, no cleanup needed

        # fsync the parent directory so the rename is durable
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        log.debug("Saved TOML (round-trip) to %s", path)
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass  # best effort cleanup


def load_as_internal(path: Path) -> dict:
    """Load TOML and normalize to internal field names.

    Convenience: load + unwrap + normalize. The output dict matches what
    policy_compiler.py expects.

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


# =========================================================================
# Host helpers
# =========================================================================


def _ensure_hosts_table(doc: tomlkit.TOMLDocument) -> Table:
    """Get or create the [hosts] table."""
    hosts = doc.get("hosts")
    if hosts is None:
        hosts = tomlkit.table()
        doc.add("hosts", hosts)
    return hosts


def _require_host_config_is_dict(host: str, host_config: Any) -> None:
    """Raise ValueError if an existing host entry is not a dict/Table.

    Silent rewrite of scalar/unexpected values hides operator hand-edit
    errors and is a transparency violation.
    """
    if not isinstance(host_config, (dict, Table, InlineTable)):
        raise ValueError(
            f"Host entry '{host}' is not a table (got {type(host_config).__name__}). "
            f"Fix the entry manually in policy.toml before using mutation helpers."
        )


def add_host_credential(
    doc: tomlkit.TOMLDocument, host: str, cred_ids: list[str]
) -> None:
    """Add credential IDs to a host entry in the [hosts] table.

    Creates the host entry if it doesn't exist. Appends to an existing
    allow list without introducing duplicates. Order is preserved: new
    credentials append after existing ones in the order given.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        host: Host pattern (e.g., "api.example.com")
        cred_ids: Credential identifiers to add (e.g., ["hmac:a1b2c3"])

    Raises:
        ValueError: if cred_ids is empty, if any id is not a string, or
            if the existing host entry is not a table (scalar, list, etc.)
            or an existing `allow` field is not a list.
    """
    if not cred_ids:
        raise ValueError("cred_ids must be a non-empty list")
    if not all(isinstance(c, str) for c in cred_ids):
        raise ValueError("cred_ids must be a list of strings")

    hosts = _ensure_hosts_table(doc)

    if host in hosts:
        host_config = hosts[host]
        _require_host_config_is_dict(host, host_config)

        existing = host_config.get("allow")
        if existing is None:
            host_config["allow"] = list(cred_ids)
            return

        if not isinstance(existing, list):
            raise ValueError(
                f"Host '{host}' has 'allow' of type {type(existing).__name__}, "
                f"expected a list. Fix the entry manually in policy.toml."
            )

        for cred in cred_ids:
            if cred not in existing:
                existing.append(cred)
    else:
        # New host entry
        it = tomlkit.inline_table()
        it.append("allow", list(cred_ids))
        hosts[host] = it


def update_host_field(
    doc: tomlkit.TOMLDocument, host: str, key: str, value: Any
) -> None:
    """Update (or create) a single field on a host entry.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        host: Host pattern
        key: TOML field name (allow, rate, bypass, unknown_creds, etc.)
        value: New value (must not be None)

    Raises:
        ValueError: if value is None, or if the existing host entry is
            not a table (scalar, list, etc.).
    """
    if value is None:
        raise ValueError(
            f"update_host_field({host!r}, {key!r}): value must not be None. "
            f"To remove a field, read the host config and delete the key directly."
        )

    hosts = _ensure_hosts_table(doc)

    if host in hosts:
        host_config = hosts[host]
        _require_host_config_is_dict(host, host_config)
        host_config[key] = value
    else:
        it = tomlkit.inline_table()
        it.append(key, value)
        hosts[host] = it


def upsert_host(doc: tomlkit.TOMLDocument, host: str, config: dict) -> None:
    """Insert or replace a host entry with the given config.

    Replaces the entire entry if the host already exists. Callers that
    want to preserve existing fields should read-modify-write themselves
    using update_host_field.

    Args:
        doc: TOMLDocument loaded via load_roundtrip
        host: Host pattern
        config: Dict of TOML field names and values
    """
    hosts = _ensure_hosts_table(doc)

    it = tomlkit.inline_table()
    for k, v in config.items():
        it.append(k, v)
    hosts[host] = it


# =========================================================================
# Agent helpers — read/write [agents] section
# =========================================================================


def _ensure_agents_table(doc: tomlkit.TOMLDocument) -> Table:
    """Get or create the [agents] table in a TOMLDocument."""
    if "agents" not in doc:
        doc.add("agents", tomlkit.table())
    return doc["agents"]


def load_agents(doc: tomlkit.TOMLDocument) -> dict:
    """Extract all agents from the [agents] section as plain dicts.

    The returned dict is independent of the TOMLDocument — mutating it
    does not affect the document. Returns an empty dict if there is no
    [agents] section.
    """
    agents = doc.get("agents")
    if agents is None:
        return {}
    # Unwrap tomlkit items to plain Python types (this creates a fresh dict)
    if hasattr(agents, "unwrap"):
        return agents.unwrap()
    return dict(agents)


def upsert_agent(
    doc: tomlkit.TOMLDocument, name: str, metadata: dict
) -> None:
    """Insert or replace an agent entry under [agents].

    Converts the metadata dict into tomlkit tables/arrays-of-tables so
    the output is well-structured TOML with proper section headers.

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

    The lock is released in a finally block, so a raising mutate_fn does
    not leave the lock held.

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

    lf = open(lock)
    try:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            doc = load_roundtrip(policy_path)
            result = mutate_fn(doc)
            save_roundtrip(policy_path, doc)
            return result
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
    finally:
        lf.close()


class LoaderNotConfigured(RuntimeError):
    """Raised when policy_path_for_loader is called on a loader with no baseline."""


class LoaderBaselineMissing(FileNotFoundError):
    """Raised when the loader's baseline path exists in memory but not on disk."""


def policy_path_for_loader(loader: Any) -> Path:
    """Extract the baseline policy path from a PolicyLoader instance.

    Returns the path if the loader has a `_baseline_path` attribute, it
    is a Path instance, and the file exists on disk.

    Raises:
        LoaderNotConfigured: if the loader has no _baseline_path attribute
            or it is not a Path (e.g. None because the loader was
            instantiated without a baseline).
        LoaderBaselineMissing: if _baseline_path is set but the file does
            not exist. Distinct from LoaderNotConfigured so callers can
            tell "never configured" from "file deleted".
    """
    path = getattr(loader, "_baseline_path", None)
    if path is None or not isinstance(path, Path):
        raise LoaderNotConfigured(
            "loader has no _baseline_path — loader was not configured with a baseline file"
        )
    if not path.exists():
        raise LoaderBaselineMissing(f"baseline path {path} does not exist on disk")
    return path
