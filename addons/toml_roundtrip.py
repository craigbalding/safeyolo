"""
toml_roundtrip.py - TOML round-trip load/save with comment preservation.

Uses tomlkit to load and save TOML files while preserving comments,
formatting, and key ordering. Mirrors yaml_roundtrip.py for the TOML
policy format.
"""

import logging
import shutil
import tempfile
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
        key: TOML field name (allow, rate, bypass, on_unknown, etc.)
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
