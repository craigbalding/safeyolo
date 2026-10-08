"""
list_loader.py - Named list loading and policy expansion.

Lists are a general-purpose policy primitive: a file of strings mapped
to a name in [lists], referenced with $name in host entries (and future
consumers). The compiler expands list references into individual entries
at compile time.

List file format:
    # comment
    pypi.org
    files.pythonhosted.org
"""

import logging
from pathlib import Path

from safeyolo.core.utils import sanitize_for_log

log = logging.getLogger("safeyolo.list-loader")


def load_list(path: Path) -> list[str]:
    """Load a list file — one entry per line, # comments, blank lines skipped.

    Also handles hosts-file format (e.g., "0.0.0.0 domain" or
    "127.0.0.1 domain") by stripping the IP prefix.

    Args:
        path: Path to the list file

    Returns:
        List of stripped, non-empty, unique entries

    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    seen: set[str] = set()
    entries: list[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Handle hosts-file format: "0.0.0.0 domain", "127.0.0.1 domain", etc.
        parts = stripped.split()
        if len(parts) >= 2 and (parts[0] in ("0.0.0.0", "127.0.0.1", "255.255.255.255") or parts[0].startswith((":", "f"))):
            stripped = parts[1]
        # Skip non-domain entries from hosts files
        if stripped in ("0.0.0.0", "127.0.0.1", "localhost", "localhost.localdomain", "local", "broadcasthost"):
            continue
        # Skip entries that aren't valid domain names (must contain a dot)
        if "." not in stripped:
            continue
        if stripped not in seen:
            seen.add(stripped)
            entries.append(stripped)
    return entries


def expand_lists(raw: dict, base_dir: Path) -> dict:
    """Expand $list_name references in the hosts section.

    Looks up names in raw["lists"], loads the referenced files,
    and replaces each $name host entry with individual entries
    sharing the same config.

    Fails closed: undefined references, missing files, and read errors
    raise ValueError with a clear message. Policy load should abort
    rather than silently dropping rules the operator wrote.

    Args:
        raw: Policy dict (modified in place)
        base_dir: Base directory for resolving relative list paths

    Returns:
        The modified raw dict

    Raises:
        ValueError: If a $name reference is undefined, the list file is
            missing, or the file cannot be read. Message includes the
            failing reference and (for undefined names) the defined names.
    """
    lists_config = raw.get("lists", {})
    if not lists_config or not isinstance(lists_config, dict):
        return raw

    hosts = raw.get("hosts", {})
    if not hosts:
        return raw

    # Collect $name entries to expand (can't modify dict during iteration)
    to_expand: list[tuple[str, str, dict]] = []  # (key, list_name, config)
    for host_key, config in hosts.items():
        if not host_key.startswith("$"):
            continue
        list_name = host_key[1:]  # strip $
        if list_name not in lists_config:
            defined = ", ".join(sorted(lists_config.keys())) or "(none)"
            raise ValueError(
                f"Undefined list reference '${list_name}' in [hosts]. "
                f"Defined lists: {defined}"
            )
        to_expand.append((host_key, list_name, config if config is not None else {}))

    if not to_expand:
        return raw

    # Load and expand each list
    for host_key, list_name, config in to_expand:
        list_path_str = lists_config[list_name]
        list_path = Path(list_path_str)
        if not list_path.is_absolute():
            list_path = base_dir / list_path

        try:
            entries = load_list(list_path)
        except FileNotFoundError as e:
            raise ValueError(
                f"List file not found: {list_path} (referenced by ${list_name})"
            ) from e
        except OSError as e:
            raise ValueError(
                f"Failed to read list file {list_path} (referenced by ${list_name}): {e}"
            ) from e

        # Remove the $name entry
        del hosts[host_key]

        # Add individual entries (don't overwrite existing explicit entries).
        # Copy the config dict so downstream mutations of one entry don't
        # propagate to all expanded entries.
        for entry in entries:
            if entry not in hosts:
                hosts[entry] = dict(config)

        log.info("Expanded $%s: %d entries from %s", sanitize_for_log(list_name), len(entries), sanitize_for_log(str(list_path)))

    return raw
