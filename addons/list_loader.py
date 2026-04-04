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

from utils import sanitize_for_log

log = logging.getLogger("safeyolo.list-loader")


def load_list(path: Path) -> list[str]:
    """Load a list file — one entry per line, # comments, blank lines skipped.

    Args:
        path: Path to the list file

    Returns:
        List of stripped, non-empty entries

    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    entries = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(stripped)
    return entries


def expand_lists(raw: dict, base_dir: Path) -> dict:
    """Expand $list_name references in the hosts section.

    Looks up names in raw["lists"], loads the referenced files,
    and replaces each $name host entry with individual entries
    sharing the same config.

    Args:
        raw: Policy dict (modified in place)
        base_dir: Base directory for resolving relative list paths

    Returns:
        The modified raw dict
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
            log.warning("List reference '$%s' not defined in [lists], skipping", sanitize_for_log(list_name))
            continue
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
        except FileNotFoundError:
            log.error("List file not found: %s (referenced by $%s)", sanitize_for_log(str(list_path)), sanitize_for_log(list_name))
            continue
        except OSError as e:
            log.error("Failed to read list file %s: %s", sanitize_for_log(str(list_path)), e)
            continue

        # Remove the $name entry
        del hosts[host_key]

        # Add individual entries (don't overwrite existing explicit entries)
        for entry in entries:
            if entry not in hosts:
                hosts[entry] = config

        log.info("Expanded $%s: %d entries from %s", sanitize_for_log(list_name), len(entries), sanitize_for_log(str(list_path)))

    return raw
