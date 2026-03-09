"""
yaml_roundtrip.py - YAML round-trip load/save with comment preservation

Uses ruamel.yaml to load and save YAML files while preserving comments,
formatting, and key ordering. Only used for write paths where human-authored
comments matter (e.g., baseline.yaml). Read paths stay on PyYAML for speed.
"""

import logging
import shutil
import tempfile
from io import StringIO
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

log = logging.getLogger("safeyolo.yaml-roundtrip")

_yaml = YAML(typ="rt")
_yaml.preserve_quotes = True
_yaml.width = 4096  # Prevent line wrapping
# Match baseline.yaml indentation: 2-space mapping, 4-space sequence (2 offset + 2 content)
_yaml.indent(mapping=2, sequence=4, offset=2)


def load_roundtrip(path: Path) -> CommentedMap:
    """Load a YAML file preserving comments and formatting.

    Args:
        path: Path to the YAML file

    Returns:
        CommentedMap with comments preserved

    Raises:
        FileNotFoundError: If the file doesn't exist
        Exception: On parse errors
    """
    return _yaml.load(path.read_text())


def save_roundtrip(path: Path, data: CommentedMap) -> None:
    """Atomic write of a CommentedMap back to YAML, preserving comments.

    Uses tempfile + move for atomic writes.

    Args:
        path: Destination file path
        data: CommentedMap to serialize
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    stream = StringIO()
    _yaml.dump(data, stream)
    content = stream.getvalue()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    shutil.move(tmp_path, path)
    log.info(f"Saved YAML (round-trip) to {path}")


def merge_into_roundtrip(
    original: CommentedMap, new_data: dict[str, Any]
) -> CommentedMap:
    """Recursively merge new dict values into a CommentedMap.

    Preserves comments on unchanged keys. For list values, replaces
    the entire list since individual item identity can't be reliably matched.

    Args:
        original: CommentedMap loaded via load_roundtrip
        new_data: Plain dict with updated values

    Returns:
        The mutated original CommentedMap
    """
    for key, value in new_data.items():
        if key in original and isinstance(original[key], CommentedMap) and isinstance(value, dict):
            # Recurse into nested dicts to preserve comments on sub-keys
            merge_into_roundtrip(original[key], value)
        elif key in original and isinstance(original[key], (list, CommentedSeq)) and isinstance(value, list):
            # Clear and repopulate in-place to preserve the original container's
            # comments and indentation metadata.
            # Save trailing comment from last item (section banners between
            # sections are stored as end-comments on the last list item's keys).
            trailing = _extract_trailing_comment(original[key])
            del original[key][:]
            for item in value:
                original[key].append(_convert_to_commented(item))
            _apply_trailing_comment(original[key], trailing)
        else:
            # Replace value (scalars, new keys, type changes)
            original[key] = _convert_to_commented(value)

    # Remove keys that are no longer in new_data
    for key in list(original.keys()):
        if key not in new_data:
            del original[key]

    return original


def _extract_trailing_comment(seq: CommentedSeq) -> Any:
    """Extract the trailing comment from the last item in a sequence.

    In ruamel.yaml, section banners that appear between a list and the next
    mapping key are stored as end-comments (index 2) on the last key of
    the last list item.
    """
    if not seq:
        return None
    last = seq[-1]
    if not isinstance(last, CommentedMap) or not hasattr(last, "ca"):
        return None
    for key in reversed(list(last.keys())):
        comment_info = last.ca.items.get(key)
        if comment_info and len(comment_info) > 2 and comment_info[2] is not None:
            return comment_info[2]
    return None


def _apply_trailing_comment(seq: CommentedSeq, comment_token: Any) -> None:
    """Attach a trailing comment to the last item of a sequence."""
    if not seq or comment_token is None:
        return
    last = seq[-1]
    if not isinstance(last, CommentedMap):
        return
    # Find the last key and attach the comment there
    keys = list(last.keys())
    if not keys:
        return
    last_key = keys[-1]
    if last_key not in last.ca.items:
        last.ca.items[last_key] = [None, None, None, None]
    items = last.ca.items[last_key]
    # Ensure list is long enough
    while len(items) <= 2:
        items.append(None)
    items[2] = comment_token


def _convert_to_commented(value: Any) -> Any:
    """Convert plain dicts/lists to CommentedMap/CommentedSeq for ruamel.yaml."""
    if isinstance(value, dict):
        cm = CommentedMap()
        for k, v in value.items():
            cm[k] = _convert_to_commented(v)
        return cm
    elif isinstance(value, list):
        cs = CommentedSeq()
        for item in value:
            cs.append(_convert_to_commented(item))
        return cs
    return value
