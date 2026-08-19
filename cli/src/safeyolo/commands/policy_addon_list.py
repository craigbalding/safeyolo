"""Safe, comment-preserving mutations for list settings in addons.yaml."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Literal

import typer
import yaml
from rich.console import Console
from rich.markup import escape

from ..config import get_config_dir

console = Console()

addon_list_app = typer.Typer(
    name="addon-list",
    help="Add or remove values in addons.yaml list settings.",
    no_args_is_help=True,
)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class AddonListError(ValueError):
    """Raised when addons.yaml cannot be mutated without ambiguity."""


def _validate_identifier(kind: str, value: str) -> None:
    if not _IDENTIFIER.fullmatch(value):
        raise AddonListError(f"{kind} must be a simple YAML identifier, got {value!r}")


def _parse_document(text: str) -> dict:
    try:
        document = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise AddonListError(f"addons.yaml is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise AddonListError("addons.yaml must contain a top-level mapping")
    addons = document.get("addons", {})
    if addons is not None and not isinstance(addons, dict):
        raise AddonListError("addons.yaml 'addons' value must be a mapping")
    return document


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _find_key(lines: list[str], key: str, indent: int, start: int = 0, end: int | None = None) -> int | None:
    pattern = re.compile(rf"^ {{{indent}}}{re.escape(key)}\s*:(?:\s|$)")
    for index in range(start, len(lines) if end is None else end):
        if pattern.match(lines[index]):
            return index
    return None


def _mapping_end(lines: list[str], header_index: int, header_indent: int) -> int:
    for index in range(header_index + 1, len(lines)):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _indent(lines[index]) <= header_indent:
            return index
    return len(lines)


def _require_block_mapping(lines: list[str], index: int, key: str) -> None:
    _, _, remainder = lines[index].partition(":")
    value = remainder.strip()
    if value and not value.startswith("#"):
        raise AddonListError(f"addons.yaml key {key!r} uses an inline value; convert it to a block mapping first")


def _render_list(values: list[str], indent: int) -> list[str]:
    return [f"{' ' * indent}- {json.dumps(value, ensure_ascii=False)}\n" for value in values]


def _replace_existing_list(
    lines: list[str],
    setting_index: int,
    setting: str,
    values: list[str],
) -> list[str]:
    setting_indent = _indent(lines[setting_index])
    block_end = _mapping_end(lines, setting_index, setting_indent)

    item_indexes: list[int] = []
    for index in range(setting_index + 1, block_end):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _indent(lines[index]) != setting_indent + 2 or not stripped.startswith("-"):
            raise AddonListError(f"addons.yaml {setting!r} uses a complex list layout; update it manually")
        item_indexes.append(index)

    item_index_set = set(item_indexes)
    without_items = [line for index, line in enumerate(lines) if index not in item_index_set]
    removed_before_setting = sum(1 for index in item_indexes if index < setting_index)
    new_setting_index = setting_index - removed_before_setting
    without_items[new_setting_index] = f"{' ' * setting_indent}{setting}:\n"
    without_items[new_setting_index + 1 : new_setting_index + 1] = _render_list(values, setting_indent + 2)
    if not values:
        without_items[new_setting_index] = f"{' ' * setting_indent}{setting}: []\n"
    return without_items


def _insert_missing_path(lines: list[str], addon: str, setting: str, values: list[str]) -> list[str]:
    addons_index = _find_key(lines, "addons", 0)
    rendered_values = _render_list(values, 6)

    if addons_index is None:
        prefix = [] if not lines or not lines[-1].strip() else ["\n"]
        return [
            *lines,
            *prefix,
            "addons:\n",
            f"  {addon}:\n",
            f"    {setting}:\n",
            *rendered_values,
        ]

    _require_block_mapping(lines, addons_index, "addons")
    if not lines[addons_index].endswith(("\n", "\r")):
        lines = [*lines]
        lines[addons_index] += "\n"
    addons_end = _mapping_end(lines, addons_index, 0)
    addon_index = _find_key(lines, addon, 2, addons_index + 1, addons_end)
    if addon_index is None:
        insertion = [f"  {addon}:\n", f"    {setting}:\n", *rendered_values]
        return [*lines[: addons_index + 1], *insertion, *lines[addons_index + 1 :]]

    _require_block_mapping(lines, addon_index, f"addons.{addon}")
    if not lines[addon_index].endswith(("\n", "\r")):
        lines = [*lines]
        lines[addon_index] += "\n"
    insertion = [f"    {setting}:\n", *rendered_values]
    return [*lines[: addon_index + 1], *insertion, *lines[addon_index + 1 :]]


def _mutate_text(
    text: str, addon: str, setting: str, value: str, operation: Literal["add", "remove"]
) -> tuple[str, bool]:
    _validate_identifier("addon", addon)
    _validate_identifier("setting", setting)

    before = _parse_document(text)
    addons_config = before.get("addons") or {}
    addon_config = addons_config.get(addon, {})
    if addon_config is None:
        addon_config = {}
    if not isinstance(addon_config, dict):
        raise AddonListError(f"addons.{addon} must be a mapping")
    current = addon_config.get(setting, [])
    if not isinstance(current, list) or not all(isinstance(item, str) for item in current):
        raise AddonListError(f"addons.{addon}.{setting} must be a list of strings")

    updated = list(current)
    if operation == "add":
        if value in updated:
            return text, False
        updated.append(value)
    else:
        if value not in updated:
            return text, False
        updated = [item for item in updated if item != value]

    lines = text.splitlines(keepends=True)
    addons_index = _find_key(lines, "addons", 0)
    addon_index: int | None = None
    setting_index: int | None = None
    if addons_index is not None:
        _require_block_mapping(lines, addons_index, "addons")
        addons_end = _mapping_end(lines, addons_index, 0)
        addon_index = _find_key(lines, addon, 2, addons_index + 1, addons_end)
        if addon_index is not None:
            _require_block_mapping(lines, addon_index, f"addons.{addon}")
            addon_end = _mapping_end(lines, addon_index, 2)
            setting_index = _find_key(lines, setting, 4, addon_index + 1, addon_end)

    if setting_index is None:
        if operation == "remove":
            return text, False
        new_lines = _insert_missing_path(lines, addon, setting, updated)
    else:
        new_lines = _replace_existing_list(lines, setting_index, setting, updated)

    new_text = "".join(new_lines)
    after = _parse_document(new_text)
    expected = deepcopy(before)
    if expected.get("addons") is None:
        expected["addons"] = {}
    expected_addon = expected.setdefault("addons", {}).get(addon)
    if expected_addon is None:
        expected["addons"][addon] = {}
    expected["addons"][addon][setting] = updated
    if after != expected:
        raise AddonListError("refusing to write addons.yaml because the round-trip changed unrelated data")
    return new_text, True


def _atomic_replace(path: Path, content: str) -> None:
    file_mode = stat.S_IMODE(path.stat().st_mode)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            os.fchmod(temp_file.fileno(), file_mode)
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, path)
        temp_path = None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def mutate_addon_list(addon: str, setting: str, value: str, operation: Literal["add", "remove"]) -> bool:
    """Mutate one addons.yaml string list under an exclusive lock."""
    path = get_config_dir() / "addons.yaml"
    if not path.exists():
        raise AddonListError(f"{path} not found; run 'safeyolo init'")
    if path.is_symlink() or not path.is_file():
        raise AddonListError(f"{path} must be a regular file, not a symlink")

    lock_path = path.parent / ".addons.yaml.lock"
    lock_path.touch(mode=0o600, exist_ok=True)
    with lock_path.open() as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            text = path.read_text(encoding="utf-8")
            updated, changed = _mutate_text(text, addon, setting, value, operation)
            if changed:
                _atomic_replace(path, updated)
            return changed
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _run_mutation(addon: str, setting: str, value: str, operation: Literal["add", "remove"]) -> None:
    try:
        changed = mutate_addon_list(addon, setting, value, operation)
    except (AddonListError, OSError) as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from exc

    action = "Added" if operation == "add" else "Removed"
    if changed:
        console.print(f"[green]{action} addon list value:[/green] {escape(addon)}.{escape(setting)} → {escape(value)}")
    else:
        console.print(f"[dim]Unchanged addon list value:[/dim] {escape(addon)}.{escape(setting)} → {escape(value)}")


@addon_list_app.command("add")
def addon_list_add(
    addon: str = typer.Argument(..., help="Addon name, for example test_context"),
    setting: str = typer.Argument(..., help="List setting, for example target_hosts"),
    value: str = typer.Argument(..., help="String value to add"),
) -> None:
    """Add a string to an addons.yaml list, without duplicates."""
    _run_mutation(addon, setting, value, "add")


@addon_list_app.command("remove")
def addon_list_remove(
    addon: str = typer.Argument(..., help="Addon name, for example circuit_breaker"),
    setting: str = typer.Argument(..., help="List setting, for example excluded_domains"),
    value: str = typer.Argument(..., help="String value to remove"),
) -> None:
    """Remove a string from an addons.yaml list; missing values are unchanged."""
    _run_mutation(addon, setting, value, "remove")
