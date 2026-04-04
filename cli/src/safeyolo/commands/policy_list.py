"""Policy named list management commands."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import tomlkit
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .policy_host import _load_toml, _save_toml

console = Console()

list_app = typer.Typer(
    name="list",
    help="Manage named lists in policy.",
    no_args_is_help=True,
)


def _get_lists_table(doc: tomlkit.TOMLDocument):
    """Get or create the [lists] table."""
    lists = doc.get("lists")
    if lists is None:
        lists = tomlkit.table()
        doc.add("lists", lists)
    return lists


def _count_entries(list_path: Path) -> int:
    """Count entries in a list file (excluding comments and blanks)."""
    if not list_path.exists():
        return -1
    count = 0
    for line in list_path.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


@list_app.command("add")
def list_add(
    name: str = typer.Argument(..., help="List name (used as $name in [hosts])"),
    path: str = typer.Argument(..., help="Path to list file (relative to config dir or absolute)"),
) -> None:
    """Register a named list in policy.

    The list file should contain one entry per line, with # comments.
    Also supports hosts-file format (0.0.0.0 domain).

    Examples:
        safeyolo policy list add known_bad lists/known-bad.txt
        safeyolo policy list add custom /path/to/custom-hosts.txt
    """
    doc, toml_path = _load_toml()
    lists = _get_lists_table(doc)

    # Resolve path for validation
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = toml_path.parent / file_path

    if not file_path.exists():
        console.print(f"[red]Error:[/red] List file not found: {escape(str(file_path))}")
        raise typer.Exit(1)

    count = _count_entries(file_path)
    lists[name] = path

    _save_toml(doc, toml_path)
    console.print(f"[green]Added list:[/green] ${escape(name)} \u2192 {escape(path)} ({count} entries)")


@list_app.command("remove")
def list_remove(
    name: str = typer.Argument(..., help="List name to remove"),
) -> None:
    """Remove a named list from policy.

    Does not delete the list file, only removes the reference from [lists].

    Examples:
        safeyolo policy list remove known_bad
    """
    doc, toml_path = _load_toml()
    lists = doc.get("lists", {})

    if name not in lists:
        console.print(f"[yellow]Not found:[/yellow] ${escape(name)}")
        raise typer.Exit(1)

    del lists[name]
    _save_toml(doc, toml_path)
    console.print(f"[green]Removed list:[/green] ${escape(name)}")


@list_app.command("show")
def list_show(
    name: Optional[str] = typer.Argument(None, help="List name (omit to show all lists)"),
) -> None:
    """Show named lists or entries in a specific list.

    Examples:
        safeyolo policy list show
        safeyolo policy list show known_bad
    """
    doc, toml_path = _load_toml()
    lists = doc.get("lists", {})

    if not lists:
        console.print("[dim]No named lists defined in [lists][/dim]")
        return

    if name:
        # Show entries in a specific list
        if name not in lists:
            console.print(f"[yellow]Not found:[/yellow] ${escape(name)}")
            raise typer.Exit(1)

        list_path_str = lists[name]
        file_path = Path(list_path_str)
        if not file_path.is_absolute():
            file_path = toml_path.parent / file_path

        if not file_path.exists():
            console.print(f"[red]Error:[/red] File not found: {escape(str(file_path))}")
            raise typer.Exit(1)

        entries = []
        for line in file_path.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Handle hosts-file format
                parts = stripped.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    stripped = parts[1]
                if "." in stripped:
                    entries.append(stripped)

        console.print(f"[bold]${escape(name)}[/bold] \u2192 {escape(str(file_path))} ({len(entries)} entries)")
        for entry in entries[:20]:
            console.print(f"  {escape(entry)}")
        if len(entries) > 20:
            console.print(f"  [dim]... and {len(entries) - 20} more[/dim]")
    else:
        # Show all lists
        table = Table(title="Named Lists")
        table.add_column("Name", style="bold")
        table.add_column("Path")
        table.add_column("Entries")

        for list_name, list_path_str in lists.items():
            file_path = Path(str(list_path_str))
            if not file_path.is_absolute():
                file_path = toml_path.parent / file_path
            count = _count_entries(file_path)
            count_str = str(count) if count >= 0 else "[red]missing[/red]"
            table.add_row(f"${list_name}", str(list_path_str), count_str)

        console.print(table)
