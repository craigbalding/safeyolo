"""Mount protection commands."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ..config import load_config, save_config

console = Console()

mount_app = typer.Typer(
    name="mount",
    help="Manage mount path protections.",
    no_args_is_help=True,
)


def get_protected_paths() -> list[str]:
    """Load protected paths from config."""
    config = load_config()
    return config.get("protected_paths", [])


def is_path_protected(host_path: str, protected_paths: list[str] | None = None) -> str | None:
    """Check if a host path falls under a protected path.

    Returns the matching protected path, or None if not protected.
    """
    if protected_paths is None:
        protected_paths = get_protected_paths()

    check = Path(host_path).resolve()
    for pp in protected_paths:
        protected = Path(pp).resolve()
        # Check exact match or parent
        if check == protected or protected in check.parents:
            return str(protected)
    return None


@mount_app.command()
def protect(
    path: str = typer.Argument(..., help="Host path that must always be mounted read-only"),
) -> None:
    """Mark a host path as read-only protected.

    Any mount of this path (or subdirectories) without :ro will be rejected.

    Examples:

        safeyolo mount protect ~/refs
        safeyolo mount protect /shared/data
    """
    resolved = str(Path(path).expanduser().resolve())

    if not Path(resolved).exists():
        console.print(f"[yellow]Warning: {resolved} does not exist yet (protecting anyway)[/yellow]")

    config = load_config()
    protected = config.get("protected_paths", [])

    if resolved in protected:
        console.print(f"[dim]Already protected:[/dim] {resolved}")
        return

    protected.append(resolved)
    config["protected_paths"] = protected
    save_config(config)
    console.print(f"[green]Protected:[/green] {resolved} (must be mounted :ro)")


@mount_app.command()
def unprotect(
    path: str = typer.Argument(..., help="Host path to remove read-only protection from"),
) -> None:
    """Remove read-only protection from a host path.

    Examples:

        safeyolo mount unprotect ~/refs
    """
    resolved = str(Path(path).expanduser().resolve())

    config = load_config()
    protected = config.get("protected_paths", [])

    if resolved not in protected:
        console.print(f"[yellow]Not protected:[/yellow] {resolved}")
        return

    protected.remove(resolved)
    if protected:
        config["protected_paths"] = protected
    else:
        del config["protected_paths"]
    save_config(config)
    console.print(f"[green]Unprotected:[/green] {resolved}")


@mount_app.command(name="list")
def list_protected() -> None:
    """List all protected mount paths."""
    protected = get_protected_paths()

    if not protected:
        console.print("[dim]No protected paths configured.[/dim]")
        console.print("Use [bold]safeyolo mount protect <path>[/bold] to add one.")
        return

    table = Table(title="Protected Paths (always :ro)")
    table.add_column("Path", style="bold")
    table.add_column("Exists")
    for p in protected:
        exists = "[green]yes[/green]" if Path(p).exists() else "[yellow]no[/yellow]"
        table.add_row(p, exists)
    console.print(table)
