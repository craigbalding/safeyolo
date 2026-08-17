"""Operator-only proxy configuration commands."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..config import load_config, save_config
from ..ignore_hosts import normalize_ignore_host, normalize_ignore_hosts
from ..proxy import is_proxy_running, sync_proxy_ignore_hosts

console = Console()

proxy_app = typer.Typer(
    name="proxy",
    help="Manage host-side proxy configuration.",
    no_args_is_help=True,
)
ignore_host_app = typer.Typer(
    name="ignore-host",
    help="Manage exact TLS passthrough hosts.",
    no_args_is_help=True,
)
proxy_app.add_typer(ignore_host_app, name="ignore-host")


def _load_entries() -> tuple[dict, list[str]]:
    config = load_config()
    proxy_config = config.setdefault("proxy", {})
    entries = normalize_ignore_hosts(proxy_config.get("ignore_hosts", []))
    proxy_config["ignore_hosts"] = entries
    return config, entries


def _save_and_sync(config: dict, entries: list[str]) -> bool:
    config["proxy"]["ignore_hosts"] = entries
    save_config(config)
    if not is_proxy_running():
        return False
    admin_port = int(config["proxy"].get("admin_port", 9090))
    if not sync_proxy_ignore_hosts(entries, admin_port=admin_port):
        console.print(
            "[red]Saved, but the running proxy could not be updated.[/red] "
            "Restart SafeYolo to apply the persisted configuration."
        )
        raise typer.Exit(1)
    return True


@ignore_host_app.command("add")
def ignore_host_add(
    host: str = typer.Argument(..., help="Exact HOST or HOST:PORT to pass through"),
) -> None:
    """Add an exact host to the TLS passthrough list."""
    try:
        normalized = normalize_ignore_host(host)
        config, entries = _load_entries()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    if normalized in entries:
        console.print(f"[yellow]Already configured:[/yellow] {escape(normalized)}")
        return

    entries.append(normalized)
    applied = _save_and_sync(config, entries)
    suffix = "applied to running proxy" if applied else "applies on next start"
    console.print(f"[green]Added TLS passthrough:[/green] {escape(normalized)} [dim]({suffix})[/dim]")


@ignore_host_app.command("remove")
def ignore_host_remove(
    host: str = typer.Argument(..., help="Exact HOST or HOST:PORT to remove"),
) -> None:
    """Remove an exact host from the TLS passthrough list."""
    try:
        normalized = normalize_ignore_host(host)
        config, entries = _load_entries()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    if normalized not in entries:
        console.print(f"[yellow]Not found:[/yellow] {escape(normalized)}")
        raise typer.Exit(1)

    entries.remove(normalized)
    applied = _save_and_sync(config, entries)
    suffix = "applied to running proxy" if applied else "applies on next start"
    console.print(f"[green]Removed TLS passthrough:[/green] {escape(normalized)} [dim]({suffix})[/dim]")


@ignore_host_app.command("list")
def ignore_host_list() -> None:
    """List exact operator-managed TLS passthrough hosts."""
    try:
        _, entries = _load_entries()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    if not entries:
        console.print("[dim]No operator-managed TLS passthrough hosts.[/dim]")
        return

    table = Table(title="TLS Passthrough Hosts")
    table.add_column("Host", style="cyan")
    for entry in entries:
        table.add_row(entry)
    console.print(table)
