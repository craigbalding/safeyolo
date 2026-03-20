"""Service definition commands for the service gateway."""

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ._service_discovery import _load_service_files

console = Console()

services_app = typer.Typer(
    name="services",
    help="View service definitions for the service gateway.",
    no_args_is_help=True,
)


@services_app.command(name="list")
def list_services() -> None:
    """List available service definitions.

    Examples:

        safeyolo services list
    """
    services = _load_service_files()

    if not services:
        console.print("[dim]No service definitions found.[/dim]")
        return

    table = Table(title="Service Definitions")
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="green")
    table.add_column("Roles", style="yellow")
    table.add_column("Description")

    for svc in services:
        identities = ", ".join(svc.get("roles", {}).keys())
        table.add_row(
            svc["name"],
            svc.get("default_host", ""),
            identities,
            svc.get("description", ""),
        )

    console.print(table)


@services_app.command()
def show(
    name: str = typer.Argument(..., help="Service name to show"),
) -> None:
    """Show details of a service definition.

    Examples:

        safeyolo services show gmail
        safeyolo services show minifuse
    """
    services = _load_service_files()
    svc = next((s for s in services if s["name"] == name), None)

    if not svc:
        console.print(f"[red]Error:[/red] Service '{escape(name)}' not found")
        available = [s["name"] for s in services]
        if available:
            console.print(f"Available: {', '.join(escape(n) for n in available)}")
        raise typer.Exit(1)

    console.print(f"[bold cyan]{escape(svc['name'])}[/bold cyan]")
    console.print(f"  Host: {escape(svc.get('default_host', ''))}")
    if svc.get("description"):
        console.print(f"  Description: {escape(svc['description'])}")
    console.print()

    roles = svc.get("roles", {})
    for role_name, role_config in roles.items():
        console.print(f"  [yellow]Role: {escape(role_name)}[/yellow]")
        auth = role_config.get("auth", {})
        console.print(f"    Auth: type={escape(auth.get('type', '?'))}")
        if auth.get("refresh_on_401"):
            console.print("    Auto-refresh: yes")

        routes = role_config.get("routes", [])
        if routes:
            console.print("    Routes:")
            for route in routes:
                effect = route.get("effect", "?")
                methods = route.get("methods", ["*"])
                path = route.get("path", "/*")
                color = "red" if effect == "deny" else "green"
                console.print(f"      [{color}]{escape(effect)}[/{color}] {escape(','.join(methods))} {escape(path)}")
        console.print()
