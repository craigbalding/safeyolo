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
    table.add_column("Capabilities", style="yellow")
    table.add_column("Description")

    for svc in services:
        caps = ", ".join(svc.get("capabilities", {}).keys())
        table.add_row(
            svc["name"],
            svc.get("default_host", ""),
            caps,
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

    auth = svc.get("auth", {})
    if auth:
        console.print(f"  Auth: type={escape(auth.get('type', '?'))}")
        if auth.get("refresh_on_401"):
            console.print("    Auto-refresh: yes")
    console.print()

    capabilities = svc.get("capabilities", {})
    for cap_name, cap_config in capabilities.items():
        console.print(f"  [yellow]Capability: {escape(cap_name)}[/yellow]")
        desc = cap_config.get("description", "")
        if desc:
            console.print(f"    {escape(desc)}")
        scopes = cap_config.get("scopes", [])
        if scopes:
            console.print(f"    Scopes: {', '.join(escape(s) for s in scopes)}")

        routes = cap_config.get("routes", [])
        if routes:
            console.print("    Routes:")
            for route in routes:
                methods = route.get("methods", ["*"])
                path = route.get("path", "/*")
                console.print(f"      [green]{escape(','.join(methods))}[/green] {escape(path)}")
        console.print()

    risky = svc.get("risky_routes", [])
    if risky:
        console.print("  [red bold]Risky Routes:[/red bold]")
        for entry in risky:
            if "group" in entry:
                console.print(f"    [red]Group: {escape(entry['group'])}[/red]")
                if entry.get("description"):
                    console.print(f"      {escape(entry['description'])}")
                tactics = entry.get("tactics", [])
                if tactics:
                    console.print(f"      Tactics: {', '.join(escape(t) for t in tactics)}")
                for route in entry.get("routes", []):
                    methods = route.get("methods", ["*"])
                    path = route.get("path", "/*")
                    console.print(f"        {escape(','.join(methods))} {escape(path)}")
            else:
                methods = entry.get("methods", ["*"])
                path = entry.get("path", "/*")
                tactics = entry.get("tactics", [])
                console.print(f"    [red]{escape(','.join(methods))} {escape(path)}[/red]")
                if entry.get("description"):
                    console.print(f"      {escape(entry['description'])}")
                if tactics:
                    console.print(f"      Tactics: {', '.join(escape(t) for t in tactics)}")
        console.print()
