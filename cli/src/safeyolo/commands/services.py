"""Service definition commands for the service gateway."""

from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

console = Console()

services_app = typer.Typer(
    name="services",
    help="View service definitions for the service gateway.",
    no_args_is_help=True,
)


def _get_services_dirs() -> list[Path]:
    """Get service definition directories (user + builtin)."""
    from ..config import _get_config_dir_path
    user_dir = _get_config_dir_path() / "services"
    builtin_dir = Path(__file__).parent.parent.parent.parent.parent.parent / "config" / "services"
    return [builtin_dir, user_dir]


def _load_service_files() -> list[dict]:
    """Load all service definition YAML files."""
    services = {}
    for directory in _get_services_dirs():
        if not directory.exists():
            continue
        for yaml_file in sorted(directory.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text())
                if raw and isinstance(raw, dict) and "name" in raw:
                    services[raw["name"]] = raw
            except Exception:
                continue
    return list(services.values())


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
            svc.get("host", ""),
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
        console.print(f"[red]Error:[/red] Service '{name}' not found")
        available = [s["name"] for s in services]
        if available:
            console.print(f"Available: {', '.join(available)}")
        raise typer.Exit(1)

    console.print(f"[bold cyan]{svc['name']}[/bold cyan]")
    console.print(f"  Host: {svc.get('host', '')}")
    if svc.get("description"):
        console.print(f"  Description: {svc['description']}")
    console.print()

    roles = svc.get("roles", {})
    for role_name, role_config in roles.items():
        console.print(f"  [yellow]Role: {role_name}[/yellow]")
        auth = role_config.get("auth", {})
        console.print(f"    Auth: type={auth.get('type', '?')}")
        if auth.get("refresh_on_401"):
            console.print("    Auto-refresh: yes")

        routes = id_config.get("routes", [])
        if routes:
            console.print("    Routes:")
            for route in routes:
                effect = route.get("effect", "?")
                methods = route.get("methods", ["*"])
                path = route.get("path", "/*")
                color = "red" if effect == "deny" else "green"
                console.print(f"      [{color}]{effect}[/{color}] {','.join(methods)} {path}")
        console.print()
