"""Command Centre configuration and launcher commands."""

from __future__ import annotations

import importlib.util

import typer
from rich.console import Console

from ..config import load_config, save_config
from ..proxy import command_centre_tailnet_status_file
from ..tailnet import read_tailnet_state

console = Console()

command_centre_app = typer.Typer(
    name="command-centre",
    help="Configure and launch the optional SafeYolo operator menu-bar app.",
    no_args_is_help=True,
)


@command_centre_app.command()
def enable(
    events_port: int = typer.Option(
        9091,
        "--events-port",
        min=1,
        max=65535,
        help="Loopback WebSocket port for live operator events.",
    ),
    share: str = typer.Option(
        "local",
        "--share",
        help="Publish locally, or explicitly publish to the tailnet.",
    ),
    tailnet_admin_port: int = typer.Option(
        9443,
        "--tailnet-admin-port",
        min=1,
        max=65535,
        help="Tailnet HTTPS port for the Admin API.",
    ),
    tailnet_events_port: int = typer.Option(
        9444,
        "--tailnet-events-port",
        min=1,
        max=65535,
        help="Tailnet HTTPS port for live events.",
    ),
) -> None:
    """Enable Command Centre locally or over an explicit Tailnet share."""
    if importlib.util.find_spec("websockets") is None:
        console.print(
            "[red]Command Centre dependencies are not installed.[/red]\n"
            "Install SafeYolo with its [bold]command-centre[/bold] extra first."
        )
        raise typer.Exit(1)

    share = share.strip().lower()
    if share not in {"local", "tailnet"}:
        console.print("[red]--share must be local or tailnet.[/red]")
        raise typer.Exit(2)
    if tailnet_admin_port == tailnet_events_port:
        console.print("[red]Tailnet Admin and event ports must differ.[/red]")
        raise typer.Exit(2)

    config = load_config()
    command_centre = config.setdefault("command_centre", {})
    command_centre["enabled"] = True
    command_centre["events_port"] = events_port
    command_centre["share"] = share
    command_centre["tailnet_admin_port"] = tailnet_admin_port
    command_centre["tailnet_events_port"] = tailnet_events_port
    save_config(config)
    if share == "tailnet":
        console.print(
            "[green]Command Centre enabled[/green] for explicit Tailnet publication "
            f"on HTTPS ports {tailnet_admin_port} (Admin) and {tailnet_events_port} (events).\n"
            "Restart SafeYolo to publish the mappings."
        )
    else:
        console.print(
            f"[green]Command Centre enabled[/green] on loopback event port {events_port}.\n"
            "Restart SafeYolo to apply the change."
        )


@command_centre_app.command()
def disable() -> None:
    """Disable the Command Centre event endpoint on next SafeYolo start."""
    config = load_config()
    config.setdefault("command_centre", {})["enabled"] = False
    save_config(config)
    console.print("[green]Command Centre disabled.[/green] Restart SafeYolo to apply the change.")


@command_centre_app.command()
def status() -> None:
    """Show configured Command Centre state."""
    command_centre = load_config().get("command_centre", {})
    state = "enabled" if command_centre.get("enabled", False) else "disabled"
    port = command_centre.get("events_port", 9091)
    share = command_centre.get("share", "local")
    console.print(f"Command Centre: [bold]{state}[/bold] (share: {share}, events: 127.0.0.1:{port})")
    if state == "enabled" and share == "tailnet":
        runtime = read_tailnet_state(command_centre_tailnet_status_file())
        runtime_state = runtime.get("state", "not running")
        console.print(f"Tailnet publication: [bold]{runtime_state}[/bold]")
        if runtime.get("admin_url"):
            console.print(f"Admin URL: {runtime['admin_url']}")
        if runtime.get("events_url"):
            console.print(f"Events URL: {runtime['events_url']}")


@command_centre_app.command(name="run")
def run_app() -> None:
    """Run the macOS menu-bar application."""
    try:
        from ..command_centre.app import main
    except (ImportError, ModuleNotFoundError) as exc:
        console.print(
            "[red]Command Centre dependencies are unavailable.[/red]\n"
            "Install SafeYolo with its [bold]command-centre[/bold] extra."
        )
        raise typer.Exit(1) from exc
    raise typer.Exit(main())
