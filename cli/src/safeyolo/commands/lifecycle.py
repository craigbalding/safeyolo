"""Container lifecycle commands: start, stop, status."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..api import APIError, get_api
from ..config import find_config_dir, get_admin_token, load_config
from ..docker import (
    DockerError,
    check_docker,
    get_container_status,
    is_running,
    start as docker_start,
    stop as docker_stop,
    wait_for_healthy,
)

console = Console()


def start(
    pull: bool = typer.Option(
        False,
        "--pull", "-p",
        help="Pull latest image before starting",
    ),
    wait: bool = typer.Option(
        True,
        "--wait/--no-wait",
        help="Wait for healthy status",
    ),
) -> None:
    """Start SafeYolo proxy container."""

    # Check config exists
    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[red]No SafeYolo configuration found.[/red]\n"
            "Run [bold]safeyolo init[/bold] first."
        )
        raise typer.Exit(1)

    # Check Docker
    if not check_docker():
        console.print("[red]Docker is not available.[/red]")
        raise typer.Exit(1)

    # Check if already running
    if is_running():
        console.print("[yellow]SafeYolo is already running.[/yellow]")
        raise typer.Exit(0)

    config = load_config()
    proxy_port = config["proxy"]["port"]
    admin_port = config["proxy"]["admin_port"]

    console.print("[bold]Starting SafeYolo...[/bold]")

    try:
        docker_start(detach=True, pull=pull)
    except DockerError as e:
        console.print(f"[red]Failed to start:[/red] {e}")
        raise typer.Exit(1)

    if wait:
        console.print("Waiting for healthy status...", end=" ")
        if wait_for_healthy(timeout=30):
            console.print("[green]ready![/green]")
        else:
            console.print("[yellow]timeout (may still be starting)[/yellow]")

    # Show connection info
    console.print(
        Panel(
            f"[green]SafeYolo is running[/green]\n\n"
            f"Proxy:     http://localhost:{proxy_port}\n"
            f"Admin API: http://localhost:{admin_port}\n\n"
            f"Configure your agent:\n"
            f"  export HTTP_PROXY=http://localhost:{proxy_port}\n"
            f"  export HTTPS_PROXY=http://localhost:{proxy_port}\n\n"
            f"View logs: [bold]safeyolo logs[/bold]",
            title="Started",
        )
    )


def stop() -> None:
    """Stop SafeYolo proxy container."""

    if not is_running():
        console.print("[yellow]SafeYolo is not running.[/yellow]")
        raise typer.Exit(0)

    console.print("[bold]Stopping SafeYolo...[/bold]")

    try:
        docker_stop()
        console.print("[green]Stopped.[/green]")
    except DockerError as e:
        console.print(f"[red]Failed to stop:[/red] {e}")
        raise typer.Exit(1)


def status() -> None:
    """Show SafeYolo status and statistics."""

    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[yellow]No SafeYolo configuration found.[/yellow]\n"
            "Run [bold]safeyolo init[/bold] to get started."
        )
        raise typer.Exit(1)

    config = load_config()

    # Container status
    container_status = get_container_status()

    if not container_status or container_status["status"] != "running":
        console.print(
            Panel(
                "[yellow]SafeYolo is not running[/yellow]\n\n"
                "Run [bold]safeyolo start[/bold] to start the proxy.",
                title="Status",
            )
        )
        raise typer.Exit(0)

    # Build status table
    table = Table(title="SafeYolo Status", show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Container", f"[green]running[/green]")
    table.add_row("Health", container_status.get("health", "unknown"))
    table.add_row("Proxy Port", str(config["proxy"]["port"]))
    table.add_row("Admin Port", str(config["proxy"]["admin_port"]))

    # Try to get stats from API
    try:
        api = get_api()
        stats = api.stats()

        # Credential guard stats
        cg = stats.get("credential-guard", {})
        if cg:
            table.add_row("", "")  # Spacer
            table.add_row("Credentials Blocked", str(cg.get("violations_total", 0)))
            table.add_row("Rules Loaded", str(cg.get("rules_count", 0)))

        # Rate limiter stats
        rl = stats.get("rate-limiter", {})
        if rl:
            table.add_row("Rate Limited", str(rl.get("limited_total", 0)))

        # Pending approvals
        pending = api.pending_approvals()
        if pending:
            table.add_row("Pending Approvals", f"[yellow]{len(pending)}[/yellow]")

    except APIError:
        table.add_row("", "")
        table.add_row("API", "[yellow]unavailable[/yellow]")

    console.print(table)

    # Show modes
    try:
        api = get_api()
        modes = api.get_modes()

        mode_table = Table(title="Addon Modes", show_header=True)
        mode_table.add_column("Addon")
        mode_table.add_column("Mode")

        for addon, mode_info in modes.items():
            mode = mode_info.get("mode", "unknown")
            style = "red bold" if mode == "block" else "yellow"
            mode_table.add_row(addon, f"[{style}]{mode}[/{style}]")

        console.print()
        console.print(mode_table)

    except APIError:
        pass  # Already shown API unavailable above
