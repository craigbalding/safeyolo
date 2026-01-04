"""Container lifecycle commands: start, stop, status."""

import json
import secrets
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..api import APIError, get_api
from ..config import (
    DEFAULT_CONFIG,
    GLOBAL_DIR_NAME,
    find_config_dir,
    get_admin_token,
    load_config,
    save_config,
)
from ..docker import (
    DockerError,
    check_docker,
    get_container_status,
    is_running,
    start as docker_start,
    stop as docker_stop,
    wait_for_healthy,
    write_compose_file,
)

console = Console()

# Default rules for common API providers
DEFAULT_RULES = {
    "credentials": [
        {
            "name": "openai",
            "pattern": "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
            "allowed_hosts": ["api.openai.com"],
        },
        {
            "name": "openai_project",
            "pattern": "sk-proj-[a-zA-Z0-9_-]{80,}",
            "allowed_hosts": ["api.openai.com"],
        },
        {
            "name": "anthropic",
            "pattern": "sk-ant-api[a-zA-Z0-9-]{90,}",
            "allowed_hosts": ["api.anthropic.com"],
        },
        {
            "name": "github",
            "pattern": "gh[ps]_[a-zA-Z0-9]{36}",
            "allowed_hosts": ["api.github.com", "github.com"],
        },
    ],
    "entropy_detection": {
        "enabled": True,
        "min_length": 20,
        "min_charset_diversity": 0.5,
        "min_shannon_entropy": 3.5,
    },
}


def _bootstrap_config(config_dir: Path) -> None:
    """Bootstrap config directory with sensible defaults."""
    # Create directories
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)

    # Generate admin token
    token = secrets.token_urlsafe(32)
    token_path = config_dir / "data" / "admin_token"
    token_path.write_text(token)
    token_path.chmod(0o600)

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    save_config(config)

    # Write rules.json
    rules_path = config_dir / "rules.json"
    rules_path.write_text(json.dumps(DEFAULT_RULES, indent=2))

    # Write docker-compose.yml
    write_compose_file(secure=False)


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
    first_run = False

    # Check Docker first
    if not check_docker():
        console.print("[red]Docker is not available.[/red]")
        raise typer.Exit(1)

    # Check config exists, bootstrap if needed
    config_dir = find_config_dir()
    if not config_dir:
        first_run = True
        config_dir = Path.home() / GLOBAL_DIR_NAME
        console.print("[bold]First run setup...[/bold]")
        _bootstrap_config(config_dir)
        console.print(f"  Created {config_dir}")

    # Check if already running
    if is_running():
        console.print("[yellow]SafeYolo is already running.[/yellow]")
        raise typer.Exit(0)

    config = load_config()
    proxy_port = config["proxy"]["port"]

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
    if first_run:
        console.print(
            Panel(
                f"[green]SafeYolo is running![/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}\n\n"
                f"Next:\n"
                f"  eval $(safeyolo cert env)   [dim]# CA trust + proxy vars[/dim]\n"
                f"  claude                      [dim]# Run your agent[/dim]\n\n"
                f"For enforced protection (autonomous agents):\n"
                f"  [bold]safeyolo sandbox setup[/bold]",
                title="Ready",
            )
        )
    else:
        console.print(
            Panel(
                f"[green]SafeYolo is running[/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}\n\n"
                f"  eval $(safeyolo cert env)   [dim]# CA trust + proxy vars[/dim]",
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
