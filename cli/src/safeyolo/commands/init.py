"""Initialize SafeYolo configuration."""

import secrets
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from ..config import (
    DEFAULT_CONFIG,
    get_config_dir,
    get_logs_dir,
    save_config,
)
from ..docker import check_docker, write_compose_file

# Path to bundled templates in package
POLICY_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "policy.toml"
ADDONS_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "addons.yaml"

console = Console()


def _generate_admin_token(config_dir: Path) -> str:
    """Generate and save admin API token."""
    token = secrets.token_urlsafe(32)
    data_dir = config_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = data_dir / "admin_token"
    token_path.write_text(token)
    token_path.chmod(0o600)
    return token


def init(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration",
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--no-interactive",
        "-i",
        help="Run interactive setup wizard",
    ),
    try_mode: bool = typer.Option(
        False,
        "--try",
        help="Use Try Mode (bypassable) instead of Sandbox Mode",
    ),
) -> None:
    """Initialize SafeYolo configuration.

    Creates configuration files for the SafeYolo security proxy. By default,
    uses Sandbox Mode with network isolation where bypass attempts fail.

    Use --try for evaluation without network isolation (agents can bypass).

    Examples:

        safeyolo init                    # Sandbox Mode (secure default)
        safeyolo init --try              # Try Mode for evaluation
        safeyolo init --no-interactive   # Use defaults
    """
    # Sandbox is default, --try disables it
    sandbox = not try_mode

    # Fixed paths
    config_dir = get_config_dir()
    logs_dir = get_logs_dir()
    config_path = config_dir / "config.yaml"

    # Check for existing config
    if config_path.exists() and not force:
        console.print(f"[yellow]Configuration already exists at {config_dir}[/yellow]")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Check Docker availability
    docker_available = check_docker()
    if not docker_available:
        console.print(
            Panel(
                "[yellow]Docker is not available.[/yellow]\n\n"
                "SafeYolo requires Docker to run. Please install Docker:\n"
                "  macOS: https://docs.docker.com/desktop/mac/install/\n"
                "  Linux: https://docs.docker.com/engine/install/",
                title="Warning",
            )
        )
        if interactive:
            if not Confirm.ask("Continue anyway?", default=True):
                raise typer.Exit(1)

    console.print(f"\n[bold]Initializing SafeYolo in {config_dir}[/bold]\n")

    # Create directories
    config_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)

    # Generate admin token
    _generate_admin_token(config_dir)
    console.print("  [green]Created[/green] admin token")

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    config["sandbox"] = sandbox
    save_config(config)
    console.print(f"  [green]Created[/green] {config_path}")

    # Copy policy.toml (policy file)
    policy_path = config_dir / "policy.toml"
    if POLICY_TEMPLATE_PATH.exists():
        shutil.copy(POLICY_TEMPLATE_PATH, policy_path)
        console.print(f"  [green]Created[/green] {policy_path}")
    else:
        console.print(f"  [red]Warning[/red]: Could not find policy template at {POLICY_TEMPLATE_PATH}")
        console.print("    The proxy will fail to start without a policy file.")

    # Copy addons.yaml (addon configuration)
    addons_path = config_dir / "addons.yaml"
    if ADDONS_TEMPLATE_PATH.exists():
        shutil.copy(ADDONS_TEMPLATE_PATH, addons_path)
        console.print(f"  [green]Created[/green] {addons_path}")

    # Write docker-compose.yml
    compose_path = write_compose_file(sandbox=sandbox)
    console.print(f"  [green]Created[/green] {compose_path}")

    # Summary
    mode_label = "[bold green]Sandbox Mode[/bold green]" if sandbox else "Try Mode"

    if sandbox:
        next_steps = (
            "Next steps:\n"
            "  1. Run: [bold]safeyolo start[/bold]\n"
            "  2. Run: [bold]safeyolo agent add claude-code[/bold]\n"
            "  3. Run your agent from [bold]./safeyolo/agents/claude-code/[/bold]"
        )
    else:
        next_steps = (
            "Next steps:\n"
            "  1. Run: [bold]safeyolo start[/bold]\n"
            "  2. Configure your agent to use proxy at localhost:8080\n"
            "  3. Run: [bold]safeyolo watch[/bold] to handle approvals"
        )

    console.print(
        Panel(
            f"[green]SafeYolo initialized![/green]\n\n"
            f"Mode: {mode_label}\n"
            f"Configuration: {config_dir}\n"
            f"Policy: {policy_path}\n"
            f"Logs: {logs_dir}\n\n"
            f"{next_steps}",
            title="Success",
        )
    )
