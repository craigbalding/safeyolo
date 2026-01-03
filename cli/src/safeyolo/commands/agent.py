"""Agent management commands."""

import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import find_config_dir, get_agents_dir, load_config
from ..docker import is_running, start as docker_start, wait_for_healthy
from ..templates import TemplateError, get_available_templates, render_template

console = Console()

agent_app = typer.Typer(
    name="agent",
    help="Manage AI agent containers for Secure Mode.",
    no_args_is_help=True,
)


@agent_app.command()
def add(
    template: str = typer.Argument(
        ...,
        help="Agent template name (e.g., claude-code)",
    ),
    project: str = typer.Option(
        None,
        "--project", "-p",
        help="Project directory to mount (default: current directory)",
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Overwrite existing agent configuration",
    ),
) -> None:
    """Add an AI agent container configuration.

    Creates a docker-compose.yml for the specified agent template,
    configured to route all traffic through SafeYolo.

    Examples:

        safeyolo agent add claude-code
        safeyolo agent add claude-code --project /path/to/myproject
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[red]No SafeYolo configuration found.[/red]\n"
            "Run [bold]safeyolo init --secure[/bold] first."
        )
        raise typer.Exit(1)

    config = load_config()
    if not config.get("secure"):
        console.print(
            "[yellow]Warning: SafeYolo is not in Secure Mode.[/yellow]\n"
            "Agent containers may be able to bypass the proxy.\n"
            "Run [bold]safeyolo init --secure[/bold] to enable network isolation.\n"
        )

    # Create agent directory
    agent_dir = get_agents_dir() / template
    if agent_dir.exists() and not force:
        console.print(f"[yellow]Agent already exists: {agent_dir}[/yellow]")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Determine project directory
    project_dir = project if project else str(Path.cwd())

    # Render template
    try:
        files = render_template(
            template_name=template,
            output_dir=agent_dir,
            project_dir=project_dir,
        )
    except TemplateError as err:
        console.print(f"[red]Template error:[/red] {err}")
        raise typer.Exit(1)

    # Show created files
    for filepath in files:
        console.print(f"  [green]Created[/green] {filepath}")

    console.print(
        Panel(
            f"[green]Agent '{template}' added![/green]\n\n"
            f"Directory: {agent_dir}\n\n"
            f"Next steps:\n"
            f"  1. Copy [bold].env.example[/bold] to [bold].env[/bold]\n"
            f"  2. Add your API key to [bold].env[/bold]\n"
            f"  3. Run: [bold]safeyolo agent run {template}[/bold]",
            title="Success",
        )
    )


@agent_app.command(name="list")
def list_templates() -> None:
    """List available agent templates."""
    templates = get_available_templates()

    if not templates:
        console.print("[yellow]No templates available.[/yellow]")
        return

    table = Table(title="Available Agent Templates")
    table.add_column("Name", style="bold")
    table.add_column("Description")

    for name, description in templates.items():
        table.add_row(name, description)

    console.print(table)


@agent_app.command()
def remove(
    name: str = typer.Argument(..., help="Agent name to remove"),
) -> None:
    """Remove an agent configuration.

    Deletes the agent's compose file and configuration directory.
    Does NOT remove any running containers or images.

    Examples:

        safeyolo agent remove claude-code
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agent_dir = get_agents_dir() / name
    if not agent_dir.exists():
        console.print(f"[yellow]Agent not found: {name}[/yellow]")
        raise typer.Exit(1)

    shutil.rmtree(agent_dir)
    console.print(f"[green]Removed agent: {name}[/green]")


@agent_app.command()
def run(
    name: str = typer.Argument(..., help="Agent name to run"),
) -> None:
    """Run an agent container interactively.

    Starts SafeYolo if not running, then launches the agent container.

    Examples:

        safeyolo agent run claude-code
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agent_dir = get_agents_dir() / name
    compose_file = agent_dir / "docker-compose.yml"

    if not compose_file.exists():
        console.print(f"[red]Agent not found: {name}[/red]")
        console.print(f"Run [bold]safeyolo agent add {name}[/bold] first.")
        raise typer.Exit(1)

    # Check .env file exists
    env_file = agent_dir / ".env"
    if not env_file.exists():
        console.print(
            f"[yellow]Warning: No .env file found.[/yellow]\n"
            f"Copy [bold]{agent_dir}/.env.example[/bold] to [bold].env[/bold] "
            f"and add your API key.\n"
        )

    # Check SafeYolo is running
    if not is_running():
        console.print("[yellow]SafeYolo is not running. Starting...[/yellow]")
        try:
            docker_start()
            if not wait_for_healthy(timeout=30):
                console.print("[red]SafeYolo failed to start.[/red]")
                raise typer.Exit(1)
            console.print("[green]SafeYolo started.[/green]\n")
        except Exception as err:
            console.print(f"[red]Failed to start SafeYolo:[/red] {err}")
            raise typer.Exit(1)

    # Run the agent container
    console.print(f"Starting {name}...\n")

    # Use subprocess.run with inherited stdin/stdout for interactive use
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "run", "--rm", name.replace("-", "")],
        cwd=agent_dir,
    )

    raise typer.Exit(result.returncode)
