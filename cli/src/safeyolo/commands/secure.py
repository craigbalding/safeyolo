"""Secure Mode commands."""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import find_config_dir
from ..docker import is_running, start as docker_start, wait_for_healthy
from ..templates import TemplateError, get_available_templates, render_template

console = Console()

secure_app = typer.Typer(
    name="secure",
    help="Secure Mode - run agents in isolated containers.",
    no_args_is_help=True,
)


@secure_app.command()
def setup(
    template: str = typer.Option(
        "claude-code",
        "--template", "-t",
        help="Agent template to use",
    ),
    output: Path = typer.Option(
        None,
        "--output", "-o",
        help="Output directory (default: ./<template-name>)",
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Overwrite existing files",
    ),
) -> None:
    """Generate an agent container template for Secure Mode.

    Creates a docker-compose.yml configured to route all traffic through
    SafeYolo. The agent runs in an isolated container with no direct
    internet access - bypass attempts fail rather than leak credentials.

    Examples:

        safeyolo secure setup                    # Uses claude-code template
        safeyolo secure setup -t openai-codex   # Uses Codex template
        safeyolo secure setup -o ~/my-agent     # Custom output directory
    """
    # Determine output directory
    if output:
        output_dir = output
    else:
        output_dir = Path.cwd() / template

    # Check if exists
    if output_dir.exists() and not force:
        console.print(f"[yellow]Directory already exists: {output_dir}[/yellow]")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Ensure SafeYolo is configured (but doesn't need to be running)
    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[yellow]SafeYolo not configured yet.[/yellow]\n"
            "Run [bold]safeyolo start[/bold] first to set up."
        )
        raise typer.Exit(1)

    # Render template
    try:
        files = render_template(
            template_name=template,
            output_dir=output_dir,
            project_dir=str(Path.cwd()),
        )
    except TemplateError as err:
        console.print(f"[red]Template error:[/red] {err}")
        raise typer.Exit(1)

    # Show created files
    for filepath in files:
        console.print(f"  [green]Created[/green] {filepath}")

    # Show next steps
    console.print(
        Panel(
            f"[green]Agent template created![/green]\n\n"
            f"Directory: {output_dir}\n\n"
            f"Next:\n"
            f"  cd {output_dir.name}\n"
            f"  docker compose run --rm {template.replace('-', '')}",
            title="Ready",
        )
    )


@secure_app.command(name="list")
def list_templates() -> None:
    """List available agent templates."""
    templates = get_available_templates()

    if not templates:
        console.print("[yellow]No templates available.[/yellow]")
        return

    table = Table(title="Available Templates")
    table.add_column("Name", style="bold")
    table.add_column("Description")

    for name, description in templates.items():
        table.add_row(name, description)

    console.print(table)
    console.print("\nUse: [bold]safeyolo secure setup -t <name>[/bold]")
