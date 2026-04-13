"""Sandbox Mode commands."""


import typer
from rich.console import Console
from rich.table import Table

from ..templates import get_available_templates

console = Console()

sandbox_app = typer.Typer(
    name="sandbox",
    help="Sandbox Mode - run agents in isolated microVMs.",
    no_args_is_help=True,
)


@sandbox_app.command(name="list")
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
    console.print("\nUse: [bold]safeyolo agent add <name> <template> <folder>[/bold]")
