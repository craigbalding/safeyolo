"""SafeYolo CLI - Security proxy for AI coding agents."""

import typer
from rich.console import Console

from . import __version__
from .commands.admin import check, mode, policies, test
from .commands.cert import cert_app
from .commands.init import init
from .commands.lifecycle import start, status, stop
from .commands.logs import logs
from .commands.watch import watch

console = Console()

# Create main app
app = typer.Typer(
    name="safeyolo",
    help="Security proxy CLI for AI coding agents.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool):
    if value:
        console.print(f"safeyolo version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version", "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    """SafeYolo - Security proxy for AI coding agents.

    Protects your API keys when using AI coding assistants like Claude Code.
    """
    pass


# Register commands
app.command()(init)
app.command()(start)
app.command()(stop)
app.command()(status)
app.command()(logs)
app.command()(watch)
app.command()(check)
app.command()(mode)
app.command()(policies)
app.command()(test)

# Register subcommand groups
app.add_typer(cert_app, name="cert")


# Convenience aliases
@app.command(name="up")
def up_alias(
    pull: bool = typer.Option(False, "--pull", "-p"),
    wait: bool = typer.Option(True, "--wait/--no-wait"),
):
    """Alias for 'start'."""
    start(pull=pull, wait=wait)


@app.command(name="down")
def down_alias():
    """Alias for 'stop'."""
    stop()


if __name__ == "__main__":
    app()
