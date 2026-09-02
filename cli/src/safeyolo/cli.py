"""SafeYolo CLI - Security proxy for AI coding agents."""

import os

import typer
from rich.console import Console

from . import __version__
from .commands.admin import check, mode, policies
from .commands.agent import agent_app
from .commands.bootstrap import bootstrap
from .commands.cert import cert_app
from .commands.coord import coord_app
from .commands.demo import demo
from .commands.doctor import doctor
from .commands.factory import factory_app
from .commands.init import init
from .commands.lifecycle import build, start, status, stop
from .commands.logs import logs
from .commands.mount import mount_app
from .commands.policy import policy_app
from .commands.proxy import proxy_app
from .commands.services import services_app
from .commands.setup import setup_app
from .commands.test_context import test_context
from .commands.tmux import tmux_app
from .commands.traffic import traffic
from .commands.vault import vault_app
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
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    """SafeYolo - Security proxy for AI coding agents.

    Protects your API keys when using AI coding assistants like Claude Code.
    """
    # Refuse to run as root unless explicitly allowed
    if os.getuid() == 0 and not os.environ.get("SAFEYOLO_ALLOW_ROOT"):
        console.print("[red]Refusing to run as root.[/red]")
        console.print("Running as root causes permission issues with mounted volumes.")
        console.print("Set SAFEYOLO_ALLOW_ROOT=1 to override.")
        raise typer.Exit(1)


# Register commands
app.command()(bootstrap)
app.command()(doctor)
app.command()(init)
app.command()(start)
app.command()(stop)
app.command()(status)
app.command()(build)
app.command()(logs)
app.command()(watch)
app.command()(demo)
app.command()(check)
app.command()(mode)
app.command()(policies)
app.command(name="test-context")(test_context)
app.command()(traffic)

# Register subcommand groups
app.add_typer(agent_app, name="agent")
app.add_typer(cert_app, name="cert")
app.add_typer(coord_app, name="coord")
app.add_typer(factory_app, name="factory")
app.add_typer(mount_app, name="mount")
app.add_typer(policy_app, name="policy")
app.add_typer(proxy_app, name="proxy")
app.add_typer(setup_app, name="setup")
app.add_typer(tmux_app, name="tmux")
app.add_typer(vault_app, name="vault")
app.add_typer(services_app, name="services")


# Convenience aliases
@app.command(name="up")
def up_alias(
    wait: bool = typer.Option(True, "--wait/--no-wait"),
    profile: bool = typer.Option(False, "--profile", help="Profile lifecycle phases"),
):
    """Alias for 'start'."""
    start(wait=wait, profile=profile)


@app.command(name="down")
def down_alias(
    all: bool = typer.Option(False, "--all", help="Also stop all agents and tear down networking"),
    profile: bool = typer.Option(False, "--profile", help="Profile lifecycle phases"),
):
    """Alias for 'stop'."""
    stop(all=all, profile=profile)


if __name__ == "__main__":
    app()
