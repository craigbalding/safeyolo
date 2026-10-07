"""SafeYolo CLI - Security proxy for AI coding agents."""

import os

import typer
from rich.console import Console

from . import __version__
from .commands.admin import check, mode, policies
from .commands.agent import agent_app
from .commands.bootstrap import bootstrap
from .commands.cert import cert_app
from .commands.command_centre import command_centre_app
from .commands.coord import coord_app
from .commands.demo import demo
from .commands.doctor import doctor
from .commands.init import init
from .commands.lab import lab
from .commands.lifecycle import build, start, status, stop
from .commands.logs import logs
from .commands.mount import mount_app
from .commands.policy import policy_app
from .commands.proxy import proxy_app
from .commands.services import services_app
from .commands.setup import setup_app
from .commands.tmux import tmux_app
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
        from .runtime_identity import load_stamped_build_identity

        build = load_stamped_build_identity()
        profile = (build.build_identifier or "unknown").rsplit("-", 1)[-1]
        if profile not in {"production", "debug"}:
            profile = "unknown"
        console.print(
            f"safeyolo version {build.package_version or __version__} "
            f"commit={build.source_revision or 'unknown'} profile={profile}",
            soft_wrap=True, markup=False,
        )
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
app.command()(lab)
app.command()(check)
app.command()(mode)
app.command()(policies)

# Register subcommand groups
app.add_typer(agent_app, name="agent")
app.add_typer(cert_app, name="cert")
app.add_typer(command_centre_app, name="command-centre")
app.add_typer(coord_app, name="coord")
app.add_typer(mount_app, name="mount")
app.add_typer(policy_app, name="policy")
app.add_typer(proxy_app, name="proxy")
app.add_typer(setup_app, name="setup")
app.add_typer(tmux_app, name="tmux")
app.add_typer(vault_app, name="vault")
app.add_typer(services_app, name="services")


if __name__ == "__main__":
    app()
