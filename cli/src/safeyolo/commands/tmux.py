"""Tmux integration - status bar setup and configuration."""

import subprocess
from pathlib import Path

import typer
from rich.console import Console

from .watch import STATUS_FILE, has_tmux, is_in_tmux

console = Console()

# Config snippet location (never touch user's .tmux.conf)
TMUX_CONFIG_DIR = Path.home() / ".config" / "tmux"
TMUX_SNIPPET_PATH = TMUX_CONFIG_DIR / "safeyolo.conf"

TMUX_CONFIG_SNIPPET = """\
# SafeYolo status bar integration
# Source this file: source-file ~/.config/tmux/safeyolo.conf
# Or add to .tmux.conf: source-file -q ~/.config/tmux/safeyolo.conf

set -g status-interval 2
set -g status-right "#(cat ~/.cache/safeyolo/tmux_status.txt 2>/dev/null || echo 'SY -') | %H:%M"

# Key binding: prefix + S to open SafeYolo watch popup
bind-key S display-popup -E "safeyolo watch"
"""

# Create the tmux subcommand app
tmux_app = typer.Typer(
    name="tmux",
    help="Tmux status bar integration.",
    no_args_is_help=True,
)


def tmux_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a tmux command."""
    return subprocess.run(["tmux"] + args, capture_output=True, text=True, check=check)


@tmux_app.command()
def setup():
    """Configure current tmux session for SafeYolo status.

    This directly configures the running tmux session without modifying
    any config files. Changes last until tmux server restarts.

    For persistent config, use 'safeyolo tmux config' and source the snippet.
    """
    if not has_tmux():
        console.print("[red]Error:[/red] tmux command not found")
        raise typer.Exit(1)

    if not is_in_tmux():
        console.print("[yellow]Warning:[/yellow] Not running inside tmux")
        console.print("[dim]Configuration will apply to the tmux server if running.[/dim]")

    try:
        # Set status interval
        tmux_cmd(["set-option", "-g", "status-interval", "2"])

        # Set status-right to read our status file
        status_right = f"#(cat {STATUS_FILE} 2>/dev/null || echo 'SY -') | %H:%M"
        tmux_cmd(["set-option", "-g", "status-right", status_right])

        # Bind S key to open watch popup
        tmux_cmd(["bind-key", "S", "display-popup", "-E", "safeyolo watch"])

        console.print("[green]Configured tmux session[/green]")
        console.print()
        console.print("Status bar will show SafeYolo status on the right.")
        console.print("Press [bold]prefix + S[/bold] to open the watch panel.")
        console.print()
        console.print("[dim]Start the status daemon with:[/dim]")
        console.print("  safeyolo watch --tmux &")

    except subprocess.CalledProcessError as err:
        console.print(f"[red]Error configuring tmux:[/red] {err.stderr}")
        raise typer.Exit(1)


@tmux_app.command()
def config(
    write: bool = typer.Option(False, "--write", "-w", help="Write config to ~/.config/tmux/safeyolo.conf"),
):
    """Output tmux config snippet.

    Prints the tmux configuration snippet that enables SafeYolo status.
    Use --write to save it to ~/.config/tmux/safeyolo.conf

    To use: add 'source-file -q ~/.config/tmux/safeyolo.conf' to your .tmux.conf
    """
    if write:
        TMUX_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        TMUX_SNIPPET_PATH.write_text(TMUX_CONFIG_SNIPPET)
        console.print(f"[green]Wrote config to:[/green] {TMUX_SNIPPET_PATH}")
        console.print()
        console.print("Add this line to your .tmux.conf:")
        console.print(f"  [cyan]source-file -q {TMUX_SNIPPET_PATH}[/cyan]")
        console.print()
        console.print("Or apply now with:")
        console.print(f"  [cyan]tmux source-file {TMUX_SNIPPET_PATH}[/cyan]")
    else:
        console.print(TMUX_CONFIG_SNIPPET)
        console.print()
        console.print("[dim]Use --write to save to ~/.config/tmux/safeyolo.conf[/dim]")


@tmux_app.command()
def status():
    """Show current SafeYolo status line.

    Reads and displays the current status from the status file.
    Useful for testing without tmux.
    """
    if STATUS_FILE.exists():
        content = STATUS_FILE.read_text().strip()
        console.print(f"Status: [bold]{content}[/bold]")
        console.print(f"[dim]File: {STATUS_FILE}[/dim]")
    else:
        console.print("[yellow]No status file found[/yellow]")
        console.print()
        console.print("Start the status daemon with:")
        console.print("  safeyolo watch --tmux &")
