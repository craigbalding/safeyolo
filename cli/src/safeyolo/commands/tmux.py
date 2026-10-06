"""Tmux integration - status bar setup and configuration."""

import os
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from .watch import STATUS_FILE, has_tmux, is_in_tmux

console = Console()


# Config snippet location (never touch user's .tmux.conf)
TMUX_CONFIG_DIR = Path.home() / ".config" / "tmux"
TMUX_SNIPPET_PATH = TMUX_CONFIG_DIR / "safeyolo.conf"
PANE_AGENT_OPTION = "@safeyolo-agent"
WINDOW_NAME_MARKER = "@safeyolo-window-name"

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


def associate_agent_pane(name: str) -> bool:
    """Associate the invoking tmux pane with an agent; no-op outside tmux."""
    pane = os.environ.get("TMUX_PANE")
    if not is_in_tmux() or not pane:
        return False
    try:
        tmux_cmd(["set-option", "-p", "-t", pane, PANE_AGENT_OPTION, name])
    except (OSError, subprocess.CalledProcessError) as exc:
        console.print(f"[yellow]Warning: could not associate tmux pane with agent {name}: {exc}[/yellow]")
        return False
    return True


def rename_window_for_agent(name: str) -> bool:
    """Rename the invoking pane's window to `name` when SafeYolo owns the name.

    Ownership rule (see issue #330):

    - local `automatic-rename` unset or `on` → rename.
    - local `automatic-rename=off` and current window name equals the
      `@safeyolo-window-name` marker → rename (SafeYolo already owns it).
    - local `automatic-rename=off` and name differs from the marker (or the
      marker is unset) → preserve; user or something else has claimed it.

    `rename-window` itself sets `automatic-rename=off`, so that flag alone
    cannot prove user ownership — hence the marker. Querying without `-g` and
    without `-A` means a user's global `set -g automatic-rename off` shows
    empty at window scope and is treated as safe.

    No-op outside tmux. Best-effort: any tmux command failure is warned and
    swallowed; agent launch is never blocked.
    """
    pane = os.environ.get("TMUX_PANE")
    if not is_in_tmux() or not pane:
        return False

    try:
        auto_rename = tmux_cmd(
            ["show-options", "-wqv", "-t", pane, "automatic-rename"],
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        console.print(
            f"[yellow]Warning: could not query tmux automatic-rename for pane {pane}: {exc}[/yellow]"
        )
        return False

    if auto_rename == "off":
        try:
            current_name = tmux_cmd(
                ["display-message", "-p", "-t", pane, "#{window_name}"],
            ).stdout.strip()
            marker = tmux_cmd(
                ["show-options", "-wqv", "-t", pane, WINDOW_NAME_MARKER],
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            console.print(
                f"[yellow]Warning: could not read tmux window ownership state for pane {pane}: {exc}[/yellow]"
            )
            return False
        if not marker or marker != current_name:
            return False

    try:
        tmux_cmd(["rename-window", "-t", pane, name])
    except (OSError, subprocess.CalledProcessError) as exc:
        console.print(
            f"[yellow]Warning: could not rename tmux window to {name}: {exc}[/yellow]"
        )
        return False

    try:
        tmux_cmd(["set-option", "-w", "-t", pane, WINDOW_NAME_MARKER, name])
    except (OSError, subprocess.CalledProcessError) as exc:
        # Non-fatal: leave the window renamed, skip the marker. The next
        # invocation will observe automatic-rename=off with no matching
        # marker and fall into the "preserve" branch — the safe fallback.
        console.print(
            f"[yellow]Warning: renamed window but could not record SafeYolo marker: {exc}[/yellow]"
        )
    return True



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
