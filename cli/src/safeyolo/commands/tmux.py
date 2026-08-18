"""Tmux integration - status bar setup and configuration."""

import os
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from ..api import APIError, get_api
from .watch import STATUS_FILE, has_tmux, is_in_tmux

console = Console()

# Config snippet location (never touch user's .tmux.conf)
TMUX_CONFIG_DIR = Path.home() / ".config" / "tmux"
TMUX_SNIPPET_PATH = TMUX_CONFIG_DIR / "safeyolo.conf"
TRAFFIC_WINDOW = "safeyolo-traffic"
PANE_AGENT_OPTION = "@safeyolo-agent"
ORIGIN_PANE_OPTION = "@safeyolo-traffic-origin"
TRAFFIC_WINDOW_OPTION = "@safeyolo-traffic-window"
TRAFFIC_KEY = "T"
RETURN_KEY = "R"

TMUX_CONFIG_SNIPPET = """\
# SafeYolo status bar integration
# Source this file: source-file ~/.config/tmux/safeyolo.conf
# Or add to .tmux.conf: source-file -q ~/.config/tmux/safeyolo.conf

set -g status-interval 2
set -g status-right "#(cat ~/.cache/safeyolo/tmux_status.txt 2>/dev/null || echo 'SY -') | %H:%M"

# Key binding: prefix + S to open SafeYolo watch popup
bind-key S display-popup -E "safeyolo watch"

# Optional shared traffic console adapter. Existing T/R bindings are preserved.
if-shell 'tmux list-keys -T prefix T >/dev/null 2>&1' 'display-message "SafeYolo: prefix + T already bound; traffic binding skipped"' 'bind-key T run-shell "safeyolo tmux traffic"'
if-shell 'tmux list-keys -T prefix R >/dev/null 2>&1' 'display-message "SafeYolo: prefix + R already bound; return binding skipped"' 'bind-key R run-shell "safeyolo tmux return-to-agent"'
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


def _pane_value(pane: str, option: str) -> str:
    result = tmux_cmd(["display-message", "-p", "-t", pane, f"#{{{option}}}"])
    return result.stdout.strip()


def _session_id(pane: str) -> str:
    result = tmux_cmd(["display-message", "-p", "-t", pane, "#{session_id}"])
    return result.stdout.strip()


def _traffic_window(session: str) -> tuple[str, bool] | None:
    result = tmux_cmd(
        [
            "list-windows",
            "-t",
            session,
            "-F",
            f"#{{window_id}}\t#{{window_name}}\t#{{pane_dead}}\t#{{{TRAFFIC_WINDOW_OPTION}}}",
        ],
    )
    for line in result.stdout.splitlines():
        window_id, separator, remainder = line.partition("\t")
        window_name, separator2, remainder = remainder.partition("\t")
        pane_dead, separator3, owned = remainder.partition("\t")
        if separator and separator2 and separator3 and window_name == TRAFFIC_WINDOW and owned == "1":
            return window_id, pane_dead == "1"
    return None


def _require_tmux_pane() -> str:
    pane = os.environ.get("TMUX_PANE")
    if not is_in_tmux() or not pane:
        console.print("[red]This command must be run from a tmux pane.[/red]")
        raise typer.Exit(1)
    return pane


@tmux_app.command(name="traffic", hidden=True)
def traffic_window() -> None:
    """Scope and open the shared traffic window for the invoking agent pane."""
    pane = _require_tmux_pane()
    agent = _pane_value(pane, PANE_AGENT_OPTION)
    if not agent:
        console.print(
            "[yellow]This pane is not associated with a SafeYolo agent.[/yellow]\n"
            "Launch one here with: safeyolo agent run NAME"
        )
        raise typer.Exit(1)

    try:
        get_api().set_traffic_scope(
            agent=agent,
            unattributed=False,
            test_id=None,
            intent=None,
            role=None,
            expect=None,
        )
    except APIError as exc:
        console.print(f"[red]Cannot update traffic scope:[/red] {exc}")
        raise typer.Exit(1) from exc

    session = _session_id(pane)
    tmux_cmd(["set-option", "-t", session, ORIGIN_PANE_OPTION, pane])
    existing = _traffic_window(session)
    attach_command = "env -u TMUX safeyolo traffic"
    if existing is None:
        result = tmux_cmd(
            [
                "new-window",
                "-d",
                "-P",
                "-F",
                "#{window_id}",
                "-t",
                session,
                "-n",
                TRAFFIC_WINDOW,
                attach_command,
            ]
        )
        window_id = result.stdout.strip()
        tmux_cmd(["set-window-option", "-t", window_id, TRAFFIC_WINDOW_OPTION, "1"])
    else:
        window_id, pane_dead = existing
        if pane_dead:
            tmux_cmd(["respawn-pane", "-k", "-t", window_id, attach_command])
    tmux_cmd(["select-window", "-t", window_id])


@tmux_app.command(name="return-to-agent", hidden=True)
def return_to_agent() -> None:
    """Return from the shared traffic window to its most recent source pane."""
    pane = _require_tmux_pane()
    session = _session_id(pane)
    result = tmux_cmd(["show-option", "-qv", "-t", session, ORIGIN_PANE_OPTION])
    origin = result.stdout.strip()
    if not origin:
        console.print("[yellow]No originating SafeYolo agent pane is recorded.[/yellow]")
        raise typer.Exit(1)
    tmux_cmd(["select-window", "-t", origin])
    tmux_cmd(["select-pane", "-t", origin])


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

        for key, command_name in (
            (TRAFFIC_KEY, "traffic"),
            (RETURN_KEY, "return-to-agent"),
        ):
            existing = tmux_cmd(["list-keys", "-T", "prefix", key], check=False)
            if existing.returncode == 0:
                console.print(
                    f"[yellow]Kept existing prefix + {key} binding; SafeYolo binding skipped.[/yellow]"
                )
                continue
            tmux_cmd(["bind-key", key, "run-shell", f"safeyolo tmux {command_name}"])

        console.print("[green]Configured tmux session[/green]")
        console.print()
        console.print("Status bar will show SafeYolo status on the right.")
        console.print("Press [bold]prefix + S[/bold] to open the watch panel.")
        console.print("Press [bold]prefix + T[/bold] for traffic scoped to this pane's agent.")
        console.print("Press [bold]prefix + R[/bold] to return to the originating agent pane.")
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
