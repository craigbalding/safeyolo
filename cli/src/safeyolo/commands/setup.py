"""Setup commands for SafeYolo system integration."""

import grp
import os
import subprocess

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()

setup_app = typer.Typer(
    name="setup",
    help="System integration setup commands.",
    no_args_is_help=True,
)


def check_docker_access() -> tuple[bool, str]:
    """Check if current user has Docker access.

    Returns:
        (has_access, reason)
    """
    # Check if user is in docker group
    try:
        docker_gid = grp.getgrnam("docker").gr_gid
        user_groups = os.getgroups()
        in_docker_group = docker_gid in user_groups
    except KeyError:
        in_docker_group = False

    # Try running docker info to confirm access
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        docker_works = result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        docker_works = False

    if docker_works:
        if in_docker_group:
            return True, "User is in docker group"
        else:
            return True, "Docker accessible (possibly via sudo or rootless)"
    else:
        if in_docker_group:
            return False, "In docker group but docker not responding"
        else:
            return False, "Not in docker group"


@setup_app.command()
def check() -> None:
    """Check system prerequisites for SafeYolo.

    Verifies Docker access and provides guidance if issues are found.

    Examples:

        safeyolo setup check
    """
    console.print("[bold]SafeYolo System Check[/bold]\n")

    # Check Docker access
    has_access, reason = check_docker_access()

    if has_access:
        console.print(f"[green]✓[/green] Docker access: {reason}")
    else:
        console.print(f"[red]✗[/red] Docker access: {reason}")
        console.print(
            Panel(
                "[bold]To add yourself to the docker group:[/bold]\n\n"
                "  sudo usermod -aG docker $USER\n"
                "  newgrp docker  # or log out and back in\n\n"
                "[dim]This allows SafeYolo to manage agent containers.[/dim]",
                title="Docker Group Setup",
                border_style="yellow",
            )
        )
        raise typer.Exit(1)

    # Check if safeyolo network exists
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", "safeyolo-internal"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            console.print("[green]✓[/green] SafeYolo network exists")
        else:
            console.print("[yellow]○[/yellow] SafeYolo network not created yet (will be created on start)")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        console.print("[yellow]○[/yellow] Could not check network status")

    console.print("\n[green]All checks passed![/green]")
