"""Initialize SafeYolo configuration."""

import secrets
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from ..config import (
    DEFAULT_CONFIG,
    get_config_dir,
    get_logs_dir,
    save_config,
)
from ..vm import check_guest_images

# Path to bundled templates in package
POLICY_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "policy.toml"
ADDONS_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "addons.yaml"
LISTS_TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "lists"

console = Console()


def _generate_admin_token(config_dir: Path) -> str:
    """Generate and save admin API token."""
    token = secrets.token_urlsafe(32)
    data_dir = config_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = data_dir / "admin_token"
    token_path.write_text(token)
    token_path.chmod(0o600)
    return token


def init(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration",
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--no-interactive",
        "-i",
        help="Run interactive setup wizard",
    ),
) -> None:
    """Initialize SafeYolo configuration.

    Creates configuration files for the SafeYolo security proxy. Agents run
    in isolated Linux sandboxes with structural egress control: the only path
    out is through SafeYolo's mitmproxy.

    Examples:

        safeyolo init
        safeyolo init --no-interactive   # Use defaults
        safeyolo init --force            # Overwrite existing configuration
    """
    # Fixed paths
    config_dir = get_config_dir()
    logs_dir = get_logs_dir()
    config_path = config_dir / "config.yaml"

    # Check for existing config
    if config_path.exists() and not force:
        console.print(f"[yellow]Configuration already exists at {config_dir}[/yellow]")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Check guest images
    if not check_guest_images():
        console.print(
            Panel(
                "[yellow]Guest VM images not found.[/yellow]\n\n"
                "Build them with:\n"
                "  cd guest && ./build-all.sh\n"
                "  mkdir -p ~/.safeyolo/share && cp guest/out/* ~/.safeyolo/share/",
                title="Note",
            )
        )

    console.print(f"\n[bold]Initializing SafeYolo in {config_dir}[/bold]\n")

    # Create directories
    config_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)

    # Generate admin token
    _generate_admin_token(config_dir)
    console.print("  [green]Created[/green] admin token")

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    save_config(config)
    console.print(f"  [green]Created[/green] {config_path}")

    # Copy policy.toml (policy file)
    policy_path = config_dir / "policy.toml"
    if POLICY_TEMPLATE_PATH.exists():
        shutil.copy(POLICY_TEMPLATE_PATH, policy_path)
        console.print(f"  [green]Created[/green] {policy_path}")
    else:
        console.print(f"  [red]Warning[/red]: Could not find policy template at {POLICY_TEMPLATE_PATH}")
        console.print("    The proxy will fail to start without a policy file.")

    # Copy addons.yaml (addon configuration)
    addons_path = config_dir / "addons.yaml"
    if ADDONS_TEMPLATE_PATH.exists():
        shutil.copy(ADDONS_TEMPLATE_PATH, addons_path)
        console.print(f"  [green]Created[/green] {addons_path}")

    # Copy lists/ directory (named list files for policy)
    lists_dir = config_dir / "lists"
    if LISTS_TEMPLATE_DIR.is_dir():
        shutil.copytree(LISTS_TEMPLATE_DIR, lists_dir, dirs_exist_ok=True)
        console.print(f"  [green]Created[/green] {lists_dir}/")

    # Create VM-related directories
    (config_dir / "share").mkdir(exist_ok=True)
    (config_dir / "bin").mkdir(exist_ok=True)
    console.print(f"  [green]Created[/green] {config_dir}/share/ and bin/")

    # Summary — `safeyolo setup` between init and start is what applies the
    # one-time host prerequisites (Linux: AppArmor profile, /dev/kvm udev rule)
    # and is idempotent on macOS. Skipping it leaves the agent-run path liable
    # to fail later with a kernel-level "operation not permitted".
    next_steps = (
        "Next steps:\n"
        "  1. Run: [bold]safeyolo setup[/bold]  [dim](one-time host prerequisites)[/dim]\n"
        "  2. Run: [bold]safeyolo start[/bold]\n"
        "  3. Run: [bold]safeyolo agent add <name> <folder> --host-script contrib/claude-host-setup.sh[/bold]\n"
        "  4. See [bold]contrib/HOST_SCRIPT_GUIDE.md[/bold] to adapt for other agents"
    )

    console.print(
        Panel(
            f"[green]SafeYolo initialized![/green]\n\n"
            f"Configuration: {config_dir}\n"
            f"Policy: {policy_path}\n"
            f"Logs: {logs_dir}\n\n"
            f"{next_steps}",
            title="Success",
        )
    )
