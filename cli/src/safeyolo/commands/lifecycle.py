"""Container lifecycle commands: start, stop, status."""

import json
import os
import secrets
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..api import APIError, get_api
from ..config import (
    DEFAULT_CONFIG,
    find_config_dir,
    get_config_dir,
    load_config,
    save_config,
)
from ..discovery import (
    DiscoveryError,
    clear_services,
    regenerate_services,
    validate_services,
)
from ..docker import (
    DOCKER_BUILD_TIMEOUT_SECONDS,
    BuildError,
    DockerError,
    build_image,
    check_docker,
    copy_ca_cert_to_host,
    get_container_status,
    get_repo_root,
    image_exists,
    is_running,
    wait_for_healthy,
    write_compose_file,
)
from ..docker import (
    start as docker_start,
)
from ..docker import (
    stop as docker_stop,
)

console = Console()

# Default rules for common API providers
DEFAULT_RULES = {
    "credentials": [
        {
            "name": "openai",
            "pattern": "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
            "allowed_hosts": ["api.openai.com"],
        },
        {
            "name": "openai_project",
            "pattern": "sk-proj-[a-zA-Z0-9_-]{80,}",
            "allowed_hosts": ["api.openai.com"],
        },
        {
            "name": "anthropic",
            "pattern": "sk-ant-api[a-zA-Z0-9-]{90,}",
            "allowed_hosts": ["api.anthropic.com"],
        },
        {
            "name": "github",
            "pattern": "gh[ps]_[a-zA-Z0-9]{36}",
            "allowed_hosts": ["api.github.com", "github.com"],
        },
    ],
    "entropy_detection": {
        "enabled": True,
        "min_length": 20,
        "min_charset_diversity": 0.5,
        "min_shannon_entropy": 3.5,
    },
}


def _bootstrap_config(config_dir: Path) -> None:
    """Bootstrap config directory with sensible defaults."""
    # Create directories
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)

    # Generate admin token
    token = secrets.token_urlsafe(32)
    token_path = config_dir / "data" / "admin_token"
    token_path.write_text(token)
    token_path.chmod(0o600)

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    save_config(config)

    # Write rules.json
    rules_path = config_dir / "rules.json"
    rules_path.write_text(json.dumps(DEFAULT_RULES, indent=2))

    # Write docker-compose.yml
    write_compose_file(sandbox=False)


def start(
    build: bool = typer.Option(
        False,
        "--build", "-b",
        help="Rebuild image before starting",
    ),
    pull: bool = typer.Option(
        False,
        "--pull", "-p",
        help="Pull latest image before starting",
    ),
    wait: bool = typer.Option(
        True,
        "--wait/--no-wait",
        help="Wait for healthy status",
    ),
    headless: bool = typer.Option(
        False,
        "--headless",
        help="Run without TUI (mitmdump instead of mitmproxy)",
    ),
) -> None:
    """Start SafeYolo proxy container."""
    first_run = False

    # Set headless env var (passthrough to container via compose)
    if headless:
        os.environ["SAFEYOLO_HEADLESS"] = "true"

    # Check Docker first
    if not check_docker():
        console.print("[red]Docker is not available.[/red]")
        raise typer.Exit(1)

    # Check config exists, bootstrap if needed
    config_dir = find_config_dir()
    if not config_dir:
        first_run = True
        config_dir = get_config_dir()
        console.print("[bold]First run setup...[/bold]")
        _bootstrap_config(config_dir)
        console.print(f"  Created {config_dir}")

    # Check if already running
    if is_running():
        console.print("[yellow]SafeYolo is already running.[/yellow]")
        raise typer.Exit(0)

    config = load_config()
    proxy_port = config["proxy"]["port"]
    image_name = config["proxy"].get("image", "safeyolo:latest")

    console.print("[bold]Starting SafeYolo...[/bold]")

    # Force rebuild if requested
    if build:
        repo_root = get_repo_root()
        if repo_root:
            console.print(f"Building from {repo_root}...")
            try:
                build_image(tag=image_name)
            except BuildError as err:
                console.print(f"[red]Build failed:[/red] {err}")
                raise typer.Exit(1)
        else:
            console.print("[red]Cannot build: repo not found.[/red]")
            raise typer.Exit(1)

    # Check if image exists, show build message if auto-building
    if not build and not pull and not image_exists(image_name):
        console.print(f"[yellow]Image '{image_name}' not found locally.[/yellow]")
        repo_root = get_repo_root()
        if repo_root:
            console.print(f"Building from {repo_root}...")
        else:
            console.print("[red]Cannot auto-build: repo not found.[/red]")
            console.print("Either build manually or pull the image:")
            console.print("  docker pull safeyolo:latest")
            raise typer.Exit(1)

    try:
        docker_start(detach=True, pull=pull)
    except BuildError as err:
        console.print(f"[red]Build failed:[/red] {err}")
        raise typer.Exit(1)
    except DockerError as err:
        console.print(f"[red]Failed to start:[/red] {err}")
        raise typer.Exit(1)

    if wait:
        console.print("Waiting for healthy status...", end=" ")
        if wait_for_healthy(timeout=30):
            console.print("[green]ready![/green]")
            # Copy CA cert to host for diagnostic access
            if copy_ca_cert_to_host():
                console.print("  CA certificate copied to host")
        else:
            console.print("[yellow]timeout (may still be starting)[/yellow]")

    # Regenerate service mappings from actual Docker state
    try:
        path, count = regenerate_services()
        if count > 0:
            console.print(f"[green]Registered {count} service(s)[/green]")
    except DiscoveryError as err:
        console.print(f"[yellow]Warning: Could not update service mappings: {err}[/yellow]")

    # Show connection info
    if first_run:
        console.print(
            Panel(
                f"[green]SafeYolo is running![/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}\n\n"
                f"Next:\n"
                f"  eval $(safeyolo cert env)   [dim]# CA trust + proxy vars[/dim]\n"
                f"  claude                      [dim]# Run your agent[/dim]\n\n"
                f"For enforced protection (autonomous agents):\n"
                f"  [bold]safeyolo sandbox setup[/bold]",
                title="Ready",
            )
        )
    else:
        console.print(
            Panel(
                f"[green]SafeYolo is running[/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}\n\n"
                f"  eval $(safeyolo cert env)   [dim]# CA trust + proxy vars[/dim]",
                title="Started",
            )
        )


def stop() -> None:
    """Stop SafeYolo proxy container."""

    if not is_running():
        console.print("[yellow]SafeYolo is not running.[/yellow]")
        raise typer.Exit(0)

    console.print("[bold]Stopping SafeYolo...[/bold]")

    try:
        docker_stop()
        console.print("[green]Stopped.[/green]")

        # Mark service mappings as stale
        clear_services()

    except DockerError as e:
        console.print(f"[red]Failed to stop:[/red] {e}")
        raise typer.Exit(1)


def status() -> None:
    """Show SafeYolo status and statistics."""

    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[yellow]No SafeYolo configuration found.[/yellow]\n"
            "Run [bold]safeyolo init[/bold] to get started."
        )
        raise typer.Exit(1)

    config = load_config()

    # Container status
    container_status = get_container_status()

    if not container_status or container_status["status"] != "running":
        console.print(
            Panel(
                "[yellow]SafeYolo is not running[/yellow]\n\n"
                "Run [bold]safeyolo start[/bold] to start the proxy.",
                title="Status",
            )
        )
        raise typer.Exit(0)

    # Build status table
    table = Table(title="SafeYolo Status", show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Container", "[green]running[/green]")
    table.add_row("Health", container_status.get("health", "unknown"))
    table.add_row("Proxy Port", str(config["proxy"]["port"]))
    table.add_row("Admin Port", str(config["proxy"]["admin_port"]))

    # Try to get stats from API
    try:
        api = get_api()
        stats = api.stats()

        # Credential guard stats
        cg = stats.get("credential-guard", {})
        if cg:
            table.add_row("", "")  # Spacer
            table.add_row("Credentials Blocked", str(cg.get("violations_total", 0)))
            table.add_row("Rules Loaded", str(cg.get("rules_count", 0)))

        # Rate limiter stats
        rl = stats.get("rate-limiter", {})
        if rl:
            table.add_row("Rate Limited", str(rl.get("limited_total", 0)))

        # Pending approvals
        pending = api.pending_approvals()
        if pending:
            table.add_row("Pending Approvals", f"[yellow]{len(pending)}[/yellow]")

    except APIError:
        table.add_row("", "")
        table.add_row("API", "[yellow]unavailable[/yellow]")

    console.print(table)

    # Show modes
    try:
        api = get_api()
        modes = api.get_modes()

        mode_table = Table(title="Addon Modes", show_header=True)
        mode_table.add_column("Addon")
        mode_table.add_column("Mode")

        for addon, mode_info in modes.items():
            mode = mode_info.get("mode", "unknown")
            style = "red bold" if mode == "block" else "yellow"
            mode_table.add_row(addon, f"[{style}]{mode}[/{style}]")

        console.print()
        console.print(mode_table)

    except APIError:
        pass  # Already shown API unavailable above

    # Validate service mappings
    console.print()
    issues = validate_services()
    if not issues:
        console.print("[green]Service mappings: valid[/green]")
    else:
        console.print("[yellow]Service mapping issues:[/yellow]")
        for issue in issues:
            console.print(f"  - {issue}")
        console.print("\nRun [bold]safeyolo sync[/bold] to fix.")


def sync() -> None:
    """Regenerate service mappings from current Docker state.

    Use this after manual docker-compose operations or to verify
    the current mapping is accurate.

    Examples:

        safeyolo sync
    """
    if not is_running():
        console.print("[yellow]SafeYolo is not running.[/yellow]")
        console.print("Run [bold]safeyolo start[/bold] first.")
        raise typer.Exit(1)

    try:
        path, count = regenerate_services()
        console.print(f"[green]Synchronized {count} service(s)[/green]")
        console.print(f"  Written to: {path}")
    except DiscoveryError as err:
        console.print(f"[red]Failed to sync:[/red] {err}")
        raise typer.Exit(1)


def build(
    tag: str = typer.Option(
        "safeyolo:latest",
        "--tag", "-t",
        help="Image tag to build",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Build without using cache",
    ),
) -> None:
    """Build SafeYolo Docker image from source.

    Builds the image from the local repo checkout. Use this when developing
    SafeYolo or when you don't want to pull from a registry.

    Examples:

        safeyolo build
        safeyolo build --tag safeyolo:dev
        safeyolo build --no-cache
    """
    if not check_docker():
        console.print("[red]Docker is not available.[/red]")
        raise typer.Exit(1)

    repo_root = get_repo_root()
    if not repo_root:
        console.print("[red]Cannot find safeyolo repo root.[/red]")
        console.print(
            "The 'build' command requires a local repo checkout.\n"
            "If installed from PyPI, pull the image instead:\n"
            "  docker pull safeyolo:latest"
        )
        raise typer.Exit(1)

    console.print(f"[bold]Building {tag}...[/bold]")
    console.print(f"Context: {repo_root}")

    import subprocess

    args = ["docker", "build", "-t", tag, str(repo_root)]
    if no_cache:
        args.insert(2, "--no-cache")

    try:
        subprocess.run(args, check=True, timeout=DOCKER_BUILD_TIMEOUT_SECONDS)
        console.print(f"[green]Built {tag}[/green]")
    except subprocess.TimeoutExpired:
        console.print(
            f"[red]Build timed out after {DOCKER_BUILD_TIMEOUT_SECONDS}s[/red]\n"
            "Check network connectivity or try: docker build --no-cache"
        )
        raise typer.Exit(1)
    except subprocess.CalledProcessError as err:
        console.print(f"[red]Build failed with exit code {err.returncode}[/red]")
        raise typer.Exit(1)
