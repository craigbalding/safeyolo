"""Container lifecycle commands: start, stop, status."""

import datetime
import os
import secrets
import shutil
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

# Path to bundled baseline.yaml in package
BASELINE_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "baseline.yaml"


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

    # Copy baseline.yaml (policy file)
    baseline_path = config_dir / "baseline.yaml"
    if BASELINE_TEMPLATE_PATH.exists():
        shutil.copy(BASELINE_TEMPLATE_PATH, baseline_path)

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
    dev: bool = typer.Option(
        False,
        "--dev",
        help="Mount source code for live editing (requires repo checkout)",
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

    if dev:
        console.print("[bold]Dev mode:[/bold] addons/ and pdp/ mounted from repo")

    try:
        docker_start(detach=True, pull=pull, dev=dev)
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

    # Uptime from container start time
    started_at = container_status.get("started_at", "")
    if started_at:
        try:
            started = datetime.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            delta = datetime.datetime.now(datetime.UTC) - started
            total_seconds = int(delta.total_seconds())
            days, remainder = divmod(total_seconds, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes = remainder // 60
            if days > 0:
                uptime_str = f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                uptime_str = f"{hours}h {minutes}m"
            else:
                uptime_str = f"{minutes}m"
            table.add_row("Uptime", uptime_str)
        except (ValueError, TypeError):
            pass

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
        modes = api.get_modes().get("modes", {})

        mode_table = Table(title="Addon Modes", show_header=True)
        mode_table.add_column("Addon")
        mode_table.add_column("Mode")

        for addon, mode in modes.items():
            style = "red bold" if mode == "block" else "yellow"
            mode_table.add_row(addon, f"[{style}]{mode}[/{style}]")

        console.print()
        console.print(mode_table)

    except APIError:
        pass  # Already shown API unavailable above

    # Agents section
    try:
        api = get_api()
        stats = api.stats()
        sd = stats.get("service-discovery", {})
        agents = sd.get("agents", {})
        if agents:
            agent_table = Table(title="Agents", show_header=True)
            agent_table.add_column("Name", style="bold")
            agent_table.add_column("IP")
            agent_table.add_column("Last Seen")
            agent_table.add_column("Idle", justify="right")

            for name, info in sorted(agents.items()):
                ip = info.get("ip", "?")
                idle = info.get("idle_seconds")
                if idle is not None:
                    idle_int = int(idle)
                    if idle_int < 60:
                        idle_str = f"{idle_int}s"
                        style = "green"
                    elif idle_int < 300:
                        idle_str = f"{idle_int // 60}m {idle_int % 60}s"
                        style = "green"
                    elif idle_int < 3600:
                        idle_str = f"{idle_int // 60}m"
                        style = "yellow"
                    else:
                        idle_str = f"{idle_int // 3600}h {(idle_int % 3600) // 60}m"
                        style = "dim"
                else:
                    idle_str = "?"
                    style = "dim"

                last_seen_str = ""
                last_seen_ts = info.get("last_seen")
                if last_seen_ts:
                    try:
                        dt = datetime.datetime.fromtimestamp(last_seen_ts, tz=datetime.UTC)
                        last_seen_str = dt.strftime("%H:%M:%S")
                    except (ValueError, OSError):
                        last_seen_str = "?"

                agent_table.add_row(name, ip, last_seen_str, f"[{style}]{idle_str}[/{style}]")

            console.print()
            console.print(agent_table)

    except APIError:
        pass

    # Memory section
    try:
        api = get_api()
        stats = api.stats()
        mem = stats.get("memory-monitor", {})
        if mem:
            mem_table = Table(title="Memory", show_header=False)
            mem_table.add_column("Key", style="bold")
            mem_table.add_column("Value")

            rss = mem.get("rss_mb", 0)
            peak = mem.get("rss_hwm_mb", 0)
            start = mem.get("rss_start_mb", 0)

            rss_style = "green" if rss < 200 else "yellow" if rss < 400 else "red"
            mem_table.add_row(
                "RSS",
                f"[{rss_style}]{rss:.0f} MB[/{rss_style}] (started: {start:.0f} MB, peak: {peak:.0f} MB)",
            )
            mem_table.add_row("Total Flows", str(mem.get("total_flows", 0)))

            conns = mem.get("connections", [])
            if conns:
                mem_table.add_row("", "")
                mem_table.add_row("Active Connections", str(len(conns)))
                for conn in conns[:5]:
                    age_m = conn["age_s"] // 60
                    mem_table.add_row(
                        f"  {conn['domain']}",
                        f"{conn['flows']} flows, {age_m}m",
                    )

            ws = mem.get("websockets", [])
            if ws:
                mem_table.add_row("", "")
                mem_table.add_row("WebSocket Sessions", str(len(ws)))
                for session in ws:
                    mem_table.add_row(
                        f"  {session['domain']}",
                        f"{session['messages']} msgs, {session['age_s'] // 60}m",
                    )

            console.print()
            console.print(mem_table)

    except APIError:
        pass  # Already shown API unavailable above



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
