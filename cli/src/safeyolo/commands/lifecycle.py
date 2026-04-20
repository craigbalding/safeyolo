"""Proxy lifecycle commands: start, stop, status, build."""

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
from ..proxy import (
    is_proxy_running,
    start_proxy,
    stop_proxy,
    wait_for_healthy,
)
from ..vm import check_guest_images, guest_image_status

console = Console()

# Path to bundled templates in package
POLICY_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "policy.toml"
ADDONS_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "addons.yaml"


def _bootstrap_config(config_dir: Path) -> None:
    """Bootstrap config directory with sensible defaults."""
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)
    (config_dir / "share").mkdir(exist_ok=True)
    (config_dir / "bin").mkdir(exist_ok=True)

    # Generate admin token
    token = secrets.token_urlsafe(32)
    token_path = config_dir / "data" / "admin_token"
    token_path.write_text(token)
    token_path.chmod(0o600)

    # Create agent token placeholder
    agent_token_path = config_dir / "data" / "agent_token"
    agent_token_path.touch()
    agent_token_path.chmod(0o600)

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    save_config(config)

    # Copy policy.toml
    policy_path = config_dir / "policy.toml"
    if POLICY_TEMPLATE_PATH.exists():
        shutil.copy(POLICY_TEMPLATE_PATH, policy_path)

    # Copy addons.yaml
    addons_path = config_dir / "addons.yaml"
    if ADDONS_TEMPLATE_PATH.exists():
        shutil.copy(ADDONS_TEMPLATE_PATH, addons_path)


def start(
    wait: bool = typer.Option(
        True,
        "--wait/--no-wait",
        help="Wait for healthy status",
    ),
    dev: bool = typer.Option(
        False,
        "--dev",
        help="Mount source code and auto-restart on changes (requires repo checkout)",
    ),
    test: bool = typer.Option(
        False,
        "--test",
        help="Enable test mode (sinkhole routing, test CA -- reads test section from config.yaml)",
    ),
) -> None:
    """Start SafeYolo proxy and firewall."""
    first_run = False

    # Check config exists, bootstrap if needed
    config_dir = find_config_dir()
    if not config_dir:
        first_run = True
        config_dir = get_config_dir()
        console.print("[bold]First run setup...[/bold]")
        _bootstrap_config(config_dir)
        console.print(f"  Created {config_dir}")

    # Check if already running
    if is_proxy_running():
        console.print("[yellow]SafeYolo proxy is already running.[/yellow]")
        raise typer.Exit(0)

    # Check guest images
    if not check_guest_images():
        status = guest_image_status()
        missing = [k for k, v in status.items() if not v]
        console.print(f"[yellow]Guest images missing: {', '.join(missing)}[/yellow]")
        console.print("Build them first: [bold]cd guest && ./build-all.sh[/bold]")
        console.print("Then install: [bold]mkdir -p ~/.safeyolo/share && cp guest/out/* ~/.safeyolo/share/[/bold]")

    config = load_config()
    proxy_port = config["proxy"]["port"]
    admin_port = config["proxy"]["admin_port"]

    # Enable test mode if --test flag passed
    if test:
        test_cfg = config.get("test", {})
        if not test_cfg.get("sinkhole_router"):
            console.print("[red]--test requires test.sinkhole_router in config.yaml[/red]")
            console.print("  Add to ~/.safeyolo/config.yaml:")
            console.print("    test:")
            console.print("      enabled: true")
            console.print("      sinkhole_router: /path/to/sinkhole_router.py")
            console.print("      ca_cert: /path/to/test-ca.crt")
            raise typer.Exit(1)
        config["test"]["enabled"] = True
        save_config(config)
        console.print("[bold]Starting SafeYolo (test mode)...[/bold]")
    else:
        # Ensure test mode is off
        if config.get("test", {}).get("enabled"):
            config["test"]["enabled"] = False
            save_config(config)
        console.print("[bold]Starting SafeYolo...[/bold]")

    # Start host mitmproxy
    try:
        start_proxy(proxy_port=proxy_port, admin_port=admin_port)
    except Exception as err:
        console.print(f"[red]Failed to start proxy:[/red] {err}")
        raise typer.Exit(1)

    # No per-agent firewall setup -- egress isolation is structural (sandbox
    # has no external interface). The bridge daemon and per-agent UDS
    # listeners are the moving parts; they come up with the proxy itself.

    if wait:
        console.print("Waiting for healthy status...", end=" ")
        if wait_for_healthy(timeout=30, admin_port=admin_port):
            console.print("[green]ready![/green]")
        else:
            console.print("[yellow]timeout (may still be starting)[/yellow]")

    # Show connection info
    if first_run:
        console.print(
            Panel(
                f"[green]SafeYolo is running![/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}\n\n"
                f"Next:\n"
                f"  safeyolo agent add myproject . --host-script contrib/claude-host-setup.sh   [dim]# Add and run an agent[/dim]\n",
                title="Ready",
            )
        )
    else:
        console.print(
            Panel(
                f"[green]SafeYolo is running[/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}",
                title="Started",
            )
        )


def stop(
    all: bool = typer.Option(False, "--all", help="Also stop all agents and tear down networking"),
) -> None:
    """Stop SafeYolo proxy. Agents keep running unless --all is passed."""

    if all:
        stop_all()
        return

    if not is_proxy_running():
        console.print("[yellow]SafeYolo proxy is not running.[/yellow]")
        raise typer.Exit(0)

    console.print("[bold]Stopping SafeYolo...[/bold]")

    # Stop proxy only -- agents and bridge sockets stay intact. Agents get
    # "connection refused" on the proxy port but remain alive and accessible
    # via SSH. When the proxy restarts, connectivity resumes.
    stop_proxy()
    console.print("[green]Stopped.[/green]")

    # Hint if agents are still running
    from ..config import get_agents_dir
    from ..platform import get_platform
    plat = get_platform()
    agents_dir = get_agents_dir()
    running = []
    if agents_dir.exists():
        for agent_dir in agents_dir.iterdir():
            if agent_dir.is_dir() and plat.is_sandbox_running(agent_dir.name):
                running.append(agent_dir.name)
    if running:
        names = ", ".join(running)
        console.print(f"  Agents still running: [bold]{names}[/bold]")
        console.print("  [dim]Stop all: safeyolo stop --all[/dim]")


def stop_all() -> None:
    """Stop SafeYolo proxy, all agents, and tear down networking."""

    console.print("[bold]Stopping SafeYolo...[/bold]")

    from ..config import get_agents_dir
    from ..platform import get_platform

    plat = get_platform()
    agents_dir = get_agents_dir()

    # Stop all running agents
    if agents_dir.exists():
        for agent_dir in agents_dir.iterdir():
            if agent_dir.is_dir():
                name = agent_dir.name
                if plat.is_sandbox_running(name):
                    console.print(f"  Stopping {name}...")
                    plat.stop_sandbox(name)

    # Clean up all networking for this instance
    try:
        plat.cleanup_all(agents_dir)
    except Exception:
        # Best-effort teardown -- partial state is better than aborting stop.
        pass

    # Unload host firewall rules (Linux: iptables. macOS: no-op).
    try:
        plat.unload_firewall_rules()
    except Exception:
        pass  # Non-fatal

    # Stop proxy
    if is_proxy_running():
        stop_proxy()

    # Stop the UDS bridge only here -- `safeyolo stop` deliberately keeps
    # it alive so running agents don't lose their /safeyolo/proxy.sock
    # inode when mitmproxy restarts. With all agents stopped above, no
    # one is holding the handle, so tearing the bridge down is safe.
    try:
        from ..proxy_bridge import stop_proxy_bridge
        stop_proxy_bridge()
    except Exception as exc:
        import logging
        logging.getLogger("safeyolo.lifecycle").warning(
            "proxy bridge stop failed: %s: %s", type(exc).__name__, exc)

    console.print("[green]Stopped.[/green]")


def status() -> None:
    """Show SafeYolo status and statistics."""

    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[yellow]No SafeYolo configuration found.[/yellow]\nRun [bold]safeyolo init[/bold] to get started."
        )
        raise typer.Exit(1)

    config = load_config()

    if not is_proxy_running():
        console.print(
            Panel(
                "[yellow]SafeYolo is not running[/yellow]\n\nRun [bold]safeyolo start[/bold] to start the proxy.",
                title="Status",
            )
        )
        raise typer.Exit(0)

    # Build status table
    table = Table(title="SafeYolo Status", show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Proxy", "[green]running[/green]")
    table.add_row("Proxy Port", str(config["proxy"]["port"]))
    table.add_row("Admin Port", str(config["proxy"]["admin_port"]))

    # Guest images
    if check_guest_images():
        table.add_row("Guest Images", "[green]available[/green]")
    else:
        table.add_row("Guest Images", "[yellow]missing[/yellow]")

    # Host firewall row removed -- egress isolation is structural (agent
    # sandbox has no external interface; the only path out is a per-agent
    # UDS). iptables on Linux is a belt-and-braces guard, not the primary
    # control, and doesn't warrant a dashboard row.

    # Try to get stats from API
    try:
        api = get_api()
        stats = api.stats()

        cg = stats.get("credential-guard", {})
        if cg:
            table.add_row("", "")
            table.add_row("Credentials Blocked", str(cg.get("violations_total", 0)))
            table.add_row("Rules Loaded", str(cg.get("rules_count", 0)))

        pending = api.pending_approvals()
        if pending:
            table.add_row("Pending Approvals", f"[yellow]{len(pending)}[/yellow]")
            table.add_row("", "[dim]Run: safeyolo watch[/dim]")

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
        # Proxy may be down or unreachable -- status view still shows the
        # rest of the system; mode table simply isn't rendered.
        pass

    # Running agents. The displayed IP is the agent's attribution address --
    # what mitmproxy sees as the request source and what service_discovery
    # maps back to the name for audit/policy. On Linux's UDS-only arch
    # every guest has HTTP_PROXY pointing at 127.0.0.1, so the guest-side
    # vm-ip file is always 127.0.0.1 and no longer identifies the agent.
    # agent_map.json is the source of truth.
    import json as _json

    from ..config import get_agent_map_path, get_agents_dir
    from ..platform import get_platform
    plat = get_platform()
    agents_dir = get_agents_dir()

    agent_map = {}
    map_path = get_agent_map_path()
    if map_path.exists():
        try:
            agent_map = _json.loads(map_path.read_text())
        except (_json.JSONDecodeError, OSError):
            agent_map = {}

    if agents_dir.exists():
        running = []
        for agent_dir in agents_dir.iterdir():
            if agent_dir.is_dir() and plat.is_sandbox_running(agent_dir.name):
                entry = agent_map.get(agent_dir.name, {})
                ip = entry.get("ip", "?")
                running.append((agent_dir.name, ip))

        if running:
            agent_table = Table(title="Running Agents", show_header=True)
            agent_table.add_column("Name", style="bold")
            agent_table.add_column("IP")

            for name, ip in sorted(running):
                agent_table.add_row(name, ip)

            console.print()
            console.print(agent_table)


def build() -> None:
    """Build guest VM images (kernel, initramfs, rootfs).

    Requires Docker for cross-compilation. Output is installed to
    ~/.safeyolo/share/.
    """
    import subprocess

    # Find build script
    repo_root = Path(__file__).resolve().parents[4]
    build_script = repo_root / "guest" / "build-all.sh"

    if not build_script.exists():
        console.print("[red]Cannot find guest/build-all.sh[/red]")
        console.print("Run from the SafeYolo repo checkout.")
        raise typer.Exit(1)

    console.print("[bold]Building guest VM images...[/bold]")
    console.print("This requires Docker and takes several minutes on first build.\n")

    try:
        subprocess.run(
            [str(build_script)],
            check=True,
        )
    except subprocess.CalledProcessError as err:
        console.print(f"[red]Build failed with exit code {err.returncode}[/red]")
        raise typer.Exit(1)

    # Install to ~/.safeyolo/share/
    share_dir = get_config_dir() / "share"
    share_dir.mkdir(parents=True, exist_ok=True)
    out_dir = build_script.parent / "out"

    for artifact in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]:
        src = out_dir / artifact
        if src.exists():
            shutil.copy2(str(src), str(share_dir / artifact))
            console.print(f"  Installed {artifact}")

    console.print(f"\n[green]Guest images installed to {share_dir}[/green]")
