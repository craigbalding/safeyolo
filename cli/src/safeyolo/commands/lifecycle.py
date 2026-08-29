"""Proxy lifecycle commands: start, stop, status, build."""

import asyncio
import platform
import secrets
import shutil
import subprocess
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
    get_logs_dir,
    load_config,
    save_config,
)
from ..coord import nats_runtime as coord_nats
from ..events import EventKind, Severity, write_event
from ..proxy import (
    is_proxy_running,
    start_proxy,
    stop_proxy,
    wait_for_healthy,
)
from ..timing import enter as _profile_enter
from ..timing import profiled_command
from ..vm import check_guest_images, missing_guest_images
from .proxy import _web_tailnet_runtime

console = Console()


def _attribution_ip_conflicts(
    running: list[tuple[str, str]],
) -> dict[str, list[str]]:
    """Return attribution IPs held by more than one running agent."""
    by_ip: dict[str, list[str]] = {}
    for name, ip in running:
        if ip != "?":
            by_ip.setdefault(ip, []).append(name)
    return {ip: names for ip, names in by_ip.items() if len(names) > 1}


# Path to bundled templates in package
POLICY_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "policy.toml"
ADDONS_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "addons.yaml"


def _start_coord_best_effort() -> None:
    """Start the coord message plane (nats-server) and bootstrap the
    coord registry. NEVER blocks the proxy path: a failure here marks
    coord degraded via a logged event and a console warning, then
    returns. `safeyolo status`/`doctor` will show the substrate as
    unhealthy so the operator knows why their agents can't reach the
    coord API.

    Bootstrap is invoked here (rather than lazily on the first coord
    request) so `safeyolo_instance_id` exists after `safeyolo start`
    completes — the #371 identity contract says the instance ID is a
    property of a running SafeYolo, not something an agent's first
    request happens to create.
    """
    try:
        pid = coord_nats.start_server(ready_timeout=10.0)
        console.print(f"[dim]coord message plane started (nats-server PID {pid})[/dim]")
    except Exception as err:  # noqa: BLE001 — coord failure is non-fatal
        write_event(
            "ops.coord_nats_start_failed",
            kind=EventKind.OPS,
            severity=Severity.MEDIUM,
            summary="nats-server did not start; coord API will return 503",
            addon="cli.lifecycle",
            details={"error_type": type(err).__name__, "error": str(err)[:500]},
        )
        console.print(
            f"[yellow]coord message plane failed to start "
            f"({type(err).__name__}): coord API will return 503.[/yellow]"
        )
        console.print(
            "[dim]The proxy itself is up and healthy. Check the coord "
            "runtime state with: safeyolo doctor[/dim]"
        )
        return

    # Bootstrap the coord registry (schema + instance_id). Lazy on
    # first coord request would still work, but the #371 contract
    # says instance_id is minted at start; do it eagerly so
    # `safeyolo status` can display it immediately.
    try:
        from ..coord import api as coord_api
        instance_id = coord_api.bootstrap()
        console.print(f"[dim]coord instance_id: {instance_id}[/dim]")
    except Exception as err:  # noqa: BLE001
        # Non-fatal: NATS is up, addon will bootstrap on first request.
        write_event(
            "ops.coord_bootstrap_failed",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary="coord bootstrap failed at start (will retry lazily on first request)",
            addon="cli.lifecycle",
            details={"error_type": type(err).__name__, "error": str(err)[:500]},
        )
        return

    try:
        asyncio.run(coord_api.recover_attention())
    except Exception as err:  # noqa: BLE001
        # Accepted manifests remain in JetStream. A later send or attention
        # wait retries the same idempotent contiguous projection.
        write_event(
            "ops.coord_attention_recovery_failed",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary="coord attention recovery is pending",
            addon="cli.lifecycle",
            details={"error_type": type(err).__name__, "error": str(err)[:500]},
        )


def _stop_coord_best_effort() -> None:
    """Stop the coord message plane. Never blocks the proxy stop path
    — coord is optional infra on top of the proxy. Wedged-server state
    surfaces as a warning so the operator can investigate, not as a
    hard failure that leaves the proxy running."""
    try:
        stopped = coord_nats.stop_server()
        if stopped:
            console.print("[dim]coord message plane stopped[/dim]")
    except coord_nats.WedgedNatsServer as err:
        console.print(f"[yellow]{err}[/yellow]")
    except Exception as err:  # noqa: BLE001
        console.print(
            f"[yellow]coord message plane stop encountered "
            f"{type(err).__name__}: {err}[/yellow]"
        )


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


@profiled_command("proxy start")
def start(  # DOC: README.md, docs/DEVELOPERS.md
    wait: bool = typer.Option(
        True,
        "--wait/--no-wait",
        help="Wait for healthy status",
    ),
    dev: bool = typer.Option(
        False,
        "--dev",
        help="Run from checkout source; code changes require a proxy restart",
    ),
    test: bool = typer.Option(
        False,
        "--test",
        help="Enable test mode (sinkhole routing, test CA -- reads test section from config.yaml)",
    ),
    flow_cache: int | None = typer.Option(
        None,
        "--flow-cache",
        min=1,
        help="Maximum flows retained in the shared live traffic view",
    ),
    profile: bool = typer.Option(
        False,
        "--profile",
        help="Profile lifecycle phases and write a JSONL timing artifact",
    ),
) -> None:
    """Start SafeYolo proxy and firewall."""
    _profile_enter("configuration bootstrap and preflight")
    first_run = False

    # Check config exists, bootstrap if needed
    config_dir = find_config_dir()
    if not config_dir:
        first_run = True
        config_dir = get_config_dir()
        console.print("[bold]First run setup...[/bold]")
        _bootstrap_config(config_dir)
        console.print(f"  Created {config_dir}")

    # Refuse to start against an empty/malformed policy (#336). Symmetric with
    # the guard in `agent add`; catches the case where a previous init only
    # wrote [agents.X] blocks without host rules, leaving the compiled
    # permissions list empty. The first-run path above just seeded from the
    # template so we don't need to check it there.
    if not first_run:
        from .policy import assert_policy_has_permissions

        assert_policy_has_permissions(config_dir)

    # Check if already running
    if is_proxy_running():
        console.print("[yellow]SafeYolo proxy is already running.[/yellow]")
        raise typer.Exit(0)

    # Check guest images (platform-aware).
    if not check_guest_images():
        missing = missing_guest_images()
        console.print(f"[yellow]Guest images missing: {', '.join(missing)}[/yellow]")
        console.print("Build and install them with: [bold]safeyolo build[/bold]")

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
    _profile_enter("proxy process launch and readiness")
    try:
        start_proxy(
            proxy_port=proxy_port,
            admin_port=admin_port,
            flow_cache=flow_cache,
            dev=dev,
        )
    except Exception as err:
        write_event(
            "ops.proxy_start_failed",
            kind=EventKind.OPS,
            severity=Severity.HIGH,
            summary="SafeYolo proxy failed during launch",
            addon="cli.lifecycle",
            details={"phase": "launch", "error_type": type(err).__name__, "error": str(err)},
        )
        console.print(f"[red]Failed to start proxy:[/red] {err}")
        raise typer.Exit(1)

    # No per-agent firewall setup -- egress isolation is structural (sandbox
    # has no external interface). The bridge daemon and per-agent UDS
    # listeners are the moving parts; they come up with the proxy itself.

    if wait:
        _profile_enter("admin API health check")
        console.print("Waiting for healthy status...", end=" ")
        if wait_for_healthy(timeout=30, admin_port=admin_port):
            console.print("[green]ready![/green]")
        else:
            console.print("[red]failed[/red]")
            stop_proxy()
            write_event(
                "ops.proxy_start_failed",
                kind=EventKind.OPS,
                severity=Severity.HIGH,
                summary="SafeYolo proxy did not remain healthy during startup",
                addon="cli.lifecycle",
                details={"phase": "health", "admin_port": admin_port},
            )
            console.print(
                "[red]SafeYolo did not remain healthy during startup.[/red]\n"
                f"Check: {get_logs_dir() / 'mitmproxy.log'}"
            )
            raise typer.Exit(1)

    # Coord message plane (nats-server). Best-effort: a failure here
    # marks coord degraded, it does NOT block the proxy from being
    # usable. `safeyolo status` and `safeyolo doctor` surface the
    # degraded state so the operator can investigate.
    _profile_enter("coord message plane (nats-server) start")
    _start_coord_best_effort()

    # Show connection info
    _profile_enter("render startup result")
    web_tailnet = _web_tailnet_runtime(config)
    tailnet_line = ""
    if web_tailnet.get("enabled") and web_tailnet.get("url"):
        tailnet_line = f"\nWebMITM: {web_tailnet['url']}"
    if first_run:
        console.print(
            Panel(
                f"[green]SafeYolo is running![/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}{tailnet_line}\n\n"
                f"Next:\n"
                f"  safeyolo agent add myproject . --host-script contrib/claude-host-setup.sh   [dim]# Add and run an agent[/dim]\n",
                title="Ready",
            )
        )
    else:
        console.print(
            Panel(
                f"[green]SafeYolo is running[/green]\n\n"
                f"Proxy: http://localhost:{proxy_port}{tailnet_line}",
                title="Started",
            )
        )


@profiled_command("proxy stop")
def stop(  # DOC: README.md
    all: bool = typer.Option(False, "--all", help="Also stop all agents and tear down networking"),
    profile: bool = typer.Option(
        False,
        "--profile",
        help="Profile lifecycle phases and write a JSONL timing artifact",
    ),
) -> None:
    """Stop SafeYolo proxy. Agents keep running unless --all is passed."""

    _profile_enter("proxy and agent state checks")

    if all:
        _profile_enter("stop all agents, networking, and proxy")
        stop_all()
        return

    if not is_proxy_running():
        # Also reap a dead remain-on-exit traffic pane left by a failed start.
        stop_proxy()
        console.print("[yellow]SafeYolo proxy is not running.[/yellow]")
        raise typer.Exit(0)

    console.print("[bold]Stopping SafeYolo...[/bold]")

    # Coord plane first: the addon holds a nats-py client that will
    # complain if the server dies out from under it during proxy
    # shutdown. Tearing NATS down first keeps the shutdown log clean
    # and matches the invariant that coord is optional infra on top
    # of the proxy.
    _profile_enter("coord message plane stop")
    _stop_coord_best_effort()

    # Stop proxy only -- agents and bridge sockets stay intact. Agents get
    # "connection refused" on the proxy port but remain alive and accessible
    # via SSH. When the proxy restarts, connectivity resumes.
    _profile_enter("terminate proxy traffic master")
    stop_proxy()
    _profile_enter("render stop result")
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
    except Exception as error:
        # Best-effort teardown -- partial state is better than aborting stop.
        console.print(
            f"  [yellow]Platform cleanup incomplete ({type(error).__name__})[/yellow]"
        )

    # Unload host firewall rules (Linux: iptables. macOS: no-op).
    try:
        plat.unload_firewall_rules()
    except Exception as error:
        console.print(
            f"  [yellow]Firewall cleanup incomplete ({type(error).__name__})[/yellow]"
        )

    # Coord plane before proxy (same reasoning as `stop`: coord is
    # optional infra on top of the proxy, so tear it down first).
    _stop_coord_best_effort()

    # Stop proxy. Per-agent UDS listeners are owned by mitmproxy
    # (UnixInstance per agent) — stopping the process tears them down
    # along with their socket files. No separate bridge process to stop.
    if is_proxy_running():
        stop_proxy()

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
    web_tailnet = _web_tailnet_runtime(config)
    if web_tailnet.get("enabled"):
        state = str(web_tailnet.get("state", "unknown"))
        style = "green" if state == "healthy" else "yellow"
        value = f"[{style}]{state}[/{style}]"
        if web_tailnet.get("url"):
            value += f" · {web_tailnet['url']}"
        table.add_row("WebMITM Tailnet", value)
    else:
        table.add_row("WebMITM Tailnet", "disabled")

    # Guest images
    if check_guest_images():
        table.add_row("Guest Images", "[green]available[/green]")
    else:
        table.add_row("Guest Images", "[yellow]missing[/yellow]")

    # Coord message plane. Degraded / not-started here means the coord
    # API will 503; the proxy stays fine. See `safeyolo doctor` for
    # detail on WHY it's degraded.
    try:
        coord_status = coord_nats.status()
    except Exception as err:  # noqa: BLE001
        table.add_row(
            "Coord (nats-server)",
            f"[yellow]unknown ({type(err).__name__})[/yellow]",
        )
    else:
        state = coord_status.get("state", "not-running")
        if state == "healthy":
            table.add_row(
                "Coord (nats-server)",
                f"[green]healthy[/green]  ({coord_status['listen']} · "
                f"pid {coord_status['pid']})",
            )
        elif state == "wedged":
            table.add_row(
                "Coord (nats-server)",
                f"[red]wedged[/red]  (pid {coord_status['pid']} alive but "
                f"/varz unverified) [dim]— see `safeyolo doctor`[/dim]",
            )
        else:
            table.add_row(
                "Coord (nats-server)",
                "[yellow]not running[/yellow]  "
                "[dim](coord API will 503; run `safeyolo doctor`)[/dim]",
            )

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
    # maps back to the name for audit/policy. agent_map.json is the source
    # of truth on both UDS/vsock platforms.
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
            conflicts = _attribution_ip_conflicts(running)
            agent_table = Table(title="Running Agents", show_header=True)
            agent_table.add_column("Name", style="bold")
            agent_table.add_column("IP")

            for name, ip in sorted(running):
                rendered_ip = (
                    f"[red]{ip} · CONFLICT[/red]" if ip in conflicts else ip
                )
                agent_table.add_row(name, rendered_ip)

            console.print()
            console.print(agent_table)
            if conflicts:
                names = sorted({
                    name
                    for conflict in conflicts.values()
                    for name in conflict
                })
                console.print(
                    "[red]Agent attribution conflict:[/red] stop and rerun "
                    f"{', '.join(names)} before trusting agent-scoped policy "
                    "or audit attribution."
                )


def _install_guest_artifacts(out_dir: Path, share_dir: Path) -> None:
    """Install built artifacts, preserving Linux rootfs ownership.

    The Linux rootfs is a directory whose uid/gid values are part of the
    rootless user-namespace contract. A normal ``shutil.copytree`` would
    recreate every entry as the invoking user, so use privileged rsync to
    preserve the uid-100000 ownership emitted by build-rootfs.sh.
    """
    for artifact in [
        "Image",
        "initramfs.cpio.gz",
        "rootfs-base.ext4",
        "cache-paths.txt",
    ]:
        src = out_dir / artifact
        if src.is_file():
            shutil.copy2(src, share_dir / artifact)
            console.print(f"  Installed {artifact}")

    rootfs_tree = out_dir / "rootfs-tree"
    if platform.system() == "Linux" and rootfs_tree.is_dir():
        destination = share_dir / "rootfs-tree"
        try:
            subprocess.run(
                [
                    "sudo", "rsync", "-aHAX", "--numeric-ids", "--delete",
                    f"{rootfs_tree}/", f"{destination}/",
                ],
                check=True,
            )
            subprocess.run(
                ["sudo", "chown", "100000:100000", str(destination)],
                check=True,
            )
        except FileNotFoundError as err:
            console.print(
                "[red]Cannot install rootfs-tree: sudo and rsync are required.[/red]"
            )
            raise typer.Exit(1) from err
        except subprocess.CalledProcessError as err:
            console.print(
                f"[red]Installing rootfs-tree failed with exit code {err.returncode}[/red]"
            )
            raise typer.Exit(1) from err

        if destination.stat().st_uid != 100000:
            console.print(
                "[red]Installed rootfs-tree has incorrect ownership; "
                "expected uid 100000.[/red]"
            )
            raise typer.Exit(1)
        console.print("  Installed rootfs-tree")


def build() -> None:  # DOC: docs/DEVELOPERS.md
    """Build guest VM images (kernel, initramfs, rootfs).

    Runs natively on Linux and through Lima on macOS. Output is installed
    to ~/.safeyolo/share/.
    """
    # Find build script
    repo_root = Path(__file__).resolve().parents[4]
    build_script = repo_root / "guest" / "build-all.sh"

    if not build_script.exists():
        console.print("[red]Cannot find guest/build-all.sh[/red]")
        console.print("Run from the SafeYolo repo checkout.")
        raise typer.Exit(1)

    console.print("[bold]Building guest VM images...[/bold]")
    console.print("This takes several minutes on first build.\n")

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

    _install_guest_artifacts(out_dir, share_dir)

    if not check_guest_images():
        missing = ", ".join(missing_guest_images())
        console.print(f"[red]Guest image installation incomplete: {missing}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[green]Guest images installed to {share_dir}[/green]")
