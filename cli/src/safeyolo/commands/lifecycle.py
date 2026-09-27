"""Proxy lifecycle commands: start, stop, status, build."""

import os
import platform
import secrets
import shutil
import subprocess
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..config import (
    DEFAULT_CONFIG,
    find_config_dir,
    get_config_dir,
    get_logs_dir,
    load_config,
    save_config,
)
from ..proxy import (
    check_running_backend,
    is_proxy_running,
    prior_python_proxy_running,
    selected_backend,
    start_proxy,
    stop_proxy,
    wait_for_healthy,
)
from ..timing import enter as _profile_enter
from ..timing import profiled_command
from ..vm import check_guest_images, missing_guest_images

console = Console()


def get_api():
    """Load the admin API client only when lifecycle status needs it."""
    from ..api import get_api as _get_api

    return _get_api()


class _LazyCoordNats:
    """Resolve the coord runtime only for lifecycle operations."""

    def __getattr__(self, name: str):
        from ..coord import nats_runtime

        return getattr(nats_runtime, name)


coord_nats = _LazyCoordNats()


def write_event(
    event: str,
    *,
    kind: str,
    severity: str,
    summary: str,
    agent: str | None = None,
    addon: str | None = None,
    details: dict | None = None,
) -> None:
    """Write a lifecycle event without loading the audit schema at import time."""
    from ..events import write_event as _write_event

    _write_event(
        event,
        kind=kind,
        severity=severity,
        summary=summary,
        agent=agent,
        addon=addon,
        details=details,
    )


def _attribution_ip_conflicts(
    running: list[tuple[str, str]],
) -> dict[str, list[str]]:
    """Return attribution IPs held by more than one running agent."""
    by_ip: dict[str, list[str]] = {}
    for name, ip in running:
        if ip != "?":
            by_ip.setdefault(ip, []).append(name)
    return {ip: names for ip, names in by_ip.items() if len(names) > 1}


def _command_supervisor_status(name: str) -> str:
    """Return a compact, read-only command-supervisor status for status."""
    from ..agent_command_supervisor import (
        SupervisorStateError,
        read_command_supervisor_state,
        supervisor_process_is_live,
    )

    try:
        state = read_command_supervisor_state(name)
    except SupervisorStateError:
        return "invalid state"
    if state is None:
        return "no command"
    lifecycle = state.get("state", "unknown")
    if lifecycle == "running" and not supervisor_process_is_live(state):
        return "failed (supervisor absent)"
    return str(lifecycle)


# Path to bundled templates in package
POLICY_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "policy.toml"
ADDONS_TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "addons.yaml"
LISTS_TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "lists"


_CoordStartOutcome = Literal["healthy", "repaired", "degraded"]


def _start_coord_best_effort() -> _CoordStartOutcome:
    """Start the coord message plane (nats-server) and bootstrap the
    coord registry. NEVER blocks the proxy path: a failure here marks
    coord degraded via a logged event and a console warning, then
    returns ``degraded``. `safeyolo status`/`doctor` will show the substrate as
    unhealthy so the operator knows why their agents can't reach the
    coord API.

    Bootstrap is invoked here (rather than lazily on the first coord
    request) so `safeyolo_instance_id` exists after `safeyolo start`
    completes — the #371 identity contract says the instance ID is a
    property of a running SafeYolo, not something an agent's first
    request happens to create.
    """
    try:
        was_healthy = coord_nats.is_healthy()
        pid = coord_nats.start_server(ready_timeout=10.0)
        state = "already healthy" if was_healthy else "started"
        console.print(
            f"[dim]coord message plane {state} (nats-server PID {pid})[/dim]"
        )
    except Exception as err:  # noqa: BLE001 — coord failure is non-fatal
        write_event(
            "ops.coord_nats_start_failed",
            kind="ops",
            severity="medium",
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
        return "degraded"

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
            kind="ops",
            severity="low",
            summary="coord bootstrap failed at start (will retry lazily on first request)",
            addon="cli.lifecycle",
            details={"error_type": type(err).__name__, "error": str(err)[:500]},
        )
        console.print(
            f"[yellow]coord bootstrap failed ({type(err).__name__}); "
            "Coord is degraded.[/yellow]"
        )
        console.print(
            "[dim]The proxy remains available. Run safeyolo doctor and inspect "
            f"{get_logs_dir() / 'safeyolo.jsonl'}.[/dim]"
        )
        return "degraded"

    try:
        import asyncio

        asyncio.run(coord_api.recover_attention())
    except Exception as err:  # noqa: BLE001
        # Accepted manifests remain in JetStream. A later send or attention
        # wait retries the same idempotent contiguous projection.
        write_event(
            "ops.coord_attention_recovery_failed",
            kind="ops",
            severity="low",
            summary="coord attention recovery is pending",
            addon="cli.lifecycle",
            details={"error_type": type(err).__name__, "error": str(err)[:500]},
        )
        console.print(
            f"[yellow]coord attention recovery failed ({type(err).__name__}); "
            "Coord is degraded.[/yellow]"
        )
        console.print(
            "[dim]The proxy remains available. Run safeyolo doctor and inspect "
            f"{get_logs_dir() / 'safeyolo.jsonl'}.[/dim]"
        )
        return "degraded"

    return "healthy" if was_healthy else "repaired"


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
    config = deepcopy(DEFAULT_CONFIG)
    config["proxy"]["rust_config"] = str((config_dir / "data" / "native.json").absolute())
    save_config(config)

    # Copy policy.toml
    policy_path = config_dir / "policy.toml"
    if POLICY_TEMPLATE_PATH.exists():
        shutil.copy(POLICY_TEMPLATE_PATH, policy_path)

    # Copy addons.yaml
    addons_path = config_dir / "addons.yaml"
    if ADDONS_TEMPLATE_PATH.exists():
        shutil.copy(ADDONS_TEMPLATE_PATH, addons_path)
    if LISTS_TEMPLATE_DIR.is_dir():
        shutil.copytree(LISTS_TEMPLATE_DIR, config_dir / "lists", dirs_exist_ok=True)


@profiled_command("proxy start")
def start(  # DOC: cli/README.md, docs/DEVELOPERS.md
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for healthy status"),
    profile: bool = typer.Option(False, "--profile", help="Profile lifecycle phases and write a JSONL timing artifact"),
) -> None:
    """Start the installed native SafeYolo proxy."""
    del profile
    _profile_enter("configuration bootstrap and preflight")
    first_run = find_config_dir() is None
    if first_run:
        config_dir = get_config_dir()
        console.print("[bold]First run setup...[/bold]")
        _bootstrap_config(config_dir)
        console.print(f"  Created {config_dir}")
    try:
        config = load_config()
        selected_backend(config)
        running = check_running_backend()
    except (OSError, ValueError, RuntimeError) as err:
        console.print(f"[red]Cannot start proxy:[/red] {escape(str(err))}")
        raise typer.Exit(1) from err
    if running:
        console.print("[yellow]SafeYolo proxy is already running.[/yellow]")
        _start_coord_best_effort()
        raise typer.Exit(0)

    console.print("[bold]Starting SafeYolo (Rust proxy)...[/bold]")
    _profile_enter("native process launch and readiness")
    try:
        start_proxy()
    except Exception as err:
        write_event(
            "ops.proxy_start_failed", kind="ops", severity="high",
            summary="SafeYolo proxy failed during launch", addon="cli.lifecycle",
            details={"phase": "launch", "error_type": type(err).__name__, "error": str(err)},
        )
        console.print(f"[red]Failed to start proxy:[/red] {escape(str(err))}")
        raise typer.Exit(1) from err

    if wait:
        _profile_enter("native readiness and health check")
        console.print("Waiting for healthy status...", end=" ")
        if not wait_for_healthy(timeout=30):
            console.print("[red]failed[/red]")
            stop_proxy()
            write_event(
                "ops.proxy_start_failed", kind="ops", severity="high",
                summary="SafeYolo proxy did not remain healthy during startup",
                addon="cli.lifecycle", details={"phase": "health", "backend": "rust"},
            )
            console.print("[red]SafeYolo did not remain healthy during startup.[/red]\n"
                          "Check the native launch diagnostics and proxy.rust_config JSON paths.")
            raise typer.Exit(1)
        console.print("[green]ready![/green]")

    _profile_enter("coord message plane (nats-server) start")
    _start_coord_best_effort()
    from .. import rust_proxy

    process = rust_proxy.read_process()
    executable = process.binary_path if process else "unknown"
    console.print(Panel(
        f"[green]SafeYolo Rust proxy is running.[/green]\n\n"
        f"Executable: {escape(executable)}\n"
        f"Native configuration: {escape(str(config['proxy'].get('rust_config', 'proxy.rust_config')))}"
        + ("\nNext: safeyolo agent add myproject ." if first_run else ""),
        title="Started",
    ))


@profiled_command("proxy stop")
def stop(  # DOC: cli/README.md
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
        if prior_python_proxy_running():
            console.print(
                "[red]A prior Python proxy is running.[/red] "
                "Stop it with the pinned prior package before using this CLI."
            )
            raise typer.Exit(1)
        # Also reap a dead remain-on-exit traffic pane left by a failed start.
        _stop_coord_best_effort()
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
    _profile_enter("terminate native proxy")
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

    if not is_proxy_running() and prior_python_proxy_running():
        console.print(
            "[red]A prior Python proxy is running.[/red] "
            "Stop it with the pinned prior package before using this CLI."
        )
        raise typer.Exit(1)

    console.print("[bold]Stopping SafeYolo...[/bold]")

    from ..agent_command_supervisor import request_command_supervisor_stop
    from ..config import get_agents_dir
    from ..platform import get_platform

    plat = get_platform()
    agents_dir = get_agents_dir()

    # Stop all running agents
    if agents_dir.exists():
        for agent_dir in agents_dir.iterdir():
            if agent_dir.is_dir():
                name = agent_dir.name
                if not request_command_supervisor_stop(name):
                    console.print(
                        f"  [yellow]Could not stop command supervisor for {name}; "
                        "leaving its sandbox running.[/yellow]"
                    )
                    continue
                from ..agent_launchers import stop_launcher

                try:
                    stop_launcher(name)
                except (OSError, RuntimeError, ValueError) as exc:
                    console.print(f"  [red]Could not stop launcher for {escape(name)}: {escape(str(exc))}[/red]")
                    raise typer.Exit(1) from exc
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

    # Remove platform egress controls if the platform created any. Current
    # platforms use structural isolation, so this call is a no-op.
    try:
        plat.unload_firewall_rules()
    except Exception as error:
        console.print(
            f"  [yellow]Firewall cleanup incomplete ({type(error).__name__})[/yellow]"
        )

    # Coord plane before proxy (same reasoning as `stop`: coord is
    # optional infra on top of the proxy, so tear it down first).
    _stop_coord_best_effort()

    # Stop proxy. Its native per-agent UDS listeners close with the process.
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

    if not is_proxy_running():
        if prior_python_proxy_running():
            console.print(Panel(
                "[yellow]A prior Python proxy is running.[/yellow]\n\n"
                "Use the pinned prior package to inspect or stop it before starting Rust.",
                title="Status",
            ))
            raise typer.Exit(1)
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

    from .. import rust_proxy

    native = rust_proxy.read_process()
    if native is None:
        raise RuntimeError("Native proxy is running without a lifetime record")
    ready = rust_proxy.readiness(native)
    table.add_row("Backend", "Rust")
    table.add_row("Executable", escape(native.binary_path or "unknown"))
    table.add_row("PID", str(native.pid))
    table.add_row("Readiness", "[green]ready[/green]" if ready else "[yellow]not ready[/yellow]")
    table.add_row("Readiness File", escape(native.readiness_file))
    if ready and ready.get("admin_port") is not None:
        table.add_row("Admin Port", str(ready["admin_port"]))
    elif native.admin_port is None:
        table.add_row("Admin Port", "not configured")
    else:
        table.add_row("Admin Port", f"{native.admin_port} (configured; not ready)")

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

    console.print(table)

    # Running agents. The displayed IP is the agent's attribution address --
    # what the native listener uses as the trusted request source and what service_discovery
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
            agent_table = Table(title="Ready Sandboxes", show_header=True)
            agent_table.add_column("Name", style="bold")
            agent_table.add_column("IP")
            agent_table.add_column("Command")
            agent_table.add_column("Agent")
            agent_table.add_column("Launcher")

            for name, ip in sorted(running):
                rendered_ip = (
                    f"[red]{ip} · CONFLICT[/red]" if ip in conflicts else ip
                )
                command_state = _command_supervisor_status(name)
                command_style = (
                    "red"
                    if command_state.startswith("failed") or command_state == "invalid state"
                    else "yellow"
                    if command_state in {"restarting", "starting"}
                    else "green"
                    if command_state in {"running", "exited", "stopped"}
                    else ""
                )
                rendered_command = (
                    f"[{command_style}]{command_state}[/{command_style}]"
                    if command_style
                    else command_state
                )
                from ..agent_launchers import observe_launch

                try:
                    observed = observe_launch(name, sandbox_ready=True)
                    selected = observed["launcher"]
                    launcher_label = f"{selected.get('script') or selected['kind']} ({selected['source']})"
                    agent_state = observed["agent_state"]
                except (OSError, ValueError, RuntimeError) as exc:
                    agent_state, launcher_label = "unknown", str(exc)
                agent_table.add_row(name, rendered_ip, rendered_command, escape(agent_state), escape(launcher_label))

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


def _build_output_dir(build_script: Path) -> Path:
    """Resolve the builder's output directory using its public override."""
    override = os.environ.get("OUTPUT_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return build_script.parent / "out"


def _probe_subordinate_ownership(
    selected_path: Path,
    *,
    non_interactive: bool = False,
) -> tuple[bool, str]:
    """Prove the selected filesystem can represent uid/gid 100000.

    Linux rootless runsc consumes a rootfs tree owned by the subordinate root
    identity. VirtioFS-backed paths inside an outer SafeYolo guest reject that
    ownership change, so detect it before spending minutes building a rootfs.
    """
    selected_path = selected_path.expanduser().resolve()
    probe_parent = selected_path
    while not probe_parent.exists() and probe_parent != probe_parent.parent:
        probe_parent = probe_parent.parent
    if not probe_parent.is_dir():
        return False, f"nearest existing path is not a directory: {probe_parent}"
    if not os.access(probe_parent, os.W_OK | os.X_OK):
        return False, f"selected path is not writable by the operator: {probe_parent}"

    probe_root = Path(tempfile.mkdtemp(prefix=".safeyolo-subuid-probe-", dir=probe_parent))
    probe = probe_root / "rootfs-tree"
    probe.mkdir()
    sudo = ["sudo"] + (["-n"] if non_interactive else [])
    changed = False
    try:
        result = subprocess.run(
            sudo + ["chown", "100000:100000", str(probe)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            return False, detail or f"chown exited {result.returncode}"
        changed = True
        stat_result = probe.stat()
        if (stat_result.st_uid, stat_result.st_gid) != (100000, 100000):
            return False, (
                "chown returned success but the filesystem reported "
                f"{stat_result.st_uid}:{stat_result.st_gid}"
            )
        return True, "uid/gid 100000 ownership is preserved"
    except FileNotFoundError as exc:
        return False, f"required ownership probe command is missing: {exc.filename}"
    except subprocess.SubprocessError as exc:
        return False, f"ownership probe failed: {exc}"
    finally:
        if changed:
            subprocess.run(
                sudo + ["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(probe_root)],
                capture_output=True,
                check=False,
            )
        try:
            shutil.rmtree(probe_root)
        except OSError:
            subprocess.run(
                sudo + ["rm", "-rf", "--", str(probe_root)],
                capture_output=True,
                check=False,
            )


def _preflight_linux_build_storage(build_script: Path) -> list[tuple[str, Path]]:
    """Fail with nested-lab guidance when build/install storage is unsuitable."""
    if platform.system() != "Linux":
        return []
    paths = [
        ("build output", _build_output_dir(build_script)),
        ("installed share", get_config_dir() / "share"),
    ]
    failures = []
    for label, path in paths:
        supported, reason = _probe_subordinate_ownership(path)
        if not supported:
            failures.append((f"{label}: {reason}", path))
    return failures


def _print_linux_build_storage_failure(failures: list[tuple[str, Path]]) -> None:
    console.print(
        "[red]Selected Linux build storage cannot preserve subordinate "
        "uid/gid 100000.[/red]"
    )
    for detail, path in failures:
        console.print(f"  {detail}\n    path: {path}")
    console.print(
        "Use a native guest-local filesystem. For SafeYolo-in-SafeYolo:\n"
        "  sudo install -d -o $(id -u) -g $(id -g) /var/lib/nested-safeyolo\n"
        "  export SAFEYOLO_CONFIG_DIR=/var/lib/nested-safeyolo\n"
        "  export SAFEYOLO_COORD_DATA_DIR=/var/lib/nested-safeyolo/coord\n"
        "  export OUTPUT_DIR=/var/lib/nested-safeyolo/build"
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


def build(  # DOC: docs/DEVELOPERS.md
    source_checkout: Path | None = typer.Option(
        None,
        "--source-checkout",
        help="Checkout containing guest/build-all.sh (needed for an installed CLI run outside the checkout).",
    ),
) -> None:
    """Build platform-specific guest artifacts.

    Linux builds an unpacked rootfs tree. macOS builds a kernel, initramfs,
    and ext4 rootfs image through Lima. Output is installed in
    ~/.safeyolo/share/.
    """
    package_checkout = Path(__file__).resolve().parents[4]
    if source_checkout is not None:
        checkout = source_checkout.expanduser().resolve()
    elif (package_checkout / "guest" / "build-all.sh").is_file():
        checkout = package_checkout
    else:
        checkout = Path.cwd().resolve()
    build_script = checkout / "guest" / "build-all.sh"

    if not build_script.is_file():
        console.print(f"[red]Cannot find guest/build-all.sh in {checkout}[/red]")
        console.print("Run from a SafeYolo checkout or pass --source-checkout PATH.")
        raise typer.Exit(1)

    storage_failures = _preflight_linux_build_storage(build_script)
    if storage_failures:
        _print_linux_build_storage_failure(storage_failures)
        raise typer.Exit(1)

    console.print(f"[bold]Building guest artifacts from {checkout}...[/bold]")
    console.print("This takes several minutes on first build.\n")

    try:
        subprocess.run(
            [str(build_script)],
            check=True,
        )
    except subprocess.CalledProcessError as err:
        console.print(f"[red]Build failed with exit code {err.returncode}[/red]")
        raise typer.Exit(1)
    except OSError as err:
        console.print(f"[red]Cannot execute {build_script}: {err}[/red]")
        raise typer.Exit(1) from err

    # Install to ~/.safeyolo/share/
    share_dir = get_config_dir() / "share"
    share_dir.mkdir(parents=True, exist_ok=True)
    out_dir = _build_output_dir(build_script)

    _install_guest_artifacts(out_dir, share_dir)

    if not check_guest_images():
        missing = ", ".join(missing_guest_images())
        console.print(f"[red]Guest image installation incomplete: {missing}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[green]Guest images installed to {share_dir}[/green]")
