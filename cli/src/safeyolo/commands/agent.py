"""Agent management commands."""

import getpass
import logging
import os
import shlex
import subprocess
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..agent_configuration import (
    GUEST_PROXY_PORT,
    _parse_mount,
    _validate_instance_name,
)
from ..agent_lifecycle import (
    _agent_host_setup_lock,
    _check_project_ownership,
    _load_agent_metadata,
    start_native_agent,
    write_event,
)
from ..agents_store import (
    load_all_agents,
    reserve_agent_tailnet_port_change,
    restore_agent_tailnet_port,
    save_agent,
)
from ..config import (
    find_config_dir,
    get_agents_dir,
    get_desktop_size,
    load_config,
    save_config,
)
from ..snapshot import invalidate_snapshot
from ..timing import enter as _t
from ..timing import profiled_command
from ..vm import (
    build_custom_rootfs,
    clone_custom_rootfs,
    stage_guest_desktop_launcher,
)
from .tmux import associate_agent_pane

log = logging.getLogger("safeyolo.agent")
console = Console()


agent_app = typer.Typer(
    name="agent",
    help="Manage AI agent sandboxes.",
    no_args_is_help=True,
)


def _get_service_name(instance_name: str) -> str:
    """Return the service name for an instance (identity mapping)."""
    return instance_name


def _resolve_preview_tailnet_port(
    name: str,
    share: str,
    requested_port: int | None,
) -> tuple[int | None, int | None]:
    """Validate preview sharing and reserve a stable per-agent port."""
    normalized = share.strip().lower()
    if normalized not in {"local", "tailnet"}:
        raise ValueError("share must be local or tailnet")
    if normalized == "local":
        if requested_port is not None:
            raise ValueError("--tailnet-port requires --share tailnet")
        return None, None

    from ..tailnet import validate_tailnet_port

    if requested_port is not None:
        validate_tailnet_port(requested_port)
    return reserve_agent_tailnet_port_change(name, requested_port)


def _rollback_preview_tailnet_port(
    name: str,
    reserved_port: int | None,
    previous_port: int | None,
) -> None:
    """Undo a changed provisional reservation after preview startup fails."""
    if reserved_port is None or reserved_port == previous_port:
        return
    try:
        restore_agent_tailnet_port(name, reserved_port, previous_port)
    except Exception as exc:  # noqa: BLE001 - preserve the original failure
        log.warning(
            "could not restore tailnet port reservation for %s: %s",
            name,
            exc,
        )


# Bundled host-script aliases. Keep in sync with pyproject.toml
# [tool.hatch.build.targets.wheel.force-include]. `--host-script @<name>`
# resolves to `contrib/<value>` under the installed package.
_HOST_SCRIPT_ALIASES: dict[str, str] = {
    "claude": "claude-host-setup.sh",
    "codex": "codex-host-setup.sh",
    "codex-coord": "codex-coord-host-setup.sh",
    "pi": "pi-host-setup.sh",
    "pi-coord": "pi-coord-host-setup.sh",
    "mise-shell": "mise-shell-host-setup.sh",
}


def _resolve_host_script_alias(alias: str) -> Path | None:
    """Resolve @alias → bundled contrib/*.sh path, or None if not found.

    Tries the installed-package location first (wheel install path), then
    falls back to the repo-root contrib/ for source checkouts where
    hatch.force-include hasn't been re-run.
    """
    if alias not in _HOST_SCRIPT_ALIASES:
        return None
    return _resolve_contrib_file(_HOST_SCRIPT_ALIASES[alias])


def _resolve_contrib_file(script_name: str) -> Path | None:
    from .. import __file__ as _safeyolo_pkg_init

    pkg_dir = Path(_safeyolo_pkg_init).resolve().parent  # cli/src/safeyolo or site-packages/safeyolo
    candidates = [
        pkg_dir / "contrib" / script_name,                        # wheel install path
        pkg_dir.parent.parent.parent / "contrib" / script_name,   # editable-from-checkout fallback
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def _resolve_host_script_path(host_script: str | None) -> Path | None:
    if not host_script:
        return None
    # @alias — bundled contrib script. Errors clearly if unknown.
    if host_script.startswith("@"):
        alias = host_script[1:]
        resolved = _resolve_host_script_alias(alias)
        if resolved is None:
            available = ", ".join(sorted(f"@{a}" for a in _HOST_SCRIPT_ALIASES))
            console.print(f"[red]Unknown host-script alias: {host_script}[/red]")
            console.print(f"  Available aliases: {available}")
            console.print("  Or pass a path: --host-script /path/to/setup.sh")
            raise typer.Exit(1)
        host_script_path = resolved
    else:
        host_script_path = Path(host_script).expanduser().resolve()
        if not host_script_path.is_file():
            console.print(f"[red]Host script not found: {host_script_path}[/red]")
            raise typer.Exit(1)
    if not os.access(host_script_path, os.X_OK):
        console.print(f"[red]Host script is not executable: {host_script_path}[/red]")
        console.print(f"  Fix: chmod +x {host_script_path}")
        raise typer.Exit(1)
    return host_script_path


def _run_host_script_for_agent(
    *,
    name: str,
    host_script_path: Path,
    folder_str: str,
) -> None:
    with _agent_host_setup_lock(name):
        from ..platform import get_platform
        from ..vm import ensure_agent_persistent_dirs, get_agent_home_dir

        if get_platform().is_sandbox_running(name):
            console.print(f"[red]Agent '{name}' is already running.[/red]")
            console.print(
                f"Stop it first: [bold]safeyolo agent stop {name}[/bold] "
                "before applying a host script."
            )
            raise typer.Exit(1)

        ensure_agent_persistent_dirs(name)
        agent_home = get_agent_home_dir(name)
        env = {
            **os.environ,
            "SAFEYOLO_AGENT_NAME": name,
            "SAFEYOLO_AGENT_HOME": str(agent_home),
            "SAFEYOLO_AGENT_FOLDER": folder_str,
            "SAFEYOLO_PYTHON": sys.executable,
        }
        console.print(f"  [bold]Running host script:[/bold] {host_script_path}")
        try:
            result = subprocess.run([str(host_script_path)], env=env, check=False)
        except OSError as err:
            console.print(f"[red]Host script failed to launch:[/red] {escape(str(err))}")
            raise typer.Exit(1)
        if result.returncode != 0:
            console.print(f"[red]Host script exited with code {result.returncode}.[/red]")
            raise typer.Exit(result.returncode)


def _parse_user_default_args(value: str | None) -> list[str] | None:
    """Parse user_default_args string into list."""
    if not value:
        return None
    try:
        return shlex.split(value)
    except ValueError:
        # If shlex fails, fall back to simple split
        return value.split()


_RESERVED_PORTS = {8080, 9090}


def _parse_port(port_spec: str) -> str:
    """Validate and normalize a port spec (host:container or bind:host:container).

    Always normalizes to 127.0.0.1:host:container.

    Raises:
        typer.Exit: If port spec is invalid.
    """
    parts = port_spec.split(":")
    if len(parts) == 2:
        bind_addr = "127.0.0.1"
        host_port_str, container_port_str = parts
    elif len(parts) == 3:
        bind_addr, host_port_str, container_port_str = parts
    else:
        console.print(
            f"[red]Invalid port format:[/red] {escape(port_spec)}\n"
            "Expected: host_port:container_port or 127.0.0.1:host_port:container_port"
        )
        raise typer.Exit(1)

    if bind_addr != "127.0.0.1":
        console.print(
            f"[red]Only localhost bind address allowed:[/red] {escape(bind_addr)}\n"
            "Use 127.0.0.1:host_port:container_port (or omit bind address)"
        )
        raise typer.Exit(1)

    for label, val in [("host", host_port_str), ("container", container_port_str)]:
        try:
            port_int = int(val)
        except ValueError:
            console.print(f"[red]Invalid {label} port (not an integer):[/red] {escape(val)}")
            raise typer.Exit(1)
        if port_int < 1 or port_int > 65535:
            console.print(f"[red]Invalid {label} port (must be 1-65535):[/red] {escape(val)}")
            raise typer.Exit(1)

    container_port = int(container_port_str)
    if container_port in _RESERVED_PORTS:
        console.print(f"[red]Container port {container_port} is reserved[/red] (used by SafeYolo proxy/admin)")
        raise typer.Exit(1)

    return f"127.0.0.1:{host_port_str}:{container_port_str}"


@agent_app.command()
def add(  # DOC: README.md, docs/AGENTS.md
    name: str = typer.Argument(
        ...,
        help="Instance name (used for run/shell/remove commands)",
    ),
    folder: str = typer.Argument(
        ...,
        help="Folder to mount in agent container",
    ),
    host_script: str = typer.Option(
        None,
        "--host-script",
        help="Path to a host setup script (runs on the host, as you, before the sandbox boots). See contrib/HOST_SCRIPT_GUIDE.md.",
    ),
    rootfs_script: str = typer.Option(
        None,
        "--rootfs-script",
        help=(
            "Path to a rootfs builder script. Produces a custom per-agent ext4 "
            "image on macOS or unpacked tree on Linux. "
            "See contrib/ROOTFS_SCRIPT_GUIDE.md."
        ),
    ),
    rootfs_from: str = typer.Option(
        None,
        "--rootfs-from",
        help=(
            "Clone another agent's immutable custom rootfs. Home, overlay, "
            "credentials, workspace, and caches are not copied."
        ),
    ),
    ephemeral: bool = typer.Option(
        False,
        "--ephemeral",
        help=(
            "Boot with a memory-backed rootfs overlay instead of the platform's "
            "persistent per-agent overlay. Writes to /etc, /usr, and /var are "
            "discarded when the agent stops. The host-mounted /home/agent remains "
            "persistent."
        ),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing agent configuration",
    ),
    no_run: bool = typer.Option(
        False,
        "--no-run",
        help="Don't run the agent after adding (just create config)",
    ),
    user_default_args: str = typer.Option(
        None,
        "--user-default-args",
        help="Default args to pass to agent CLI (e.g., '--continue')",
    ),
    mount: list[str] = typer.Option(
        [],
        "--mount",
        "-m",
        help="Extra folder to mount (/local/path:/container/path[:ro], repeatable)",
    ),
    port: list[str] = typer.Option(
        [],
        "--port",
        help="Expose container port to host (host_port:container_port, repeatable)",
    ),
    dangerously_allow_unowned: bool = typer.Option(
        False,
        "--dangerously-allow-unowned",
        help="Allow mounting directories you don't own",
    ),
) -> None:
    """Add an AI agent sandbox and run it.

    Creates a persistent per-agent sandbox, optionally populated by a
    host script that runs on the host (as you) before the sandbox
    boots. The host script may write into ~/.safeyolo/agents/<name>/home/ to
    seed auth, settings, user extensions -- and in particular write a
    .safeyolo-command file that `agent run` will execute.

    Without --host-script, the sandbox boots to an interactive bash
    shell with a fresh per-agent /home/agent (seeded from /etc/skel).

    --rootfs-script replaces the default SafeYolo base rootfs with one the
    script produces (full replacement, any distro). --rootfs-from clones an
    existing agent's custom rootfs without its mutable runtime state. These
    options are mutually exclusive. See contrib/ROOTFS_SCRIPT_GUIDE.md.

    Examples:

        safeyolo agent add plain .
        safeyolo agent add claude . --host-script contrib/claude-host-setup.sh
        safeyolo agent add boris . --host-script ./my-setup.sh --mount ~/data:/data
        safeyolo agent add pentest-two ~/other-target --rootfs-from pentest
        safeyolo agent add pentest ~/target \\
            --rootfs-script contrib/kali-pentest/build-kali-rootfs.sh \\
            --host-script contrib/claude-host-setup.sh
    """
    # Validate instance name (hostname rules)
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]\nRun [bold]safeyolo init[/bold] first.")
        raise typer.Exit(1)

    # Refuse to add against an empty/malformed policy (#336): find_config_dir()
    # only checks that ~/.safeyolo/ exists, not that a usable policy lives in
    # it. An empty compiled permissions list means every request the new agent
    # makes 403s at network_guard's fail-closed path with no diagnostic.
    from .policy import assert_policy_has_permissions

    assert_policy_has_permissions(config_dir)

    # Validate folder early
    folder_path = Path(folder).expanduser().resolve()
    if not folder_path.is_dir():
        console.print(f"[red]Folder not found: {folder_path}[/red]")
        raise typer.Exit(1)
    _check_project_ownership(folder_path, dangerously_allow_unowned)
    folder_str = str(folder_path)

    host_script_path = _resolve_host_script_path(host_script)

    if rootfs_script and rootfs_from:
        console.print(
            "[red]--rootfs-script and --rootfs-from are mutually exclusive[/red]"
        )
        raise typer.Exit(1)
    if rootfs_from:
        _validate_instance_name(rootfs_from)

    rootfs_script_path: Path | None = None
    if rootfs_script:
        rootfs_script_path = Path(rootfs_script).expanduser().resolve()
        if not rootfs_script_path.is_file():
            console.print(f"[red]Rootfs script not found: {rootfs_script_path}[/red]")
            raise typer.Exit(1)
        if not os.access(rootfs_script_path, os.X_OK):
            console.print(f"[red]Rootfs script is not executable: {rootfs_script_path}[/red]")
            console.print(f"  Fix: chmod +x {rootfs_script_path}")
            raise typer.Exit(1)

    # Validate and normalize every declarative input before rootfs builders,
    # cloning, platform preparation, or host setup can change host state.
    # These values are also the exact normalized values persisted below.
    parsed_mounts = [_parse_mount(m) for m in mount]
    parsed_ports = [_parse_port(p) for p in port]
    parsed_args = _parse_user_default_args(user_default_args)

    # Instance directory = instance name
    agent_dir = get_agents_dir() / name

    # Check if agent already exists
    existing = _load_agent_metadata(name)
    if agent_dir.exists():
        if existing:
            existing_host = existing.get("host_script")
            existing_rootfs = existing.get("rootfs_script")
            existing_rootfs_from = existing.get("rootfs_from")
            existing_folder = existing.get("folder")
            requested_host = str(host_script_path) if host_script_path else None
            requested_rootfs = str(rootfs_script_path) if rootfs_script_path else None
            requested_rootfs_from = rootfs_from or None

            same_config = (
                existing_host == requested_host
                and existing_rootfs == requested_rootfs
                and existing_rootfs_from == requested_rootfs_from
                and existing_folder == folder_str
            )
            if same_config and not force:
                # Same config, no --force - idempotent, just run
                console.print(f"Agent '{name}' already configured.")
                if not no_run:
                    associate_agent_pane(name)
                    exit_code = start_native_agent(
                        name,
                        dangerously_allow_unowned=dangerously_allow_unowned,
                    )
                    raise typer.Exit(exit_code)
                return
            else:
                # Different config
                if not force:
                    def _fmt(host, rootfs, rootfs_source, folder):
                        bits = []
                        bits.append(host or "(no host script)")
                        if rootfs:
                            bits.append(f"rootfs-script={rootfs}")
                        if rootfs_source:
                            bits.append(f"rootfs-from={rootfs_source}")
                        return f"{' '.join(bits)} → {folder}"
                    console.print(
                        f"[yellow]Agent '{name}' exists with different config:[/yellow]\n"
                        f"  Current:  {_fmt(existing_host, existing_rootfs, existing_rootfs_from, existing_folder)}\n"
                        f"  Requested: {_fmt(requested_host, requested_rootfs, requested_rootfs_from, folder_str)}\n"
                        "Use --force to overwrite, or 'safeyolo agent start' to run existing."
                    )
                    raise typer.Exit(1)
                # With --force, continue to overwrite below
        else:
            # No metadata, treat as needing --force
            if not force:
                console.print(f"[yellow]Agent '{name}' already exists[/yellow]")
                console.print("Use --force to overwrite")
                raise typer.Exit(1)

    # --rootfs-script runs before platform.prepare_rootfs so the selected
    # platform can find its custom output. Linux uses the per-agent rootfs/
    # tree. Darwin uses rootfs.ext4. Without custom output, Linux selects the
    # shared tree and Darwin creates its default per-agent ext4 image.
    if rootfs_script_path is not None:
        console.print(f"  [bold]Running rootfs script:[/bold] {rootfs_script_path}")
        try:
            build_custom_rootfs(name, rootfs_script_path)
        except Exception as err:
            console.print(f"[red]Rootfs script failed:[/red] {escape(str(err))}")
            raise typer.Exit(1)
    elif rootfs_from:
        console.print(f"  [bold]Cloning rootfs from agent:[/bold] {rootfs_from}")
        try:
            clone_custom_rootfs(rootfs_from, name)
        except Exception as err:
            console.print(f"[red]Rootfs clone failed:[/red] {escape(str(err))}")
            raise typer.Exit(1)

    # Select or create the platform rootfs: a per-agent ext4 image on macOS,
    # or the shared/custom unpacked tree on Linux.
    from ..platform import get_platform
    try:
        rootfs = get_platform().prepare_rootfs(name)
        console.print(f"  [green]Created[/green] {rootfs}")
    except Exception as err:
        console.print(f"[red]Failed to create agent rootfs:[/red] {escape(str(err))}")
        raise typer.Exit(1)

    # Persistent /home/agent host-side dir. start_vm re-ensures this
    # so existing agents get backfilled, but creating it on `add`
    # covers the --no-run path and is required before running the
    # host script (which writes into it).
    from ..vm import ensure_agent_persistent_dirs
    ensure_agent_persistent_dirs(name)

    # Run the host script (if provided). Host-side, as the invoking
    # user. It sees SAFEYOLO_AGENT_NAME, SAFEYOLO_AGENT_HOME (the
    # persistent bind-mount source for /home/agent), SAFEYOLO_AGENT_FOLDER.
    if host_script_path is not None:
        try:
            _run_host_script_for_agent(name=name, host_script_path=host_script_path, folder_str=folder_str)
        except typer.Exit as exc:
            console.print(
                f"  Agent '{name}' setup is incomplete; its rootfs and home were retained. "
                "Re-run with --force after fixing the script."
            )
            raise exc

    # Write metadata to policy.toml [agents]
    metadata: dict = {"folder": folder_str}
    if host_script_path is not None:
        metadata["host_script"] = str(host_script_path)
        if host_script in {"@codex-coord", "@pi-coord"}:
            metadata["launcher"] = "supervisor"
    if rootfs_script_path is not None:
        metadata["rootfs_script"] = str(rootfs_script_path)
    if rootfs_from:
        metadata["rootfs_from"] = rootfs_from
    if ephemeral:
        # Stored as a typed string rather than a bool so the schema can
        # grow: future overlay backings (e.g. "disk-persistent-ro",
        # "copy-on-write-clone") slot in without another toml-level
        # migration. "memory" = gVisor tmpfs / VZ safeyolo.ephemeral_upper=1.
        metadata["rootfs_overlay"] = "memory"
    if parsed_args:
        metadata["user_default_args"] = parsed_args
    if parsed_mounts:
        metadata["mounts"] = parsed_mounts
    if parsed_ports:
        metadata["ports"] = parsed_ports
    # Durable random agent_id, distinct from `name`; consumer / grant identity
    # in the coord plane (see #371). Removal + re-add produces a different ID.
    from ..agents_store import _new_agent_id
    metadata["agent_id"] = _new_agent_id()
    save_agent(name, metadata)
    if no_run:
        # The installed CLI may prepare a stopped agent before the native
        # proxy is the only remaining host runtime. Stage the same guest boot
        # inputs that an ordinary CLI run would prepare.
        from ..vm import stage_native_boot_inputs
        try:
            stage_native_boot_inputs(name, metadata)
        except Exception as err:
            log.warning("Native boot staging for %s failed", name, exc_info=True)
            console.print(
                f"[yellow]Native agent boot inputs are not ready:[/yellow] {escape(str(err))}"
            )

    panel_lines = [
        f"[green]Agent '{name}' added![/green]\n",
        f"Folder: {folder_str}",
        f"Rootfs: {rootfs}",
    ]
    if ephemeral:
        panel_lines.append(
            "[yellow]Rootfs overlay: memory (tmpfs)[/yellow] — "
            "writes to / will NOT persist across stop"
        )
    if host_script_path is not None:
        panel_lines.append(f"Host script: {host_script_path}")
    if rootfs_script_path is not None:
        panel_lines.append(f"Rootfs script: {rootfs_script_path}")
    if rootfs_from:
        panel_lines.append(f"Rootfs cloned from: {rootfs_from}")
    if parsed_args:
        panel_lines.append(f"Default args: {' '.join(parsed_args)}")
    if parsed_mounts:
        panel_lines.append(f"Mounts: {len(parsed_mounts)}")
        for m in parsed_mounts:
            panel_lines.append(f"  {m}")
    panel_lines.append(
        f"Proxy: http://127.0.0.1:{GUEST_PROXY_PORT} (via in-guest forwarder)"
    )
    console.print(Panel("\n".join(panel_lines), title="Success"))

    event_details: dict = {"folder": folder_str}
    if host_script_path is not None:
        event_details["host_script"] = str(host_script_path)
    if rootfs_script_path is not None:
        event_details["rootfs_script"] = str(rootfs_script_path)
    if rootfs_from:
        event_details["rootfs_from"] = rootfs_from
    write_event(
        "agent.added",
        kind="agent",
        severity="low",
        summary=f"Agent {name} added",
        agent=name,
        details=event_details,
    )

    # Auto-run unless --no-run
    if not no_run:
        console.print()
        associate_agent_pane(name)
        exit_code = start_native_agent(
            name,
            dangerously_allow_unowned=dangerously_allow_unowned,
        )
        raise typer.Exit(exit_code)


@agent_app.command(name="list")
def list_agents() -> None:
    """List configured agent instances."""
    agents_dir = get_agents_dir()
    all_agents = load_all_agents()

    if agents_dir.exists():
        # Ask the platform for the expected rootfs path: an ext4 file on
        # Darwin, or a shared/custom unpacked directory on Linux.
        from ..platform import get_platform
        plat = get_platform()
        instances = [
            d for d in agents_dir.iterdir()
            if d.is_dir() and plat.agent_rootfs_path(d.name).exists()
        ]

        if instances:
            table = Table(title="Configured Agents")
            table.add_column("Name", style="bold")
            table.add_column("Folder")
            table.add_column("Host script")
            table.add_column("Sandbox")
            table.add_column("Agent")
            table.add_column("Launcher")
            from ..agent_lifecycle import list_agent_runtimes

            runtimes = {runtime["name"]: runtime for runtime in list_agent_runtimes()}
            for inst_dir in sorted(instances, key=lambda d: d.name):
                metadata = all_agents.get(inst_dir.name, {})
                folder = metadata.get("folder", "?")
                host_script = metadata.get("host_script", "")
                runtime = runtimes.get(inst_dir.name)
                launcher = runtime.get("launcher") if runtime else None
                label = f"{launcher.get('script') or launcher['kind']} ({launcher['source']})" if launcher else "unknown"
                table.add_row(inst_dir.name, folder, host_script,
                              runtime.get("sandbox_state", "unknown") if runtime else "unknown",
                              runtime.get("agent_state", "unknown") if runtime else "unknown", label)
            console.print(table)
        else:
            console.print("[dim]No agents configured.[/dim]")
    else:
        console.print("[dim]No agents configured.[/dim]")


@agent_app.command()
@profiled_command("agent start")
def start(
    name: str = typer.Argument(..., help="Agent instance name"),
    arguments: list[str] = typer.Argument(None, help="One-launch arguments after --"),
    foreground: bool = typer.Option(False, "--foreground", help="Use the caller's terminal"),
    sandbox_only: bool = typer.Option(False, "--sandbox-only", help="Start only the sandbox"),
    dangerously_allow_unowned: bool = typer.Option(False, "--dangerously-allow-unowned"),
    profile: bool = typer.Option(False, "--profile", help="Profile the native lifecycle call"),
) -> None:
    """Start the configured agent through the installed native CLI.

    Use native agent configure for workspace, memory, mounts and launchers.
    Native agent start accepts --foreground, --sandbox-only and -- ARGUMENTS.
    """
    if foreground and sandbox_only:
        raise typer.BadParameter("--foreground and --sandbox-only select different launch modes")
    raise typer.Exit(start_native_agent(
        name, launch_mode="sandbox" if sandbox_only else "foreground" if foreground else "background",
        dangerously_allow_unowned=dangerously_allow_unowned, agent_args=arguments or None,
    ))


@agent_app.command()
def preview(  # DOC: README.md
    name: str = typer.Argument(..., help="Agent instance name"),
    guest_port: int = typer.Argument(..., help="Agent-local HTTP port to preview"),
    host_port: int = typer.Option(
        0,
        "--host-port",
        help="Host loopback port to bind (default: choose a free port)",
    ),
    open_browser: bool = typer.Option(
        False,
        "--open",
        help="Open the preview URL in the default browser",
    ),
    ttl: str | None = typer.Option(
        None,
        "--ttl",
        help="Close automatically after a duration like 30s, 10m, or 1h",
    ),
    start_vnc: bool = typer.Option(
        False,
        "--start-vnc",
        help="Start/restart SafeYolo's optional guest desktop before previewing",
    ),
    vnc_size: str | None = typer.Option(
        None,
        "--vnc-size",
        help="noVNC size override used with --start-vnc or --browser: auto or WIDTHxHEIGHT",
    ),
    browser_url: str | None = typer.Option(
        None,
        "--browser",
        "-b",
        help="Start the guest desktop and open this URL in an available browser",
    ),
    share: str = typer.Option(
        "local",
        "--share",
        help="Preview transport: local or tailnet",
    ),
    tailnet_port: int | None = typer.Option(
        None,
        "--tailnet-port",
        help="Tailnet HTTPS port (default: stable per-agent allocation)",
    ),
) -> None:
    """Preview an agent-local HTTP service from the host browser.

    Creates an explicit, token-gated localhost listener for one running
    agent and one guest port. The browser URL never selects the agent; the
    route is bound to this command's session.
    """
    _validate_instance_name(name)

    from ..platform import get_platform
    from ..preview import (
        PreviewConfig,
        parse_ttl,
        resolve_vnc_geometry,
        serve_agent_preview,
        validate_guest_port,
    )

    try:
        validate_guest_port(guest_port)
        ttl_seconds = parse_ttl(ttl)
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(1)

    plat = get_platform()
    if not plat.is_sandbox_running(name):
        console.print(f"[red]Agent '{name}' is not running.[/red]")
        console.print(f"Start it with: [bold]safeyolo agent start {name}[/bold]")
        raise typer.Exit(1)

    try:
        resolved_tailnet_port, previous_tailnet_port = _resolve_preview_tailnet_port(
            name, share, tailnet_port,
        )
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(1)

    start_novnc = start_vnc or browser_url is not None
    if start_novnc:
        try:
            preferred_size = get_desktop_size()
            vnc_geometry, detected_display_size = resolve_vnc_geometry(
                vnc_size if vnc_size is not None else preferred_size
            )
        except ValueError as exc:
            _rollback_preview_tailnet_port(
                name, resolved_tailnet_port, previous_tailnet_port,
            )
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(1)
        if detected_display_size:
            action = "Starting noVNC"
            if browser_url:
                action += f" and Chromium for {browser_url}"
            console.print(
                f"{action} in '{name}' at {vnc_geometry} "
                f"(host display {detected_display_size[0]}x{detected_display_size[1]})..."
            )
        else:
            action = "Starting noVNC"
            if browser_url:
                action += f" and Chromium for {browser_url}"
            console.print(f"{action} in '{name}' at {vnc_geometry}...")
        if guest_port != 6080:
            console.print(
                f"[yellow]Warning:[/yellow] noVNC starts on guest port 6080; "
                f"this preview is forwarding port {guest_port}."
            )
        stage_guest_desktop_launcher(name, preferred_size=preferred_size)
        command = (
            "SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start "
            f"{shlex.quote(vnc_geometry)}"
        )
        if browser_url:
            command += (
                " && /safeyolo/guest-desktop browser "
                f"{shlex.quote(browser_url)}"
            )
        start_exit = plat.exec_in_sandbox(name, command, user="agent", interactive=False)
        if start_exit != 0:
            _rollback_preview_tailnet_port(
                name, resolved_tailnet_port, previous_tailnet_port,
            )
            raise typer.Exit(start_exit)

    config = PreviewConfig(
        agent=name,
        guest_port=guest_port,
        host_port=host_port,
        ttl_seconds=ttl_seconds,
        open_browser=open_browser,
        display_path="/vnc.html#autoconnect=true&resize=remote" if start_novnc else "/",
        tailnet_port=resolved_tailnet_port,
    )
    try:
        exit_code = serve_agent_preview(config, plat)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _rollback_preview_tailnet_port(
            name, resolved_tailnet_port, previous_tailnet_port,
        )
        console.print(f"[red]Preview failed:[/red] {escape(str(exc))}")
        raise typer.Exit(1)
    raise typer.Exit(exit_code)


@agent_app.command()
def desktop(
    name: str = typer.Argument(..., help="Agent instance name"),
    open_browser: bool = typer.Option(
        False,
        "--open",
        help="Open the token-gated desktop preview in the default browser",
    ),
    ttl: str | None = typer.Option(
        None,
        "--ttl",
        help="Close the host preview after a duration like 30s, 10m, or 1h",
    ),
    size: str | None = typer.Option(
        None,
        "--size",
        "--vnc-size",
        help="Desktop size override: auto or WIDTHxHEIGHT (default: config desktop.size)",
    ),
    remember_size: bool = typer.Option(
        False,
        "--remember-size",
        help="Persist the explicit --size as this host's default",
    ),
    browser_url: str | None = typer.Option(
        None,
        "--browser",
        "-b",
        help="Launch an available guest browser at this URL",
    ),
    host_port: int = typer.Option(
        0,
        "--host-port",
        help="Host loopback port to bind (default: choose a free port)",
    ),
    share: str = typer.Option(
        "local",
        "--share",
        help="Preview transport: local or tailnet",
    ),
    tailnet_port: int | None = typer.Option(
        None,
        "--tailnet-port",
        help="Tailnet HTTPS port (default: stable per-agent allocation)",
    ),
    status: bool = typer.Option(
        False,
        "--status",
        help="Report guest desktop status without opening a preview",
    ),
    stop: bool = typer.Option(
        False,
        "--stop",
        help="Stop the guest desktop stack",
    ),
) -> None:
    """Start and securely access an optional graphical agent desktop.

    SafeYolo owns desktop lifecycle and preview security. The running agent's
    rootfs only needs to supply the graphical packages and optional browser.
    """
    _validate_instance_name(name)
    if status and stop:
        console.print("[red]Use only one of --status or --stop.[/red]")
        raise typer.Exit(2)
    if (status or stop) and (
        open_browser or ttl is not None or browser_url is not None
        or host_port != 0 or size is not None or share != "local"
        or tailnet_port is not None or remember_size
    ):
        console.print(
            "[red]--status and --stop cannot be combined with preview or browser options.[/red]"
        )
        raise typer.Exit(2)
    if remember_size and size is None:
        console.print("[red]--remember-size requires an explicit --size.[/red]")
        raise typer.Exit(2)

    from ..platform import get_platform
    from ..preview import (
        PreviewConfig,
        parse_ttl,
        resolve_vnc_geometry,
        serve_agent_preview,
    )

    platform = get_platform()
    if not platform.is_sandbox_running(name):
        console.print(f"[red]Agent '{escape(name)}' is not running.[/red]")
        console.print(f"Start it with: [bold]safeyolo agent start {escape(name)}[/bold]")
        raise typer.Exit(1)

    if status or stop:
        stage_guest_desktop_launcher(name)
        action = "status" if status else "stop"
        exit_code = platform.exec_in_sandbox(
            name,
            f"/safeyolo/guest-desktop {action}",
            user="agent",
            interactive=False,
        )
        raise typer.Exit(exit_code)

    try:
        preferred_size = get_desktop_size()
        geometry, detected_display_size = resolve_vnc_geometry(
            size if size is not None else preferred_size
        )
        ttl_seconds = parse_ttl(ttl)
        resolved_tailnet_port, previous_tailnet_port = _resolve_preview_tailnet_port(
            name, share, tailnet_port,
        )
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(1)

    if remember_size:
        remembered_size = size.strip().lower()
        config = load_config()
        desktop_config = config.setdefault("desktop", {})
        if not isinstance(desktop_config, dict):
            console.print("[red]desktop config must be a mapping[/red]")
            raise typer.Exit(1)
        desktop_config["size"] = remembered_size
        save_config(config)
        preferred_size = remembered_size
        console.print(
            f"[green]Remembered host desktop size:[/green] {remembered_size}"
        )

    stage_guest_desktop_launcher(name, preferred_size=preferred_size)

    if detected_display_size:
        console.print(
            f"Starting desktop in '{escape(name)}' at {geometry} "
            f"(host display {detected_display_size[0]}x{detected_display_size[1]})..."
        )
    else:
        console.print(f"Starting desktop in '{escape(name)}' at {geometry}...")

    command = (
        "SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start "
        f"{shlex.quote(geometry)}"
    )
    if browser_url:
        command += (
            " && /safeyolo/guest-desktop browser "
            f"{shlex.quote(browser_url)}"
        )
    start_exit = platform.exec_in_sandbox(
        name, command, user="agent", interactive=False,
    )
    if start_exit != 0:
        _rollback_preview_tailnet_port(
            name, resolved_tailnet_port, previous_tailnet_port,
        )
        raise typer.Exit(start_exit)

    config = PreviewConfig(
        agent=name,
        guest_port=6080,
        host_port=host_port,
        ttl_seconds=ttl_seconds,
        open_browser=open_browser,
        display_path="/vnc.html#autoconnect=true&resize=remote",
        tailnet_port=resolved_tailnet_port,
    )
    try:
        exit_code = serve_agent_preview(config, platform)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _rollback_preview_tailnet_port(
            name, resolved_tailnet_port, previous_tailnet_port,
        )
        console.print(f"[red]Desktop preview failed:[/red] {escape(str(exc))}")
        raise typer.Exit(1)
    raise typer.Exit(exit_code)


@agent_app.command()
@profiled_command("agent stop")
def stop(
    name: str = typer.Argument(..., help="Agent instance name to stop"),
    profile: bool = typer.Option(
        False,
        "--profile",
        help="Profile lifecycle phases and write a JSONL timing artifact",
    ),
) -> None:
    """Stop a running agent sandbox.

    Examples:

        safeyolo agent stop myproject
    """
    _t("validate agent and inspect sandbox state")
    _validate_instance_name(name)

    from ..agent_lifecycle import AgentLifecycleError, stop_agent_by_name
    try:
        observed = stop_agent_by_name(name, on_phase=_t)
    except AgentLifecycleError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        console.print(f"Run `safeyolo agent diagnostics {name}` and retry.")
        raise typer.Exit(1)
    console.print_json(data=observed)


@agent_app.command(name="rebuild-snapshot")
def rebuild_snapshot(
    name: str = typer.Argument(..., help="Agent instance name"),
) -> None:
    """Delete an agent's warm-boot snapshot so the next run re-captures.

    Use this when you suspect a snapshot is stale or corrupt, or after
    a guest/kernel/CA change that the version fingerprint didn't catch.

    Examples:

        safeyolo agent rebuild-snapshot myproject
    """
    _validate_instance_name(name)
    invalidate_snapshot(name)
    console.print(f"[green]Snapshot invalidated for {name}.[/green]")
    console.print("  Next run will cold-boot and re-capture.")


def _load_vault():
    """Import Vault class and return an unlocked vault instance.

    Returns (Vault, VaultCredential) tuple.
    """
    from .vault import _load_vault as vault_loader

    return vault_loader()


def _auto_credential_name(service_name: str, existing_names: list[str]) -> str:
    """Generate a unique credential name like {service}-cred, {service}-cred-2, etc."""
    base = f"{service_name}-cred"
    if base not in existing_names:
        return base
    n = 2
    while f"{base}-{n}" in existing_names:
        n += 1
    return f"{base}-{n}"


def _load_policy_hosts() -> dict:
    """Load hosts section from policy file (TOML or YAML)."""
    from ..config import _get_config_dir_path

    config_dir = _get_config_dir_path()

    # Prefer .toml, fall back to .yaml
    toml_path = config_dir / "policy.toml"
    yaml_path = config_dir / "policy.yaml"

    if toml_path.exists():
        try:
            import tomlkit

            raw = tomlkit.parse(toml_path.read_text())
            hosts = raw.get("hosts", {})
            # Normalize TOML field names: allow->credentials, rate->rate_limit
            result = {}
            for host, config in hosts.items():
                if isinstance(config, dict):
                    entry = {}
                    for k, v in config.items():
                        if k == "allow":
                            entry["credentials"] = v
                        elif k == "rate":
                            entry["rate_limit"] = v
                        elif k == "unknown_creds":
                            entry["unknown_credentials"] = v
                        else:
                            entry[k] = v
                    result[host] = entry
                else:
                    result[host] = config
            return result
        except (OSError, ValueError):
            pass  # Best-effort: invalid TOML is not fatal here

    if yaml_path.exists():
        try:
            raw = yaml.safe_load(yaml_path.read_text())
            if raw and isinstance(raw, dict):
                return raw.get("hosts", {})
        except (OSError, yaml.YAMLError):
            pass  # Best-effort: missing or invalid policy is not fatal here

    return {}


@agent_app.command()
def authorize(  # DOC: docs/SERVICE_DISCOVERY.md
    agent_name: str = typer.Argument(..., help="Agent instance name"),
    service_name: str = typer.Argument(..., help="Service to authorize"),
    capability: str = typer.Option(None, "--capability", "-c", help="Capability within the service"),
    token: str = typer.Option(None, "--token", help="Credential value (inline)"),
    token_file: Path = typer.Option(None, "--token-file", help="Read credential from file"),
    token_env: str = typer.Option(None, "--token-env", help="Read credential from environment variable"),
    credential_name: str = typer.Option(None, "--credential-name", "-n", help="Reuse existing vault credential"),
) -> None:
    """Authorize an agent to use a service.

    Resolves the service, picks a capability, stores a credential when the
    service requires one, and updates policy.toml. Operator-sourced bindings require a
    separate agent-side binding submission and operator approval.

    Examples:

        safeyolo agent authorize boris gmail --capability read_and_send --token-env GMAIL_TOKEN
        safeyolo agent authorize boris slack --token-file ~/slack.key
        safeyolo agent authorize boris gmail --credential-name gmail-oauth2
    """
    from ._service_discovery import ServiceDiscoveryError, find_service

    # 1. Validate agent exists
    _validate_instance_name(agent_name)

    metadata = _load_agent_metadata(agent_name)
    if not metadata:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' not found")
        raise typer.Exit(1)

    # 2. Resolve service
    try:
        svc = find_service(service_name)
    except ServiceDiscoveryError as error:
        console.print(f"[red]Service definitions failed to load:[/red] {escape(str(error))}")
        raise typer.Exit(1) from error
    if not svc:
        console.print(f"[red]Error:[/red] Service '{escape(service_name)}' not found")
        raise typer.Exit(1)

    capabilities = svc.get("capabilities", {})
    if not capabilities:
        console.print(f"[red]Error:[/red] Service '{escape(service_name)}' has no capabilities defined")
        raise typer.Exit(1)

    # 3. Resolve capability
    cap_names = list(capabilities.keys())
    if capability:
        if capability not in capabilities:
            console.print(f"[red]Error:[/red] Capability '{escape(capability)}' not found in {escape(service_name)}")
            console.print(f"Available capabilities: {', '.join(escape(c) for c in cap_names)}")
            raise typer.Exit(1)
        selected_cap = capability
    elif len(cap_names) == 1:
        selected_cap = cap_names[0]
        console.print(f"Auto-selected capability: [cyan]{escape(selected_cap)}[/cyan]")
    else:
        console.print("Available capabilities:")
        for i, cn in enumerate(cap_names, 1):
            desc = capabilities[cn].get("description", "")
            desc_str = f" -- {escape(desc)}" if desc else ""
            console.print(f"  \\[{i}] {escape(cn)}{desc_str}")
        choice = input("Select capability [1]: ").strip()
        if not choice:
            choice = "1"
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(cap_names):
                raise ValueError
            selected_cap = cap_names[idx]
        except ValueError:
            console.print("[red]Error:[/red] Invalid selection")
            raise typer.Exit(1)

    auth_config = svc.get("auth")
    requires_credential = auth_config is not None
    auth_config = auth_config or {}
    auth_type = auth_config.get("type", "bearer")

    # 4. Resolve credential
    vault = None
    VaultCredential = None
    cred_name = None

    if not requires_credential and not (credential_name or token or token_file or token_env):
        pass
    elif credential_name:
        # Reuse existing vault entry
        vault, VaultCredential = _load_vault()
        existing = vault.get(credential_name)
        if not existing:
            console.print(f"[red]Error:[/red] Credential '{escape(credential_name)}' not found in vault")
            names = vault.list_names()
            if names:
                console.print(f"Available: {', '.join(escape(n) for n in names)}")
            raise typer.Exit(1)
        cred_name = credential_name
    elif token or token_file or token_env:
        # Store new credential in vault
        if token:
            cred_value = token
        elif token_file:
            if not token_file.exists():
                console.print(f"[red]Error:[/red] File not found: {token_file}")
                raise typer.Exit(1)
            cred_value = token_file.read_text().strip()
        else:
            cred_value = os.environ.get(token_env, "")
            if not cred_value:
                console.print(f"[red]Error:[/red] Environment variable '{escape(token_env)}' is empty or not set")
                raise typer.Exit(1)

        vault, VaultCredential = _load_vault()
        existing_names = vault.list_names()
        cred_name = _auto_credential_name(service_name, existing_names)
        cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
        vault.store(cred)
        console.print(f"[green]Stored credential:[/green] {escape(cred_name)} (type={escape(auth_type)})")
    else:
        # Interactive flow
        vault, VaultCredential = _load_vault()
        existing_names = vault.list_names()
        matching = [n for n in existing_names if n.startswith(f"{service_name}-")]

        if matching:
            console.print("Existing credentials:")
            for i, n in enumerate(matching, 1):
                console.print(f"  \\[{i}] {escape(n)}")
            console.print(f"  \\[{len(matching) + 1}] Paste new")
            choice = input("Select [1]: ").strip()
            if not choice:
                choice = "1"
            try:
                idx = int(choice) - 1
                if idx < 0 or idx > len(matching):
                    raise ValueError
                if idx < len(matching):
                    cred_name = matching[idx]
                else:
                    # Paste new
                    cred_value = getpass.getpass("Credential value: ")
                    if not cred_value:
                        console.print("[red]Error:[/red] Empty credential value")
                        raise typer.Exit(1)
                    cred_name = _auto_credential_name(service_name, existing_names)
                    cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
                    vault.store(cred)
                    console.print(f"[green]Stored credential:[/green] {escape(cred_name)} (type={escape(auth_type)})")
            except ValueError:
                console.print("[red]Error:[/red] Invalid selection")
                raise typer.Exit(1)
        else:
            cred_value = getpass.getpass("Credential value: ")
            if not cred_value:
                console.print("[red]Error:[/red] Empty credential value")
                raise typer.Exit(1)
            cred_name = _auto_credential_name(service_name, existing_names)
            cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
            vault.store(cred)
            console.print(f"[green]Stored credential:[/green] {escape(cred_name)} (type={escape(auth_type)})")

    # 6. Write to policy.toml (via admin API, with fallback to local write)
    try:
        from ..api import APIError, get_api

        api = get_api()
        api.authorize_service(
            agent=agent_name,
            service=service_name,
            capability=selected_cap,
            credential=cred_name,
        )
    except APIError as exc:
        if exc.status_code is not None:
            console.print(f"[red]Authorization refused by running gateway:[/red] {escape(str(exc))}")
            raise typer.Exit(1) from exc
        log.warning("Admin API unavailable (%s), falling back to local write", exc)
        services = metadata.setdefault("services", {})
        services[service_name] = {"capability": selected_cap}
        if cred_name is not None:
            services[service_name]["token"] = cred_name
        save_agent(agent_name, metadata)
    except OSError as exc:
        log.warning("Admin API unavailable (%s), falling back to local write", exc)
        services = metadata.setdefault("services", {})
        services[service_name] = {"capability": selected_cap}
        if cred_name is not None:
            services[service_name]["token"] = cred_name
        save_agent(agent_name, metadata)

    esc_agent = escape(agent_name)
    esc_svc = escape(service_name)
    esc_cap = escape(selected_cap)
    credential_summary = f", credential={escape(cred_name)}" if cred_name is not None else ""
    console.print(f"\n[green]Authorized:[/green] {esc_agent} → {esc_svc} (capability={esc_cap}{credential_summary})")

    selected_cap_config = capabilities[selected_cap]
    contract_config = (
        selected_cap_config.get("contract", {})
        if isinstance(selected_cap_config, dict)
        else {}
    )
    bindings_config = (
        contract_config.get("bindings", {})
        if isinstance(contract_config, dict)
        else {}
    )
    contract_template = (
        contract_config.get("template", "")
        if isinstance(contract_config, dict)
        else ""
    )
    if not isinstance(bindings_config, dict):
        bindings_config = {}
    operator_binding_defs = [
        (str(name), binding)
        for name, binding in bindings_config.items()
        if isinstance(binding, dict)
        and binding.get("source", "agent") == "operator"
    ]

    matching_bound_values = None
    contract_bindings = metadata.get("contract_bindings", [])
    if isinstance(contract_bindings, list):
        for binding in contract_bindings:
            if not isinstance(binding, dict):
                continue
            if (
                binding.get("service") == service_name
                and binding.get("capability") == selected_cap
                and binding.get("template", "") == contract_template
            ):
                bound_values = binding.get("bound_values", {})
                if isinstance(bound_values, dict):
                    matching_bound_values = bound_values
                break

    required_operator_bindings = []
    for name, binding in operator_binding_defs:
        if matching_bound_values is None:
            required_operator_bindings.append(name)
            continue
        required_if = binding.get("required_if", {})
        if (
            not required_if
            or not isinstance(required_if, dict)
            or all(
                matching_bound_values.get(key) == value
                for key, value in required_if.items()
            )
        ):
            required_operator_bindings.append(name)

    matching_binding_active = matching_bound_values is not None and all(
        name in matching_bound_values and matching_bound_values[name] is not None
        for name in required_operator_bindings
    )

    if required_operator_bindings and not matching_binding_active:
        console.print(
            f"\n[yellow bold]Setup incomplete:[/yellow bold] {esc_svc}.{esc_cap} "
            "requires operator-sourced contract bindings:"
        )
        for binding_name in required_operator_bindings:
            console.print(f"  - [bold]{escape(binding_name)}[/bold]")
        console.print(
            f"\n[yellow]Contract binding next step:[/yellow] Have agent "
            f"'{esc_agent}' submit the operator-provided values to its Agent API:"
        )
        console.print("    [bold]POST /gateway/submit-binding[/bold]")
        console.print(f"    [dim]service={esc_svc}, capability={esc_cap}[/dim]")
        console.print(
            "\n  Then approve the pending contract binding with "
            "[bold]safeyolo watch[/bold]."
        )

    # 7. Check policy.yaml for host binding
    default_host = svc.get("default_host", "")
    if default_host:
        esc_host = escape(default_host)
        hosts = _load_policy_hosts()
        host_config = hosts.get(default_host)
        if isinstance(host_config, dict) and host_config.get("service") == service_name:
            console.print(f"[green]Host binding found:[/green] {esc_host}")
        else:
            hosts_section = escape("[hosts]")
            console.print(
                f"\n[yellow]Next step:[/yellow] Add to policy.toml under "
                f"{hosts_section}:"
            )
            console.print(
                f"    [bold]safeyolo policy host add {esc_host} "
                f"--service {esc_svc}[/bold]"
            )
            console.print(f"\n  [dim]Verify with: safeyolo policy show --section hosts | grep {esc_svc}[/dim]")
    else:
        hosts_section = escape("[hosts]")
        console.print(
            f"\n[yellow]Next step:[/yellow] Map the service host in policy.toml "
            f"under {hosts_section}:"
        )
        console.print(
            f"    [bold]safeyolo policy host add <your-host> "
            f"--service {esc_svc}[/bold]"
        )
        console.print(f"\n  [dim]Verify with: safeyolo policy show --section hosts | grep {esc_svc}[/dim]")


@agent_app.command()
def revoke(
    agent_name: str = typer.Argument(..., help="Agent instance name"),
    service_name: str = typer.Argument(..., help="Service to revoke"),
) -> None:
    """Revoke an agent's access to a service.

    Removes the service binding from policy.toml. The vault credential
    is preserved (print reminder to remove manually).

    Examples:

        safeyolo agent revoke boris gmail
    """
    # 1. Load agent metadata
    _validate_instance_name(agent_name)

    metadata = _load_agent_metadata(agent_name)
    if not metadata:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' not found")
        raise typer.Exit(1)

    services = metadata.get("services", {})
    if service_name not in services:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' is not authorized for '{escape(service_name)}'")
        raise typer.Exit(1)

    # 2. Note credential name before removing
    service_entry = services[service_name]
    cred_name = service_entry.get("token", "") if isinstance(service_entry, dict) else ""

    # 3. Remove service entry (via admin API, with fallback to local write)
    try:
        from ..api import APIError, get_api

        api = get_api()
        result = api.revoke_service(agent=agent_name, service=service_name)
        cred_name = result.get("credential", cred_name)
    except (APIError, OSError) as exc:
        log.warning("Admin API unavailable (%s), falling back to local write", exc)
        del services[service_name]
        if not services:
            del metadata["services"]
        save_agent(agent_name, metadata)

    # 4. Confirm
    console.print(f"[green]Revoked:[/green] {escape(agent_name)} → {escape(service_name)}")

    # 5. Credential reminder (only if it actually exists in vault)
    if cred_name:
        try:
            vault, _ = _load_vault()
            if vault.get(cred_name):
                console.print(
                    f"Credential '{escape(cred_name)}' still in vault. "
                    f"To remove: [bold]safeyolo vault remove {escape(cred_name)}[/bold]"
                )
        except (OSError, ValueError):
            pass  # Vault unavailable or locked -- skip reminder
