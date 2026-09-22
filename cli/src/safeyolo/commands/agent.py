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
    DEFAULT_AGENT_MEMORY_MB,
    _parse_mount,
    _validate_instance_name,
)
from ..agent_lifecycle import (
    _agent_host_setup_lock,
    _check_project_ownership,
    _load_agent_metadata,
    _run_agent,
    write_event,
)
from ..agents_store import (
    load_all_agents,
    mutate_agent,
    reserve_agent_tailnet_port_change,
    restore_agent_tailnet_port,
    save_agent,
)
from ..agents_store import remove_agent as _store_remove_agent
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
from .agent_vm import vm_app
from .tmux import associate_agent_pane

log = logging.getLogger("safeyolo.agent")
console = Console()


agent_app = typer.Typer(
    name="agent",
    help="Manage AI agent sandboxes.",
    no_args_is_help=True,
)
agent_app.add_typer(vm_app, name="vm")


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
    no_rename_window: bool = typer.Option(
        False,
        "--no-rename-window",
        help="Don't rename the invoking tmux window to the agent name (auto-run only).",
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
                    exit_code = _run_agent(
                        name,
                        dangerously_allow_unowned=dangerously_allow_unowned,
                        no_snapshot=True,
                        rename_tmux_window=not no_rename_window,
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
                        "Use --force to overwrite, or 'safeyolo agent run' to run existing."
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
    cfg = load_config()
    panel_lines.append(f"Proxy: http://127.0.0.1:{cfg.get('proxy', {}).get('port', 8080)} (via in-guest forwarder)")
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
        exit_code = _run_agent(
            name,
            dangerously_allow_unowned=dangerously_allow_unowned,
            no_snapshot=True,
            rename_tmux_window=not no_rename_window,
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

            runtimes = {runtime.name: runtime for runtime in list_agent_runtimes()}
            for inst_dir in sorted(instances, key=lambda d: d.name):
                metadata = all_agents.get(inst_dir.name, {})
                folder = metadata.get("folder", "?")
                host_script = metadata.get("host_script", "")
                runtime = runtimes.get(inst_dir.name)
                launcher = runtime.launcher if runtime else None
                label = f"{launcher.get('script') or launcher['kind']} ({launcher['source']})" if launcher else "unknown"
                table.add_row(inst_dir.name, folder, host_script,
                              runtime.sandbox_state if runtime else "unknown",
                              runtime.agent_state if runtime else "unknown", label)
            console.print(table)
        else:
            console.print("[dim]No agents configured.[/dim]")
    else:
        console.print("[dim]No agents configured.[/dim]")


@agent_app.command()
def remove(
    name: str = typer.Argument(..., help="Agent instance name to remove"),
) -> None:
    """Remove an agent configuration.

    Stops the sandbox if running, tears down per-agent networking
    (netns + veth), and deletes the agent's on-disk state.

    Examples:

        safeyolo agent remove claude-code
    """
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agents_dir = get_agents_dir()
    agent_dir = agents_dir / name
    if not agent_dir.exists():
        console.print(f"[yellow]Agent not found: {escape(name)}[/yellow]")
        raise typer.Exit(1)

    from ..platform import get_platform
    plat = get_platform()

    # Mark the command supervisor before touching the sandbox. If the host
    # supervisor cannot be identified and stopped, leave everything intact so
    # a command cannot be restarted after its agent is being removed.
    from ..agent_command_supervisor import request_command_supervisor_stop

    if not request_command_supervisor_stop(name):
        console.print(
            f"[red]Could not stop the command supervisor for {name}.[/red]\n"
            "The agent was not removed to prevent an automatic restart. "
            f"Run `safeyolo agent diag {name}` and retry."
        )
        raise typer.Exit(1)

    # Read the persistent network slot before removing agent metadata. Current
    # platforms have no host-side interface to tear down, but preserving the
    # platform contract here avoids reintroducing name-order allocation.
    network_slot = _load_agent_metadata(name).get("network_slot")
    agent_index = network_slot if type(network_slot) is int else -1
    from ..agent_launchers import stop_launcher, wait_for_launcher_exit

    stop_launcher(name)

    # stop_sandbox is idempotent on both platforms (Linux probes runsc
    # state first; Darwin's stop_vm returns early if no pid). Calling
    # unconditionally ensures cleanup of `stopped` or `created` runsc
    # containers too, which is_sandbox_running() doesn't report as running
    # and therefore the old conditional skipped -- leaving stale state
    # that broke the next `runsc create`.
    if plat.is_sandbox_running(name):
        console.print(f"  Stopping {name}...")
    plat.stop_sandbox(name)
    wait_for_launcher_exit(name)

    # Teardown per-agent networking. Linux's stop_sandbox already did
    # this (idempotent netns delete), but Darwin's didn't -- it only
    # shuts the VM down. Explicit call here keeps the remove semantics
    # consistent across platforms: after remove, the agent has no
    # residual networking state.
    if agent_index >= 0:
        try:
            plat.teardown_networking(agent_index)
        except Exception as err:
            console.print(f"[yellow]  Warning: network teardown failed: {err}[/yellow]")

    # Delete the agent's on-disk state. Platform-dispatched because on Linux
    # overlayfs leaves root-owned directories behind after unmount, which a
    # plain shutil.rmtree can't clean up.
    plat.remove_agent_dir(name)
    _store_remove_agent(name)
    # Drop the per-agent UnixInstance if mitmproxy is running.
    config = load_config()
    admin_port = config.get("proxy", {}).get("admin_port", 9090)
    from ..proxy import sync_proxy_modes
    sync_proxy_modes(admin_port=admin_port)
    write_event("agent.removed", kind="agent", severity="low", summary=f"Agent {name} removed", agent=name)
    console.print(f"[green]Removed agent: {name}[/green]")


@agent_app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
@profiled_command("agent run")
def run(  # DOC: README.md, docs/AGENTS.md
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Agent instance name to run"),
    folder: str = typer.Option(None, "--folder", "-f", help="Override folder to mount (default: from agent add)"),
    host_script: str = typer.Option(
        None,
        "--host-script",
        help="Run/reapply a host setup script before booting this existing agent",
    ),
    yolo: bool = typer.Option(True, "--yolo/--no-yolo", help="Auto-accept mode (skips permission prompts)"),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore user_default_args, start fresh session"),
    detach: bool = typer.Option(
        False,
        "--detach",
        "-d",
        help="Run the agent in a persistent host session or its configured manager",
    ),
    sandbox_only: bool = typer.Option(False, "--sandbox-only", help="Boot only the sandbox; do not launch an agent or hooks"),
    interactive: bool = typer.Option(False, "--interactive", help="Temporarily run a stopped managed agent's interactive harness"),
    mount: list[str] = typer.Option(
        [],
        "--mount",
        "-m",
        help="Extra folder to mount (/local/path:/container/path[:ro], repeatable, one-off)",
    ),
    port: list[str] = typer.Option(
        [],
        "--port",
        help="Expose container port to host (host_port:container_port, repeatable, one-off)",
    ),
    dangerously_allow_unowned: bool = typer.Option(
        False,
        "--dangerously-allow-unowned",
        help="Allow mounting directories you don't own",
    ),
    snapshot: bool = typer.Option(
        False,
        "--snapshot",
        help="Enable warm-boot snapshot capture/restore (currently disabled by "
             "default while we investigate a VZ save incompatibility with the "
             "new vsock proxy relay).",
    ),
    profile: bool = typer.Option(
        False,
        "--profile",
        help="Profile lifecycle phases and write a JSONL timing artifact",
    ),
    no_rename_window: bool = typer.Option(
        False,
        "--no-rename-window",
        help="Don't rename the invoking tmux window to the agent name.",
    ),
) -> None:
    """Run the coding agent in an existing or newly started sandbox.

    Starts SafeYolo if not running, then launches the agent container.
    Yolo mode is on by default (auto-accepts permission prompts).
    Use --no-yolo to require manual approval.

    Pass agent-specific flags after '--':

        safeyolo agent run boris -- --continue
        safeyolo agent run boris -- --resume my-session

    Detach mode starts a persistent host session (or the configured manager):

        safeyolo agent run myproject --detach
        safeyolo agent attach myproject # reconnect to the same agent
        safeyolo agent stop myproject   # stop when done

    Use --sandbox-only to boot without running an agent. 'agent shell' opens
    an independent guest shell and never launches the configured harness.

    If user_default_args is configured (via 'agent config'), those args
    are used by default. Use --fresh to ignore them.

    Persistent mounts (from 'agent add --mount' or 'agent config --add-mount')
    are always included. Use --mount/-m here for additional one-off mounts.
    Use --host-script to apply or refresh a host setup script on an existing
    agent before boot; the script can update /home/agent and
    .safeyolo-command.

    Examples:

        safeyolo agent run myproject
        safeyolo agent run myproject -f ~/other/folder
        safeyolo agent run myproject --no-yolo
        safeyolo agent run myproject --detach
        safeyolo agent run myproject --host-script contrib/codex-host-setup.sh
        safeyolo agent run myproject --mount ~/data:/data:ro
        safeyolo agent run myproject --port 6080:6080
        safeyolo agent run myproject -- --continue
        safeyolo agent run myproject --fresh
    """
    _t("agent command validation and host setup")
    if sandbox_only and interactive:
        raise typer.BadParameter("--sandbox-only does not launch an interactive agent")
    # ctx.args contains everything after '--'
    agent_args = ctx.args if ctx.args else None

    # Validate transient mount specs
    parsed_mounts = [_parse_mount(m) for m in mount]

    # Validate transient port specs
    parsed_ports = [_parse_port(p) for p in port]

    host_script_path = _resolve_host_script_path(host_script)
    if host_script_path is not None:
        metadata = _load_agent_metadata(name)
        if not metadata:
            console.print(f"[red]Agent '{name}' is not configured.[/red]")
            console.print("Create it first with: [bold]safeyolo agent add[/bold]")
            raise typer.Exit(1)
        folder_for_script = folder or metadata.get("folder")
        if not folder_for_script:
            console.print(f"[red]Agent '{name}' has no configured folder.[/red]")
            raise typer.Exit(1)
        folder_path = Path(folder_for_script).expanduser().resolve()
        if not folder_path.is_dir():
            console.print(f"[red]Folder not found: {folder_path}[/red]")
            raise typer.Exit(1)
        _check_project_ownership(folder_path, dangerously_allow_unowned)
        _run_host_script_for_agent(
            name=name,
            host_script_path=host_script_path,
            folder_str=str(folder_path),
        )

        # The setup script can take arbitrarily long. Persist only its selected
        # path against the latest authoritative record so a concurrent config,
        # reservation, grant, or identity update cannot be overwritten by the
        # metadata snapshot loaded before the script ran.
        def persist_host_script(current):
            current["host_script"] = str(host_script_path)
            if host_script in {"@codex-coord", "@pi-coord"}:
                current["launcher"] = "supervisor"

        try:
            mutate_agent(name, persist_host_script)
        except KeyError:
            console.print(
                f"[red]Agent '{name}' was removed while its host script was running.[/red]"
            )
            console.print(
                "The setup script completed, but SafeYolo did not recreate the "
                "deleted configuration."
            )
            raise typer.Exit(1)

    associate_agent_pane(name)
    # A terminal reached over SSH is a viewer, not a durable process owner.
    # Host tmux already provides ownership when invoked inside that session.
    remote_viewer = bool(os.environ.get("SSH_CONNECTION") and not os.environ.get("TMUX"))
    exit_code = _run_agent(
        name,
        folder_override=folder,
        yolo=yolo,
        dangerously_allow_unowned=dangerously_allow_unowned,
        agent_args=agent_args,
        skip_default_args=fresh,
        extra_mounts=parsed_mounts if parsed_mounts else None,
        extra_ports=parsed_ports if parsed_ports else None,
        launch_mode="sandbox" if sandbox_only else "background" if detach or remote_viewer else "foreground",
        interactive=interactive,
        no_snapshot=not snapshot,
        rename_tmux_window=not detach and not no_rename_window,
    )
    if remote_viewer and not detach and not sandbox_only and exit_code == 0:
        from ..agent_launchers import attach_agent, read_launch

        current = read_launch(name)
        if current and current["launcher"]["kind"] != "supervisor":
            exit_code = attach_agent(name)
    raise typer.Exit(exit_code)


@agent_app.command()
def shell(  # DOC: docs/agent-debugging.md
    name: str = typer.Argument(..., help="Agent instance name"),
    command: str = typer.Option(None, "--command", "-c", help="Run a command instead of interactive shell"),
    persistent: bool = typer.Option(False, "--persistent", help="Open or reattach a host-tmux-backed operator shell"),
    root: bool = typer.Option(
        False,
        "--root",
        help="Operator recovery shell as guest root (default: agent user)",
    ),
    agent_command: bool = typer.Option(False, "--agent-command", help="Run the launcher's configured guest entrypoint in this terminal"),
    launch_id: str | None = typer.Option(None, "--launch-id", help="Current launch identity supplied by the host launcher"),
) -> None:
    """Open a shell in a running agent sandbox.

    By default, opens as the non-root agent user. Agents can use the in-guest
    sudo helper for routine package installation; --root is the
    operator-mediated recovery path. Use -c to run a single command and
    return its exit code.

    Examples:

        safeyolo agent shell myproject
        safeyolo agent shell myproject --root
        safeyolo agent shell myproject -c "uname -a"
        safeyolo agent shell myproject -c "pytest -v /tests"
    """
    _validate_instance_name(name)

    if persistent and (command is not None or agent_command or launch_id):
        raise typer.BadParameter("--persistent opens an interactive operator shell; it cannot be combined with --command, --agent-command, or --launch-id")

    if agent_command:
        if command or root or not launch_id:
            raise typer.BadParameter("--agent-command requires --launch-id and cannot be combined with --command or --root")
        from ..agent_launchers import run_entrypoint

        raise typer.Exit(run_entrypoint(name, launch_id))

    from ..platform import get_platform
    plat = get_platform()

    if not plat.is_sandbox_running(name):
        console.print(f"[red]Agent '{name}' is not running.[/red]")
        console.print(f"Start it with: [bold]safeyolo agent run {name}[/bold]")
        raise typer.Exit(1)

    if persistent:
        from ..shell_sessions import open_persistent_shell

        try:
            exit_code = open_persistent_shell(name, root=root)
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(1) from None
        raise typer.Exit(exit_code)

    user = "root" if root else "agent"
    exit_code = plat.exec_in_sandbox(
        name, command, user=user, interactive=not command,
    )
    raise typer.Exit(exit_code)


@agent_app.command()
def attach(name: str = typer.Argument(..., help="Agent whose existing terminal session to attach")) -> None:
    """Attach to an existing coding-agent session without starting another one."""
    from ..agent_launchers import attach_agent

    try:
        code = attach_agent(name)
    except RuntimeError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(1) from None
    raise typer.Exit(code)


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
        console.print(f"Start it with: [bold]safeyolo agent run {name}[/bold]")
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
        console.print(f"Start it with: [bold]safeyolo agent run {escape(name)}[/bold]")
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
def diag(
    name: str = typer.Argument(..., help="Agent instance name to diagnose"),
    hang: bool = typer.Option(False, "--hang", help="Save a bounded macOS VM hang dump through its independent control socket"),
) -> None:
    """Probe agent egress and, on macOS, the shell and VM helper control paths.

    Runs through the hops from the agent out to mitmproxy and back,
    checking each link:
        agent map entry → proxy socket → attribution IP →
        mitmproxy process → VM process → command supervisor → proxy transport →
        authenticated Agent API + source attribution

    On macOS, also require a bounded SSH banner and inspect the running helper's
    identity, relay counters and executor health. --hang saves a private JSON
    dump through the independent helper control socket. SSH authentication is
    not performed by this diagnostic.

    Exits 0 if everything checks out, 1 if any link is broken. Output
    is one line per check, PASS/FAIL/WARN prefix, so piping to grep
    FAIL shows you what's wrong at a glance.
    """
    _validate_instance_name(name)
    from ..agent_diag import run_agent_diag  # noqa: PLC0415
    exit_code = run_agent_diag(name, hang=hang)
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
    from ..platform import get_platform

    was_running = get_platform().is_sandbox_running(name)
    if was_running:
        console.print(f"Stopping {name}...")
    try:
        stop_agent_by_name(name, on_phase=_t)
    except AgentLifecycleError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        if "command supervisor" in str(exc):
            console.print(f"Run `safeyolo agent diag {name}` and retry.")
        raise typer.Exit(1)
    if was_running:
        console.print(f"[green]Stopped {name}.[/green]")
    else:
        console.print(f"Agent '{name}' sandbox is not running; command supervisor stopped.")


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


@agent_app.command()
def config(
    name: str | None = typer.Argument(None, help="Agent instance name; omit to configure host launch defaults"),
    launcher: str | None = typer.Option(None, "--launcher", help="interactive, supervisor, tmux-window, tmux-pane, or an absolute script path; empty inherits"),
    default_launcher: str | None = typer.Option(None, "--default-launcher", help="Host-wide launcher for ordinary agents; empty restores built-in defaults"),
    tmux_session: str | None = typer.Option(None, "--tmux-session", help="Shared host tmux session for future launches"),
    folder: str = typer.Option(
        None,
        "--folder",
        "-f",
        help="Set the persistent host folder mounted at /workspace on future runs",
    ),
    dangerously_allow_unowned: bool = typer.Option(
        False,
        "--dangerously-allow-unowned",
        help="Allow a --folder not owned by the current user",
    ),
    user_default_args: str = typer.Option(
        None,
        "--user-default-args",
        help="Set default args for agent CLI (use '' to clear)",
    ),
    memory: int = typer.Option(
        None,
        "--memory",
        min=1,
        help="Set memory in MiB for future runs",
    ),
    add_mount: list[str] = typer.Option(
        [],
        "--add-mount",
        help="Add persistent mount (/local/path:/container/path[:ro], repeatable)",
    ),
    remove_mount: list[str] = typer.Option(
        [],
        "--remove-mount",
        help="Remove persistent mount by container path (repeatable)",
    ),
    clear_mounts: bool = typer.Option(
        False,
        "--clear-mounts",
        help="Remove all persistent mounts",
    ),
    add_port: list[str] = typer.Option(
        [],
        "--add-port",
        help="Add persistent port mapping (host_port:container_port, repeatable)",
    ),
    remove_port: list[str] = typer.Option(
        [],
        "--remove-port",
        help="Remove persistent port mapping by container port (repeatable)",
    ),
    clear_ports: bool = typer.Option(
        False,
        "--clear-ports",
        help="Remove all persistent port mappings",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Show current configuration",
    ),
) -> None:
    """View or update agent configuration.

    Examples:

        safeyolo agent config boris --show
        safeyolo agent config boris --folder ~/code/boris
        safeyolo agent config boris --memory 8192
        safeyolo agent config boris --user-default-args="--continue"
        safeyolo agent config boris --add-mount ~/data:/data
        safeyolo agent config boris --add-mount ~/refs:/refs:ro
        safeyolo agent config boris --remove-mount /data
        safeyolo agent config boris --clear-mounts
        safeyolo agent config boris --add-port 6080:6080
        safeyolo agent config boris --remove-port 6080
        safeyolo agent config boris --clear-ports
    """
    from ..agent_launchers import resolve_launcher, validate_script

    if name is None:
        from ..config import save_config

        if (launcher is not None or folder is not None or memory is not None or user_default_args is not None
                or add_mount or remove_mount or clear_mounts or add_port or remove_port or clear_ports):
            raise typer.BadParameter("Supply an agent name for per-agent settings")
        host_config = load_config()
        defaults = host_config.setdefault("agent_launcher", {})
        if default_launcher is not None:
            selection = resolve_launcher({"launcher": default_launcher}, {}, "background")
            validate_script(selection)
            if selection.kind == "supervisor" or selection.kind == "manager":
                raise typer.BadParameter("Select managers per agent, not as an ordinary-agent default")
            defaults["default"] = default_launcher
        if tmux_session is not None:
            defaults["tmux_session"] = tmux_session
        if default_launcher is not None or tmux_session is not None:
            save_config(host_config)
        table = Table(title="Host agent launch defaults")
        table.add_column("Setting")
        table.add_column("Value", overflow="fold")
        table.add_row("Launcher", defaults.get("default") or "current terminal (foreground), tmux-window (background)")
        table.add_row("Host tmux session", defaults.get("tmux_session", "safeyolo"))
        table.add_row("Optional launcher template", str(_resolve_contrib_file("agent-launcher-template.sh")))
        table.add_row("Configuration prompt", str(_resolve_contrib_file("agent-launcher-prompt.md")))
        console.print(table)
        return
    if default_launcher is not None or tmux_session is not None:
        raise typer.BadParameter("Omit the agent name when changing host launch defaults")
    _validate_instance_name(name)

    metadata = _load_agent_metadata(name)
    if not metadata:
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        raise typer.Exit(1)

    has_updates = (
        launcher is not None
        or folder is not None
        or memory is not None
        or user_default_args is not None
        or add_mount
        or remove_mount
        or clear_mounts
        or add_port
        or remove_port
        or clear_ports
    )

    if show or not has_updates:
        # Show current config
        table = Table(title=f"Agent: {name}")
        table.add_column("Setting", style="bold")
        table.add_column("Value")
        table.add_row("Folder", metadata.get("folder", "?"))
        selected_launcher = resolve_launcher(metadata, load_config(), "background")
        table.add_row("Launcher", f"{selected_launcher.script or selected_launcher.kind} ({selected_launcher.source})")
        configured_memory = metadata.get("memory_mb")
        table.add_row(
            "Memory",
            f"{configured_memory} MiB"
            if configured_memory is not None
            else f"{DEFAULT_AGENT_MEMORY_MB} MiB (default)",
        )
        host_script = metadata.get("host_script")
        if host_script:
            table.add_row("Host script", host_script)
        rootfs_script = metadata.get("rootfs_script")
        if rootfs_script:
            table.add_row("Rootfs script", rootfs_script)
        rootfs_from = metadata.get("rootfs_from")
        if rootfs_from:
            table.add_row("Rootfs cloned from", rootfs_from)
        current_args = metadata.get("user_default_args")
        if current_args:
            table.add_row("Default args", " ".join(current_args))
        else:
            table.add_row("Default args", "[dim]not set[/dim]")
        current_mounts = metadata.get("mounts", [])
        if current_mounts:
            table.add_row("Mounts", "\n".join(current_mounts))
        else:
            table.add_row("Mounts", "[dim]none[/dim]")
        current_ports = metadata.get("ports", [])
        if current_ports:
            table.add_row("Ports", "\n".join(current_ports))
        else:
            table.add_row("Ports", "[dim]none[/dim]")
        tailnet_https_port = metadata.get("tailnet_port")
        table.add_row(
            "Tailnet HTTPS",
            str(tailnet_https_port) if tailnet_https_port else "[dim]not reserved[/dim]",
        )
        console.print(table)
        return

    # Normalize and validate every input before taking the policy mutation
    # lock. In particular this reuses the exact ownership boundary enforced by
    # `agent add` and `agent run`.
    normalized_folder: str | None = None
    if folder is not None:
        folder_path = Path(folder).expanduser().resolve()
        if not folder_path.is_dir():
            console.print(f"[red]Folder not found: {folder_path}[/red]")
            raise typer.Exit(1)
        _check_project_ownership(folder_path, dangerously_allow_unowned)
        normalized_folder = str(folder_path)

    parsed_args = (
        _parse_user_default_args(user_default_args)
        if user_default_args is not None
        else None
    )
    parsed_mounts = [_parse_mount(spec) for spec in add_mount]
    parsed_ports = [_parse_port(spec) for spec in add_port]
    if launcher is not None:
        validate_script(resolve_launcher({"launcher": launcher}, {}, "background"))

    sandbox_running: bool | None = None
    runtime_change_requested = (
        normalized_folder is not None
        and metadata.get("folder") != normalized_folder
    ) or (
        memory is not None
        and metadata.get("memory_mb", DEFAULT_AGENT_MEMORY_MB) != memory
    )
    if runtime_change_requested:
        # Check before committing so a broken platform installation cannot
        # leave a successfully persisted folder paired with a failed command
        # and missing audit record.
        from ..platform import get_platform

        sandbox_running = get_platform().is_sandbox_running(name)

    def apply_updates(current) -> tuple[list[str], list[tuple[str, str]]]:
        changes: list[str] = []
        messages: list[tuple[str, str]] = []

        if launcher is not None:
            if launcher:
                current["launcher"] = launcher
            else:
                current.pop("launcher", None)
            changes.append("launcher")
            messages.append(("green", f"Launcher updated for future runs of {name}"))

        if normalized_folder is not None:
            if current.get("folder") != normalized_folder:
                current["folder"] = normalized_folder
                changes.append("folder")
            else:
                messages.append(("dim", f"Folder unchanged for {name}"))

        if memory is not None:
            old_memory = current.get("memory_mb", DEFAULT_AGENT_MEMORY_MB)
            if old_memory != memory:
                current["memory_mb"] = memory
                changes.append("memory_mb")
            else:
                messages.append(("dim", f"Memory unchanged for {name}"))

        if user_default_args is not None:
            old_args = current.get("user_default_args")
            if parsed_args:
                if old_args != parsed_args:
                    current["user_default_args"] = parsed_args
                    changes.append("user_default_args")
                    messages.append(("green", f"Set user_default_args for {name}: {' '.join(parsed_args)}"))
            elif "user_default_args" in current:
                del current["user_default_args"]
                changes.append("user_default_args")
                messages.append(("green", f"Cleared user_default_args for {name}"))

        old_mounts = list(current.get("mounts", []))
        new_mounts = list(old_mounts)
        if clear_mounts:
            new_mounts = []
            messages.append(("green", f"Cleared all mounts for {name}"))
        for spec in remove_mount:
            before = len(new_mounts)
            new_mounts = [
                mount
                for mount in new_mounts
                if mount.split(":")[1] != spec.rstrip("/")
            ]
            if before != len(new_mounts):
                messages.append(("green", f"Removed mount for {spec}"))
            else:
                messages.append(("yellow", f"No mount found for container path: {spec}"))
        for parsed in parsed_mounts:
            container_path = parsed.split(":")[1]
            new_mounts = [
                mount
                for mount in new_mounts
                if mount.split(":")[1] != container_path
            ]
            new_mounts.append(parsed)
            messages.append(("green", f"Added mount: {parsed}"))
        if new_mounts != old_mounts:
            if new_mounts:
                current["mounts"] = new_mounts
            else:
                current.pop("mounts", None)
            changes.append("mounts")

        old_ports = list(current.get("ports", []))
        new_ports = list(old_ports)
        if clear_ports:
            new_ports = []
            messages.append(("green", f"Cleared all ports for {name}"))
        for spec in remove_port:
            before = len(new_ports)
            new_ports = [
                port
                for port in new_ports
                if port.rsplit(":", 1)[-1] != spec
            ]
            if before != len(new_ports):
                messages.append(("green", f"Removed port mapping for container port {spec}"))
            else:
                messages.append(("yellow", f"No port mapping found for container port: {spec}"))
        for parsed in parsed_ports:
            container_port = parsed.rsplit(":", 1)[-1]
            new_ports = [
                port
                for port in new_ports
                if port.rsplit(":", 1)[-1] != container_port
            ]
            new_ports.append(parsed)
            messages.append(("green", f"Added port: {parsed}"))
        if new_ports != old_ports:
            if new_ports:
                current["ports"] = new_ports
            else:
                current.pop("ports", None)
            changes.append("ports")

        return changes, messages

    try:
        changed, (changes, messages) = mutate_agent(name, apply_updates)
    except KeyError:
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        raise typer.Exit(1)

    for style, message in messages:
        console.print(f"[{style}]{escape(message)}[/{style}]")

    if "folder" in changes:
        console.print(f"[green]Set persistent folder for {name}:[/green] {normalized_folder}")
        if sandbox_running:
            console.print(
                "[yellow]The running sandbox is unchanged:[/yellow] its current "
                "/workspace stays mounted until you stop and run the agent again."
            )
        else:
            console.print("The new folder will be mounted at /workspace on the next run.")

    if "memory_mb" in changes:
        console.print(f"[green]Set memory for {name}:[/green] {memory} MiB")
        if sandbox_running:
            console.print(
                "[yellow]The running sandbox is unchanged:[/yellow] stop and run "
                "the agent again to apply the new memory allocation."
            )
        else:
            console.print("The new memory allocation will apply on the next run.")

    if not changed:
        return

    write_event(
        "agent.config_changed",
        kind="agent",
        severity="low",
        summary=f"Agent {name} config changed: {', '.join(changes)}",
        agent=name,
        details={"changes": changes},
    )


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

    Resolves the service, picks a capability, stores the credential, and updates
    policy.toml. Capabilities with operator-sourced contract bindings require a
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

    # Auth type comes from service-level auth (v1 schema)
    auth_config = svc.get("auth", {})
    auth_type = auth_config.get("type", "bearer")

    # 4. Resolve credential
    vault = None
    VaultCredential = None
    cred_name = None

    if credential_name:
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
        services[service_name] = {"capability": selected_cap, "token": cred_name}
        save_agent(agent_name, metadata)
    except OSError as exc:
        log.warning("Admin API unavailable (%s), falling back to local write", exc)
        services = metadata.setdefault("services", {})
        services[service_name] = {"capability": selected_cap, "token": cred_name}
        save_agent(agent_name, metadata)

    esc_agent = escape(agent_name)
    esc_svc = escape(service_name)
    esc_cap = escape(selected_cap)
    esc_cred = escape(cred_name)

    console.print(f"\n[green]Authorized:[/green] {esc_agent} → {esc_svc} (capability={esc_cap}, credential={esc_cred})")

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
