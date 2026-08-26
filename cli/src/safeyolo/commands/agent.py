"""Agent management commands."""

import getpass
import logging
import os
import re
import shlex
import subprocess
from pathlib import Path, PurePosixPath

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..agents_store import load_agent as _store_load_agent
from ..agents_store import (
    load_all_agents,
    reserve_agent_network_slot,
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
from ..events import EventKind, Severity, write_event
from ..proxy import is_proxy_running, start_proxy, wait_for_healthy
from ..snapshot import (
    compute_snapshot_version,
    invalidate_snapshot,
    is_snapshot_valid,
    platform_supports_snapshot,
    snapshot_path,
    write_snapshot_version,
)
from ..timing import emit as _timing_emit
from ..timing import enter as _t
from ..timing import profiled_command
from ..vm import (
    _update_agent_map,
    build_custom_rootfs,
    clone_custom_rootfs,
    get_agent_config_share_dir,
    get_agent_status_dir,
    prepare_config_share,
    stage_guest_desktop_launcher,
)
from ._service_discovery import find_service
from .mount import is_path_protected
from .tmux import associate_agent_pane, rename_window_for_agent

log = logging.getLogger("safeyolo.agent")
console = Console()



agent_app = typer.Typer(
    name="agent",
    help="Manage AI agent sandboxes.",
    no_args_is_help=True,
)


def _check_project_ownership(project_path: Path, allow_unowned: bool) -> None:
    """Check that user owns the project directory."""
    import os

    try:
        stat_info = project_path.stat()
        if stat_info.st_uid != os.getuid():
            if allow_unowned:
                console.print(f"[yellow]Warning: You don't own {project_path}[/yellow]")
            else:
                console.print(f"[red]You don't own {project_path}[/red]\nUse --dangerously-allow-unowned to override.")
                raise typer.Exit(1)
    except OSError as err:
        console.print(f"[red]Cannot access {escape(str(project_path))}:[/red] {escape(str(err))}")
        raise typer.Exit(1)


def _get_service_name(instance_name: str) -> str:
    """Return the service name for an instance (identity mapping)."""
    return instance_name


# RFC 1123 hostname: lowercase alphanumeric, hyphens allowed (not at start/end), max 63 chars
HOSTNAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _validate_instance_name(name: str) -> None:
    """Validate instance name follows hostname conventions."""
    if not name:
        console.print("[red]Instance name cannot be empty[/red]")
        raise typer.Exit(1)
    if len(name) > 63:
        console.print(f"[red]Instance name too long ({len(name)} chars, max 63)[/red]")
        raise typer.Exit(1)
    if not HOSTNAME_PATTERN.match(name):
        console.print(
            f"[red]Invalid instance name: {escape(name)}[/red]\n"
            "Must be lowercase alphanumeric with hyphens (not at start/end)."
        )
        raise typer.Exit(1)


def _load_agent_metadata(name: str) -> dict:
    """Load agent metadata from policy.toml [agents] section."""
    return _store_load_agent(name)


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
    "mise-shell": "mise-shell-host-setup.sh",
}


def _resolve_host_script_alias(alias: str) -> Path | None:
    """Resolve @alias → bundled contrib/*.sh path, or None if not found.

    Tries the installed-package location first (wheel install path), then
    falls back to the repo-root contrib/ (for `uv tool install --editable .`
    from a checkout where hatch.force-include hasn't been re-run).
    """
    if alias not in _HOST_SCRIPT_ALIASES:
        return None
    script_name = _HOST_SCRIPT_ALIASES[alias]
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
    from ..vm import ensure_agent_persistent_dirs, get_agent_home_dir

    ensure_agent_persistent_dirs(name)
    agent_home = get_agent_home_dir(name)
    env = {
        **os.environ,
        "SAFEYOLO_AGENT_NAME": name,
        "SAFEYOLO_AGENT_HOME": str(agent_home),
        "SAFEYOLO_AGENT_FOLDER": folder_str,
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


def _capture_snapshot_blocking(
    *,
    name: str,
    helper_pid: int,
    config_share_dir: Path,
    version: dict,
    plat,
) -> bool:
    """Drive the safeyolo-vm helper through a snapshot capture.

    Waits for the guest's /safeyolo/static-init-done marker, sends SIGUSR1
    to the helper, waits for snapshot.bin to stop growing, and writes
    snapshot.version.json on success.

    Always writes per-run-go before returning so the guest is never
    stranded on the gate -- even if the snapshot fails, we fall back to
    a normal cold boot and the agent still launches.

    Returns True on success, False if we gave up (snapshot unusable).
    """
    import os
    import signal
    import time as _time

    from ..snapshot import (
        MIN_SNAPSHOT_BYTES,
        snapshot_path,
    )

    status_dir = get_agent_status_dir(name)
    static_done = status_dir / "static-init-done"
    per_run_go = config_share_dir / "per-run-go"
    snap = snapshot_path(name)

    def _give_up(note: str) -> bool:
        invalidate_snapshot(name)
        try:
            per_run_go.write_text("")
        except OSError:
            # Best-effort: if we can't write the gate here, the guest's
            # orchestrator will time out on its 30s wait and proceed
            # regardless. The warning below is what actually matters.
            pass
        log.warning("snapshot capture skipped: %s", note)
        return False

    # Phase 1: wait for the guest to finish static init.
    deadline = _time.time() + 30.0
    while _time.time() < deadline:
        if static_done.exists():
            break
        if not plat.is_sandbox_running(name):
            return _give_up("VM exited before static-init-done")
        _time.sleep(0.05)
    else:
        return _give_up("timeout waiting for static-init-done")

    # Phase 2: tell the helper to snapshot. The Swift side pauses the VM,
    # writes memory to snapshot.bin, clones the per-agent overlay (if
    # attached — ephemeral-mode agents have no disk to clone), and resumes.
    try:
        os.kill(helper_pid, signal.SIGUSR1)
    except ProcessLookupError:
        return _give_up("helper process gone before SIGUSR1")

    # Phase 3: wait for snapshot.bin to appear and stop growing. A 200ms
    # size-stable window is enough to tell we're past VZ's flush.
    deadline = _time.time() + 60.0
    last_size = -1
    stable_since: float | None = None
    while _time.time() < deadline:
        if not plat.is_sandbox_running(name):
            return _give_up("VM died during snapshot")
        if snap.exists():
            try:
                sz = snap.stat().st_size
            except OSError:
                sz = -1
            if sz != last_size:
                last_size = sz
                stable_since = _time.time()
            elif stable_since and (_time.time() - stable_since) >= 0.2 and last_size > 0:
                break
        _time.sleep(0.05)
    else:
        return _give_up("timeout waiting for snapshot to stabilize")

    # Phase 4: sanity-check size and persist our version sidecar.
    if last_size < MIN_SNAPSHOT_BYTES:
        return _give_up(f"snapshot too small ({last_size} bytes)")
    try:
        write_snapshot_version(name, version)
    except OSError as e:
        return _give_up(f"could not write snapshot.version.json: {e}")

    try:
        per_run_go.write_text("")
    except OSError:
        # Guest will timeout on its 30s gate and still proceed; we've
        # written version.json so the snapshot itself is usable.
        pass
    return True


def _linux_interactive_command(
    command_host: Path,
    effective_agent_args: list[str],
    explicit_agent_args: list[str] | None,
) -> str | None:
    """Build the Linux runsc-exec command without losing agent arguments."""
    if command_host.exists() and os.access(command_host, os.X_OK):
        return shlex.join([
            "/home/agent/.safeyolo-command",
            *effective_agent_args,
        ])
    if explicit_agent_args:
        # A plain-shell agent has no host-script command to receive appended
        # arguments, so preserve the existing explicit command override.
        return shlex.join(explicit_agent_args)
    return None


def _run_agent(
    name: str,
    folder_override: str | None = None,
    yolo: bool = False,
    dangerously_allow_unowned: bool = False,
    agent_args: list[str] | None = None,
    skip_default_args: bool = False,
    extra_mounts: list[str] | None = None,
    extra_ports: list[str] | None = None,
    detach: bool = False,
    no_snapshot: bool = False,
    rename_tmux_window: bool = False,
) -> int:
    """Run an agent VM. Returns exit code.

    Shared logic used by both `add` (auto-run) and `run` commands.

    detach: Boot VM in background and return after boot confirmation.
    no_snapshot: skip snapshot capture and restore for this run;
        don't touch an existing snapshot on disk either way.
    rename_tmux_window: rename the invoking tmux window to `name` once
        launch preflight has committed. See issue #330.
    """
    _t("cli entry (metadata, proxy check)")
    _validate_instance_name(name)

    # Rootfs path is platform-specific -- Darwin uses an ext4 disk image file,
    # Linux uses an overlayfs merged directory. Ask the platform which to check.
    from ..platform import get_platform
    rootfs = get_platform().agent_rootfs_path(name)
    if not rootfs.exists():
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        console.print("Run [bold]safeyolo agent add <name> <folder>[/bold] first.")
        raise typer.Exit(1)

    # Load metadata for user_default_args
    metadata = _load_agent_metadata(name)

    # Check SafeYolo proxy is running
    config = load_config()
    proxy_port = config.get("proxy", {}).get("port", 8080)
    admin_port = config.get("proxy", {}).get("admin_port", 9090)
    if not is_proxy_running():
        console.print("[yellow]SafeYolo proxy is not running. Starting...[/yellow]")
        try:
            start_proxy(proxy_port=proxy_port, admin_port=admin_port)
            if not wait_for_healthy(timeout=30):
                console.print("[red]SafeYolo proxy failed to start.[/red]")
                raise typer.Exit(1)
            console.print("[green]SafeYolo proxy started.[/green]\n")
        except Exception as err:
            console.print(f"[red]Failed to start SafeYolo:[/red] {escape(str(err))}")
            raise typer.Exit(1)

    # Check if sandbox is already running
    from ..platform import get_platform as _get_plat
    if _get_plat().is_sandbox_running(name):
        console.print(f"[red]Agent '{name}' is already running.[/red]")
        console.print(
            f"To open a shell in it:  [bold]safeyolo agent shell {name}[/bold]\n"
            f"To stop it first:       [bold]safeyolo agent stop {name}[/bold]\n"
            f"To run another agent:   [bold]safeyolo agent add <new-name> <folder>[/bold]"
        )
        raise typer.Exit(1)

    # Resolve workspace path
    workspace = folder_override or metadata.get("folder", ".")
    workspace_path = Path(workspace).expanduser().resolve()
    if not workspace_path.is_dir():
        console.print(f"[red]Folder not found: {workspace_path}[/red]")
        raise typer.Exit(1)
    _check_project_ownership(workspace_path, dangerously_allow_unowned)

    # Revalidate persistent metadata on every run, merge one-off mounts, and
    # resolve the public CLI syntax to the platform contract. Transient mounts
    # override a persistent mount at the same guest destination for this run.
    extra_shares = _resolve_extra_shares(metadata, extra_mounts)

    # Build agent args string for guest env
    effective_agent_args: list[str] = []
    if agent_args:
        effective_agent_args = list(agent_args)
    elif not skip_default_args and metadata.get("user_default_args"):
        effective_agent_args = list(metadata["user_default_args"])
    agent_args_str = " ".join(effective_agent_args)

    # Extra env for yolo mode
    extra_env = {}
    if yolo:
        extra_env["SAFEYOLO_YOLO_MODE"] = "1"
    if detach:
        extra_env["SAFEYOLO_DETACH"] = "1"
    import sys as _sys
    if _sys.platform == "linux" and not detach:
        extra_env["SAFEYOLO_HOST_TERMINAL"] = "1"

    # Set up network isolation (platform-specific: vsock on macOS, netns on Linux)
    from ..platform import get_platform
    plat = get_platform()

    try:
        agent_index = reserve_agent_network_slot(name)
    except (KeyError, ValueError, OSError) as err:
        console.print(
            f"[red]Agent network allocation failed:[/red] {escape(str(err))}"
        )
        raise typer.Exit(1)

    try:
        _t("setup_networking")
        fw_alloc = plat.setup_networking(agent_index)
        _t("load_firewall_rules")
        subnet = fw_alloc.get("subnet")
        plat.load_firewall_rules(
            proxy_port=proxy_port,
            admin_port=admin_port,
            active_subnets=[subnet] if subnet else [],
        )
    except Exception as err:
        console.print(f"[red]Network isolation failed:[/red] {err}")
        console.print()
        console.print("  SafeYolo will not start an agent without enforced egress control.")
        raise typer.Exit(1)

    gateway_ip = fw_alloc["host_ip"]
    guest_ip = fw_alloc["guest_ip"]

    # Identity attribution: `attribution_ip` is the source IP mitmproxy
    # sees, which service_discovery maps back to the agent name.
    # Per-agent UDS lives at `<sockets_dir>/<ip>_<agent>/proxy.sock` —
    # mitmproxy's UnixInstance binds it and parses identity from the
    # directory name. agent_map.json is written before start_sandbox so
    # service_discovery is ready when the first request arrives, and
    # the admin-API call below triggers mitmproxy to bind the socket.
    attribution_ip = fw_alloc.get("attribution_ip", guest_ip)
    from ..sockets import path_for as _sock_path_for
    try:
        sock_path_p = _sock_path_for(name, attribution_ip)
    except ValueError as exc:
        console.print(f"[red]Invalid agent socket path:[/red] {exc}")
        raise typer.Exit(1)
    sock_path = str(sock_path_p)
    _t("write agent attribution map")
    _update_agent_map(name, ip=attribution_ip, socket=sock_path)

    if fw_alloc.get("needs_bridge_socket"):
        # Push the updated mode list to mitmproxy so it spawns the
        # UnixInstance and creates the per-agent socket file. Best
        # effort: if the admin call fails (mitmproxy not running),
        # the socket will be bound on next proxy start via
        # `_initial_mode_specs`.
        from ..proxy import sync_proxy_modes
        _t("synchronize proxy listener modes")
        sync_proxy_modes(admin_port=admin_port)

        # Wait up to 5s for mitmproxy's UnixInstance to bind the
        # socket. Without this, the OCI bind-mount source path doesn't
        # exist and gVisor's gofer caches a ghost inode (same gotcha
        # as the earlier restart-cycle bug).
        import time as _time_wait
        _t("wait for per-agent proxy socket")
        _deadline = _time_wait.time() + 5.0
        while _time_wait.time() < _deadline:
            if sock_path_p.is_socket():
                break
            _time_wait.sleep(0.05)
        else:
            console.print(
                f"[yellow]Warning:[/yellow] per-agent socket {sock_path} "
                "did not appear; agent will see ENOENT on proxy connect. "
                "Is `safeyolo start` running?"
            )

    # Snapshot mode decision (macOS only for now -- Linux is always
    # passthrough until PR 5 adds runsc checkpoint/restore).
    #
    # restore      -- valid snapshot on disk; resume from it (fast path).
    # capture      -- no valid snapshot; cold-boot and take one.
    # passthrough  -- --no-snapshot or unsupported platform; cold-boot
    #                with no snapshot interaction.
    cpus_for_run = 4
    memory_for_run = 4096
    snapshot_version: dict | None = None
    snapshot_mode = "passthrough"
    if no_snapshot and platform_supports_snapshot():
        console.print(
            "  [dim]Note: warm-boot snapshot disabled. "
            "Re-enable with [bold]--snapshot[/bold] once the VZ save "
            "incompatibility is fixed (cold-boot only for now).[/dim]"
        )
    _t("compute_snapshot_version (hash kernel/initrd/rootfs/scripts)")
    if not no_snapshot and platform_supports_snapshot():
        snapshot_version = compute_snapshot_version(
            memory_mb=memory_for_run,
            cpus=cpus_for_run,
            gateway_ip=gateway_ip,
            guest_ip=guest_ip,
            extra_shares=extra_shares,
        )
        if is_snapshot_valid(name, snapshot_version):
            snapshot_mode = "restore"
        else:
            snapshot_mode = "capture"
            # Stale/invalid metadata would confuse a later restore.
            invalidate_snapshot(name)

    # Prepare config share (proxy env, CA cert, SSH key, agent env, instructions).
    # Capture mode writes per-run-go itself, after snapshot completes,
    # so the guest pauses at the static/per-run boundary long enough for
    # us to send SIGUSR1. Restore and passthrough pre-write -- on restore
    # the snapshotted guest wakes up on the gate and sees it immediately.
    _debug_mode = os.environ.get("SAFEYOLO_DEBUG") == "1"
    # Guest's HTTP_PROXY port. Both platforms use the in-guest forwarder
    # on a fixed port (8080); the host bridge decouples it from whatever
    # port mitmproxy is actually on.
    guest_proxy_port = 8080

    def _do_prepare_config_share(for_mode: str) -> None:
        prepare_config_share(
            name=name,
            workspace_path=str(workspace_path),
            agent_args=agent_args_str,
            extra_env=extra_env,
            proxy_port=guest_proxy_port,
            gateway_ip=gateway_ip,
            guest_ip=guest_ip,
            attribution_ip=attribution_ip,
            host_mounts=extra_shares,
            pre_write_per_run_go=(for_mode != "capture"),
            debug_mode=_debug_mode,
        )

    try:
        _t("prepare_config_share (write env files, scripts)")
        _do_prepare_config_share(snapshot_mode)
    except Exception as err:
        console.print(f"[red]Failed to prepare VM config:[/red] {err}")
        raise typer.Exit(1)

    # Launch is committed here: every preflight that can fail on user or
    # infrastructure error has passed. Any tmux window rename must happen
    # at this boundary, not earlier — an earlier failure would leave the
    # window renamed with nothing behind it (issue #330).
    if rename_tmux_window:
        rename_window_for_agent(name)

    run_background = detach

    write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} started", agent=name)
    exit_code = 0
    try:
        import time as _time
        config_share_dir = get_agent_config_share_dir(name)
        config_share = config_share_dir
        status_dir = get_agent_status_dir(name)
        per_run_started = status_dir / "per-run-started"

        # --- Restore attempt (macOS warm-boot fast path) -------------------
        # If the valid-snapshot path fails -- typically because VZ rejects
        # the save data (exit 75 from safeyolo-vm) -- we invalidate the
        # snapshot, re-prepare the config share for capture, and fall
        # through to the cold-boot path below. The user's agent always
        # comes up; a broken snapshot never blocks startup.
        if snapshot_mode == "restore":
            console.print("  Restoring agent...", end="")
            restore_src = snapshot_path(name)
            # Capture helper_pid so the post-session os.waitpid() call
            # on macOS can block on the actual child instead of polling.
            # Restore doesn't need SIGUSR1 (that's capture-mode only),
            # but liveness still needs the pid.
            _t("start_sandbox (restore: spawn helper + VZ.restore)")
            helper_pid = plat.start_sandbox(
                name=name,
                workspace_path=str(workspace_path),
                config_share=config_share,
                fw_alloc=fw_alloc,
                cpus=cpus_for_run,
                memory_mb=memory_for_run,
                extra_shares=extra_shares,
                background=run_background,
                restore_from_path=restore_src,
                ephemeral=(metadata.get("rootfs_overlay") == "memory"),
            )
            # agent_map was populated pre-start_sandbox (attribution_ip +
            # optional bridge socket). Nothing to re-register here.

            # Definitive readiness: the guest's per-run phase writes
            # /safeyolo/per-run-started as its first real action, after
            # forcing a VirtioFS readdir so the host sees the write
            # promptly. prepare_config_share unlinked any stale copy, so
            # appearance of this file means the restored VM actually
            # resumed and got into per-run -- no race against stale
            # any static-phase marker, with no need for a settle wait.
            #
            # Budget: 8s. On success the happy path is ~1-2s (VZ restore
            # + VirtioFS dentry cache TTL + per-run startup). A failed
            # restore causes safeyolo-vm to exit within ~500ms (sidecar
            # mismatch or VZ rejection), so is_sandbox_running catches
            # that quickly. 8s leaves headroom for slow disks / first-
            # boot cold caches without dragging out the fallback.
            deadline = _time.time() + 8.0
            restore_ok = False
            _t("wait per-run-started (guest wake + per-run prefix)")
            # Diagnostic escape hatch: skip the per-run-started gate and
            # treat a helper alive for 3s as successful. For exploring
            # whether the guest is actually usable post-restore even
            # when the marker mechanism isn't propagating. Gated behind
            # SAFEYOLO_DEBUG=1 to keep production from accidentally
            # shipping a run that skipped a readiness check.
            _debug_enabled = os.environ.get("SAFEYOLO_DEBUG") == "1"
            _skip_marker = _debug_enabled and os.environ.get("SAFEYOLO_RESTORE_SKIP_MARKER") == "1"
            if _skip_marker:
                import time as _t2
                _t2.sleep(3.0)
                restore_ok = plat.is_sandbox_running(name)
            else:
                while _time.time() < deadline:
                    if not plat.is_sandbox_running(name):
                        break
                    if per_run_started.exists():
                        restore_ok = True
                        break
                    _time.sleep(0.05)

            if restore_ok:
                console.print(" [green]ready[/green]")
            else:
                console.print(" [yellow]failed[/yellow]")
                console.print("  [yellow]Snapshot invalidated; cold-booting.[/yellow]")
                # Make sure the helper is fully cleaned up before we
                # restart. stop_sandbox is a no-op if it already exited.
                plat.stop_sandbox(name)
                invalidate_snapshot(name)
                snapshot_mode = "capture"
                # Re-prepare the share so per-run-go isn't pre-written --
                # capture needs the guest to pause on the gate.
                try:
                    _do_prepare_config_share("capture")
                except Exception as err:
                    console.print(f"[red]Failed to re-prepare VM config:[/red] {err}")
                    raise typer.Exit(1)

        # --- Cold boot (capture or passthrough) ----------------------------
        if snapshot_mode != "restore":
            start_label = (
                "Starting agent (first-time snapshot)"
                if snapshot_mode == "capture"
                else "Starting agent"
            )
            console.print(f"  {start_label}...", end="")
            capture_path = snapshot_path(name) if snapshot_mode == "capture" else None
            _t(f"start_sandbox ({snapshot_mode}: spawn helper + guest boot)")
            helper_pid = plat.start_sandbox(
                name=name,
                workspace_path=str(workspace_path),
                config_share=config_share,
                fw_alloc=fw_alloc,
                cpus=cpus_for_run,
                memory_mb=memory_for_run,
                extra_shares=extra_shares,
                background=run_background,
                snapshot_capture_path=capture_path,
                ephemeral=(metadata.get("rootfs_overlay") == "memory"),
            )
            # agent_map was populated pre-start_sandbox (attribution_ip +
            # optional bridge socket). Nothing to re-register here.

            if snapshot_mode == "capture":
                # Capture happens between static and per-run -- static has
                # completed by the time we get here. Snapshot orchestration
                # releases the per-run gate before returning, after which the
                # guest writes per-run-started.
                _t("capture orchestration (static-done → SIGUSR1 → save + clone)")
                _capture_snapshot_blocking(
                    name=name,
                    helper_pid=helper_pid,
                    config_share_dir=config_share_dir,
                    version=snapshot_version or {},
                    plat=plat,
                )

            # Wait until the guest reaches its per-run phase. The marker was
            # cleared by prepare_config_share, so its appearance belongs to
            # this boot rather than a prior run.
            _t("wait per-run-started (cold boot)")
            # Poll fast (50ms) for the first 2s so the host detects the file
            # within ~50ms instead of waiting up to 500ms; fall back to 0.5s
            # after that to keep the long-tail wait cheap.
            deadline = _time.time() + 120
            fast_until = _time.time() + 2.0
            boot_ready = False
            while _time.time() < deadline and plat.is_sandbox_running(name):
                if per_run_started.exists():
                    boot_ready = True
                    break
                _time.sleep(0.05 if _time.time() < fast_until else 0.5)

            if not boot_ready:
                console.print(" [red]failed[/red]")
                if plat.is_sandbox_running(name):
                    console.print("  Guest did not reach per-run startup within 120s.")
                    plat.stop_sandbox(name)
                # Point the user at the log that actually exists on their
                # platform. On macOS the Swift VM helper writes the guest
                # serial console to serial.log. On Linux there is no serial
                # console; guest-init redirects its stdout/stderr to
                # status/boot.log (a host bind-mount, so it survives a
                # sandbox exit). See cli/src/safeyolo/platform/linux.py
                # _generate_oci_config for the redirection.
                if _sys.platform == "linux":
                    console.print(
                        f"  Check logs: ~/.safeyolo/agents/{name}/status/boot.log"
                    )
                    console.print(
                        "  [dim](empty file = sandbox didn't start; check "
                        "`journalctl --user` and `safeyolo doctor`)[/dim]"
                    )
                else:
                    console.print(
                        f"  Check logs: ~/.safeyolo/agents/{name}/serial.log"
                    )
                exit_code = 1
            else:
                console.print(" [green]ready[/green]")

        # --- Post-boot (shared by restore and cold-boot success paths) ----
        if plat.is_sandbox_running(name):
            if detach:
                console.print("  Agent running (detached)")
                console.print(f"  Connect: [bold]safeyolo agent shell {name}[/bold]")
                console.print(f"  Stop:    [bold]safeyolo agent stop {name}[/bold]")
                _t("detach return")
                _timing_emit()
                return 0

            # `agent run --profile` measures launch-to-ready, not how long the
            # operator subsequently keeps an interactive agent session open.
            _t("agent ready; hand off interactive session")
            _timing_emit()
            _t("interactive session")
            if _sys.platform == "linux":
                # Linux: launch the agent via runsc exec. The guest runs
                # /home/agent/.safeyolo-command if present (written by
                # the host script into the persistent home), else drops
                # to an interactive bash login.
                from ..vm import get_agent_home_dir
                command_host = get_agent_home_dir(name) / ".safeyolo-command"
                full_cmd = _linux_interactive_command(
                    command_host,
                    effective_agent_args,
                    agent_args,
                )
                exit_code = plat.exec_in_sandbox(name, command=full_cmd, user="agent")
                plat.stop_sandbox(name)
            else:
                # macOS: safeyolo-vm + vsock-term handle the interactive
                # session. Block on the helper process itself -- one
                # syscall that returns the instant the child exits and
                # reaps the zombie in the same step. Previously a 500ms
                # is_sandbox_running poll + `ps` zombie check loop, which
                # added up to ~500ms of dead time at every agent exit.
                try:
                    os.waitpid(helper_pid, 0)
                except ChildProcessError:
                    # Already reaped (e.g., GC'd Popen.__del__) -- the
                    # VM is gone, proceed to cleanup.
                    pass
                except KeyboardInterrupt:
                    # User interrupted the wait; cleanup below still runs.
                    pass

    except Exception as err:
        console.print(" [red]error[/red]")
        console.print(f"  {err}")
        exit_code = 1
    except KeyboardInterrupt:
        exit_code = 130

    write_event("agent.stopped", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} stopped (exit {exit_code})", agent=name, details={"exit_code": exit_code})

    # Clean up PID file (not for detach -- VM is still running).
    if not detach:
        pid_path = get_agents_dir() / name / "vm.pid"
        pid_path.unlink(missing_ok=True)

    _timing_emit()
    return exit_code


def _parse_user_default_args(value: str | None) -> list[str] | None:
    """Parse user_default_args string into list."""
    if not value:
        return None
    try:
        return shlex.split(value)
    except ValueError:
        # If shlex fails, fall back to simple split
        return value.split()


def _parse_mount(mount_spec: str) -> str:
    """Validate and normalize a mount spec (/local/path:/container/path[:ro]).

    Returns normalized string with resolved host path.

    Raises:
        typer.Exit: If mount spec is invalid or host path doesn't exist.
    """
    parts = mount_spec.split(":")
    if len(parts) < 2 or len(parts) > 3:
        console.print(
            f"[red]Invalid mount format:[/red] {escape(mount_spec)}\nExpected: /host/path:/container/path[:ro]"
        )
        raise typer.Exit(1)

    host_path = Path(parts[0]).expanduser().resolve()
    container_path = parts[1]

    if not container_path.startswith("/"):
        console.print(f"[red]Container path must be absolute:[/red] {escape(container_path)}")
        raise typer.Exit(1)
    if ".." in PurePosixPath(container_path).parts:
        console.print(f"[red]Container path cannot contain '..':[/red] {escape(container_path)}")
        raise typer.Exit(1)
    container_path = str(PurePosixPath(container_path))
    protected_destinations = {
        "/",
        "/home/agent",
        "/workspace",
    }
    protected_trees = ("/dev", "/proc", "/safeyolo", "/safeyolo-status", "/sys")
    if container_path in protected_destinations or any(
        container_path == root or container_path.startswith(f"{root}/")
        for root in protected_trees
    ):
        console.print(
            f"[red]Container mount destination is reserved:[/red] "
            f"{escape(container_path)}"
        )
        raise typer.Exit(1)

    if not host_path.exists():
        console.print(f"[red]Host path not found:[/red] {host_path}")
        raise typer.Exit(1)

    is_ro = len(parts) == 3 and parts[2] == "ro"

    if len(parts) == 3 and not is_ro:
        console.print(f"[red]Invalid mount option:[/red] {escape(parts[2])} (only 'ro' supported)")
        raise typer.Exit(1)

    # Enforce protected paths
    protected_by = is_path_protected(str(host_path))
    if protected_by and not is_ro:
        console.print(
            f"[red]Refused:[/red] {host_path} is under protected path {protected_by}\n"
            f"Protected paths must be mounted read-only.\n"
            f"Use: {host_path}:{container_path}:ro"
        )
        raise typer.Exit(1)

    if is_ro:
        return f"{host_path}:{container_path}:ro"

    return f"{host_path}:{container_path}"


def _mount_spec_to_share(mount_spec: str) -> tuple[str, str, bool]:
    """Convert a validated mount string to (host, guest destination, read-only)."""
    parts = mount_spec.split(":")
    return parts[0], parts[1], len(parts) == 3


def _resolve_extra_shares(
    metadata: dict,
    transient_mounts: list[str] | None,
) -> list[tuple[str, str, bool]]:
    """Merge persistent and one-off mounts, with one-off destinations winning."""
    persistent = metadata.get("mounts", []) or []
    if not isinstance(persistent, list) or not all(
        isinstance(item, str) for item in persistent
    ):
        console.print("[red]Agent mount metadata is invalid; expected a list of strings.[/red]")
        raise typer.Exit(1)

    by_destination: dict[str, tuple[str, str, bool]] = {}
    for spec in [*persistent, *(transient_mounts or [])]:
        normalized = _parse_mount(spec)
        share = _mount_spec_to_share(normalized)
        # Reinsert so a transient override also takes the later mount's order.
        by_destination.pop(share[1], None)
        by_destination[share[1]] = share
    return list(by_destination.values())


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
        help="Path to a rootfs builder script. Produces a custom per-agent rootfs image instead of cloning the default base. See contrib/ROOTFS_SCRIPT_GUIDE.md.",
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
            "Boot with a tmpfs overlay upper instead of a per-agent writable "
            "disk. Writes to /etc, /usr, /var etc. are discarded when the agent "
            "stops. /home/agent remains persistent (virtiofs-bound). Useful for "
            "one-shot sandboxes and security experiments that want a pristine "
            "rootfs every run."
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

    # --rootfs-script runs before platform.prepare_rootfs so the script's
    # output is in place when the platform layer goes looking for the image.
    # On Linux, writes ~/.safeyolo/agents/<name>/rootfs/. On Darwin,
    # writes rootfs.ext4. Platform layer then finds the pre-built image and
    # skips its default clone/share step.
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

    # Create rootfs for this agent (platform-specific: APFS clone on macOS, overlayfs on Linux)
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
    write_event("agent.added", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} added", agent=name, details=event_details)

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
        # Ask the platform for the expected rootfs path (ext4 file on Darwin,
        # overlayfs directory on Linux) so the filter works on both.
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
            for inst_dir in sorted(instances, key=lambda d: d.name):
                metadata = all_agents.get(inst_dir.name, {})
                folder = metadata.get("folder", "?")
                host_script = metadata.get("host_script", "")
                table.add_row(inst_dir.name, folder, host_script)
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

    # Read the persistent network slot before removing agent metadata. Current
    # platforms have no host-side interface to tear down, but preserving the
    # platform contract here avoids reintroducing name-order allocation.
    network_slot = _load_agent_metadata(name).get("network_slot")
    agent_index = network_slot if type(network_slot) is int else -1

    # stop_sandbox is idempotent on both platforms (Linux probes runsc
    # state first; Darwin's stop_vm returns early if no pid). Calling
    # unconditionally ensures cleanup of `stopped` or `created` runsc
    # containers too, which is_sandbox_running() doesn't report as running
    # and therefore the old conditional skipped -- leaving stale state
    # that broke the next `runsc create`.
    if plat.is_sandbox_running(name):
        console.print(f"  Stopping {name}...")
    plat.stop_sandbox(name)

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
    write_event("agent.removed", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} removed", agent=name)
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
    detach: bool = typer.Option(False, "--detach", "-d", help="Boot VM in background and return (use 'agent shell' to connect)"),
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
    """Run an existing agent container.

    Starts SafeYolo if not running, then launches the agent container.
    Yolo mode is on by default (auto-accepts permission prompts).
    Use --no-yolo to require manual approval.

    Pass agent-specific flags after '--':

        safeyolo agent run boris -- --continue
        safeyolo agent run boris -- --resume my-session

    Detach mode boots the VM in the background:

        safeyolo agent run myproject --detach
        safeyolo agent shell myproject  # connect later
        safeyolo agent stop myproject   # stop when done

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
        updated_metadata = dict(metadata)
        updated_metadata["host_script"] = str(host_script_path)
        save_agent(name, updated_metadata)

    associate_agent_pane(name)
    exit_code = _run_agent(
        name,
        folder_override=folder,
        yolo=yolo,
        dangerously_allow_unowned=dangerously_allow_unowned,
        agent_args=agent_args,
        skip_default_args=fresh,
        extra_mounts=parsed_mounts if parsed_mounts else None,
        extra_ports=parsed_ports if parsed_ports else None,
        detach=detach,
        no_snapshot=not snapshot,
        rename_tmux_window=not detach and not no_rename_window,
    )
    raise typer.Exit(exit_code)


@agent_app.command()
def shell(  # DOC: docs/agent-debugging.md
    name: str = typer.Argument(..., help="Agent instance name"),
    command: str = typer.Option(None, "--command", "-c", help="Run a command instead of interactive shell"),
    root: bool = typer.Option(
        False,
        "--root",
        help="Operator recovery shell as guest root (default: agent user)",
    ),
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

    from ..platform import get_platform
    plat = get_platform()

    if not plat.is_sandbox_running(name):
        console.print(f"[red]Agent '{name}' is not running.[/red]")
        console.print(f"Start it with: [bold]safeyolo agent run {name}[/bold]")
        raise typer.Exit(1)

    user = "root" if root else "agent"
    exit_code = plat.exec_in_sandbox(
        name, command, user=user, interactive=not command,
    )
    raise typer.Exit(exit_code)


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
) -> None:
    """Probe the full agent egress chain and report where (if anywhere)
    it's broken.

    Runs through the hops from the agent out to mitmproxy and back,
    checking each link:
        agent map entry → proxy socket → attribution IP →
        mitmproxy process → VM process → end-to-end UDS probe

    Exits 0 if everything checks out, 1 if any link is broken. Output
    is one line per check, PASS/FAIL/WARN prefix, so piping to grep
    FAIL shows you what's wrong at a glance.
    """
    _validate_instance_name(name)
    from ..agent_diag import run_agent_diag  # noqa: PLC0415
    exit_code = run_agent_diag(name)
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

    from ..platform import get_platform
    plat = get_platform()

    if not plat.is_sandbox_running(name):
        console.print(f"Agent '{name}' is not running.")
        raise typer.Exit(0)

    console.print(f"Stopping {name}...")
    _t("platform sandbox shutdown and cleanup")
    plat.stop_sandbox(name)
    # Drop the per-agent UnixInstance. `stop_sandbox` already removed
    # the agent from agent_map.json, so this push reflects its absence.
    # If the proxy is down, its next start reads the already-updated map. Avoid
    # a guaranteed refused admin connection (and noisy warning) in that case.
    from ..proxy import is_proxy_running as _proxy_is_running
    from ..proxy import sync_proxy_modes
    _t("check proxy before listener reconciliation")
    if _proxy_is_running():
        config = load_config()
        admin_port = config.get("proxy", {}).get("admin_port", 9090)
        _t("remove proxy listener for stopped agent")
        sync_proxy_modes(admin_port=admin_port)
    _t("record and render stop result")
    write_event("agent.stopped", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} stopped by user", agent=name, details={"reason": "user_request"})
    console.print(f"[green]Stopped {name}.[/green]")


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
    name: str = typer.Argument(..., help="Agent instance name"),
    user_default_args: str = typer.Option(
        None,
        "--user-default-args",
        help="Set default args for agent CLI (use '' to clear)",
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
        safeyolo agent config boris --user-default-args="--continue"
        safeyolo agent config boris --add-mount ~/data:/data
        safeyolo agent config boris --add-mount ~/refs:/refs:ro
        safeyolo agent config boris --remove-mount /data
        safeyolo agent config boris --clear-mounts
        safeyolo agent config boris --add-port 6080:6080
        safeyolo agent config boris --remove-port 6080
        safeyolo agent config boris --clear-ports
    """
    _validate_instance_name(name)

    metadata = _load_agent_metadata(name)
    if not metadata:
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        raise typer.Exit(1)

    has_updates = (
        user_default_args is not None
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

    # Update user_default_args
    if user_default_args is not None:
        if user_default_args == "":
            if "user_default_args" in metadata:
                del metadata["user_default_args"]
            console.print(f"[green]Cleared user_default_args for {name}[/green]")
        else:
            parsed_args = _parse_user_default_args(user_default_args)
            if parsed_args:
                metadata["user_default_args"] = parsed_args
                console.print(f"[green]Set user_default_args for {name}:[/green] {' '.join(parsed_args)}")

    # Handle mount updates
    current_mounts = list(metadata.get("mounts", []))

    if clear_mounts:
        current_mounts = []
        console.print(f"[green]Cleared all mounts for {name}[/green]")

    for spec in remove_mount:
        # Match by container path (the part after the first colon)
        before = len(current_mounts)
        current_mounts = [m for m in current_mounts if m.split(":")[1] != spec.rstrip("/")]
        removed = before - len(current_mounts)
        if removed:
            console.print(f"[green]Removed mount for {spec}[/green]")
        else:
            console.print(f"[yellow]No mount found for container path: {spec}[/yellow]")

    for spec in add_mount:
        parsed = _parse_mount(spec)
        # Check for duplicate container path
        container_path = parsed.split(":")[1]
        current_mounts = [m for m in current_mounts if m.split(":")[1] != container_path]
        current_mounts.append(parsed)
        console.print(f"[green]Added mount: {parsed}[/green]")

    if current_mounts:
        metadata["mounts"] = current_mounts
    elif "mounts" in metadata:
        del metadata["mounts"]

    # Handle port updates
    current_ports = list(metadata.get("ports", []))

    if clear_ports:
        current_ports = []
        console.print(f"[green]Cleared all ports for {name}[/green]")

    for spec in remove_port:
        # Match by container port (last colon-separated part)
        before = len(current_ports)
        current_ports = [p for p in current_ports if p.rsplit(":", 1)[-1] != spec]
        removed = before - len(current_ports)
        if removed:
            console.print(f"[green]Removed port mapping for container port {spec}[/green]")
        else:
            console.print(f"[yellow]No port mapping found for container port: {spec}[/yellow]")

    for spec in add_port:
        parsed = _parse_port(spec)
        # Dedup by container port (last colon-separated part)
        container_port = parsed.rsplit(":", 1)[-1]
        current_ports = [p for p in current_ports if p.rsplit(":", 1)[-1] != container_port]
        current_ports.append(parsed)
        console.print(f"[green]Added port: {parsed}[/green]")

    if current_ports:
        metadata["ports"] = current_ports
    elif "ports" in metadata:
        del metadata["ports"]

    save_agent(name, metadata)

    # Build list of what changed for the event
    changes = []
    if user_default_args is not None:
        changes.append("user_default_args")
    if add_mount or remove_mount or clear_mounts:
        changes.append("mounts")
    if add_port or remove_port or clear_ports:
        changes.append("ports")
    write_event("agent.config_changed", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} config changed: {', '.join(changes)}", agent=name, details={"changes": changes})


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
    policy.toml. One command takes an agent from "no access" to "authorized."

    Examples:

        safeyolo agent authorize boris gmail --capability read_and_send --token-env GMAIL_TOKEN
        safeyolo agent authorize boris slack --token-file ~/slack.key
        safeyolo agent authorize boris gmail --credential-name gmail-oauth2
    """
    # 1. Validate agent exists
    _validate_instance_name(agent_name)

    metadata = _load_agent_metadata(agent_name)
    if not metadata:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' not found")
        raise typer.Exit(1)

    # 2. Resolve service
    svc = find_service(service_name)
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
    except (APIError, OSError) as exc:
        log.warning("Admin API unavailable (%s), falling back to local write", exc)
        services = metadata.setdefault("services", {})
        services[service_name] = {"capability": selected_cap, "token": cred_name}
        save_agent(agent_name, metadata)

    esc_agent = escape(agent_name)
    esc_svc = escape(service_name)
    esc_cap = escape(selected_cap)
    esc_cred = escape(cred_name)

    console.print(f"\n[green]Authorized:[/green] {esc_agent} → {esc_svc} (capability={esc_cap}, credential={esc_cred})")

    # 7. Check policy.yaml for host binding
    default_host = svc.get("default_host", "")
    if default_host:
        esc_host = escape(default_host)
        hosts = _load_policy_hosts()
        host_config = hosts.get(default_host)
        if isinstance(host_config, dict) and host_config.get("service") == service_name:
            console.print(f"[green]Host binding found:[/green] {esc_host}")
        else:
            console.print("\n[yellow]Next step:[/yellow] Add to policy.toml under [hosts]:")
            console.print(f"    [bold]{esc_host}: {{ service: {esc_svc} }}[/bold]")
            console.print(f"\n  [dim]Verify with: safeyolo policy show --section hosts | grep {esc_svc}[/dim]")
    else:
        console.print("\n[yellow]Next step:[/yellow] Map the service host in policy.toml under [hosts]:")
        console.print(f"    [bold]<your-host>: {{ service: {esc_svc} }}[/bold]")
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
