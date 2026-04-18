"""Agent management commands."""

import getpass
import logging
import os
import re
import shlex
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..agents_store import load_agent as _store_load_agent
from ..agents_store import load_all_agents, save_agent
from ..agents_store import remove_agent as _store_remove_agent
from ..config import find_config_dir, get_agents_dir, load_config
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
from ..templates import TemplateError, get_agent_config, get_available_templates
from ..timing import emit as _timing_emit
from ..timing import enter as _t
from ..vm import (
    _update_agent_map,
    get_agent_config_share_dir,
    get_agent_status_dir,
    prepare_config_share,
)
from ._service_discovery import find_service
from .mount import is_path_protected

log = logging.getLogger("safeyolo.agent")
console = Console()



def _ensure_host_config(template_name: str, ephemeral: bool) -> None:
    """Ensure host config directories exist for the agent.

    Creates directories from agent.toml [host] config if they don't exist.
    """
    try:
        agent_config = get_agent_config(template_name)
    except TemplateError:
        return  # Will fail later in render_template

    home = Path.home()
    console.print("\n[bold]Host config:[/bold]")

    has_any = False

    # Check/create directories
    for dir_name in agent_config.host.config_dirs:
        dir_path = home / dir_name
        if dir_path.exists():
            console.print(f"  [green]Found[/green] {dir_path} (will mount)")
            has_any = True
        elif ephemeral:
            console.print("  [yellow]Ephemeral mode[/yellow] - settings lost on container exit")
        else:
            dir_path.mkdir(mode=0o700, exist_ok=True)
            console.print(f"  [green]Created[/green] {dir_path}")
            has_any = True

    # Check files (don't create, just report)
    for file_name in agent_config.host.config_files:
        file_path = home / file_name
        if file_path.exists():
            console.print(f"  [green]Found[/green] {file_path} (will mount)")
            has_any = True

    if not has_any and not ephemeral:
        console.print("  [dim]No host config found[/dim]")

    console.print()


agent_app = typer.Typer(
    name="agent",
    help="Manage AI agent containers for Sandbox Mode.",
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
    """Get service name for an instance.

    Service name equals instance name (used in docker-compose).
    """
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


def _get_agent_binary(metadata: dict) -> str | None:
    """Get the agent binary name from template config."""
    template_name = metadata.get("template")
    if not template_name:
        return None
    try:
        agent_config = get_agent_config(template_name)
        return agent_config.install.binary
    except TemplateError:
        return None


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
    stranded on the gate — even if the snapshot fails, we fall back to
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
    # writes memory to snapshot.bin, clones the rootfs, and resumes.
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
) -> int:
    """Run an agent VM. Returns exit code.

    Shared logic used by both `add` (auto-run) and `run` commands.

    detach: Boot VM in background and return after boot confirmation.
    no_snapshot: skip snapshot capture and restore for this run;
        don't touch an existing snapshot on disk either way.
    """
    _t("cli entry (metadata, proxy check)")
    _validate_instance_name(name)

    # Rootfs path is platform-specific — Darwin uses an ext4 disk image file,
    # Linux uses an overlayfs merged directory. Ask the platform which to check.
    from ..platform import get_platform
    rootfs = get_platform().agent_rootfs_path(name)
    if not rootfs.exists():
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        console.print("Run [bold]safeyolo agent add <name> <template> <folder>[/bold] first.")
        raise typer.Exit(1)

    # Load metadata for user_default_args and binary name
    metadata = _load_agent_metadata(name)
    binary = _get_agent_binary(metadata)

    # Check SafeYolo proxy is running
    if not is_proxy_running():
        console.print("[yellow]SafeYolo proxy is not running. Starting...[/yellow]")
        try:
            start_proxy()
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
            f"To run another agent:   [bold]safeyolo agent add <new-name> <template> <folder>[/bold]"
        )
        raise typer.Exit(1)

    # Resolve workspace path
    workspace = folder_override or metadata.get("folder", ".")
    workspace_path = Path(workspace).expanduser().resolve()
    if not workspace_path.is_dir():
        console.print(f"[red]Folder not found: {workspace_path}[/red]")
        raise typer.Exit(1)
    _check_project_ownership(workspace_path, dangerously_allow_unowned)

    # Build agent args string for guest env
    agent_args_str = ""
    if agent_args:
        agent_args_str = " ".join(agent_args)
    elif not skip_default_args and metadata.get("user_default_args"):
        agent_args_str = " ".join(metadata["user_default_args"])

    # Extra env for yolo mode
    extra_env = {}
    if yolo:
        extra_env["SAFEYOLO_YOLO_MODE"] = "1"
    if detach:
        extra_env["SAFEYOLO_DETACH"] = "1"
    import sys as _sys
    if _sys.platform == "linux" and not detach:
        extra_env["SAFEYOLO_HOST_TERMINAL"] = "1"

    # Get mise package, host config, instructions, and auto_args from template
    mise_package = ""
    host_shares = []  # (host_path, tag, read_only) for VirtioFS mounts
    host_config_files = []  # Individual files to copy into config share
    instructions_content = ""
    instructions_path = ""
    auto_args = ""
    template_name = metadata.get("template", "")
    if template_name:
        try:
            agent_config = get_agent_config(template_name)
            mise_package = agent_config.install.mise
            auto_args = agent_config.run.auto_args_str
            # Instructions injection (e.g., CLAUDE.md)
            if agent_config.instructions.content and agent_config.instructions.path:
                instructions_content = agent_config.instructions.content
                instructions_path = agent_config.instructions.path
            # Mount host config dirs into guest /home/agent/
            home = Path.home()
            share_idx = 0
            for dir_name in agent_config.host.config_dirs:
                host_path = home / dir_name
                if host_path.is_dir():
                    host_shares.append((str(host_path), f"hostcfg{share_idx}", False))
                    share_idx += 1
            # Individual config files: copy into config share (not VirtioFS,
            # since mounting parent dir could expose $HOME)
            host_config_files = [f for f in agent_config.host.config_files
                                 if (home / f).exists()]
        except TemplateError:
            # Template missing or malformed — continue with empty host
            # mounts/instructions; the agent name was already validated
            # earlier so it's safe to proceed without template extras.
            pass

    # Set up network isolation (platform-specific: vsock on macOS, netns on Linux)
    config = load_config()
    proxy_port = config.get("proxy", {}).get("port", 8080)
    admin_port = config.get("proxy", {}).get("admin_port", 9090)

    from ..platform import get_platform
    plat = get_platform()

    agents_dir = get_agents_dir()
    existing = sorted(d.name for d in agents_dir.iterdir() if d.is_dir()) if agents_dir.exists() else []
    agent_index = existing.index(name) if name in existing else len(existing)

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
    # sees, which service_discovery maps back to the agent name. Both
    # platforms populate it in setup_networking as a synthetic 127.0.0.X
    # — the proxy_bridge binds its upstream TCP source to this address
    # and listens on a per-agent UDS (needs_bridge_socket=True).
    # agent_map.json is written BEFORE start_sandbox so service_discovery
    # is ready when the first request arrives, and the bridge polls it
    # to create listeners.
    attribution_ip = fw_alloc.get("attribution_ip", guest_ip)
    bridge_sock = None
    if fw_alloc.get("needs_bridge_socket"):
        from ..proxy_bridge import socket_path_for as _bridge_sock_for
        bridge_sock = str(_bridge_sock_for(name))
    _update_agent_map(name, ip=attribution_ip, socket=bridge_sock)
    if bridge_sock:
        # Wait up to 5s for the bridge to create the listener socket.
        # Without this, the OCI bind-mount source path doesn't exist
        # and gVisor's gofer caches a ghost inode (same gotcha as the
        # earlier restart-cycle bug).
        import time as _time_wait
        _deadline = _time_wait.time() + 5.0
        _sock_path = Path(bridge_sock)
        while _time_wait.time() < _deadline:
            if _sock_path.is_socket():
                break
            _time_wait.sleep(0.05)
        else:
            console.print(
                f"[yellow]Warning:[/yellow] bridge socket {bridge_sock} "
                "did not appear; agent will see ENOENT on proxy connect. "
                "Is `safeyolo start` running?"
            )

    # Snapshot mode decision (macOS only for now — Linux is always
    # passthrough until PR 5 adds runsc checkpoint/restore).
    #
    # restore      — valid snapshot on disk; resume from it (fast path).
    # capture      — no valid snapshot; cold-boot and take one.
    # passthrough  — --no-snapshot or unsupported platform; cold-boot
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
            agent_binary=binary or "",
            mise_package=mise_package,
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
    # us to send SIGUSR1. Restore and passthrough pre-write — on restore
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
            agent_binary=binary or "",
            mise_package=mise_package,
            agent_args=agent_args_str,
            extra_env=extra_env,
            proxy_port=guest_proxy_port,
            host_mounts=host_shares if host_shares else None,
            host_config_files=host_config_files if host_config_files else None,
            instructions_content=instructions_content,
            instructions_path=instructions_path,
            auto_args=auto_args,
            gateway_ip=gateway_ip,
            guest_ip=guest_ip,
            attribution_ip=attribution_ip,
            pre_write_per_run_go=(for_mode != "capture"),
            debug_mode=_debug_mode,
        )

    try:
        _t("prepare_config_share (write env files, scripts)")
        _do_prepare_config_share(snapshot_mode)
    except Exception as err:
        console.print(f"[red]Failed to prepare VM config:[/red] {err}")
        raise typer.Exit(1)

    run_background = detach

    write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} started", agent=name)
    exit_code = 0
    try:
        import time as _time
        config_share_dir = get_agent_config_share_dir(name)
        config_share = config_share_dir
        status_dir = get_agent_status_dir(name)
        ip_file = status_dir / "vm-ip"

        # --- Restore attempt (macOS warm-boot fast path) -------------------
        # If the valid-snapshot path fails — typically because VZ rejects
        # the save data (exit 75 from safeyolo-vm) — we invalidate the
        # snapshot, re-prepare the config share for capture, and fall
        # through to the cold-boot path below. The user's agent always
        # comes up; a broken snapshot never blocks startup.
        if snapshot_mode == "restore":
            console.print("  Restoring snapshot...", end="")
            restore_src = snapshot_path(name)
            # No helper_pid binding here: restore doesn't need SIGUSR1
            # (that's capture-mode only). Liveness is checked via
            # plat.is_sandbox_running(name), which reads the pid file.
            _t("start_sandbox (restore: spawn helper + VZ.restore)")
            plat.start_sandbox(
                name=name,
                workspace_path=str(workspace_path),
                config_share=config_share,
                fw_alloc=fw_alloc,
                cpus=cpus_for_run,
                memory_mb=memory_for_run,
                extra_shares=host_shares if host_shares else None,
                background=run_background,
                restore_from_path=restore_src,
            )
            # agent_map was populated pre-start_sandbox (attribution_ip +
            # optional bridge socket). Nothing to re-register here.

            # Definitive readiness: the guest's per-run phase writes
            # /safeyolo/per-run-started as its first real action, after
            # forcing a VirtioFS readdir so the host sees the write
            # promptly. prepare_config_share unlinked any stale copy, so
            # appearance of this file means the restored VM actually
            # resumed and got into per-run — no race against stale
            # vm-ip, no need for a settle wait.
            #
            # Budget: 8s. On success the happy path is ~1-2s (VZ restore
            # + VirtioFS dentry cache TTL + per-run startup). A failed
            # restore causes safeyolo-vm to exit within ~500ms (sidecar
            # mismatch or VZ rejection), so is_sandbox_running catches
            # that quickly. 8s leaves headroom for slow disks / first-
            # boot cold caches without dragging out the fallback.
            per_run_started = status_dir / "per-run-started"
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
                console.print(f" {guest_ip}")
            else:
                console.print(" [yellow]failed[/yellow]")
                console.print("  [yellow]Snapshot invalidated; cold-booting.[/yellow]")
                # Make sure the helper is fully cleaned up before we
                # restart. stop_sandbox is a no-op if it already exited.
                plat.stop_sandbox(name)
                invalidate_snapshot(name)
                snapshot_mode = "capture"
                # Re-prepare the share so per-run-go isn't pre-written —
                # capture needs the guest to pause on the gate.
                try:
                    _do_prepare_config_share("capture")
                except Exception as err:
                    console.print(f"[red]Failed to re-prepare VM config:[/red] {err}")
                    raise typer.Exit(1)

        # --- Cold boot (capture or passthrough) ----------------------------
        if snapshot_mode != "restore":
            boot_label = "Booting VM (first-time snapshot)" if snapshot_mode == "capture" else "Booting VM"
            console.print(f"  {boot_label}...", end="")
            capture_path = snapshot_path(name) if snapshot_mode == "capture" else None
            _t(f"start_sandbox ({snapshot_mode}: spawn helper + guest boot)")
            helper_pid = plat.start_sandbox(
                name=name,
                workspace_path=str(workspace_path),
                config_share=config_share,
                fw_alloc=fw_alloc,
                cpus=cpus_for_run,
                memory_mb=memory_for_run,
                extra_shares=host_shares if host_shares else None,
                background=run_background,
                snapshot_capture_path=capture_path,
            )
            # agent_map was populated pre-start_sandbox (attribution_ip +
            # optional bridge socket). Nothing to re-register here.

            if snapshot_mode == "capture":
                # Capture happens between static and per-run — static has
                # already written vm-ip by the time we get here, so the
                # subsequent vm-ip poll will complete on the first iteration.
                _t("capture orchestration (static-done → SIGUSR1 → save + clone)")
                _capture_snapshot_blocking(
                    name=name,
                    helper_pid=helper_pid,
                    config_share_dir=config_share_dir,
                    version=snapshot_version or {},
                    plat=plat,
                )

            # Wait for VM IP (indicates guest init is running).
            _t("wait vm-ip (guest static write)")
            # Poll fast (50ms) for the first 2s so the host detects the file
            # within ~50ms instead of waiting up to 500ms; fall back to 0.5s
            # after that to keep the long-tail wait cheap.
            deadline = _time.time() + 120
            fast_until = _time.time() + 2.0
            while _time.time() < deadline and plat.is_sandbox_running(name):
                if ip_file.exists() and ip_file.read_text().strip():
                    break
                _time.sleep(0.05 if _time.time() < fast_until else 0.5)

            if not plat.is_sandbox_running(name):
                console.print(" [red]failed[/red]")
                console.print(f"  Check logs: ~/.safeyolo/agents/{name}/serial.log")
                exit_code = 1
            else:
                console.print(f" {guest_ip}")

        # --- Post-boot (shared by restore and cold-boot success paths) ----
        if plat.is_sandbox_running(name):
            # Watch for agent install. Per-run runs on every boot (including
            # restore), so if the agent binary isn't yet installed in the
            # rootfs we'll see the "installing" status mark.
            _t("install watch (guest per-run mise install if any)")
            status_file = status_dir / "vm-status"
            shown_installing = False
            deadline2 = _time.time() + 120
            while _time.time() < deadline2 and plat.is_sandbox_running(name):
                status = status_file.read_text().strip() if status_file.exists() else ""
                if status == "installing" and not shown_installing:
                    agent_label = binary or template_name
                    console.print(f"  Installing {agent_label}...")
                    shown_installing = True
                elif status == "install-failed":
                    console.print("  [red]Install failed[/red]")
                    break
                elif status == "ready":
                    break
                _time.sleep(1)

            if detach:
                console.print("  VM running (detached)")
                console.print(f"  Connect: [bold]safeyolo agent shell {name}[/bold]")
                console.print(f"  Stop:    [bold]safeyolo agent stop {name}[/bold]")
                _t("detach return")
                _timing_emit()
                return 0

            _t("interactive session")
            if _sys.platform == "linux":
                # Linux: launch the agent via runsc exec — it bridges the
                # user's terminal into the sandbox, same role vsock-term
                # plays on macOS. The command comes from the template config.
                agent_cmd_parts = []
                if binary:
                    agent_cmd_parts.append(binary)
                    if yolo and auto_args:
                        agent_cmd_parts.append(auto_args)
                    if agent_args_str:
                        agent_cmd_parts.append(agent_args_str)
                full_cmd = " ".join(agent_cmd_parts) if agent_cmd_parts else None
                exit_code = plat.exec_in_sandbox(name, command=full_cmd, user="agent")
                plat.stop_sandbox(name)
            else:
                # macOS: safeyolo-vm + vsock-term handle the interactive
                # session. Wait for the VM to exit.
                while plat.is_sandbox_running(name):
                    try:
                        _time.sleep(0.5)
                    except KeyboardInterrupt:
                        break

    except Exception as err:
        console.print(" [red]error[/red]")
        console.print(f"  {err}")
        exit_code = 1
    except KeyboardInterrupt:
        exit_code = 130

    write_event("agent.stopped", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} stopped (exit {exit_code})", agent=name, details={"exit_code": exit_code})

    # Clean up PID file (not for detach — VM is still running).
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
def add(
    name: str = typer.Argument(
        ...,
        help="Instance name (used for run/shell/remove commands)",
    ),
    template: str = typer.Argument(
        ...,
        help="Agent template (e.g., claude-code, openai-codex, byoa)",
    ),
    folder: str = typer.Argument(
        ...,
        help="Folder to mount in agent container",
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
    ephemeral: bool = typer.Option(
        False,
        "--ephemeral",
        help="Don't persist config (credentials lost on container exit)",
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
    """Add an AI agent and run it.

    Creates config for the specified agent template, then runs it.
    If agent already exists with same config, just runs it (idempotent).

    Examples:

        safeyolo agent add myproject claude-code .
        safeyolo agent add work claude-code ~/projects/myapp
        safeyolo agent add assistant openai-codex ~/code --no-run
        safeyolo agent add boris claude-code . --mount ~/data:/data --mount ~/refs:/refs:ro
    """
    # Validate instance name (hostname rules)
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]\nRun [bold]safeyolo init[/bold] first.")
        raise typer.Exit(1)

    config = load_config()
    if not config.get("sandbox"):
        console.print(
            "[yellow]Warning: SafeYolo is not in Sandbox Mode.[/yellow]\n"
            "Agent containers may be able to bypass the proxy.\n"
            "Run [bold]safeyolo init[/bold] to enable network isolation (sandbox is the default).\n"
        )

    # Validate folder early
    folder_path = Path(folder).expanduser().resolve()
    if not folder_path.is_dir():
        console.print(f"[red]Folder not found: {folder_path}[/red]")
        raise typer.Exit(1)
    _check_project_ownership(folder_path, dangerously_allow_unowned)
    folder_str = str(folder_path)

    # Validate template exists
    try:
        get_agent_config(template)
    except TemplateError as err:
        console.print(f"[red]Template error:[/red] {escape(str(err))}")
        raise typer.Exit(1)

    # Instance directory = instance name
    agent_dir = get_agents_dir() / name

    # Check if agent already exists
    existing = _load_agent_metadata(name)
    if agent_dir.exists():
        if existing:
            existing_template = existing.get("template")
            existing_folder = existing.get("folder")

            if existing_template == template and existing_folder == folder_str and not force:
                # Same config, no --force - idempotent, just run
                console.print(f"Agent '{name}' already configured.")
                if not no_run:
                    exit_code = _run_agent(name, dangerously_allow_unowned=dangerously_allow_unowned, no_snapshot=True)
                    raise typer.Exit(exit_code)
                return
            else:
                # Different config
                if not force:
                    console.print(
                        f"[yellow]Agent '{name}' exists with different config:[/yellow]\n"
                        f"  Current:  {existing_template} → {existing_folder}\n"
                        f"  Requested: {template} → {folder_str}\n"
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

    # Ensure host config directories exist
    _ensure_host_config(template, ephemeral)

    # Create rootfs for this agent (platform-specific: APFS clone on macOS, overlayfs on Linux)
    from ..platform import get_platform
    try:
        rootfs = get_platform().prepare_rootfs(name)
        console.print(f"  [green]Created[/green] {rootfs}")
    except Exception as err:
        console.print(f"[red]Failed to create agent rootfs:[/red] {escape(str(err))}")
        raise typer.Exit(1)

    # Validate and normalize mount specs
    parsed_mounts = [_parse_mount(m) for m in mount]

    # Validate and normalize port specs
    parsed_ports = [_parse_port(p) for p in port]

    # Write metadata to policy.toml [agents]
    metadata = {"template": template, "folder": folder_str}
    parsed_args = _parse_user_default_args(user_default_args)
    if parsed_args:
        metadata["user_default_args"] = parsed_args
    if parsed_mounts:
        metadata["mounts"] = parsed_mounts
    if parsed_ports:
        metadata["ports"] = parsed_ports
    save_agent(name, metadata)

    panel_lines = [
        f"[green]Agent '{name}' added![/green]\n",
        f"Template: {template}",
        f"Folder: {folder_str}",
        f"Rootfs: {rootfs}",
    ]
    if parsed_args:
        panel_lines.append(f"Default args: {' '.join(parsed_args)}")
    if parsed_mounts:
        panel_lines.append(f"Mounts: {len(parsed_mounts)}")
        for m in parsed_mounts:
            panel_lines.append(f"  {m}")
    cfg = load_config()
    panel_lines.append(f"Proxy: http://127.0.0.1:{cfg.get('proxy', {}).get('port', 8080)} (via in-guest forwarder)")
    console.print(Panel("\n".join(panel_lines), title="Success"))

    write_event("agent.added", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} added (template={template})", agent=name, details={"template": template, "folder": folder_str})

    # Auto-run unless --no-run
    if not no_run:
        console.print()
        exit_code = _run_agent(name, dangerously_allow_unowned=dangerously_allow_unowned, no_snapshot=True)
        raise typer.Exit(exit_code)


@agent_app.command(name="list")
def list_agents() -> None:
    """List available agent templates and instances."""
    # Show templates
    templates = get_available_templates()
    if templates:
        table = Table(title="Available Templates")
        table.add_column("Template", style="bold")
        table.add_column("Description")
        for tpl_name, description in templates.items():
            table.add_row(tpl_name, description)
        console.print(table)
        console.print()

    # Show instances
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
            table.add_column("Template")
            table.add_column("Folder")
            for inst_dir in sorted(instances, key=lambda d: d.name):
                metadata = all_agents.get(inst_dir.name, {})
                template = metadata.get("template", "?")
                folder = metadata.get("folder", "?")
                table.add_row(inst_dir.name, template, folder)
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

    # Agent index must be computed before the agent dir disappears,
    # since it's derived from the sorted list of agent dirs — the same
    # allocation rule used by setup_networking. Using the stale index
    # here is what lets us target this agent's netns/veth for teardown
    # rather than leaking them.
    existing = sorted(d.name for d in agents_dir.iterdir() if d.is_dir())
    agent_index = existing.index(name) if name in existing else -1

    # stop_sandbox is idempotent on both platforms (Linux probes runsc
    # state first; Darwin's stop_vm returns early if no pid). Calling
    # unconditionally ensures cleanup of `stopped` or `created` runsc
    # containers too, which is_sandbox_running() doesn't report as running
    # and therefore the old conditional skipped — leaving stale state
    # that broke the next `runsc create`.
    if plat.is_sandbox_running(name):
        console.print(f"  Stopping {name}...")
    plat.stop_sandbox(name)

    # Teardown per-agent networking. Linux's stop_sandbox already did
    # this (idempotent netns delete), but Darwin's didn't — it only
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
    write_event("agent.removed", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} removed", agent=name)
    console.print(f"[green]Removed agent: {name}[/green]")


@agent_app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Agent instance name to run"),
    folder: str = typer.Option(None, "--folder", "-f", help="Override folder to mount (default: from agent add)"),
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

    Examples:

        safeyolo agent run myproject
        safeyolo agent run myproject -f ~/other/folder
        safeyolo agent run myproject --no-yolo
        safeyolo agent run myproject --detach
        safeyolo agent run myproject --mount ~/data:/data:ro
        safeyolo agent run myproject --port 6080:6080
        safeyolo agent run myproject -- --continue
        safeyolo agent run myproject --fresh
    """
    # ctx.args contains everything after '--'
    agent_args = ctx.args if ctx.args else None

    # Validate transient mount specs
    parsed_mounts = [_parse_mount(m) for m in mount]

    # Validate transient port specs
    parsed_ports = [_parse_port(p) for p in port]

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
    )
    raise typer.Exit(exit_code)


@agent_app.command()
def shell(
    name: str = typer.Argument(..., help="Agent instance name"),
    command: str = typer.Option(None, "--command", "-c", help="Run a command instead of interactive shell"),
    root: bool = typer.Option(
        False,
        "--root",
        help="Open shell as root (default: non-root agent user)",
    ),
) -> None:
    """Open a shell in a running agent sandbox.

    By default, opens as the non-root agent user. Use --root for root access.
    Use -c to run a single command and return its exit code.

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
def diag(
    name: str = typer.Argument(..., help="Agent instance name to diagnose"),
) -> None:
    """Probe the full agent egress chain and report where (if anywhere)
    it's broken.

    Runs through the hops from the agent out to mitmproxy and back,
    checking each link:
        agent map entry → bridge socket → attribution IP alias →
        proxy_bridge process → VM process → end-to-end UDS probe

    Exits 0 if everything checks out, 1 if any link is broken. Output
    is one line per check, PASS/FAIL/WARN prefix, so piping to grep
    FAIL shows you what's wrong at a glance.
    """
    _validate_instance_name(name)
    from ..agent_diag import run_agent_diag  # noqa: PLC0415
    exit_code = run_agent_diag(name)
    raise typer.Exit(exit_code)


@agent_app.command()
def stop(
    name: str = typer.Argument(..., help="Agent instance name to stop"),
) -> None:
    """Stop a running agent sandbox.

    Examples:

        safeyolo agent stop myproject
    """
    _validate_instance_name(name)

    from ..platform import get_platform
    plat = get_platform()

    if not plat.is_sandbox_running(name):
        console.print(f"Agent '{name}' is not running.")
        raise typer.Exit(0)

    console.print(f"Stopping {name}...")
    plat.stop_sandbox(name)
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
        table.add_row("Template", metadata.get("template", "?"))
        table.add_row("Folder", metadata.get("folder", "?"))
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


@agent_app.command(name="help")
def agent_help(
    name: str = typer.Argument(..., help="Agent instance name"),
) -> None:
    """Show agent CLI help.

    Runs the agent's --help command inside the container to show available flags.
    Use 'safeyolo agent shell <name>' to experiment with other flags interactively.

    Examples:

        safeyolo agent help boris
    """
    _validate_instance_name(name)

    # Use passthrough with --help (or configured help_arg)
    metadata = _load_agent_metadata(name)
    template_name = metadata.get("template")

    help_arg = "--help"
    if template_name:
        try:
            agent_config = get_agent_config(template_name)
            help_arg = agent_config.run.help_arg
        except TemplateError:
            pass  # Optional - continue with default --help if template lookup fails

    # Parse help_arg in case it has multiple parts
    help_args = help_arg.split()

    exit_code = _run_agent(name, agent_args=help_args, skip_default_args=True)

    # Suggest shell for experimentation
    console.print(f"\n[dim]To experiment with flags: safeyolo agent shell {name}[/dim]")

    raise typer.Exit(exit_code)


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
def authorize(
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
            desc_str = f" — {escape(desc)}" if desc else ""
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
            pass  # Vault unavailable or locked — skip reminder
