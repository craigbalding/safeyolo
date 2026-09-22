"""Typed agent lifecycle operations shared by CLI and operator clients."""

from __future__ import annotations

import fcntl
import logging
import os
import stat
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from .agent_configuration import (
    _effective_agent_memory_mb,
    _resolve_extra_shares,
    _validate_instance_name,
)
from .agents_store import get_agent_by_id, get_or_mint_agent_id, load_agent, load_all_agents

log = logging.getLogger(__name__)
console = Console()


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
    """Write an agent event without loading the audit schema at CLI import time."""
    from .events import write_event as _write_event

    _write_event(
        event,
        kind=kind,
        severity=severity,
        summary=summary,
        agent=agent,
        addon=addon,
        details=details,
    )


def _check_project_ownership(project_path: Path, allow_unowned: bool) -> None:
    """Check that user owns the project directory."""
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


def _load_agent_metadata(name: str) -> dict:
    """Load agent metadata from policy.toml [agents] section."""
    return load_agent(name)


class AgentLifecycleError(RuntimeError):
    """A configured agent could not complete a lifecycle transition."""

    def __init__(self, message: str, *, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class AgentRuntime:
    """Operator-facing state for one configured agent."""

    agent_id: str
    name: str
    sandbox_state: str
    agent_state: str = "stopped"
    launcher: dict | None = None
    attachable: bool = False
    launch_id: str | None = None
    exit_code: int | None = None
    error: str | None = None
    hook_errors: list[dict] = field(default_factory=list)
    harness: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _configured_harness(metadata: dict) -> str | None:
    """Identify bundled setup scripts; do not guess what custom scripts run."""
    script = Path(metadata.get("host_script") or "").name
    return {
        "codex-host-setup.sh": "codex",
        "codex-coord-host-setup.sh": "codex",
        "pi-host-setup.sh": "pi",
        "pi-coord-host-setup.sh": "pi",
        "claude-host-setup.sh": "claude",
        "mise-shell-host-setup.sh": "shell",
    }.get(script)


def _runtime(name: str, agent_id: str, *, metadata: dict | None = None) -> AgentRuntime:
    from .agent_launchers import observe_launch
    from .platform import get_platform

    ready = get_platform().is_sandbox_running(name)
    try:
        observed = observe_launch(name, sandbox_ready=ready)
    except (OSError, ValueError, RuntimeError) as exc:
        # One broken launcher must not hide every other configured agent.
        observed = {"agent_state": "unknown", "error": str(exc)}
    if metadata is None:
        metadata = load_agent(name) or {}
    return AgentRuntime(agent_id=agent_id, name=name, sandbox_state="ready" if ready else "stopped",
                        harness=_configured_harness(metadata), **observed)


def list_agent_runtimes() -> list[AgentRuntime]:
    """Return all configured agents with stable identities and live state."""
    agents = load_all_agents()
    runtimes = []
    for name, metadata in sorted(agents.items()):
        agent_id = str(metadata.get("agent_id") or get_or_mint_agent_id(name))
        runtimes.append(_runtime(name, agent_id, metadata=metadata))
    return runtimes


def _resolve(agent_id: str) -> tuple[str, str]:
    found = get_agent_by_id(agent_id)
    if found is None:
        raise AgentLifecycleError("Agent not found", status_code=404)
    name, _ = found
    return name, agent_id


def start_agent(agent_id: str, *, interactive: bool = False) -> AgentRuntime:
    """Start one configured agent using the ordinary fixed lifecycle path."""
    name, stable_id = _resolve(agent_id)
    from .platform import get_platform

    platform = get_platform()

    try:
        exit_code = _run_agent(
            name=name,
            yolo=True,
            launch_mode="background",
            interactive=interactive,
            no_snapshot=True,
            rename_tmux_window=False,
        )
    except Exception as exc:
        from .core.audit_schema import sanitize_for_log

        log.exception("Agent %s failed to start", sanitize_for_log(name, max_len=None))
        detail = str(exc).strip() or "no additional detail"
        exit_code = getattr(exc, "exit_code", None)
        if exit_code is not None:
            detail = f"exit code {exit_code}: {detail}"
        raise AgentLifecycleError(
            f"Agent start failed: {type(exc).__name__}: {detail}",
        ) from exc
    if exit_code != 0 or not platform.is_sandbox_running(name):
        raise AgentLifecycleError(f"Agent start failed with exit code {exit_code}")
    return _runtime(name, stable_id)


def stop_agent(agent_id: str) -> AgentRuntime:
    """Stop one configured agent and its command supervisor."""
    name, stable_id = _resolve(agent_id)
    return stop_agent_by_name(name, agent_id=stable_id)


def stop_agent_by_name(
    name: str,
    *,
    agent_id: str = "",
    on_phase: Callable[[str], None] | None = None,
) -> AgentRuntime:
    """Stop one named agent; the CLI also permits an absent stale name."""
    with _agent_host_setup_lock(name):
        return _stop_agent_by_name(name, agent_id=agent_id, on_phase=on_phase)


def _stop_agent_by_name(name: str, *, agent_id: str, on_phase: Callable[[str], None] | None) -> AgentRuntime:
    from .agent_command_supervisor import request_command_supervisor_stop
    from .agent_launchers import stop_launcher
    from .platform import get_platform

    if on_phase:
        on_phase("command supervisor stop intent")
    if not request_command_supervisor_stop(name):
        raise AgentLifecycleError(
            "Could not stop the command supervisor; the sandbox was left intact "
            "to prevent an automatic restart",
        )

    # An external manager must see stop intent before its sandbox disappears;
    # otherwise it may treat the shutdown as a crash and relaunch the agent.
    stop_launcher(name)
    platform = get_platform()
    if not platform.is_sandbox_running(name):
        return _runtime(name, agent_id)

    if on_phase:
        on_phase("platform sandbox shutdown and cleanup")
    platform.stop_sandbox(name)

    # stop_sandbox updates agent_map.json. Reconcile the live proxy listener
    # when there is a proxy to notify; its next start otherwise reads the map.
    from .config import load_config
    from .proxy import is_proxy_running, sync_proxy_modes

    if on_phase:
        on_phase("check proxy before listener reconciliation")
    if is_proxy_running():
        admin_port = load_config().get("proxy", {}).get("admin_port", 9090)
        if on_phase:
            on_phase("remove proxy listener for stopped agent")
        sync_proxy_modes(admin_port=admin_port)

    from .events import write_event

    if on_phase:
        on_phase("record and render stop result")
    write_event(
        "agent.stopped",
        kind="agent",
        severity="low",
        summary=f"Agent {name} stopped by user",
        agent=name,
        details={"reason": "user_request"},
    )
    return _runtime(name, agent_id)


class _SetupLockHandle:
    """An agent setup lock that can be released after the boot transition."""

    def __init__(self, fd: int | None, name: str, held: set[str]) -> None:
        self._fd = fd
        self._name = name
        self._held = held

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            self._held.discard(self._name)


_setup_lock_state = threading.local()


def _held_setup_locks() -> set[str]:
    held = getattr(_setup_lock_state, "names", None)
    if held is None:
        held = set()
        _setup_lock_state.names = held
    return held


def _open_safe_setup_directory(path: Path, name: str) -> int:
    """Open an agent's setup directory without following its final path."""
    try:
        path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    except OSError as exc:
        raise RuntimeError(f"unsafe host setup directory for agent {name!r}: {exc}") from None

    # Only metadata and relative lock opens need this handle. O_PATH also
    # avoids gVisor following a final symlink with O_RDONLY | O_DIRECTORY.
    flags = getattr(os, "O_PATH", os.O_RDONLY)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"unsafe host setup directory for agent {name!r}: {exc}") from None
    try:
        info = os.fstat(fd)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(
                f"unsafe host setup directory for agent {name!r}: expected a directory"
            )
        if info.st_uid != os.getuid():
            raise RuntimeError(
                f"unsafe host setup directory for agent {name!r}: owner is not the invoking user"
            )
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError(
                f"unsafe host setup directory for agent {name!r}: group/world write is not allowed"
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _agent_host_setup_lock(name: str):
    """Serialize setup/start transitions and validate the lock entry."""
    from .vm import ensure_agent_persistent_dirs, get_agent_home_dir

    held = _held_setup_locks()
    if name in held:
        # Factory startup holds every role lock while calling the ordinary
        # setup/run helpers. Re-entry in this thread must not acquire a second
        # file descriptor, while other threads still block on flock().
        yield _SetupLockHandle(None, name, held)
        return

    ensure_agent_persistent_dirs(name)
    setup_dir = get_agent_home_dir(name) / ".safeyolo"
    setup_dir_fd = _open_safe_setup_directory(setup_dir, name)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        try:
            try:
                fd = os.open("host-setup.lock", flags, 0o600, dir_fd=setup_dir_fd)
            except OSError as exc:
                raise RuntimeError(f"unsafe host setup lock for agent {name!r}: {exc}") from None
        finally:
            os.close(setup_dir_fd)

        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(
                f"unsafe host setup lock for agent {name!r}: expected a regular file"
            )
        if info.st_nlink != 1:
            raise RuntimeError(
                f"unsafe host setup lock for agent {name!r}: hard links are not allowed"
            )
        if info.st_uid != os.getuid():
            raise RuntimeError(
                f"unsafe host setup lock for agent {name!r}: owner is not the invoking user"
            )
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)

        held.add(name)
        handle = _SetupLockHandle(fd, name, held)
        fd = None
        try:
            yield handle
        finally:
            handle.release()
    finally:
        if fd is not None:
            os.close(fd)


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
    import signal
    import time as _time

    from .snapshot import (
        MIN_SNAPSHOT_BYTES,
        invalidate_snapshot,
        snapshot_path,
        write_snapshot_version,
    )
    from .vm import get_agent_status_dir

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


def _run_agent(*args, launch_mode="foreground", interactive=False, **kwargs) -> int:
    """Ensure sandbox readiness and launch exactly one selected coding agent."""
    from .agent_launchers import (
        configured_guest_command,
        invoke_launcher,
        launch_lock,
        observe_launch,
        prepare_launch,
        resolve_launcher,
    )
    from .config import load_config
    from .platform import get_platform

    name = kwargs.get("name") if "name" in kwargs else args[0]
    _validate_instance_name(name)
    # Validate local setup before runtime inspection or launch-state creation.
    # A missing agent must not require an installed sandbox runtime to report.
    rootfs = get_platform().agent_rootfs_path(name)
    if not rootfs.exists():
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        console.print("Run [bold]safeyolo agent add <name> <folder>[/bold] first.")
        raise typer.Exit(1)
    record = None
    with _agent_host_setup_lock(name):
        with launch_lock(name):
            metadata = _load_agent_metadata(name)
            selection = resolve_launcher(metadata, load_config(), launch_mode, interactive=interactive)
            ready = get_platform().is_sandbox_running(name)
            observed = observe_launch(name, sandbox_ready=ready)
            if observed["agent_state"] in {"starting", "launching", "running", "restarting", "stopping", "finishing", "unknown"}:
                if interactive:
                    raise RuntimeError("Stop the managed agent before running it interactively")
                console.print(f"Agent {name}: {observed['agent_state']} (existing run)")
                return 0
            # A stopped manager must not restart during temporary debugging.
            from .agent_command_supervisor import request_command_supervisor_stop

            if not request_command_supervisor_stop(name):
                raise RuntimeError("Could not stop the previous command supervisor")
            if not ready:
                code = _run_agent_impl(*args, **kwargs)
                if code:
                    return code
            if launch_mode == "sandbox":
                console.print(f"Sandbox {name} is ready; no coding agent was launched.")
                return 0
            effective_args = kwargs.get("agent_args")
            if effective_args is None:
                effective_args = [] if kwargs.get("skip_default_args") else metadata.get("user_default_args", [])
            is_debug = interactive and metadata.get("launcher") == "supervisor"
            command = configured_guest_command(name, effective_args or [], interactive=is_debug)
            record = prepare_launch(name, selection, launch_mode, command)
        # Launch scripts return a session, not a terminal stream. Keep launch
        # and stop ordered; release the record lock so the child can claim it.
        if selection.kind != "interactive":
            result = invoke_launcher(record)
    if selection.kind == "interactive":
        result = invoke_launcher(record)
        if result == 0:
            # Preserve the ordinary foreground lifecycle. Failed/interrupted
            # commands leave the sandbox available for diagnosis; persistent
            # launchers own their lifetime independently of an attach client.
            stop_agent_by_name(name)
    if launch_mode == "foreground" and record["launcher"]["kind"] not in {"interactive", "supervisor"}:
        from .agent_launchers import attach_agent

        return attach_agent(name)
    if launch_mode == "background":
        followup = f"safeyolo agent diag {name}" if selection.kind == "supervisor" else f"safeyolo agent attach {name}"
        console.print(f"Agent {name}: launch requested. Use {followup}.")
    # Launcher is frozen: the complementary interactive/non-interactive paths
    # above always assign result. CodeQL does not correlate these two checks.
    return result  # lgtm[py/uninitialized-local-variable]


def _run_agent_impl(
    name: str,
    folder_override: str | None = None,
    yolo: bool = False,
    dangerously_allow_unowned: bool = False,
    agent_args: list[str] | None = None,
    skip_default_args: bool = False,
    extra_mounts: list[str] | None = None,
    extra_ports: list[str] | None = None,
    no_snapshot: bool = False,
    rename_tmux_window: bool = False,
    *,
    _start_lock: _SetupLockHandle | None = None,
) -> int:
    """Run an agent VM. Returns exit code.

    Shared logic used by both `add` (auto-run) and `run` commands.

    Boot only: the launcher owns the coding-agent terminal or supervisor.
    no_snapshot: skip snapshot capture and restore for this run;
        don't touch an existing snapshot on disk either way.
    rename_tmux_window: rename the invoking tmux window to `name` once
        launch preflight has committed. See issue #330.
    """
    import sys as _sys

    from .agents_store import reserve_agent_network_slot
    from .commands.tmux import rename_window_for_agent
    from .config import load_config
    from .proxy import is_proxy_running, start_proxy, wait_for_healthy
    from .snapshot import (
        compute_snapshot_version,
        invalidate_snapshot,
        is_snapshot_valid,
        platform_supports_snapshot,
        snapshot_path,
    )
    from .timing import emit as _timing_emit
    from .timing import enter as _t
    from .vm import (
        _update_agent_map,
        get_agent_config_share_dir,
        get_agent_status_dir,
        prepare_config_share,
        vm_helper_failure_summary,
    )

    _t("cli entry (metadata, proxy check)")
    _validate_instance_name(name)

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
    from .platform import get_platform as _get_plat

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
    extra_env["SAFEYOLO_DETACH"] = "1"

    # Set up network isolation (platform-specific: vsock on macOS, netns on Linux)
    from .platform import get_platform

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
    from .sockets import path_for as _sock_path_for

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
        from .proxy import sync_proxy_modes

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
    try:
        memory_for_run = _effective_agent_memory_mb(metadata)
    except ValueError as err:
        console.print(f"[red]Invalid agent configuration:[/red] {err}")
        raise typer.Exit(1)
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
            workspace_path=workspace_path,
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

    run_background = True

    write_event("agent.started", kind="agent", severity="low", summary=f"Agent {name} started", agent=name)
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
            if restore_ok and _start_lock is not None:
                _start_lock.release()

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
            if _start_lock is not None:
                _start_lock.release()
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
                        f"  {escape(vm_helper_failure_summary(name, helper_pid))}"
                    )
                exit_code = 1
            else:
                console.print(" [green]ready[/green]")

        if plat.is_sandbox_running(name) and per_run_started.exists():
            _timing_emit()
            return 0

    except Exception as err:
        console.print(" [red]error[/red]")
        console.print(f"  {err}")
        exit_code = 1
    except KeyboardInterrupt:
        exit_code = 130

    write_event(
        "agent.stopped",
        kind="agent",
        severity="low",
        summary=f"Agent {name} stopped (exit {exit_code})",
        agent=name,
        details={"exit_code": exit_code},
    )

    _timing_emit()
    return exit_code
