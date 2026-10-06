"""Agent lifecycle helpers still used by Python workflow callers."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import threading
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from .agent_configuration import _validate_instance_name
from .agents_store import load_agent

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


def _native_cli(arguments: list[str], *, setup_name: str | None = None,
                capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    """Run the installed native owner; retain a workflow's existing setup lock."""
    from .config import get_config_dir

    root = get_config_dir().resolve()
    executable = root / "bin" / "safeyolo"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise AgentLifecycleError(f"Native CLI is missing: {executable}; install the native host artifacts")
    environment = os.environ.copy()
    environment.pop("SAFEYOLO_HOST_SETUP_LOCK_FD", None)
    descriptor = _held_setup_locks().get(setup_name)
    descriptors = () if descriptor is None else (descriptor,)
    if descriptor is not None:
        environment["SAFEYOLO_HOST_SETUP_LOCK_FD"] = str(descriptor)
    try:
        return subprocess.run(
            [str(executable), "--root", str(root), *arguments],
            env=environment, pass_fds=descriptors, text=True,
            capture_output=capture_output, check=False,
        )
    except OSError as exc:
        raise AgentLifecycleError(f"Cannot execute native CLI {executable}: {exc}") from exc


def _native_result(arguments: list[str], *, setup_name: str | None = None) -> dict:
    result = _native_cli(arguments, setup_name=setup_name, capture_output=True)
    if result.returncode:
        raise AgentLifecycleError(result.stderr.strip() or f"Native CLI exited {result.returncode}")
    try:
        value = json.loads(result.stdout)
    except ValueError as exc:
        raise AgentLifecycleError("Native CLI returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AgentLifecycleError("Native CLI returned no status object")
    return value


def list_agent_runtimes() -> list[dict]:
    """Read native reconciled observations without another runtime projection."""
    agents = _native_result(["status"]).get("agents")
    if not isinstance(agents, list) or any(not isinstance(agent, dict) for agent in agents):
        raise AgentLifecycleError("Native CLI returned no agent inventory")
    return agents


def native_agent_status(name: str) -> dict:
    _validate_instance_name(name)
    observed = _native_result(["agent", "status", name])
    if not isinstance(observed.get("runtime_state"), str):
        raise AgentLifecycleError("Native CLI returned no runtime state")
    return observed


def stop_agent_by_name(name: str, *, on_phase: Callable[[str], None] | None = None) -> dict:
    """Delegate stop intent, backend cleanup and listener reconciliation to Rust."""
    _validate_instance_name(name)
    if on_phase:
        on_phase("native agent stop and reconciliation")
    return _native_result(["agent", "stop", name], setup_name=name)


class _SetupLockHandle:
    """An agent setup lock that can be released after the boot transition."""

    def __init__(self, fd: int | None, name: str, held: dict[str, int]) -> None:
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
            self._held.pop(self._name, None)


_setup_lock_state = threading.local()


def _held_setup_locks() -> dict[str, int]:
    held = getattr(_setup_lock_state, "names", None)
    if held is None:
        held = {}
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
            # Concurrent setup may create it after lstat; the safe open below verifies it.
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
    from .config import get_agents_dir
    from .vm import ensure_agent_persistent_dirs

    held = _held_setup_locks()
    if name in held:
        # Factory startup holds every role lock while calling the ordinary
        # setup/run helpers. Re-entry in this thread must not acquire a second
        # file descriptor, while other threads still block on flock().
        yield _SetupLockHandle(None, name, held)
        return

    ensure_agent_persistent_dirs(name)
    # Native lifecycle and remaining workflow callers must lock the same
    # protected inode. The guest can replace entries in its writable home.
    setup_dir = get_agents_dir() / name
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

        held[name] = fd
        handle = _SetupLockHandle(fd, name, held)
        fd = None
        try:
            yield handle
        finally:
            handle.release()
    finally:
        if fd is not None:
            os.close(fd)


def start_native_agent(
    name: str,
    *,
    launch_mode: str = "foreground",
    dangerously_allow_unowned: bool = False,
    agent_args: list[str] | None = None,
) -> int:
    """Start through the native owner with local, one-launch arguments."""
    _validate_instance_name(name)
    arguments = ["agent", "start", name]
    if launch_mode == "foreground":
        arguments.append("--foreground")
    elif launch_mode == "sandbox":
        arguments.append("--sandbox-only")
    elif launch_mode != "background":
        raise ValueError(f"Unknown native launch mode: {launch_mode}")
    if dangerously_allow_unowned:
        arguments.append("--dangerously-allow-unowned")
    if agent_args is not None:
        arguments.extend(["--", *(agent_args or [])])
    return _native_cli(arguments, setup_name=name).returncode
