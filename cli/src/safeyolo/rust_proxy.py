"""Launch and stop the explicitly selected development Rust proxy."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .agent_command_supervisor import _write_json, _write_text
from .config import get_agent_map_path, get_bridge_sockets_dir, get_data_dir, get_logs_dir
from .runtime_identity import process_is_alive, process_start_token
from .rust_listener_json import update_listeners
from .sockets import remove_stale_sockets
from .traffic_session import (
    capture_session,
    session_process_id,
    start_session,
)

log = logging.getLogger("safeyolo.proxy")
STARTUP_TIMEOUT = 10.0


@contextmanager
def lifecycle_lock():
    """Serialize CLI starts and stops for the shared traffic session."""
    directory = get_data_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "proxy.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def state_file() -> Path:
    return get_data_dir() / "proxy-rust.json"


@dataclass
class RustProcess:
    pid: int | None
    start_token: str | None
    readiness_file: str
    admin_port: int | None
    admin_token_file: str | None
    config_file: str | None = None
    working_directory: str | None = None


def read_process() -> RustProcess | None:
    """Read lifetime state without treating damaged ownership as a stopped proxy."""
    try:
        raw = json.loads(state_file().read_text())
        process = RustProcess(**raw)
    except FileNotFoundError:
        return None
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RuntimeError(f"Invalid Rust proxy process record: {state_file()}") from exc
    if (
        (process.pid is not None and (type(process.pid) is not int or process.pid <= 1))
        or (process.start_token is not None and (
            not isinstance(process.start_token, str) or not process.start_token
        ))
        or not isinstance(process.readiness_file, str) or not Path(process.readiness_file).is_absolute()
        or (process.admin_port is not None and (
            type(process.admin_port) is not int or not 0 <= process.admin_port <= 65535
        ))
        or (process.admin_token_file is not None and (
            not isinstance(process.admin_token_file, str) or not Path(process.admin_token_file).is_absolute()
        ))
        or any(value is not None and (not isinstance(value, str) or not Path(value).is_absolute())
               for value in (process.config_file, process.working_directory))
    ):
        raise RuntimeError(f"Invalid Rust proxy process record: {state_file()}")
    return process


def is_alive(process: RustProcess, *, allow_unobservable_exit: bool = False) -> bool:
    """Return whether the recorded process is alive and still ours.

    ``allow_unobservable_exit`` is only used after a verified termination
    request.  Some macOS process states keep ``kill(pid, 0)`` successful for a
    short window after exit while ``ps`` no longer provides a start token.  At
    that point the process cannot be live and safely signalable through this
    receipt, so the stop wait treats the observation as an exit.  Callers that
    may signal a process keep the strict default and refuse unknown identity.
    """
    if process.pid is None:
        raise RuntimeError("Cannot identify the launched Rust proxy; its lifetime record and console have been retained")
    if not process_is_alive(process.pid):
        return False
    observed = process_start_token(process.pid)
    if observed is None or process.start_token is None:
        if allow_unobservable_exit:
            return False
        raise RuntimeError("Cannot verify Rust proxy process identity; lifetime state has been retained")
    return observed == process.start_token


def clear_process(process: RustProcess) -> None:
    """Remove an exited launch's records while the caller holds the lifecycle lock."""
    pid_file = get_data_dir() / "proxy.pid"
    try:
        if pid_file.read_text().strip() == str(process.pid):
            pid_file.unlink(missing_ok=True)
    except FileNotFoundError:
        # Native startup may fail before publishing the legacy PID file.
        pass
    readiness = Path(process.readiness_file)
    try:
        marker = json.loads(readiness.read_text())
    except (OSError, UnicodeError, ValueError):
        marker = None
    if not isinstance(marker, dict) or marker.get("pid") == process.pid:
        readiness.unlink(missing_ok=True)
    try:
        remove_stale_sockets()
    except OSError as exc:
        # A stale socket is secondary cleanup; retain the successful process
        # receipt cleanup while making the obstacle visible to diagnostics.
        log.warning("Could not remove stale Rust proxy sockets: %s", exc)
    state_file().unlink(missing_ok=True)


def _path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must name a filesystem path")
    return Path(value).absolute()


@dataclass(frozen=True)
class RustLaunch:
    binary: Path
    config: Path
    readiness: Path
    listeners: int
    admin_port: int | None
    admin_token: Path | None


def _binary() -> Path:
    supplied = os.environ.get("SAFEYOLO_RUST_PROXY")
    if supplied:
        candidates = [Path(supplied).expanduser()]
    else:
        checkout = Path(__file__).resolve().parents[3]
        candidates = [
            Path(__file__).with_name("bin") / "safeyolo-proxy",
            checkout / "proxy" / "target" / "release" / "safeyolo-proxy",
            checkout / "proxy" / "target" / "debug" / "safeyolo-proxy",
        ]
    candidate = next((path.absolute() for path in candidates if path.is_file()), candidates[0].absolute())
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise RuntimeError("Rust proxy executable missing; set SAFEYOLO_RUST_PROXY to a built safeyolo-proxy")
    try:
        result = subprocess.run([str(candidate), "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("Cannot run the selected Rust proxy --version") from exc
    if result.returncode != 0 or not result.stdout.startswith("safeyolo-proxy "):
        raise RuntimeError("Selected executable did not report a safeyolo-proxy version")
    return candidate


def prepare(config: dict) -> RustLaunch:
    """Read launch metadata; the Rust executable validates its complete JSON schema."""
    configured_path = config.get("proxy", {}).get("rust_config")
    if isinstance(configured_path, str):
        configured_path = os.path.expanduser(configured_path)
    path = _path(configured_path, "proxy.rust_config")
    try:
        source = path.read_text()
        native = json.loads(source)
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError(f"Cannot read native JSON configuration: {path}") from exc
    if not isinstance(native, dict):
        raise ValueError("Native JSON configuration must be an object")
    _path(native.get("policy_file"), "native policy_file")
    if native.get("temporary_policy_socket") is not None:
        raise ValueError("CLI Rust startup requires policy_file without temporary_policy_socket")
    readiness = _path(native.get("readiness_file"), "native readiness_file")
    _check_control_paths(native, path, readiness)
    listeners = native.get("listeners")
    if not isinstance(listeners, list):
        raise ValueError("Native listeners must be a JSON array")
    port = native.get("admin_port")
    if port is not None and (type(port) is not int or not 0 <= port <= 65535):
        raise ValueError("Native admin_port must be an integer from 0 to 65535")
    token = native.get("admin_api_token_file")
    token_path = _path(token, "native admin_api_token_file") if token else None
    binary = _binary()
    reconciled = _reconcile_listeners(native, Path.cwd())
    if reconciled != native:
        updated = update_listeners(source, listeners, reconciled["listeners"])
        _write_text(path, updated, mode=stat.S_IMODE(path.stat().st_mode))
    listeners = reconciled["listeners"]
    return RustLaunch(binary, path, readiness, len(listeners), port, token_path)


def _agent_listeners() -> list[dict] | None:
    """Read one agent-map snapshot; invalid input must never become an empty map."""
    from .sockets import path_for

    try:
        mapping = json.loads(get_agent_map_path().read_text())
    except FileNotFoundError:
        return None
    if not isinstance(mapping, dict):
        raise ValueError("agent_map.json must contain an object")
    listeners = []
    for name, entry in mapping.items():
        if not isinstance(entry, dict):
            raise ValueError("agent_map.json entries must contain objects")
        address = entry.get("ip")
        if address is None or address == "":
            continue
        if not isinstance(address, str):
            raise ValueError("agent_map.json addresses must be strings")
        listeners.append({"agent_id": name, "socket_path": str(path_for(name, address).absolute()),
                          "source_id": address})
    return listeners


def _reconcile_listeners(native: dict, working_directory: Path) -> dict:
    """Replace conventional CLI sockets and preserve operator-defined listeners."""
    from .sockets import parse

    configured = native.get("listeners")
    if not isinstance(configured, list):
        raise ValueError("Native listeners must be a JSON array")
    mapped = _agent_listeners()
    if mapped is None:
        return native
    directory = get_bridge_sockets_dir().resolve()
    retained = []
    for entry in configured:
        if not isinstance(entry, dict) or not isinstance(entry.get("socket_path"), str):
            raise ValueError("Native listeners need socket_path strings")
        path = (working_directory / entry["socket_path"]).resolve()
        managed = False
        if path.parent.parent == directory:
            try:
                parse(path)
                managed = True
            except ValueError:
                # Custom paths do not belong to the CLI's conventional socket set.
                pass
        if not managed:
            retained.append(entry)
    return {**native, "listeners": [*retained, *mapped]}


def sync_listeners(timeout: float = 5.0) -> bool:
    """Request a full native reload and confirm its listener update acknowledgement."""
    try:
        with lifecycle_lock():
            process = read_process()
            if process is None or not is_alive(process):
                return False
            if process.config_file is None or process.working_directory is None:
                raise RuntimeError("Restart the Rust proxy once to record its configuration path for listener updates")
            return _sync_running_listeners(process, timeout)
    except (OSError, ValueError, RuntimeError) as exc:
        log.warning("Rust listener synchronization failed: %s", exc)
        return False


def _sync_running_listeners(process: RustProcess, timeout: float) -> bool:
    path = Path(process.config_file)
    working_directory = Path(process.working_directory)
    source = path.read_text()
    native = json.loads(source)
    if not isinstance(native, dict):
        raise ValueError("Native JSON configuration must be an object")
    candidate = _reconcile_listeners(native, working_directory)
    requested = uuid.uuid4().hex
    candidate = {**candidate, "reload_id": requested}
    ready = candidate.get("readiness_file")
    if not isinstance(ready, str) or not ready:
        raise ValueError("Native readiness_file must name a filesystem path")
    observing = replace(process, readiness_file=str((working_directory / ready).absolute()))
    _check_control_paths(candidate, path, Path(observing.readiness_file), working_directory)
    updated = update_listeners(source, native["listeners"], candidate["listeners"], requested)
    _write_text(path, updated, mode=stat.S_IMODE(path.stat().st_mode))
    _signal_process(process, signal.SIGHUP)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not is_alive(process):
            raise RuntimeError("Rust proxy exited before acknowledging the listener update")
        marker = readiness(observing, listeners=len(candidate["listeners"]))
        if marker is not None and marker.get("reload_id") == requested:
            if not is_alive(process):
                raise RuntimeError("Rust proxy exited while acknowledging the listener update")
            _write_json(state_file(), asdict(observing))
            log.info("Rust listener update accepted (%d listeners)", marker["listeners"])
            return True
        time.sleep(0.05)
    log.warning("Rust listener update was not acknowledged within %gs; requested JSON remains for the next reload/start",
                timeout)
    return False


def _check_control_paths(native: dict, config: Path, ready: Path, working_directory: Path | None = None) -> None:
    """Do not unlink native input/state files or overwrite the CLI's ownership."""
    directory = working_directory if working_directory is not None else Path.cwd()
    controls = {state_file().resolve(), (get_data_dir() / "proxy.pid").resolve(),
                (get_data_dir() / "proxy.lock").resolve()}
    paths = [config, get_logs_dir() / "safeyolo.jsonl"]
    for field in (
        "policy_file", "agent_map_file", "admin_api_token_file", "tls_ca_file", "upstream_ca_file",
        "circuit_state_file", "flow_store_db_path", "audit_log_path", "event_log",
    ):
        if isinstance(native.get(field), str) and native[field]:
            paths.append(Path(native[field]))
    inspection = native.get("inspection")
    if isinstance(inspection, dict) and isinstance(inspection.get("policy_file"), str):
        paths.append(Path(inspection["policy_file"]))
    if ready.resolve() in controls or any((directory / path).resolve() in controls | {ready.resolve()} for path in paths):
        raise ValueError("Native input/state paths, readiness and CLI process records must not overlap")


def readiness(process: RustProcess, *, listeners: int | None = None) -> dict | None:
    """Accept only a complete marker published by the identified process."""
    try:
        marker = json.loads(Path(process.readiness_file).read_text())
    except (FileNotFoundError, UnicodeError, ValueError):
        # Replacement is atomic, but a stale or incomplete marker is not readiness.
        return None
    if not isinstance(marker, dict):
        return None
    valid = (
        marker.get("ready") is True
        and type(marker.get("pid")) is int and marker["pid"] == process.pid
        and marker.get("backend") == "rust-m2"
        and isinstance(marker.get("instance_id"), str) and bool(marker["instance_id"])
        and type(marker.get("listeners")) is int and marker["listeners"] >= 0
        and (listeners is None or marker["listeners"] == listeners)
    )
    port = marker.get("admin_port")
    if process.admin_port is not None:
        valid = valid and type(port) is int and 1 <= port <= 65535
        valid = valid and (process.admin_port == 0 or port == process.admin_port)
    else:
        valid = valid and port is None
    return marker if valid else None


def stop(process: RustProcess) -> None:
    """Wait for native transport and evidence cleanup, retaining state on interruption."""
    if is_alive(process):
        log.info("Waiting for Rust proxy transport and evidence cleanup (PID %d)", process.pid)
        try:
            _terminate(process)
        except ProcessLookupError:
            # It exited between the ownership observation and signal delivery.
            pass
        while is_alive(process, allow_unobservable_exit=True):
            time.sleep(0.1)
    # Keep the exited console for diagnostics. start_session reaps a dead pane
    # on the next launch. A failed pane query must never kill a replacement pane.
    clear_process(process)


def _terminate(process: RustProcess) -> None:
    _signal_process(process, signal.SIGTERM)


def _signal_process(process: RustProcess, selected_signal: int) -> None:
    """Pin Linux signal delivery to the identity observed after opening its PID handle."""
    if process.pid is None:
        raise RuntimeError("Cannot signal an unidentified Rust proxy")
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        descriptor = os.pidfd_open(process.pid)
        try:
            if is_alive(process):
                signal.pidfd_send_signal(descriptor, selected_signal)
        finally:
            os.close(descriptor)
    elif is_alive(process):
        # Other supported hosts use the existing start-token check and POSIX
        # signal convention; they do not provide Linux's atomic PID handle.
        os.kill(process.pid, selected_signal)


def _wait_ready(process: RustProcess, launch: RustLaunch) -> dict:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if not is_alive(process):
            raise RuntimeError("Rust proxy exited before readiness")
        marker = readiness(process, listeners=launch.listeners)
        if marker is not None:
            return marker
        time.sleep(0.05)
    raise RuntimeError(f"Rust proxy did not signal ready within {STARTUP_TIMEOUT:g}s")


def _console() -> str:
    try:
        return capture_session()
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        # Diagnostics are secondary; preserve the launch failure when tmux fails.
        return f"Console unavailable ({type(exc).__name__})"


def _cleanup_failed_start(process: RustProcess, failure: BaseException | None) -> None:
    try:
        stop(process)
    except (OSError, RuntimeError) as cleanup:
        if failure is None:
            raise
        # Preserve the original startup failure or cancellation and the receipt.
        failure.add_note(f"Rust proxy cleanup incomplete: {cleanup}")
        log.error("Rust proxy cleanup incomplete: %s", cleanup)


def start(config: dict) -> None:
    """Launch once in the private PTY; never select another backend on failure."""
    launch = prepare(config)
    if session_process_id() is not None:
        raise RuntimeError("The traffic session is still running; stop it before launching Rust")
    launch.readiness.unlink(missing_ok=True)
    log.warning(
        "Starting development Rust proxy from explicit JSON; HTTP credential inspection, "
        "vault injection and the full operator UI/management workflows are not yet implemented"
    )
    env = os.environ.copy()
    env["SAFEYOLO_DATA_DIR"] = str(get_data_dir().absolute())
    env["SAFEYOLO_LOG_PATH"] = str((get_logs_dir(create=True) / "safeyolo.jsonl").absolute())
    # The native proxy invokes only this fixed SafeYolo presenter module for
    # desktop approvals.  The interpreter is inherited from the trusted CLI
    # launcher; request data supplies a validated stable agent ID only.
    env["SAFEYOLO_DESKTOP_PRESENTER_PYTHON"] = sys.executable
    process = RustProcess(None, None, str(launch.readiness), launch.admin_port,
                          str(launch.admin_token) if launch.admin_token else None,
                          str(launch.config), str(Path.cwd()))
    # A failed identity observation must not send a later stop down the legacy
    # PID path. Retain one lifetime record throughout launch, even before readiness.
    _write_json(state_file(), asdict(process))
    try:
        process.pid = start_session(
            [str(launch.binary), "--config", str(launch.config)],
            env=env, exec_command=True, cwd=Path.cwd(),
        )
    except (OSError, subprocess.CalledProcessError):
        # start_session owns cleanup when session creation fails. Cancellation
        # retains uncertain ownership instead of treating the process as absent.
        state_file().unlink(missing_ok=True)
        raise
    _write_json(state_file(), asdict(process))
    if process.pid is not None:
        process.start_token = process_start_token(process.pid)
        _write_json(state_file(), asdict(process))
    if process.pid is None or process.start_token is None:
        raise RuntimeError(f"Cannot identify the launched Rust proxy; lifetime record retained.\n{_console()}")
    pid = process.pid
    complete = False
    try:
        try:
            marker = _wait_ready(process, launch)
        except RuntimeError as exc:
            raise RuntimeError(f"{exc}\nRust proxy console:\n{_console()}") from exc
        process.admin_port = marker.get("admin_port")
        _write_json(state_file(), asdict(process))
        _write_json(get_data_dir() / "proxy.pid", pid)
        complete = True
    finally:
        if not complete:
            _cleanup_failed_start(process, sys.exception())
    log.info("Rust proxy ready (PID %d, %d listeners)", pid, launch.listeners)
