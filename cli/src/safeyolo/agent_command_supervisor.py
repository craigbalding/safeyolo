"""Runtime supervision for a detached agent command.

The VM and the command running inside it have different lifetimes.  This
module owns the latter: a small host-side process starts the configured
command, retries unexpected exits with bounded backoff, and records enough
state for the normal CLI diagnostics to explain what happened.  It deliberately
does not create or consume Coord work and it never restarts the sandbox.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from .config import get_agent_command_supervisor_state_path

SCHEMA_VERSION = 1
MAX_STATE_BYTES = 128 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_FAILURES = 5
INITIAL_BACKOFF_SECONDS = 0.25
MAX_BACKOFF_SECONDS = 10.0
STOP_WAIT_SECONDS = 5.0
_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
log = logging.getLogger("safeyolo.agent-command-supervisor")


class SupervisorStateError(ValueError):
    """The persisted runtime supervisor state is not trustworthy."""


def _validate_name(name: str) -> None:
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"invalid agent name: {name!r}")


def _state_path(name: str) -> Path:
    _validate_name(name)
    return get_agent_command_supervisor_state_path(name)


def _stop_path(name: str) -> Path:
    return _state_path(name).with_name("command-supervisor.stop")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _bounded_text(value: str | None, limit: int = MAX_STDERR_BYTES) -> str:
    if not value:
        return ""
    if len(value.encode("utf-8", errors="replace")) <= limit:
        return value
    # Keep the most recent output: it normally contains the useful traceback
    # or shell error, while the beginning is often startup noise.
    encoded = value.encode("utf-8", errors="replace")[-limit:]
    return encoded.decode("utf-8", errors="replace")


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_state(name: str) -> dict | None:
    path = _state_path(name)
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise SupervisorStateError("state file exceeds diagnostic limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorStateError(f"cannot read state: {type(exc).__name__}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise SupervisorStateError("unsupported state schema")
    if value.get("name") != name or not isinstance(value.get("command"), str):
        raise SupervisorStateError("state identity is invalid")
    return value


def read_command_supervisor_state(name: str) -> dict | None:
    """Read the bounded diagnostic state without changing it."""
    return _read_state(name)


def _process_token(pid: int) -> str | None:
    from .runtime_identity import process_start_token

    return process_start_token(pid)


def _supervisor_is_ours(state: dict) -> bool:
    pid = state.get("supervisor_pid")
    token = state.get("supervisor_start_token")
    return type(pid) is int and pid > 0 and isinstance(token, str) and token == _process_token(pid)


def supervisor_process_is_live(state: dict) -> bool:
    """Return whether persisted supervisor identity still matches the OS."""
    return _supervisor_is_ours(state)


def _base_state(name: str, command: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "command": command,
        "state": "starting",
        "supervisor_pid": None,
        "supervisor_start_token": None,
        "started_at": _now(),
        "updated_at": _now(),
        "restart_count": 0,
        "consecutive_failures": 0,
        "last_exit_code": None,
        "last_exit_signal": None,
        "last_exit_reason": None,
        "last_stderr": "",
        "next_restart_at": None,
    }


def _update_state(name: str, **changes: object) -> dict:
    current = _read_state(name)
    if current is None:
        raise SupervisorStateError("supervisor state disappeared")
    current.update(changes)
    current["updated_at"] = _now()
    _write_json(_state_path(name), current)
    return current


def _drain(stream: TextIO | None, output: list[str], stop: threading.Event) -> None:
    if stream is None:
        return
    try:
        while True:
            chunk = stream.readline()
            if not chunk:
                break
            if output is not None:
                output.append(chunk)
                while sum(len(item.encode("utf-8", errors="replace")) for item in output) > MAX_STDERR_BYTES:
                    output.pop(0)
    except (OSError, ValueError):
        pass
    finally:
        stop.set()


def _collect_output(process: subprocess.Popen[str]) -> tuple[int, str]:
    """Drain both pipes so a verbose command cannot deadlock its supervisor."""
    stderr: list[str] = []
    stdout_done = threading.Event()
    stderr_done = threading.Event()
    stdout_thread = threading.Thread(
        target=_drain, args=(process.stdout, [], stdout_done), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_drain, args=(process.stderr, stderr, stderr_done), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()
    returncode = process.wait()
    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)
    return returncode, _bounded_text("".join(stderr))


class CommandSupervisor:
    """Testable supervision loop for one already-running sandbox command."""

    def __init__(
        self,
        name: str,
        command: str,
        *,
        platform,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
        max_failures: int = MAX_FAILURES,
    ) -> None:
        _validate_name(name)
        if not command.strip():
            raise ValueError("command cannot be empty")
        self.name = name
        self.command = command
        self.platform = platform
        self.sleep = sleep
        self.now = now
        self.max_failures = max_failures
        self.stop_requested = threading.Event()
        self.child: subprocess.Popen[str] | None = None

    def request_stop(self, *_signal_args: object) -> None:
        self.stop_requested.set()
        child = self.child
        if child is not None and child.poll() is None:
            try:
                child.terminate()
            except OSError:
                pass

    def _stop_marker_exists(self) -> bool:
        return _stop_path(self.name).exists()

    def _record_exit(self, returncode: int, stderr: str) -> None:
        signal_number = -returncode if returncode < 0 else None
        exit_code = returncode if returncode >= 0 else None
        _update_state(
            self.name,
            last_exit_code=exit_code,
            last_exit_signal=signal_number,
            last_exit_reason="intentional-stop"
            if self.stop_requested.is_set() or self._stop_marker_exists()
            else "command-exit",
            last_stderr=_bounded_text(stderr),
        )

    def run(self) -> int:
        failures = 0
        restart_count = 0
        try:
            while True:
                if self.stop_requested.is_set() or self._stop_marker_exists():
                    _update_state(
                        self.name,
                        state="stopped",
                        last_exit_reason="intentional-stop",
                        next_restart_at=None,
                    )
                    return 0

                try:
                    self.child = self.platform.popen_in_sandbox(
                        self.name, self.command, user="agent"
                    )
                    if self.child.stdin is not None:
                        self.child.stdin.close()
                    _update_state(
                        self.name,
                        state="running",
                        restart_count=restart_count,
                        consecutive_failures=failures,
                        next_restart_at=None,
                    )
                    returncode, stderr = _collect_output(self.child)
                except Exception as exc:  # noqa: BLE001 - runtime boundary
                    returncode = 1
                    stderr = f"{type(exc).__name__}: {exc}"
                finally:
                    self.child = None

                self._record_exit(returncode, stderr)
                if self.stop_requested.is_set() or self._stop_marker_exists():
                    _update_state(
                        self.name,
                        state="stopped",
                        next_restart_at=None,
                    )
                    return 0
                if returncode == 0:
                    _update_state(
                        self.name,
                        state="exited",
                        consecutive_failures=0,
                        next_restart_at=None,
                    )
                    return 0

                failures += 1
                restart_count += 1
                if failures >= self.max_failures:
                    _update_state(
                        self.name,
                        state="failed",
                        restart_count=restart_count,
                        consecutive_failures=failures,
                        next_restart_at=None,
                    )
                    return returncode

                delay = min(
                    INITIAL_BACKOFF_SECONDS * (2 ** (failures - 1)),
                    MAX_BACKOFF_SECONDS,
                )
                restart_at = self.now() + delay
                _update_state(
                    self.name,
                    state="restarting",
                    restart_count=restart_count,
                    consecutive_failures=failures,
                    next_restart_at=restart_at,
                )
                self.sleep(delay)
        except Exception as exc:  # state/reporting failures are terminal
            try:
                _update_state(
                    self.name,
                    state="failed",
                    last_exit_reason=f"supervisor-error: {type(exc).__name__}",
                    last_stderr=_bounded_text(str(exc)),
                    next_restart_at=None,
                )
            except Exception as state_error:  # noqa: BLE001 - preserve original failure
                log.debug("could not persist supervisor failure state: %s", state_error)
            return 1


def _run_supervisor(name: str) -> int:
    state = _read_state(name)
    if state is None:
        return 1
    from .platform import get_platform

    supervisor = CommandSupervisor(
        name,
        state["command"],
        platform=get_platform(),
    )
    signal.signal(signal.SIGTERM, supervisor.request_stop)
    signal.signal(signal.SIGINT, supervisor.request_stop)
    _write_json(
        _state_path(name),
        {
            **state,
            "supervisor_pid": os.getpid(),
            "supervisor_start_token": _process_token(os.getpid()),
            "state": "starting",
            "updated_at": _now(),
        },
    )
    result = supervisor.run()
    # Keep the final state useful after the process itself exits. A stale PID
    # is intentionally retained only as evidence; diagnostics verify its
    # token before describing a live supervisor.
    return result


def start_command_supervisor(name: str, command: str) -> None:
    """Start one independent host-side supervisor for a detached command."""
    _validate_name(name)
    if not command.strip():
        raise ValueError("detached agent has no command to run")
    existing = _read_state(name)
    if existing and existing.get("state") in {"starting", "running", "restarting"}:
        if _supervisor_is_ours(existing):
            raise RuntimeError(f"agent command supervisor already running for {name}")
        raise RuntimeError(f"stale command supervisor state for {name}; stop it first")
    state = _base_state(name, command)
    _stop_path(name).unlink(missing_ok=True)
    _write_json(_state_path(name), state)
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "safeyolo.agent_command_supervisor", "--run", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError:
        _update_state(
            name,
            state="failed",
            last_exit_reason="supervisor-start-failed",
            last_stderr="host runtime supervisor could not be started",
        )
        raise
    # The child records its own PID/token. This avoids a parent/child race in
    # which a very short command exits before the parent can publish identity.
    if process.poll() is not None and process.returncode != 0:
        _update_state(
            name,
            state="failed",
            last_exit_reason="supervisor-start-failed",
            last_stderr=f"host supervisor exited {process.returncode}",
        )


def request_command_supervisor_stop(name: str, *, timeout: float = STOP_WAIT_SECONDS) -> bool:
    """Suppress and stop the matching supervisor, verifying PID identity."""
    _validate_name(name)
    state = _read_state(name)
    if state is None:
        return True
    _write_json(_stop_path(name), {"requested_at": _now(), "name": name})
    pid = state.get("supervisor_pid")
    if _supervisor_is_ours(state):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return False
    elif state.get("state") in {"running", "restarting"}:
        return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current = _read_state(name)
        except SupervisorStateError:
            return False
        if current is None or current.get("state") == "stopped":
            return True
        time.sleep(0.05)
    return False


def clear_command_supervisor_stop(name: str) -> None:
    """Remove a stop marker only as part of starting a new run."""
    _stop_path(name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "--run":
        return _run_supervisor(args[1])
    print("usage: python -m safeyolo.agent_command_supervisor --run AGENT", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
