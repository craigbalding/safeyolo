"""State and testable policy for detached agent-command supervision.

The VM and the command running inside it have different lifetimes.  The
production owner is guest PID 1, which launches the standalone supervisor from
the config share.  This module publishes the shared state and retains the
same policy as a testable host-side model; it never creates or consumes Coord
work and it never restarts the sandbox.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from .config import get_agent_command_supervisor_state_path

SCHEMA_VERSION = 1
MAX_STATE_BYTES = 128 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_FAILURES = 5
STABLE_INTERVAL_SECONDS = 60.0
INITIAL_BACKOFF_SECONDS = 0.25
MAX_BACKOFF_SECONDS = 10.0
STOP_WAIT_SECONDS = 5.0
READ_CHUNK_BYTES = 4096
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


_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))"
)


def sanitize_terminal_text(value: str) -> str:
    """Keep diagnostics printable without allowing terminal control input."""
    value = _ANSI_RE.sub("", value)
    return "".join(
        char if char in "\n\t\r" or ord(char) >= 32 else f"\\x{ord(char):02x}"
        for char in value
    )


class _CapturedOutput:
    """Bounded tail plus complete byte accounting for one command attempt."""

    def __init__(self) -> None:
        self._tail = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()

    def add(self, value: str | bytes) -> None:
        encoded = (
            value.encode("utf-8", errors="replace")
            if isinstance(value, str)
            else value
        )
        self.total_bytes += len(encoded)
        self.digest.update(encoded)
        self._tail.extend(encoded)
        if len(self._tail) > MAX_STDERR_BYTES:
            del self._tail[: len(self._tail) - MAX_STDERR_BYTES]

    @property
    def text(self) -> str:
        return sanitize_terminal_text(
            bytes(self._tail).decode("utf-8", errors="replace")
        )

    @property
    def truncated(self) -> bool:
        return self.total_bytes > MAX_STDERR_BYTES


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
    """Return whether the persisted runtime owner still reports liveness."""
    if state.get("runtime_owner") == "guest-pid1":
        heartbeat = state.get("heartbeat_at")
        return (
            state.get("state") == "running"
            and isinstance(heartbeat, (int, float))
            and 0 <= time.time() - heartbeat <= 5.0
        )
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
        "last_stderr_bytes": 0,
        "last_stderr_truncated": False,
        "last_stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "last_uptime_seconds": None,
        "attempt_started_at": None,
        "failure_window_started_at": None,
        "heartbeat_at": None,
        "runtime_owner": "guest-pid1",
        "command_pid": None,
        "command_start_token": None,
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


def _drain(
    stream: TextIO | BinaryIO | None,
    output: _CapturedOutput | None,
    stop: threading.Event,
) -> None:
    if stream is None:
        return
    try:
        while True:
            # Fixed-size reads prevent a newline-free diagnostic record from
            # allocating without bound before the tail can be capped.
            chunk = stream.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            if output is not None:
                output.add(chunk)
    except (OSError, ValueError):
        pass
    finally:
        stop.set()


def _collect_output(process: subprocess.Popen[str]) -> tuple[int, _CapturedOutput]:
    """Drain both pipes so a verbose command cannot deadlock its supervisor."""
    stderr = _CapturedOutput()
    stdout_done = threading.Event()
    stderr_done = threading.Event()
    stdout_thread = threading.Thread(
        target=_drain, args=(process.stdout, None, stdout_done), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_drain, args=(process.stderr, stderr, stderr_done), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()
    returncode = process.wait()
    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)
    return returncode, stderr


class CommandSupervisor:
    """Testable supervision loop for one already-running sandbox command."""

    def __init__(
        self,
        name: str,
        command: str,
        *,
        platform,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
        max_failures: int = MAX_FAILURES,
        stable_interval_seconds: float = STABLE_INTERVAL_SECONDS,
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
        self.stable_interval_seconds = stable_interval_seconds
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

    def _record_exit(
        self,
        returncode: int,
        stderr: _CapturedOutput,
        uptime_seconds: float,
    ) -> None:
        signal_number = -returncode if returncode < 0 else None
        exit_code = returncode if returncode >= 0 else None
        intentional = self.stop_requested.is_set() or self._stop_marker_exists()
        reason = "intentional-stop" if intentional else (
            "command-exit-clean" if returncode == 0 else
            "command-signal" if returncode < 0 else "command-exit-nonzero"
        )
        _update_state(
            self.name,
            last_exit_code=exit_code,
            last_exit_signal=signal_number,
            last_exit_reason=reason,
            last_stderr=stderr.text,
            last_stderr_bytes=stderr.total_bytes,
            last_stderr_truncated=stderr.truncated,
            last_stderr_sha256=stderr.digest.hexdigest(),
            last_uptime_seconds=uptime_seconds,
        )

    def run(self) -> int:
        current = _read_state(self.name)
        failures = int((current or {}).get("consecutive_failures", 0) or 0)
        restart_count = int((current or {}).get("restart_count", 0) or 0)
        failure_window_started_at = (current or {}).get("failure_window_started_at")
        if current and current.get("state") == "running":
            previous_started = current.get("attempt_started_at")
            previous_uptime = (
                max(0.0, self.now() - previous_started)
                if isinstance(previous_started, (int, float))
                else 0.0
            )
            if previous_uptime >= self.stable_interval_seconds:
                failures = 0
            failures += 1
            failure_window_started_at = failure_window_started_at or self.now()
            _update_state(
                self.name,
                last_exit_reason="supervisor-restarted",
                last_uptime_seconds=previous_uptime,
                command_pid=None,
                command_start_token=None,
                consecutive_failures=failures,
                failure_window_started_at=failure_window_started_at,
            )
            if failures >= self.max_failures:
                _update_state(self.name, state="failed", next_restart_at=None)
                return 1
        try:
            while True:
                if self.stop_requested.is_set() or self._stop_marker_exists():
                    _update_state(
                        self.name,
                        state="stopped",
                        next_restart_at=None,
                    )
                    return 0

                try:
                    self.child = self.platform.popen_in_sandbox(
                        self.name, self.command, user="agent"
                    )
                    if self.child.stdin is not None:
                        self.child.stdin.close()
                    attempt_started_at = self.now()
                    _update_state(
                        self.name,
                        state="running",
                        restart_count=restart_count,
                        consecutive_failures=failures,
                        attempt_started_at=attempt_started_at,
                        heartbeat_at=self.now(),
                        next_restart_at=None,
                    )
                    returncode, stderr = _collect_output(self.child)
                except Exception as exc:  # noqa: BLE001 - runtime boundary
                    returncode = 1
                    stderr = _CapturedOutput()
                    stderr.add(f"{type(exc).__name__}: {exc}")
                    attempt_started_at = locals().get("attempt_started_at", self.now())
                finally:
                    self.child = None

                uptime_seconds = max(0.0, self.now() - attempt_started_at)
                self._record_exit(returncode, stderr, uptime_seconds)
                if self.stop_requested.is_set() or self._stop_marker_exists():
                    _update_state(
                        self.name,
                        state="stopped",
                        next_restart_at=None,
                    )
                    return 0
                if uptime_seconds >= self.stable_interval_seconds:
                    failures = 0
                    failure_window_started_at = self.now()
                else:
                    failure_window_started_at = failure_window_started_at or self.now()
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
                    failure_window_started_at=failure_window_started_at,
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


def start_command_supervisor(name: str, command: str) -> None:
    """Publish a command for the already-running guest PID 1 owner.

    The state file is on the persistent home share.  Guest PID 1 notices it
    and owns the supervisor process, so the host CLI and its transport can
    exit without orphaning a recovery authority.
    """
    _validate_name(name)
    if not command.strip():
        raise ValueError("detached agent has no command to run")
    existing = _read_state(name)
    if existing and existing.get("state") in {"starting", "running", "restarting"}:
        if supervisor_process_is_live(existing) or _supervisor_is_ours(existing):
            raise RuntimeError(f"agent command supervisor already running for {name}")
        raise RuntimeError(f"stale command supervisor state for {name}; stop it first")
    state = _base_state(name, command)
    _stop_path(name).unlink(missing_ok=True)
    _write_json(_state_path(name), state)


def request_command_supervisor_stop(name: str, *, timeout: float = STOP_WAIT_SECONDS) -> bool:
    """Suppress and stop the matching supervisor, verifying PID identity."""
    _validate_name(name)
    state = _read_state(name)
    if state is None:
        return True
    _write_json(_stop_path(name), {"requested_at": _now(), "name": name})
    if state.get("state") in {"stopped", "failed", "exited"}:
        if state.get("state") != "stopped":
            _update_state(name, state="stopped", next_restart_at=None)
        return True
    pid = state.get("supervisor_pid")
    if _supervisor_is_ours(state):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return False
    elif (
        state.get("runtime_owner") != "guest-pid1"
        and state.get("state") in {"running", "restarting"}
    ):
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
