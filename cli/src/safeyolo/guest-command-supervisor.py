#!/usr/bin/env python3
"""PID-1-owned supervisor for a detached SafeYolo command.

This file is copied into the per-run config share.  It intentionally has no
SafeYolo package dependency: custom rootfs images only need the Python runtime
already required by the standard guest.  The guest init process owns this
process and starts a replacement if this process is killed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path

STATE = Path(
    os.environ.get(
        "SAFEYOLO_COMMAND_SUPERVISOR_STATE",
        "/home/agent/.safeyolo-command-supervisor.json",
    )
)
STOP = Path(
    os.environ.get(
        "SAFEYOLO_COMMAND_SUPERVISOR_STOP",
        "/home/agent/.safeyolo-command-supervisor.stop",
    )
)
SCHEMA_VERSION = 1
MAX_STATE_BYTES = 128 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_FAILURES = 5
STABLE_INTERVAL_SECONDS = 60.0
INITIAL_BACKOFF_SECONDS = 0.25
MAX_BACKOFF_SECONDS = 10.0
CHUNK_BYTES = 4096
_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))"
)
_STATE_LOCK = threading.Lock()


def _now() -> float:
    return time.time()


def _sanitize(value: str) -> str:
    value = _ANSI_RE.sub("", value)
    return "".join(
        char if char in "\n\t\r" or ord(char) >= 32 else f"\\x{ord(char):02x}"
        for char in value
    )


class _Tail:
    def __init__(self) -> None:
        self.data = bytearray()
        self.total = 0
        self.digest = hashlib.sha256()

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        self.digest.update(chunk)
        self.data.extend(chunk)
        if len(self.data) > MAX_STDERR_BYTES:
            del self.data[: len(self.data) - MAX_STDERR_BYTES]

    @property
    def text(self) -> str:
        return _sanitize(bytes(self.data).decode("utf-8", errors="replace"))

    @property
    def truncated(self) -> bool:
        return self.total > MAX_STDERR_BYTES


def _write(value: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_name(f".{STATE.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE)
    finally:
        temporary.unlink(missing_ok=True)


def _read() -> dict | None:
    try:
        if STATE.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("state file exceeds diagnostic limit")
        value = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read state: {type(exc).__name__}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported state schema")
    if not isinstance(value.get("command"), str) or not value["command"].strip():
        raise ValueError("state command is invalid")
    return value


def _update(**changes: object) -> dict | None:
    with _STATE_LOCK:
        state = _read()
        if state is None:
            return None
        state.update(changes)
        state["updated_at"] = _now()
        _write(state)
        return state


def _proc_token(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        return fields[21]
    except (OSError, IndexError, ValueError):
        return None


def _kill_old_command(state: dict) -> None:
    pid = state.get("command_pid")
    token = state.get("command_start_token")
    if type(pid) is not int or pid <= 0 or not isinstance(token, str):
        return
    if _proc_token(pid) != token:
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return
    deadline = _now() + 1.0
    while _now() < deadline and _proc_token(pid) == token:
        time.sleep(0.05)
    if _proc_token(pid) == token:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass


def _drain(stream, capture: _Tail | None) -> None:
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            if capture is not None:
                capture.add(chunk)
    except (OSError, ValueError):
        return


def _collect(child: subprocess.Popen[bytes]) -> tuple[int, _Tail]:
    stderr = _Tail()
    stdout_thread = threading.Thread(target=_drain, args=(child.stdout, None), daemon=True)
    stderr_thread = threading.Thread(target=_drain, args=(child.stderr, stderr), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    returncode = child.wait()
    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)
    return returncode, stderr


class GuestSupervisor:
    def __init__(self) -> None:
        self.stop_requested = threading.Event()
        self.child: subprocess.Popen[bytes] | None = None

    def request_stop(self, *_args: object) -> None:
        self.stop_requested.set()
        child = self.child
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except OSError:
                try:
                    child.terminate()
                except OSError:
                    pass

    def run(self) -> int:
        heartbeat_stop = threading.Event()
        stop_watcher_stop = threading.Event()

        def heartbeat() -> None:
            while not heartbeat_stop.wait(1.0):
                try:
                    state = _read()
                    if state and state.get("state") == "running":
                        _update(heartbeat_at=_now())
                except (OSError, ValueError):
                    pass

        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
        heartbeat_thread.start()

        def stop_watcher() -> None:
            while not stop_watcher_stop.wait(0.1):
                if STOP.exists():
                    self.request_stop()
                    return

        stop_watcher_thread = threading.Thread(target=stop_watcher, daemon=True)
        stop_watcher_thread.start()
        try:
            return self._run_loop()
        finally:
            heartbeat_stop.set()
            stop_watcher_stop.set()
            heartbeat_thread.join(timeout=1.0)
            stop_watcher_thread.join(timeout=1.0)

    def _run_loop(self) -> int:
        failures = 0
        restarts = 0
        state = _read()
        if state is not None:
            failures = int(state.get("consecutive_failures", 0) or 0)
            restarts = int(state.get("restart_count", 0) or 0)
            _kill_old_command(state)
            if state.get("state") == "running":
                previous_started = state.get("attempt_started_at")
                previous_uptime = (
                    max(0.0, _now() - previous_started)
                    if isinstance(previous_started, (int, float))
                    else 0.0
                )
                if previous_uptime >= STABLE_INTERVAL_SECONDS:
                    failures = 0
                failures += 1
                _update(
                    last_exit_reason="supervisor-restarted",
                    last_uptime_seconds=previous_uptime,
                    command_pid=None,
                    command_start_token=None,
                    consecutive_failures=failures,
                    failure_window_started_at=_now() if failures == 1 else state.get(
                        "failure_window_started_at"
                    ),
                )
                if failures >= MAX_FAILURES:
                    _update(state="failed", next_restart_at=None)
                    return 1

        while True:
            if self.stop_requested.is_set() or STOP.exists():
                _update(
                    state="stopped",
                    next_restart_at=None,
                    command_pid=None,
                    command_start_token=None,
                )
                return 0

            state = _read()
            if state is None:
                time.sleep(0.2)
                continue
            if state.get("state") in {"stopped", "failed"}:
                return 0 if state.get("state") == "stopped" else 1

            attempt_started = _now()
            try:
                self.child = subprocess.Popen(
                    ["/bin/bash", "-lc", state["command"]],
                    cwd="/workspace",
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                _update(
                    state="running",
                    runtime_owner="guest-pid1",
                    supervisor_pid=os.getpid(),
                    supervisor_start_token=_proc_token(os.getpid()),
                    command_pid=self.child.pid,
                    command_start_token=_proc_token(self.child.pid),
                    attempt_started_at=attempt_started,
                    heartbeat_at=_now(),
                    next_restart_at=None,
                    restart_count=restarts,
                    consecutive_failures=failures,
                )
                returncode, stderr = _collect(self.child)
            except Exception as exc:  # noqa: BLE001 - guest runtime boundary
                returncode = 1
                stderr = _Tail()
                stderr.add(f"{type(exc).__name__}: {exc}".encode())
            finally:
                self.child = None

            uptime = max(0.0, _now() - attempt_started)
            intentional = self.stop_requested.is_set() or STOP.exists()
            reason = "intentional-stop" if intentional else (
                "command-exit-clean" if returncode == 0 else
                "command-signal" if returncode < 0 else "command-exit-nonzero"
            )
            if uptime >= STABLE_INTERVAL_SECONDS:
                failures = 0
            if not intentional:
                failures += 1
            _update(
                last_exit_code=returncode if returncode >= 0 else None,
                last_exit_signal=-returncode if returncode < 0 else None,
                last_exit_reason=reason,
                last_stderr=stderr.text,
                last_stderr_bytes=stderr.total,
                last_stderr_truncated=stderr.truncated,
                last_stderr_sha256=stderr.digest.hexdigest(),
                last_uptime_seconds=uptime,
                command_pid=None,
                command_start_token=None,
                consecutive_failures=failures,
            )
            if intentional:
                _update(state="stopped", next_restart_at=None)
                return 0
            restarts += 1
            if failures >= MAX_FAILURES:
                _update(
                    state="failed",
                    restart_count=restarts,
                    consecutive_failures=failures,
                    next_restart_at=None,
                )
                return returncode
            delay = min(INITIAL_BACKOFF_SECONDS * (2 ** (failures - 1)), MAX_BACKOFF_SECONDS)
            _update(
                state="restarting",
                restart_count=restarts,
                consecutive_failures=failures,
                next_restart_at=_now() + delay,
            )
            time.sleep(delay)


def main() -> int:
    supervisor = GuestSupervisor()
    signal.signal(signal.SIGTERM, supervisor.request_stop)
    signal.signal(signal.SIGINT, supervisor.request_stop)
    try:
        return supervisor.run()
    except Exception as exc:  # noqa: BLE001 - state/reporting boundary
        try:
            _update(
                state="failed",
                last_exit_reason=f"supervisor-error: {type(exc).__name__}",
                last_stderr=_sanitize(str(exc)),
                next_restart_at=None,
            )
        except Exception:
            return 1
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
