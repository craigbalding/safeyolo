"""Opt-in, cross-process lifecycle profiling.

The public CLI enables this with ``--profile``. ``SAFEYOLO_TIMING=1`` remains
supported for existing agent-run diagnostics. Events are appended atomically
to a per-command JSONL artifact so the proxy child can contribute timings
without changing synchronization or readiness behavior.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from . import PROCESS_STARTED_AT_NS

P = ParamSpec("P")
R = TypeVar("R")

_PATH_ENV = "SAFEYOLO_PROFILE_PATH"
_OPERATION_ENV = "SAFEYOLO_PROFILE_OPERATION"
_PROCESS_ENV = "SAFEYOLO_PROFILE_PROCESS"

_path: Path | None = Path(os.environ[_PATH_ENV]) if os.environ.get(_PATH_ENV) else None
_operation = os.environ.get(_OPERATION_ENV, "lifecycle")
_process = os.environ.get(_PROCESS_ENV, "cli")
_command_started_ns = PROCESS_STARTED_AT_NS
_checkpoint_name: str | None = None
_checkpoint_started_ns = 0
_emitted = False
_addon_totals: dict[tuple[str, str], list[float | int]] = defaultdict(
    lambda: [0.0, 0, 0.0]
)
_addon_profiler_installed = False
_original_addon_invoke: Callable[..., Any] | None = None


def enabled() -> bool:
    return _path is not None


def _safe_operation(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-") or "lifecycle"


def _default_path(operation: str) -> Path:
    # Lazy import avoids pulling configuration into the traffic-master child.
    from .config import get_logs_dir

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return get_logs_dir() / "profiles" / f"{stamp}-{_safe_operation(operation)}-{os.getpid()}.jsonl"


def _append(payload: dict[str, Any]) -> None:
    if _path is None:
        return
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    except OSError:
        # Profiling must never change proxy or sandbox lifecycle behavior if a
        # diagnostics filesystem disappears or fills after the command begins.
        return


def _event(
    name: str,
    started_ns: int,
    ended_ns: int,
    *,
    category: str = "phase",
    details: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "schema": 1,
        "operation": _operation,
        "process": _process,
        "pid": os.getpid(),
        "category": category,
        "name": name,
        "started_ns": started_ns,
        "ended_ns": ended_ns,
        "duration_ms": round((ended_ns - started_ns) / 1_000_000, 3),
    }
    if details:
        payload["details"] = details
    _append(payload)


def enable(operation: str, *, requested: bool = True) -> Path | None:
    """Enable a fresh command profile, returning its artifact path."""
    global _path, _operation, _process, _command_started_ns, _emitted
    global _checkpoint_name, _checkpoint_started_ns

    if not requested and os.environ.get("SAFEYOLO_TIMING") != "1":
        return None
    if _path is not None and os.environ.get(_PATH_ENV) and not _emitted:
        # Child processes inherit an existing profile rather than truncating it.
        return _path

    _operation = operation
    _process = "cli"
    _command_started_ns = PROCESS_STARTED_AT_NS
    _path = _default_path(operation)
    _path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _path.unlink(missing_ok=True)
    _path.touch(mode=0o600)
    _path.chmod(0o600)
    os.environ[_PATH_ENV] = str(_path)
    os.environ[_OPERATION_ENV] = operation
    os.environ[_PROCESS_ENV] = "cli"
    _emitted = False
    _checkpoint_name = "command dispatch"
    _checkpoint_started_ns = time.monotonic_ns()
    _event(
        "SafeYolo package/CLI imports and argument parsing",
        PROCESS_STARTED_AT_NS,
        _checkpoint_started_ns,
    )
    return _path


def child_environment(process: str) -> dict[str, str]:
    """Return profile variables to merge into a child environment."""
    if _path is None or _emitted:
        return {}
    return {
        _PATH_ENV: str(_path),
        _OPERATION_ENV: _operation,
        _PROCESS_ENV: process,
    }


def enter(name: str) -> None:
    """Close the current sequential phase and start ``name``."""
    global _checkpoint_name, _checkpoint_started_ns
    if _path is None and os.environ.get("SAFEYOLO_TIMING") == "1":
        enable("agent run", requested=True)
    if _path is None or _emitted:
        return
    now = time.monotonic_ns()
    if _checkpoint_name is not None:
        _event(_checkpoint_name, _checkpoint_started_ns, now)
    _checkpoint_name = name
    _checkpoint_started_ns = now


@contextmanager
def phase(name: str, *, category: str = "phase") -> Iterator[None]:
    """Record a possibly nested phase without changing sequential checkpoints."""
    if _path is None or _emitted:
        yield
        return
    started_ns = time.monotonic_ns()
    try:
        yield
    finally:
        _event(name, started_ns, time.monotonic_ns(), category=category)


def record_process_imports(name: str) -> None:
    """Record child imports from package initialization to this call."""
    if _path is not None:
        _event(name, PROCESS_STARTED_AT_NS, time.monotonic_ns())


def _addon_name(addon: Any) -> str:
    name = getattr(addon, "name", None)
    if isinstance(name, str) and name:
        return Path(name).stem
    return addon.__class__.__name__


def install_mitmproxy_addon_profiling() -> None:
    """Aggregate lifecycle-hook costs while profiling a traffic master.

    This mirrors mitmproxy's small ``invoke_addon`` dispatcher only when the
    profile flag is active. Request/response hooks are deliberately excluded,
    and the wrapper is removed at readiness so it cannot affect live traffic.
    """
    global _addon_profiler_installed, _original_addon_invoke
    if _path is None or _addon_profiler_installed:
        return

    from mitmproxy import addonmanager

    async def profiled_invoke(manager, addon, event):
        hook_name = event.__class__.__name__.removesuffix("Hook").lower()
        tracked = hook_name in {"load", "configure", "running"}
        for child, func in manager._iter_hooks(addon, event):
            started_ns = time.monotonic_ns() if tracked else 0
            try:
                result = func(*event.args())
                if result is not None and inspect.isawaitable(result):
                    await result
            finally:
                if tracked:
                    duration_ms = (time.monotonic_ns() - started_ns) / 1_000_000
                    totals = _addon_totals[(_addon_name(child), hook_name)]
                    totals[0] = float(totals[0]) + duration_ms
                    totals[1] = int(totals[1]) + 1
                    totals[2] = max(float(totals[2]), duration_ms)

    _original_addon_invoke = addonmanager.AddonManager.invoke_addon
    addonmanager.AddonManager.invoke_addon = profiled_invoke
    _addon_profiler_installed = True


def uninstall_mitmproxy_addon_profiling() -> None:
    """Restore mitmproxy's dispatcher after startup reaches readiness."""
    global _addon_profiler_installed, _original_addon_invoke
    if not _addon_profiler_installed or _original_addon_invoke is None:
        return
    from mitmproxy import addonmanager

    addonmanager.AddonManager.invoke_addon = _original_addon_invoke
    _original_addon_invoke = None
    _addon_profiler_installed = False


def flush_addon_profile(stage: str) -> None:
    """Append aggregate addon-hook measurements collected so far."""
    if _path is None:
        return
    now = time.monotonic_ns()
    for (addon, hook), (total_ms, count, max_ms) in sorted(_addon_totals.items()):
        _append(
            {
                "schema": 1,
                "operation": _operation,
                "process": _process,
                "pid": os.getpid(),
                "category": "addon",
                "name": f"{addon}.{hook}",
                "stage": stage,
                "ended_ns": now,
                "duration_ms": round(float(total_ms), 3),
                "details": {"count": int(count), "max_ms": round(float(max_ms), 3)},
            }
        )
    _addon_totals.clear()


def _read_events() -> list[dict[str, Any]]:
    if _path is None:
        return []
    events: list[dict[str, Any]] = []
    try:
        for line in _path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("operation") == _operation:
                events.append(event)
    except OSError:
        pass
    return events


def emit() -> None:
    """Finish and print the current profile once."""
    global _checkpoint_name, _emitted
    if _path is None or _emitted:
        return
    now = time.monotonic_ns()
    if _checkpoint_name is not None:
        _event(_checkpoint_name, _checkpoint_started_ns, now)
        _checkpoint_name = None
    _event("TOTAL PROFILED WALL TIME", _command_started_ns, now, category="total")
    events = _read_events()
    phases = [event for event in events if event.get("category") == "phase"]
    addons = [event for event in events if event.get("category") == "addon"]
    total_ms = (now - _command_started_ns) / 1_000_000

    sys.stderr.write(f"\n=== SAFEYOLO PROFILE: {_operation} ===\n")
    for event in sorted(phases, key=lambda item: item.get("started_ns", 0)):
        process = str(event.get("process", "?"))
        name = str(event.get("name", "?"))
        duration = float(event.get("duration_ms", 0.0))
        label = f"{process}: {name}"
        sys.stderr.write(f"  {label:<72s} {duration:9.1f} ms\n")
    if addons:
        sys.stderr.write("  Addon lifecycle totals (inclusive):\n")
        for event in sorted(addons, key=lambda item: float(item.get("duration_ms", 0)), reverse=True):
            duration = float(event.get("duration_ms", 0.0))
            details = event.get("details", {})
            count = int(details.get("count", 0))
            sys.stderr.write(
                f"    {str(event.get('name', '?')):<68s} {duration:9.1f} ms  ({count} calls)\n"
            )
    sys.stderr.write(f"  {'TOTAL PROFILED WALL TIME':69s} {total_ms:9.1f} ms\n")
    sys.stderr.write(f"  JSONL: {_path}\n")
    sys.stderr.write("==========================================\n")
    _emitted = True


def profiled_command(operation: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Emit a lifecycle profile around a Typer command with ``profile``."""
    def decorate(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            requested = kwargs.get("profile") is True
            enable(operation, requested=requested)
            try:
                return func(*args, **kwargs)
            finally:
                emit()

        return wrapped

    return decorate
