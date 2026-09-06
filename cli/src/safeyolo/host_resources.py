"""Host-level resource admission and enforcement reporting.

The guard protects the host as a whole. Agent memory and CPU values remain
per-agent sizing inputs; the guard only decides whether another agent may
start. It does not schedule or resize running agents.
"""

from __future__ import annotations

import fcntl
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import (
    get_agents_dir,
    get_config_dir,
    get_data_dir,
    get_logs_dir,
    load_config,
)

DEFAULT_AGENT_CPUS = 4

_MEMINFO_RE = re.compile(r"^(MemTotal|MemAvailable):\s+(\d+)\s+kB$")


class HostResourceAdmissionError(RuntimeError):
    """A new agent would cross a host resource protection boundary."""


@dataclass(frozen=True)
class ResourceLimit:
    """One detected and effective host resource boundary."""

    detected: int | None
    effective: int | None
    source: str
    enforcement: str


@dataclass(frozen=True)
class DiskCapacity:
    """Capacity and guard state for one filesystem used by SafeYolo."""

    path: str
    total: int | None
    free: int | None
    block_size: int | None
    effective_min_free: int
    source: str
    enforcement: str


@dataclass(frozen=True)
class HostResourceReport:
    """Host facts and effective protection shown to the operator."""

    cpu: ResourceLimit
    memory: ResourceLimit
    disks: tuple[DiskCapacity, ...]
    processes: ResourceLimit
    process_current: int | None
    active_cpu: int
    active_memory_mb: int
    platform: str
    memory_available: int | None = None
    memory_available_source: str = "unavailable: available memory could not be detected"

    @property
    def degraded(self) -> bool:
        """Return whether any protection is unavailable or admission-only."""
        limits = (self.cpu, self.memory, self.processes)
        return (
            self.memory_available is None
            or any(limit.effective is None for limit in limits)
            or any(
                "degraded" in limit.enforcement
                or "admission-only" in limit.enforcement
                for limit in limits
            )
            or any("degraded" in disk.enforcement for disk in self.disks)
        )

    def as_detail_lines(self) -> list[str]:
        """Render bounded, operator-readable derivation and enforcement facts."""
        memory_detected = _format_bytes(self.memory.detected)
        memory_effective = _format_bytes(self.memory.effective)
        lines = [
            (
                f"CPU capacity: {self.cpu.detected or 'unavailable'}; "
                f"ceiling: {self.cpu.effective or 'unavailable'}; "
                f"source: {self.cpu.source}; enforcement: {self.cpu.enforcement}"
            ),
            (
                f"Memory detected: {memory_detected}; ceiling: {memory_effective}; "
                f"available now: {_format_bytes(self.memory_available)}; "
                f"active allocation: {self.active_memory_mb} MiB; "
                f"source: {self.memory.source}; "
                f"live source: {self.memory_available_source}; "
                f"enforcement: {self.memory.enforcement}"
            ),
        ]
        for disk in self.disks:
            lines.append(
                f"Disk {disk.path}: free {_format_bytes(disk.free)}; "
                f"minimum free {_format_bytes(disk.effective_min_free)}; "
                f"source: {disk.source}; enforcement: {disk.enforcement}"
            )
        process_limit = self.processes.effective
        lines.append(
            f"Processes: current {self.process_current if self.process_current is not None else 'unavailable'}; "
            f"limit {process_limit if process_limit is not None else 'unavailable'}; "
            f"source: {self.processes.source}; enforcement: {self.processes.enforcement}"
        )
        return lines


@dataclass(frozen=True)
class HostResourceDecision:
    """Result of testing one requested agent against a host report."""

    allowed: bool
    reasons: tuple[str, ...]
    report: HostResourceReport


def _format_bytes(value: int | None) -> str:
    if value is None:
        return "unavailable"
    if value < 1024 * 1024:
        return f"{value} bytes"
    if value % (1024 * 1024) == 0:
        return f"{value // (1024 * 1024)} MiB"
    return f"{value} bytes"


def _runtime_allocation_path(name: str) -> Path:
    return get_agents_dir() / name / "runtime-resources.json"


def record_running_agent_allocation(
    name: str, *, cpus: int, memory_mb: int
) -> None:
    """Persist the resources used by the currently running guest.

    This is deliberately separate from policy metadata: an operator may edit
    next-run sizing while a guest is running, but admission must account for
    the allocation that was actually launched.
    """
    if type(cpus) is not int or cpus <= 0:
        raise ValueError("runtime CPU allocation must be a positive integer")
    if type(memory_mb) is not int or memory_mb <= 0:
        raise ValueError("runtime memory allocation must be a positive integer")
    path = _runtime_allocation_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=".runtime-resources-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump({"cpus": cpus, "memory_mb": memory_mb}, handle)
            handle.write("\n")
        fd = -1
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def clear_running_agent_allocation(name: str) -> None:
    """Remove the runtime allocation after a guest has stopped."""
    _runtime_allocation_path(name).unlink(missing_ok=True)


def _read_running_agent_allocation(name: str) -> tuple[int, int] | None:
    path = _runtime_allocation_path(name)
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise HostResourceAdmissionError(
            f"cannot inspect runtime allocation for agent {name!r}: "
            f"{type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict):
        raise HostResourceAdmissionError(
            f"runtime allocation for agent {name!r} is invalid"
        )
    cpus = payload.get("cpus")
    memory_mb = payload.get("memory_mb")
    if (
        type(cpus) is not int
        or cpus <= 0
        or type(memory_mb) is not int
        or memory_mb <= 0
    ):
        raise HostResourceAdmissionError(
            f"runtime allocation for agent {name!r} is invalid"
        )
    return cpus, memory_mb


def _host_resource_config(config: dict | None = None) -> dict:
    """Return validated host-resource overrides from config.yaml."""
    values = (config if config is not None else load_config()).get(
        "host_resources", {}
    )
    if values is None:
        return {}
    if not isinstance(values, dict):
        raise ValueError("host_resources must be a mapping")
    allowed = {
        "cpu_ceiling",
        "memory_ceiling_mb",
        "disk_min_free_bytes",
        "process_limit",
    }
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(
            f"host_resources contains unsupported setting(s): {', '.join(unknown)}"
        )
    result: dict[str, int] = {}
    for key, value in values.items():
        if value is None:
            continue
        if type(value) is not int:
            raise ValueError(f"host_resources.{key} must be an integer or null")
        if key == "disk_min_free_bytes":
            if value < 0:
                raise ValueError(f"host_resources.{key} must be non-negative")
        elif value <= 0:
            raise ValueError(f"host_resources.{key} must be positive")
        result[key] = value
    return result


def _read_cpu_capacity() -> tuple[int | None, str]:
    try:
        if hasattr(os, "sched_getaffinity"):
            capacity = len(os.sched_getaffinity(0))
            if capacity > 0:
                return capacity, "automatic: sched_getaffinity"
    except OSError:
        pass
    capacity = os.cpu_count()
    if capacity and capacity > 0:
        return capacity, "automatic: os.cpu_count"
    return None, "unavailable: host CPU count could not be detected"


def _read_darwin_memory_capacity() -> tuple[int | None, int | None, str]:
    """Read macOS memory without relying on unsupported sysconf names."""
    total: int | None = None
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if result.returncode == 0:
            value = int(result.stdout.strip())
            if value > 0:
                total = value
    except (OSError, ValueError, subprocess.SubprocessError):
        pass

    available: int | None = None
    try:
        result = subprocess.run(
            ["vm_stat"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if result.returncode == 0:
            page_match = re.search(r"page size of (\d+) bytes", result.stdout)
            page_size = int(page_match.group(1)) if page_match else None
            page_names = "free|inactive|speculative"
            pages = re.findall(
                rf"^Pages ({page_names}):\s+(\d+)",
                result.stdout,
                re.MULTILINE,
            )
            if page_size and pages:
                available = page_size * sum(int(value) for _name, value in pages)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass

    if total is None:
        return None, available, "unavailable: Darwin hw.memsize could not be detected"
    if available is None:
        return total, None, "automatic: Darwin sysctl hw.memsize; available unknown"
    return (
        total,
        available,
        "automatic: Darwin sysctl hw.memsize; vm_stat free+inactive+speculative",
    )


def _sysconf_positive(name: str) -> int | None:
    try:
        value = os.sysconf(name)
    except (AttributeError, OSError, ValueError):
        return None
    return value if value > 0 else None


def _read_memory_capacity() -> tuple[int | None, int | None, str]:
    """Return total bytes, currently available bytes, and derivation source."""
    if platform.system() == "Darwin":
        return _read_darwin_memory_capacity()

    total: int | None = None
    available: int | None = None
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                match = _MEMINFO_RE.match(line)
                if not match:
                    continue
                value = int(match.group(2)) * 1024
                if match.group(1) == "MemTotal":
                    total = value
                else:
                    available = value
        except (OSError, ValueError):
            total = available = None
        if total is not None:
            if available is not None:
                return total, available, "automatic: /proc/meminfo MemAvailable"
            return total, None, "automatic: /proc/meminfo MemTotal; available unknown"

    page_size = _sysconf_positive("SC_PAGE_SIZE")
    total_pages = _sysconf_positive("SC_PHYS_PAGES")
    available_pages = _sysconf_positive("SC_AVPHYS_PAGES")
    if page_size is not None and total_pages is not None:
        total = page_size * total_pages
    if page_size is not None and available_pages is not None:
        available = page_size * available_pages
    if total is None:
        return None, available, "unavailable: host memory capacity could not be detected"
    if available is not None:
        return total, available, "automatic: sysconf available physical pages"
    return total, None, "automatic: sysconf physical pages; available unknown"


def _configured_limit(
    detected: int | None,
    override: int | None,
    *,
    automatic: int | None = None,
    automatic_source: str,
) -> ResourceLimit:
    if override is not None:
        if detected is not None:
            effective = min(override, detected)
            source = "operator override" if override <= detected else (
                "operator override capped by detected capacity"
            )
        else:
            effective = override
            source = "operator override; detected capacity unavailable"
        return ResourceLimit(
            detected=detected,
            effective=effective,
            source=source,
            enforcement="admission",
        )
    if automatic is None:
        return ResourceLimit(
            detected=detected,
            effective=None,
            source=f"unavailable: {automatic_source}",
            enforcement="degraded: admission unavailable",
        )
    return ResourceLimit(
        detected=detected,
        effective=automatic,
        source=automatic_source,
        enforcement="admission",
    )


def _cgroup_value(filename: str) -> int | None:
    """Read a finite cgroup-v2 value for this process, if exposed."""
    try:
        relative = Path("/proc/self/cgroup").read_text().splitlines()
        relative_path = next(
            line.split(":", 2)[2] for line in relative if line.startswith("0::")
        )
        path = Path("/sys/fs/cgroup") / relative_path.lstrip("/") / filename
        value = path.read_text().strip()
    except (OSError, StopIteration, IndexError):
        return None
    if value == "max":
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _process_count() -> int | None:
    try:
        return sum(1 for item in Path("/proc").iterdir() if item.name.isdigit())
    except OSError:
        return None


def _read_process_capacity() -> tuple[int | None, int | None, str]:
    """Read one aggregate process boundary, not a per-agent cgroup limit."""
    current = _process_count()
    try:
        pid_max = int(Path("/proc/sys/kernel/pid_max").read_text().strip())
    except (OSError, ValueError):
        pid_max = None
    if pid_max is not None and pid_max > 0 and current is not None:
        return pid_max, current, "automatic: /proc process count; kernel pid_max"

    # A cgroup limit is only a fallback when the corresponding current count
    # comes from that same cgroup. It must not be copied as TasksMax onto every
    # agent scope: that would turn an aggregate limit into N separate limits.
    cgroup_current = _cgroup_value("pids.current")
    cgroup_limit = _cgroup_value("pids.max")
    if cgroup_limit is not None:
        return cgroup_limit, cgroup_current, "automatic: current cgroup pids.max"
    if pid_max is not None and pid_max > 0:
        return pid_max, current, "automatic: kernel pid_max"
    return None, current, "unavailable: process capacity could not be detected"


def _existing_path(path: Path) -> Path:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def _runtime_paths(extra_paths: list[Path] | None = None) -> list[Path]:
    """Return every known filesystem on which SafeYolo may write."""
    paths = [get_config_dir(), get_logs_dir()]
    paths.extend(extra_paths or [])
    try:
        from .agents_store import load_all_agents

        agents = load_all_agents()
    except Exception:  # noqa: BLE001 - doctor must report missing facts, not crash
        agents = {}
    for metadata in agents.values():
        if not isinstance(metadata, dict):
            continue
        folder = metadata.get("folder")
        if isinstance(folder, str):
            paths.append(Path(folder).expanduser())
        mounts = metadata.get("mounts", [])
        if isinstance(mounts, list):
            for mount in mounts:
                if isinstance(mount, str) and ":" in mount:
                    paths.append(Path(mount.split(":", 1)[0]).expanduser())
    unique: dict[int | str, Path] = {}
    for path in paths:
        existing = _existing_path(path)
        try:
            key: int | str = existing.stat().st_dev
        except OSError:
            key = str(existing)
        unique.setdefault(key, existing)
    return list(unique.values())


def _read_disks(
    paths: list[Path],
    override: int | None,
) -> tuple[DiskCapacity, ...]:
    disks: list[DiskCapacity] = []
    for path in paths:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            disks.append(
                DiskCapacity(
                    path=str(path),
                    total=None,
                    free=None,
                    block_size=None,
                    effective_min_free=override or 0,
                    source=(
                        "operator override"
                        if override is not None
                        else "unavailable: disk capacity could not be detected"
                    ),
                    enforcement="degraded: admission unavailable",
                )
            )
            continue
        disks.append(
            DiskCapacity(
                path=str(path),
                total=usage.total,
                free=usage.free,
                block_size=getattr(usage, "block_size", None),
                effective_min_free=override if override is not None else 0,
                source=(
                    "operator override"
                    if override is not None
                    else "automatic: refuse only when filesystem free space is zero"
                ),
                enforcement="admission",
            )
        )
    return tuple(disks)


def _systemd_scope_status() -> str:
    """Return whether Linux can apply the existing per-agent scope limits."""
    if platform.system() != "Linux":
        return "admission-only: platform has no SafeYolo aggregate cgroup scope"
    try:
        from .platform.linux import _systemd_user_scope_available

        available, reason = _systemd_user_scope_available()
    except Exception as exc:  # noqa: BLE001 - status must expose a degraded mode
        return f"degraded: systemd scope probe failed ({type(exc).__name__})"
    if available:
        return "admission + per-agent systemd scope"
    return f"degraded: aggregate admission only ({reason})"


def build_host_resource_report(
    *,
    extra_paths: list[Path] | None = None,
    active_cpu: int = 0,
    active_memory_mb: int = 0,
    config: dict | None = None,
) -> HostResourceReport:
    """Detect host capacity and derive effective protection boundaries."""
    overrides = _host_resource_config(config)
    cpu_capacity, cpu_source = _read_cpu_capacity()
    memory_total, memory_available, memory_source = _read_memory_capacity()
    process_capacity, process_current, process_source = _read_process_capacity()

    cpu_automatic = cpu_capacity
    memory_automatic = memory_available
    # A missing available-memory measurement is not silently converted into a
    # total-memory ceiling. The latter would imply that current host users have
    # no memory cost and would fail the protection invariant.
    cpu = _configured_limit(
        cpu_capacity,
        overrides.get("cpu_ceiling"),
        automatic=cpu_automatic,
        automatic_source=cpu_source,
    )
    memory = _configured_limit(
        memory_total,
        overrides.get("memory_ceiling_mb", None) * 1024 * 1024
        if overrides.get("memory_ceiling_mb") is not None
        else None,
        automatic=memory_automatic,
        automatic_source=memory_source,
    )
    processes = _configured_limit(
        process_capacity,
        overrides.get("process_limit"),
        automatic=process_capacity,
        automatic_source=process_source,
    )
    disks = _read_disks(
        _runtime_paths(extra_paths), overrides.get("disk_min_free_bytes")
    )
    scope_status = _systemd_scope_status()
    cpu = ResourceLimit(cpu.detected, cpu.effective, cpu.source, scope_status)
    memory = ResourceLimit(memory.detected, memory.effective, memory.source, scope_status)
    process_enforcement = "admission"
    if process_current is None:
        process_enforcement = "degraded: current process count unavailable"
    processes = ResourceLimit(
        processes.detected,
        processes.effective,
        processes.source,
        process_enforcement,
    )
    return HostResourceReport(
        cpu=cpu,
        memory=memory,
        disks=disks,
        processes=processes,
        process_current=process_current,
        active_cpu=active_cpu,
        active_memory_mb=active_memory_mb,
        platform=platform.system(),
        memory_available=memory_available,
        memory_available_source=memory_source,
    )


def evaluate_admission(
    report: HostResourceReport,
    *,
    requested_cpu: int,
    requested_memory_mb: int,
) -> HostResourceDecision:
    """Apply the explicit aggregate safety invariants to one new agent."""
    if requested_cpu <= 0 or requested_memory_mb <= 0:
        raise ValueError("requested agent resources must be positive")
    reasons: list[str] = []
    if report.cpu.effective is None:
        reasons.append("CPU capacity is unavailable; cannot establish a host ceiling")
    elif report.active_cpu + requested_cpu > report.cpu.effective:
        reasons.append(
            f"CPU allocation {report.active_cpu + requested_cpu} exceeds ceiling "
            f"{report.cpu.effective} ({report.cpu.source})"
        )

    if report.memory.effective is None:
        reasons.append("memory ceiling is unavailable; cannot establish a host boundary")
    elif report.memory.source.startswith("operator override"):
        if (report.active_memory_mb + requested_memory_mb) * 1024 * 1024 > report.memory.effective:
            reasons.append(
                f"memory allocation {report.active_memory_mb + requested_memory_mb} MiB "
                f"exceeds ceiling {_format_bytes(report.memory.effective)} "
                f"({report.memory.source})"
            )
    if report.memory_available is None:
        reasons.append(
            "currently available host memory is unavailable; "
            "cannot establish a live-pressure boundary"
        )
    elif requested_memory_mb * 1024 * 1024 > report.memory_available:
        reasons.append(
            f"memory request {requested_memory_mb} MiB exceeds currently available "
            f"memory {_format_bytes(report.memory_available)} "
            f"({report.memory_available_source})"
        )

    if report.processes.effective is None:
        reasons.append("process capacity is unavailable; cannot establish a host boundary")
    elif report.process_current is None:
        reasons.append("current process count is unavailable; cannot check exhaustion")
    elif report.process_current >= report.processes.effective:
        reasons.append(
            f"process table is exhausted ({report.process_current} of "
            f"{report.processes.effective}; {report.processes.source})"
        )
    for disk in report.disks:
        if disk.free is None:
            reasons.append(
                f"filesystem {disk.path} free space is unavailable; "
                "cannot check disk exhaustion"
            )
        elif disk.free <= disk.effective_min_free:
            reasons.append(
                f"filesystem {disk.path} has {_format_bytes(disk.free)} free; "
                f"minimum is {_format_bytes(disk.effective_min_free)} "
                f"({disk.source})"
            )
    return HostResourceDecision(not reasons, tuple(reasons), report)


def running_agent_allocations(exclude: str | None = None) -> tuple[int, int]:
    """Return launched CPU and memory allocations for running agents."""
    try:
        from .agents_store import load_all_agents
        from .platform import get_platform

        platform_impl = get_platform()
        agents = load_all_agents()
    except Exception as exc:  # noqa: BLE001 - fail closed when state is unreadable
        raise HostResourceAdmissionError(
            f"cannot inspect configured agents for aggregate admission: {type(exc).__name__}"
        ) from exc
    active_cpu = 0
    active_memory_mb = 0
    for name, metadata in agents.items():
        if name == exclude or not isinstance(metadata, dict):
            continue
        try:
            running = platform_impl.is_sandbox_running(name)
        except Exception as exc:  # noqa: BLE001 - fail closed on runtime uncertainty
            raise HostResourceAdmissionError(
                f"cannot inspect whether agent {name!r} is running: {type(exc).__name__}"
            ) from exc
        if not running:
            continue
        allocation = _read_running_agent_allocation(name)
        if allocation is None:
            raise HostResourceAdmissionError(
                f"cannot determine the runtime allocation for running agent {name!r}"
            )
        cpus, memory_mb = allocation
        active_cpu += cpus
        active_memory_mb += memory_mb
    return active_cpu, active_memory_mb


class HostResourceGuard:
    """Serialize start admission across concurrent SafeYolo agent launches."""

    def __init__(self, *, name: str, requested_cpu: int, requested_memory_mb: int):
        self.name = name
        self.requested_cpu = requested_cpu
        self.requested_memory_mb = requested_memory_mb
        self._lock_file = None
        self.report: HostResourceReport | None = None

    def acquire(self) -> HostResourceGuard:
        if self._lock_file is not None:
            return self
        data_dir = get_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_path = data_dir / "host-resources.lock"
        self._lock_file = open(lock_path, "a+")
        fcntl.flock(self._lock_file, fcntl.LOCK_EX)
        return self

    def record_started(self) -> None:
        """Record the allocation after the runtime launch has succeeded."""
        record_running_agent_allocation(
            self.name,
            cpus=self.requested_cpu,
            memory_mb=self.requested_memory_mb,
        )

    def admit(self, *, extra_paths: list[Path] | None = None) -> HostResourceReport:
        if self._lock_file is None:
            raise RuntimeError("host resource guard must be acquired before admission")
        active_cpu, active_memory_mb = running_agent_allocations(exclude=self.name)
        report = build_host_resource_report(
            extra_paths=extra_paths,
            active_cpu=active_cpu,
            active_memory_mb=active_memory_mb,
        )
        decision = evaluate_admission(
            report,
            requested_cpu=self.requested_cpu,
            requested_memory_mb=self.requested_memory_mb,
        )
        if not decision.allowed:
            raise HostResourceAdmissionError("; ".join(decision.reasons))
        self.report = report
        return report

    def release(self) -> None:
        if self._lock_file is None:
            return
        lock_file, self._lock_file = self._lock_file, None
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    def __enter__(self) -> HostResourceGuard:
        return self.acquire()

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.release()
        return False
