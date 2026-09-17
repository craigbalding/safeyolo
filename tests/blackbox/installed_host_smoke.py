#!/usr/bin/env python3
"""Discover and lightly exercise an installed Rust proxy on a supported host.

This is the stage-A companion to run-lane.sh. It deliberately uses the
existing installed safeyolo start/stop commands and the existing per-agent UDS
layout. It never installs SafeYolo, builds a binary, starts a VM, or treats a
host-driven UDS request as guest-isolation evidence.

discover is read-only apart from its evidence file. smoke requires a
caller-created disposable config directory marked with
.safeyolo-platform-smoke; it starts and stops that instance through the
selected CLI and performs one authenticated Agent API health request through
one existing UDS listener.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = 1
COMMAND_TIMEOUT = 20.0
OUTPUT_LIMIT = 4_096
JSON_LIMIT = 4 * 1024 * 1024
AGENT_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class SmokeError(RuntimeError):
    """A selected host or runtime cannot satisfy this probe's contract."""


def _resolve_executable(value: str | os.PathLike[str] | None, label: str) -> Path:
    """Resolve one executable without accepting a missing or non-executable path."""
    if value is None:
        raise SmokeError(f"{label} is required")
    candidate = Path(value).expanduser()
    if len(candidate.parts) == 1:
        selected = shutil.which(str(candidate))
        if selected is None:
            raise SmokeError(f"{label} was not found on PATH: {candidate}")
        candidate = Path(selected)
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise SmokeError(f"{label} does not exist: {candidate}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SmokeError(f"{label} is not executable: {resolved}")
    return resolved


def _run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command without a shell and cap retained output."""
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SmokeError(f"command failed to start: {command[0]}") from exc
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        (result.stdout or "")[-OUTPUT_LIMIT:],
        (result.stderr or "")[-OUTPUT_LIMIT:],
    )


def _version(executable: Path, arguments: list[str], label: str) -> str:
    """Read one bounded executable version and reject nonzero identity probes."""
    result = _run([str(executable), *arguments])
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0 or not output:
        raise SmokeError(f"{label} version check failed (exit {result.returncode})")
    return output[:OUTPUT_LIMIT]


def _sha256(path: Path) -> str:
    """Hash an executable in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_identity(path: Path) -> dict[str, Any]:
    """Capture source revision when the selected artifact belongs to a checkout."""
    for root in (path, *path.parents):
        if not (root / ".git").exists():
            continue
        try:
            revision = _run(["git", "rev-parse", "HEAD"], cwd=root, timeout=5)
            dirty = _run(["git", "status", "--porcelain"], cwd=root, timeout=5)
        except SmokeError:
            return {"root": str(root), "revision": None, "dirty": None}
        return {
            "root": str(root),
            "revision": revision.stdout.strip() or None,
            "dirty": bool(dirty.stdout.strip()),
        }
    return {"root": None, "revision": None, "dirty": None}


def _interpreter_from_shebang(executable: Path) -> Path | None:
    """Find a Python interpreter for a script launcher, when it is explicit."""
    try:
        first = executable.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return None
    if not first.startswith("#!"):
        return None
    fields = first[2:].split()
    if not fields:
        return None
    if Path(fields[0]).name == "env" and len(fields) > 1:
        selected = shutil.which(fields[1])
        return Path(selected).resolve() if selected else None
    interpreter = Path(fields[0])
    return interpreter.resolve() if interpreter.is_file() else None


def _cli_identity(value: str | os.PathLike[str] | None) -> dict[str, Any]:
    """Identify the installed CLI and, where possible, its loaded package."""
    executable = _resolve_executable(
        value or os.environ.get("SAFEYOLO_CLI") or "safeyolo", "SafeYolo CLI"
    )
    version = _version(executable, ["--version"], "SafeYolo CLI")
    result: dict[str, Any] = {
        "path": str(executable),
        "sha256": _sha256(executable),
        "version": version,
        "source": _git_identity(executable.parent),
    }
    interpreter = _interpreter_from_shebang(executable)
    if interpreter is not None:
        result["interpreter"] = str(interpreter)
        package = _run(
            [
                str(interpreter),
                "-c",
                "import safeyolo; print(safeyolo.__file__ or '')",
            ],
            timeout=5,
        )
        if package.returncode == 0 and package.stdout.strip():
            result["package_location"] = package.stdout.strip()[-OUTPUT_LIMIT:]
        else:
            result["package_location"] = None
            result["package_error"] = "selected CLI interpreter could not import safeyolo"
    else:
        result["interpreter"] = None
        result["package_location"] = None
        result["package_error"] = "CLI launcher does not expose a Python shebang"
    return result


def _rust_identity(value: str | os.PathLike[str] | None) -> tuple[Path, dict[str, Any]]:
    """Identify the supplied native executable and reject a different program."""
    executable = _resolve_executable(
        value or os.environ.get("SAFEYOLO_RUST_PROXY"), "Rust proxy executable"
    )
    version = _version(executable, ["--version"], "Rust proxy executable")
    if version.split(maxsplit=1)[0] != "safeyolo-proxy":
        raise SmokeError(f"Rust proxy executable has unexpected identity: {version[:200]}")
    identity = {
        "path": str(executable),
        "sha256": _sha256(executable),
        "version": version,
        "source": _git_identity(executable.parent),
    }
    return executable, identity


def _config_dir(value: str | os.PathLike[str] | None) -> Path:
    """Resolve the selected SafeYolo instance directory."""
    selected = value or os.environ.get("SAFEYOLO_CONFIG_DIR") or str(Path.home() / ".safeyolo")
    try:
        return Path(selected).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise SmokeError(f"SafeYolo config directory does not exist: {selected}") from exc


def _require_disposable(config_dir: Path) -> None:
    """Refuse to start or stop an unmarked or conventional live instance."""
    if config_dir == (Path.home() / ".safeyolo").resolve():
        raise SmokeError("refusing to exercise the default operator config; use a disposable directory")
    marker = config_dir / ".safeyolo-platform-smoke"
    if not marker.is_file():
        raise SmokeError(
            f"disposable marker missing: {marker}; create it only in an owned test instance"
        )
    if marker.is_symlink():
        raise SmokeError(f"disposable marker must not be a symlink: {marker}")
    if marker.stat().st_uid != os.getuid():
        raise SmokeError(f"disposable marker is not owned by this user: {marker}")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    """Read a bounded JSON object used for runtime or native configuration."""
    try:
        if path.stat().st_size > JSON_LIMIT:
            raise SmokeError(f"{label} is too large to inspect safely: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except SmokeError:
        raise
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SmokeError(f"{label} is missing or malformed: {path}") from exc
    if not isinstance(raw, dict):
        raise SmokeError(f"{label} must be a JSON object: {path}")
    return raw


def _absolute_path(value: str, cwd: Path) -> Path:
    """Resolve paths using the existing CLI working-directory contract."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else (cwd / path).resolve()


def _native_config(path: Path, cwd: Path) -> dict[str, Any]:
    """Read native JSON and expose paths as resolved inspection metadata."""
    native = _read_json(path, "native Rust configuration")
    listeners = native.get("listeners")
    if not isinstance(listeners, list):
        raise SmokeError("native Rust configuration listeners must be an array")
    for entry in listeners:
        if not isinstance(entry, dict) or not isinstance(entry.get("agent_id"), str):
            raise SmokeError("native Rust configuration has an invalid listener")
        if not isinstance(entry.get("socket_path"), str):
            raise SmokeError("native Rust configuration listener has no socket_path")
    policy = native.get("policy_file")
    if not isinstance(policy, str) or not policy:
        raise SmokeError("native Rust configuration needs policy_file for installed startup")
    readiness = native.get("readiness_file")
    if not isinstance(readiness, str) or not readiness:
        raise SmokeError("native Rust configuration needs readiness_file")
    return {
        "path": str(path),
        "raw": native,
        "policy_file": str(_absolute_path(policy, cwd)),
        "readiness_file": str(_absolute_path(readiness, cwd)),
        "listeners": [
            {
                **entry,
                "socket_path": str(_absolute_path(entry["socket_path"], cwd)),
            }
            for entry in listeners
        ],
    }


def _read_cli_yaml(config_dir: Path) -> dict[str, Any]:
    """Read config.yaml only to verify that the existing CLI selects Rust."""
    try:
        import yaml
    except ImportError as exc:
        raise SmokeError("PyYAML is required to inspect the installed CLI config") from exc
    try:
        config = yaml.safe_load((config_dir / "config.yaml").read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SmokeError(f"installed CLI config is missing or malformed: {config_dir / 'config.yaml'}") from exc
    if not isinstance(config, dict):
        raise SmokeError("installed CLI config must be a mapping")
    return config


def _configured_rust_config(config: dict[str, Any], cwd: Path) -> Path:
    """Verify backend selection and return the configured native JSON path."""
    proxy = config.get("proxy")
    if not isinstance(proxy, dict) or proxy.get("backend") != "rust":
        raise SmokeError("installed CLI config must explicitly select proxy.backend: rust")
    value = proxy.get("rust_config")
    if not isinstance(value, str) or not value:
        raise SmokeError("installed CLI config must name proxy.rust_config")
    return _absolute_path(value, cwd)


def _pid_alive(pid: int) -> bool:
    """Return whether a process exists without selecting or killing it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    if sys.platform.startswith("linux"):
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        except OSError:
            return True
        fields = stat_text.rsplit(")", 1)[-1].split()
        if not fields:
            return False
        return fields[0] != "Z"
    return True


def _process_start_token(pid: int) -> str | None:
    """Return the same OS-backed lifetime token recorded by the CLI."""
    if sys.platform.startswith("linux"):
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            fields_after_command = stat_text.rsplit(")", 1)[1].split()
            start_ticks = fields_after_command[19]
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        except (IndexError, OSError):
            return None
        return f"linux:{boot_id}:{pid}:{start_ticks}"
    try:
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    started = result.stdout.strip()
    return f"ps:{pid}:{started}" if result.returncode == 0 and started else None


def _process_executable(pid: int) -> Path | None:
    """Read the actual Linux process executable, when the host exposes it."""
    proc = Path(f"/proc/{pid}/exe")
    try:
        return proc.resolve(strict=True)
    except (FileNotFoundError, OSError):
        return None


def _read_receipt(config_dir: Path) -> dict[str, Any] | None:
    """Read the CLI-owned native receipt, preserving stale records for diagnosis."""
    path = config_dir / "data" / "proxy-rust.json"
    if not path.exists():
        return None
    return _read_json(path, "Rust process receipt")


def _validate_marker(marker: dict[str, Any], pid: int, expected_listeners: int | None = None) -> None:
    """Validate process-bound readiness rather than trusting a stale file."""
    if marker.get("ready") is not True:
        raise SmokeError("Rust readiness marker is not ready")
    if type(marker.get("pid")) is not int or marker["pid"] != pid:
        raise SmokeError("Rust readiness marker belongs to a different process")
    if marker.get("backend") != "rust-m2":
        raise SmokeError("Rust readiness marker does not identify rust-m2")
    if not isinstance(marker.get("instance_id"), str) or not marker["instance_id"]:
        raise SmokeError("Rust readiness marker has no instance identity")
    listeners = marker.get("listeners")
    if type(listeners) is not int or listeners < 0:
        raise SmokeError("Rust readiness marker has an invalid listener count")
    if expected_listeners is not None and listeners != expected_listeners:
        raise SmokeError("Rust readiness listener count disagrees with native configuration")
    admin_port = marker.get("admin_port")
    if admin_port is not None and (type(admin_port) is not int or not 1 <= admin_port <= 65535):
        raise SmokeError("Rust readiness marker has an invalid admin port")


def _socket_accepting(path: Path, timeout: float = 0.5) -> bool:
    """Check that a UDS accepts a connection, without sending application data."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
    except OSError:
        return False
    return True


def _runtime_observation(
    config_dir: Path,
    native: dict[str, Any],
    candidate: Path,
    *,
    require_running: bool,
) -> dict[str, Any]:
    """Inspect receipt, actual process, marker, and configured listeners."""
    receipt = _read_receipt(config_dir)
    if receipt is None:
        if require_running:
            raise SmokeError("Rust process receipt is missing; no selected native runtime is ready")
        return {"status": "stopped", "receipt": None}
    pid = receipt.get("pid")
    if type(pid) is not int or pid <= 1:
        raise SmokeError("Rust process receipt has an invalid pid")
    recorded_token = receipt.get("start_token")
    if not isinstance(recorded_token, str) or not recorded_token:
        raise SmokeError("Rust process receipt has no process start token")
    if not _pid_alive(pid):
        raise SmokeError(f"Rust process receipt is stale for pid {pid}")
    observed_token = _process_start_token(pid)
    if observed_token is None or observed_token != recorded_token:
        raise SmokeError(f"Rust process receipt does not own pid {pid}")
    readiness_value = receipt.get("readiness_file")
    if not isinstance(readiness_value, str) or not Path(readiness_value).is_absolute():
        raise SmokeError("Rust process receipt readiness_file must be absolute")
    marker = _read_json(Path(readiness_value), "Rust readiness marker")
    _validate_marker(marker, pid, len(native["listeners"]))
    actual = _process_executable(pid)
    if actual is not None and actual != candidate:
        raise SmokeError(f"running pid {pid} is {actual}, expected selected Rust binary {candidate}")
    listeners = []
    for entry in native["listeners"]:
        path = Path(entry["socket_path"])
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise SmokeError(f"configured Rust listener is unavailable: {path}") from exc
        if not stat.S_ISSOCK(mode):
            raise SmokeError(f"configured Rust listener is not a Unix socket: {path}")
        listeners.append(
            {
                "agent_id": entry["agent_id"],
                "path": str(path),
                "mode": oct(stat.S_IMODE(mode)),
                "accepting": _socket_accepting(path),
            }
        )
    if listeners and not all(item["accepting"] for item in listeners):
        raise SmokeError("one or more configured Rust listeners are not accepting")
    return {
        "status": "ready",
        "pid": pid,
        "actual_executable": str(actual) if actual else None,
        "receipt": receipt,
        "readiness": marker,
        "listeners": listeners,
        "authenticated_runtime_identity": {
            "status": "unavailable",
            "reason": "native admin runtime-identity endpoint is not implemented",
        },
    }


def _agent_map(config_dir: Path) -> list[dict[str, Any]]:
    """Derive trusted listener paths from the existing agent map identity."""
    path = config_dir / "data" / "agent_map.json"
    if not path.exists():
        return []
    value = _read_json(path, "agent map")
    listeners = []
    sockets_dir = config_dir / "data" / "sockets"
    for name, entry in value.items():
        if not isinstance(name, str) or AGENT_NAME.fullmatch(name) is None:
            raise SmokeError(f"agent map has an invalid agent name: {name!r}")
        if not isinstance(entry, dict) or not isinstance(entry.get("ip"), str):
            raise SmokeError(f"agent map entry has no IPv4 identity: {name}")
        try:
            ipaddress.IPv4Address(entry["ip"])
        except ipaddress.AddressValueError as exc:
            raise SmokeError(f"agent map entry has an invalid IPv4 identity: {name}") from exc
        expected = sockets_dir / f"{entry['ip']}_{name}" / "proxy.sock"
        declared = entry.get("socket")
        if declared is not None and _absolute_path(declared, config_dir) != expected:
            raise SmokeError(f"agent map socket disagrees with derived identity: {name}")
        listeners.append({"agent_id": name, "ip": entry["ip"], "path": str(expected)})
    return listeners


def _probe_agent_health(listener: dict[str, Any], config_dir: Path) -> dict[str, Any]:
    """Authenticate the reserved health endpoint over one existing UDS."""
    token_path = config_dir / "data" / "agent_token"
    try:
        token = token_path.read_text(encoding="utf-8").strip().encode()
    except (FileNotFoundError, OSError, UnicodeError) as exc:
        raise SmokeError(f"agent token is unavailable for UDS health probe: {token_path}") from exc
    if not token or b"\r" in token or b"\n" in token:
        raise SmokeError("agent token is empty or contains a line break")
    request = (
        b"GET /health HTTP/1.1\r\n"
        b"Host: _safeyolo.proxy.internal\r\n"
        b"Authorization: Bearer " + token + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(listener["path"])
            client.sendall(request)
            response = bytearray()
            while len(response) < 1024 * 1024:
                chunk = client.recv(16_384)
                if not chunk:
                    break
                response.extend(chunk)
    except OSError as exc:
        raise SmokeError(f"authenticated UDS health probe failed: {type(exc).__name__}: {exc}") from exc
    head, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator:
        raise SmokeError("authenticated UDS health probe returned malformed HTTP")
    first, *header_lines = head.split(b"\r\n")
    fields = {}
    for line in header_lines:
        name, marker, value = line.partition(b":")
        if marker:
            fields[name.decode("ascii", "replace").lower()] = value.strip().decode("ascii", "replace")
    parts = first.split()
    if len(parts) < 2 or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"}:
        raise SmokeError("authenticated UDS health probe returned an invalid status line")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise SmokeError("authenticated UDS health probe returned an invalid status code") from exc
    if status != 200 or fields.get("x-safeyolo-agent-api", "").casefold() != "true":
        raise SmokeError(f"authenticated UDS health probe returned HTTP {status} without Agent API marker")
    try:
        payload = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SmokeError("authenticated UDS health probe returned non-JSON body") from exc
    if not isinstance(payload, dict) or payload.get("agent_api") != "ok":
        raise SmokeError("authenticated UDS health probe did not report agent_api=ok")
    return {
        "agent_id": listener["agent_id"],
        "status": status,
        "agent_api": payload.get("agent_api"),
        "pdp": payload.get("pdp"),
        "scope": "host-driven UDS only; guest isolation is unverified",
    }


def _substrate_identity(config_dir: Path) -> dict[str, Any]:
    """Discover the platform bridge prerequisite without booting a guest."""
    system = platform.system()
    if system == "Linux":
        runsc = shutil.which("runsc")
        if runsc is None:
            return {
                "status": "unavailable",
                "kind": "gvisor",
                "path": None,
                "reason": "runsc is not installed on this Linux host",
            }
        executable = Path(runsc).resolve()
        try:
            version = _version(executable, ["--version"], "runsc")
        except SmokeError as exc:
            return {"status": "unavailable", "kind": "gvisor", "path": str(executable), "reason": str(exc)}
        return {"status": "discovered", "kind": "gvisor", "path": str(executable), "version": version}
    if system == "Darwin":
        helper = config_dir / "bin" / "safeyolo-vm"
        if not helper.is_file() or not os.access(helper, os.X_OK):
            return {
                "status": "unavailable",
                "kind": "virtualization.framework",
                "path": str(helper),
                "reason": "safeyolo-vm is not installed in the selected instance",
            }
        try:
            version = _version(helper.resolve(), ["--version", "--json"], "safeyolo-vm")
        except SmokeError as exc:
            return {
                "status": "unavailable",
                "kind": "virtualization.framework",
                "path": str(helper.resolve()),
                "reason": str(exc),
            }
        return {
            "status": "discovered",
            "kind": "virtualization.framework",
            "path": str(helper.resolve()),
            "version": version,
        }
    return {"status": "unsupported", "kind": system, "reason": "SafeYolo supports Linux and macOS hosts"}


def _base_report(cli: dict[str, Any], candidate: dict[str, Any], substrate: dict[str, Any]) -> dict[str, Any]:
    """Create a machine-readable report with no bearer or vault material."""
    return {
        "schema": SCHEMA,
        "kind": "installed_host_rust_proxy_smoke",
        "captured_at": datetime.now(UTC).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "cli": cli,
        "candidate": candidate,
        "substrate": substrate,
        "limitations": [
            "No guest was booted by this probe.",
            "Host-driven UDS health is not guest-isolation acceptance.",
            "Native authenticated runtime-identity endpoint is unavailable in the current development slice.",
            "Allowed/denied origin requests and cross-guest socket access remain stage-B work.",
        ],
    }


def _write_report(output: Path, report: dict[str, Any]) -> None:
    """Write one private evidence artifact, creating only its parent directory."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _discover(args: argparse.Namespace, *, require_running: bool = False) -> tuple[dict[str, Any], int]:
    """Run read-only discovery and return report plus an exit code."""
    cli = _cli_identity(args.cli)
    candidate_path, candidate = _rust_identity(args.rust_bin)
    config_dir = _config_dir(args.config_dir)
    cwd = Path(args.working_directory).expanduser().resolve()
    substrate = _substrate_identity(config_dir)
    report = _base_report(cli, candidate, substrate)
    report["instance"] = {"config_dir": str(config_dir), "mode": args.mode}
    try:
        if substrate["status"] == "unsupported":
            raise SmokeError(substrate["reason"])
        native_path = _absolute_path(args.rust_config, cwd)
        native = _native_config(native_path, cwd)
        report["native"] = {key: value for key, value in native.items() if key != "raw"}
        report["runtime"] = _runtime_observation(
            config_dir, native, candidate_path, require_running=require_running
        )
        report["guest_ingress"] = {
            "agents": _agent_map(config_dir),
            "scope": "host-driven UDS only; guest isolation is unverified",
        }
        if require_running:
            agents = report["guest_ingress"]["agents"]
            if not agents:
                raise SmokeError("agent map has no registered guest ingress listener")
            selected = next((item for item in agents if item["agent_id"] == args.agent), None) if args.agent else agents[0]
            if selected is None:
                raise SmokeError(f"requested guest ingress agent is not registered: {args.agent}")
            report["guest_ingress"]["health"] = _probe_agent_health(selected, config_dir)
    except SmokeError as exc:
        report["status"] = "infrastructure_failure"
        report["error"] = str(exc)
        return report, 2
    report["status"] = "discovered" if not require_running else "smoke_ready_with_gaps"
    return report, 0


def _smoke(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    """Start and stop one explicitly marked disposable instance through the CLI."""
    config_dir = _config_dir(args.config_dir)
    _require_disposable(config_dir)
    cwd = Path(args.working_directory).expanduser().resolve()
    cli = _cli_identity(args.cli)
    candidate_path, candidate = _rust_identity(args.rust_bin)
    config = _read_cli_yaml(config_dir)
    configured = _configured_rust_config(config, cwd)
    supplied = _absolute_path(args.rust_config, cwd)
    if configured != supplied:
        raise SmokeError(f"CLI proxy.rust_config points to {configured}, not supplied {supplied}")
    native = _native_config(supplied, cwd)
    substrate = _substrate_identity(config_dir)
    report = _base_report(cli, candidate, substrate)
    report["instance"] = {"config_dir": str(config_dir), "mode": "smoke"}
    report["native"] = {key: value for key, value in native.items() if key != "raw"}
    if substrate["status"] == "unsupported":
        report["status"] = "infrastructure_failure"
        report["error"] = substrate["reason"]
        return report, 2
    data_dir = config_dir / "data"
    receipt = data_dir / "proxy-rust.json"
    if receipt.exists():
        raise SmokeError(f"refusing to reuse an existing Rust process receipt: {receipt}")
    env = os.environ.copy()
    env["SAFEYOLO_CONFIG_DIR"] = str(config_dir)
    env["SAFEYOLO_RUST_PROXY"] = str(candidate_path)
    cli_path = _resolve_executable(args.cli or os.environ.get("SAFEYOLO_CLI") or "safeyolo", "SafeYolo CLI")
    start_command = [str(cli_path), "start", "--wait"]
    start_result = _run(start_command, env=env, cwd=cwd)
    report["commands"] = {
        "start": {
            "argv": start_command,
            "exit": start_result.returncode,
            "stdout_tail": start_result.stdout,
            "stderr_tail": start_result.stderr,
        },
    }
    if start_result.returncode != 0:
        report["status"] = "startup_failure"
        report["error"] = "selected Rust CLI start failed; no Python fallback was attempted"
        try:
            failed = _read_receipt(config_dir)
        except SmokeError as exc:
            report["failed_receipt"] = {"status": "malformed", "error": str(exc)}
            failed = None
        if failed is not None:
            failed_pid = failed.get("pid")
            if type(failed_pid) is int and failed_pid > 1 and _pid_alive(failed_pid):
                cleanup = _run([str(cli_path), "stop"], env=env, cwd=cwd)
                report["commands"]["cleanup_stop"] = {
                    "argv": [str(cli_path), "stop"],
                    "exit": cleanup.returncode,
                    "stdout_tail": cleanup.stdout,
                    "stderr_tail": cleanup.stderr,
                }
        return report, 2
    try:
        # CLI startup reconciles its conventional listeners from agent_map.json.
        # Inspect the on-disk native config after that existing mutation.
        native = _native_config(supplied, cwd)
        report["native"] = {key: value for key, value in native.items() if key != "raw"}
        runtime = _runtime_observation(config_dir, native, candidate_path, require_running=True)
        report["runtime"] = runtime
        agents = _agent_map(config_dir)
        if not agents:
            raise SmokeError("agent map has no registered guest ingress listener")
        selected = next((item for item in agents if item["agent_id"] == args.agent), None) if args.agent else agents[0]
        if selected is None:
            raise SmokeError(f"requested guest ingress agent is not registered: {args.agent}")
        report["guest_ingress"] = {
            "agents": agents,
            "scope": "host-driven UDS only; guest isolation is unverified",
            "health": _probe_agent_health(selected, config_dir),
        }
    except SmokeError as exc:
        report["status"] = "runtime_failure"
        report["error"] = str(exc)
        cleanup = _run([str(cli_path), "stop"], env=env, cwd=cwd)
        report["commands"]["cleanup_stop"] = {
            "argv": [str(cli_path), "stop"],
            "exit": cleanup.returncode,
            "stdout_tail": cleanup.stdout,
            "stderr_tail": cleanup.stderr,
        }
        return report, 2
    runtime_pid = report["runtime"]["pid"]
    stop_command = [str(cli_path), "stop"]
    stop_result = _run(stop_command, env=env, cwd=cwd)
    report["commands"]["stop"] = {
        "argv": stop_command,
        "exit": stop_result.returncode,
        "stdout_tail": stop_result.stdout,
        "stderr_tail": stop_result.stderr,
    }
    if stop_result.returncode != 0:
        report["status"] = "shutdown_failure"
        report["error"] = "selected Rust CLI stop failed; process ownership remains for operator diagnosis"
        return report, 2
    if receipt.exists():
        report["status"] = "shutdown_failure"
        report["error"] = "Rust process receipt remained after selected CLI stop"
        return report, 2
    report["post_stop"] = {
        "receipt_exists": False,
        "readiness_exists": Path(native["readiness_file"]).exists(),
        "pid_alive": _pid_alive(runtime_pid),
    }
    if report["post_stop"]["readiness_exists"] or report["post_stop"]["pid_alive"]:
        report["status"] = "shutdown_failure"
        report["error"] = "Rust process or readiness marker remained after selected CLI stop"
        return report, 2
    report["status"] = "smoke_ready_with_gaps"
    return report, 0


def main(argv: list[str] | None = None) -> int:
    """Run the selected discovery or disposable lifecycle smoke."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("discover", "smoke"), default="discover")
    parser.add_argument("--cli", help="installed safeyolo executable (defaults to SAFEYOLO_CLI/PATH)")
    parser.add_argument("--rust-bin", help="supplied safeyolo-proxy executable")
    parser.add_argument("--rust-config", required=True, help="native proxy JSON selected by proxy.rust_config")
    parser.add_argument("--config-dir", help="SafeYolo config directory (required and disposable for --mode smoke)")
    parser.add_argument("--working-directory", default=os.getcwd(), help="working directory used for relative native paths")
    parser.add_argument("--agent", help="agent name for the UDS health probe")
    parser.add_argument("--output", type=Path, required=True, help="JSON evidence output outside the checkout")
    args = parser.parse_args(argv)
    try:
        if args.mode == "smoke":
            report, code = _smoke(args)
        else:
            report, code = _discover(args, require_running=False)
    except SmokeError as exc:
        report = {
            "schema": SCHEMA,
            "kind": "installed_host_rust_proxy_smoke",
            "captured_at": datetime.now(UTC).isoformat(),
            "status": "infrastructure_failure",
            "host": {"system": platform.system(), "machine": platform.machine()},
            "error": str(exc),
        }
        code = 2
    try:
        _write_report(args.output, report)
    except OSError as exc:
        print(f"ERROR: unable to write evidence: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report.get("status"), "output": str(args.output)}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
