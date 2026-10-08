#!/usr/bin/env python3
"""Discover and lightly exercise an installed Rust proxy on a supported host.

Use the installed safeyolo start/stop commands and per-agent UDS layout.
This probe never installs SafeYolo, builds a binary, starts a VM, or treats a
host-driven UDS request as guest-isolation evidence. run-installed-package.sh
prepares the package before invoking this probe.

discover is read-only apart from its report. smoke requires a
caller-created disposable config directory marked with
.safeyolo-platform-smoke; it starts and stops that instance through the
selected CLI, authenticates exact runtime identity and Agent API health, and
checks native allow/deny with delivery/no-delivery at owned HTTP origins.
The current smoke uses one loopback listener for the allowed IP authority and
denied localhost authority. --http-port selects a fixed fixture port when needed.
Verified process, listener and origin cleanup completes the host-only claim.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
    # Keep the selected launcher spelling (including a venv/PATH symlink) for
    # invocation. Resolve only when a separate identity comparison needs it.
    selected = Path(os.path.abspath(os.fspath(candidate)))
    if not selected.is_file() or not os.access(selected, os.X_OK):
        raise SmokeError(f"{label} is not executable: {selected}")
    return selected


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


def _cli_identity(value: str | os.PathLike[str] | None) -> dict[str, Any]:
    """Identify a native installation; refuse a Python or shell product fallback."""
    executable = _resolve_executable(value or os.environ.get("SAFEYOLO_CLI") or "safeyolo", "SafeYolo CLI")
    with executable.open("rb") as stream:
        magic = stream.read(4)
    if magic not in {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
        raise SmokeError("selected CLI is not a native executable; Python/script fallback is refused")
    root = executable.resolve().parent.parent
    try:
        fields = dict(line.split("=", 1) for line in (root / "package-info").read_text().splitlines())
    except (OSError, ValueError) as exc:
        raise SmokeError("selected native CLI has no usable installed package-info") from exc
    revision, profile = fields.get("source_commit"), fields.get("profile")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None or profile not in {"production", "debug"}:
        raise SmokeError("installed package has no immutable source/profile identity")
    version = _version(executable, ["--version"], "SafeYolo CLI")
    if not version.startswith("safeyolo ") or f"commit={revision} profile={profile}" not in version:
        raise SmokeError("native CLI identity differs from installed package-info")
    return {"path": str(executable), "sha256": _sha256(executable), "version": version,
            "package_root": str(root), "source_revision": revision, "profile": profile,
            "source": _git_identity(executable.parent)}


def _installed_rust_binary(cli_path: str | os.PathLike[str]) -> tuple[Path, dict[str, Any]]:
    """Select the native proxy in the same verified installed layout."""
    cli = _cli_identity(cli_path)
    binary, identity = _rust_identity(Path(cli["package_root"]) / "bin/safeyolo-proxy")
    if f"commit={cli['source_revision']} profile={cli['profile']}" not in identity["version"]:
        raise SmokeError("installed proxy source/profile differs from its CLI")
    return binary, cli


def _rust_identity(value: str | os.PathLike[str] | None) -> tuple[Path, dict[str, Any]]:
    """Identify the supplied native executable and reject a different program."""
    executable = _resolve_executable(
        value or os.environ.get("SAFEYOLO_RUST_PROXY"), "Rust proxy executable"
    )
    with executable.open("rb") as stream:
        if stream.read(4) not in {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
            raise SmokeError("selected proxy is not a native executable; script fallback is refused")
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
    return (path if path.is_absolute() else cwd / path).resolve()


def _native_config(path: Path, cwd: Path) -> dict[str, Any]:
    """Read native JSON and expose paths as resolved inspection metadata."""
    if path.suffix == ".toml":
        try:
            native = tomllib.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise SmokeError(f"native TOML configuration is missing or malformed: {path}") from exc
        cwd = path.parent
        for key, default in (("policy_file", "policy.toml"), ("readiness_file", "data/ready.json"),
                             ("admin_api_token_file", "data/admin_token"), ("flow_store_db_path", "logs/flows.sqlite3"),
                             ("circuit_state_file", "data/circuits.json")):
            native[key] = str(_absolute_path(native.get(key, default), cwd))
        native.setdefault("listeners", [])
        for key in ("upstream_ca_file", "gateway_services_dir", "gateway_builtin_services_dir"):
            if native.get(key):
                native[key] = str(_absolute_path(native[key], cwd))
    else:
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


def _proxy_status(socket_path: str, url: str) -> int:
    """Drive one ordinary HTTP request through an installed proxy UDS."""
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.netloc:
        raise SmokeError(f"installed HTTP probe URL must be an HTTP URL: {url}")
    request = (
        f"GET {url} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(socket_path)
            client.sendall(request)
            response = bytearray()
            while len(response) < JSON_LIMIT:
                chunk = client.recv(16_384)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\r\n\r\n" in response:
                    head, _, body = bytes(response).partition(b"\r\n\r\n")
                    content_length = next(
                        (
                            int(line.split(b":", 1)[1].strip())
                            for line in head.split(b"\r\n")[1:]
                            if line.lower().startswith(b"content-length:")
                        ),
                        None,
                    )
                    if content_length is not None and len(body) >= content_length:
                        break
    except OSError as exc:
        raise SmokeError(f"installed HTTP probe failed for {url}") from exc
    first_line = bytes(response).split(b"\r\n", 1)[0].split()
    if len(first_line) < 2:
        raise SmokeError(f"installed HTTP probe returned no status for {url}")
    try:
        return int(first_line[1])
    except ValueError as exc:
        raise SmokeError(f"installed HTTP probe returned an invalid status for {url}") from exc


def _process_start_token(process_id: int) -> str | None:
    """Observe native receipts without importing a product Python package."""
    if __package__:
        from .harness.process_identity import process_start_token
    else:
        from harness.process_identity import process_start_token
    return process_start_token(process_id)


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


def _process_executable(pid: int) -> Path | None:
    """Read the actual supported-host executable, when the host exposes it."""
    if sys.platform.startswith("linux"):
        proc = Path(f"/proc/{pid}/exe")
        try:
            return proc.resolve(strict=True)
        except (FileNotFoundError, OSError):
            return None
    if platform.system() != "Darwin":
        return None
    # libproc reports the kernel's executable path without requiring ps,
    # which is unavailable inside the physical Mac test seatbelt.
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        pid_path = library.proc_pidpath
        pid_path.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        pid_path.restype = ctypes.c_int
        path_buffer = ctypes.create_string_buffer(4096)
        if pid_path(pid, path_buffer, ctypes.sizeof(path_buffer)) > 0:
            path = Path(os.fsdecode(path_buffer.value))
            if path.is_absolute():
                return path.resolve(strict=True)
    except (AttributeError, OSError, ValueError):
        pass
    # Preserve the earlier ps path for Macs where libproc is unavailable.
    # `comm` is preferred; `command` can also provide an absolute argv[0].
    for arguments in (("-o", "comm="), ("-o", "command=")):
        result = _run(["ps", "-p", str(pid), *arguments], timeout=5)
        if result.returncode != 0:
            continue
        try:
            fields = shlex.split(result.stdout.strip())
        except ValueError:
            continue
        if not fields or not Path(fields[0]).is_absolute():
            continue
        try:
            return Path(fields[0]).resolve(strict=True)
        except (FileNotFoundError, OSError):
            continue
    return None


def _read_receipt(config_dir: Path) -> dict[str, Any] | None:
    """Read the CLI-owned native receipt, preserving stale records for diagnosis."""
    path = config_dir / "data" / "proxy-process.json"
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


def _process_command_line(pid: int) -> list[bytes]:
    """Observe the running proxy's exact configuration argument."""
    if sys.platform.startswith("linux"):
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        except OSError as exc:
            raise SmokeError("cannot inspect the selected proxy's command") from exc
    if __package__:
        from .harness.macos_process_argv import process_argv
    else:
        from harness.macos_process_argv import process_argv
    return process_argv(pid)


def _runtime_observation(
    config_dir: Path,
    native: dict[str, Any],
    candidate: Path,
    *,
    config_path: Path,
    working_directory: Path,
    require_running: bool,
    require_authenticated_identity: bool = False,
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
    recorded_token = receipt.get("token")
    if not isinstance(recorded_token, str) or not recorded_token:
        raise SmokeError("Rust process receipt has no process start token")
    if not _pid_alive(pid):
        raise SmokeError(f"Rust process receipt is stale for pid {pid}")
    observed_token = _process_start_token(pid)
    if observed_token is None or observed_token != recorded_token:
        raise SmokeError(f"Rust process receipt does not own pid {pid}")
    if config_path.resolve() != (config_dir / "config.toml").resolve():
        raise SmokeError("selected runtime configuration does not belong to this native instance")
    argv = _process_command_line(pid)
    if b"--config" not in argv or argv[-1] == b"--config" or argv[argv.index(b"--config") + 1] != os.fsencode(config_path.resolve()):
        raise SmokeError("running proxy command does not use the selected native configuration")
    readiness_path = Path(native["readiness_file"])
    marker = _read_json(readiness_path, "Rust readiness marker")
    _validate_marker(marker, pid, len(native["listeners"]))
    actual = _process_executable(pid)
    if actual is None:
        raise SmokeError("cannot observe the running Rust executable identity on this supported host")
    try:
        expected = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise SmokeError(f"selected Rust executable disappeared during smoke: {candidate}") from exc
    if actual != expected:
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
    identity = (
        _authenticated_runtime_identity(native, marker, pid, recorded_token)
        if require_authenticated_identity
        else {"status": "not_checked"}
    )
    return {
        "status": "ready",
        "pid": pid,
        "actual_executable": str(actual) if actual else None,
        "receipt": {**receipt, "start_token": recorded_token},
        "readiness": marker,
        "listeners": listeners,
        "authenticated_runtime_identity": identity,
    }


def _authenticated_runtime_identity(
    native: dict[str, Any], marker: dict[str, Any], pid: int, recorded_token: str
) -> dict[str, Any]:
    """Bind the authenticated operator identity to the observed native process."""
    port = marker.get("admin_port")
    token_file = native["raw"].get("admin_api_token_file")
    if type(port) is not int or not 1 <= port <= 65535 or not isinstance(token_file, str):
        raise SmokeError("native runtime identity needs an admin listener and token file")
    try:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise SmokeError("native admin token file is unavailable") from exc
    if not token or "\r" in token or "\n" in token:
        raise SmokeError("native admin token file is invalid")
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(
                "GET", "/admin/runtime-identity",
                headers={"Authorization": f"Bearer {token}"},
            )
            response = connection.getresponse()
            status = response.status
            body = response.read(JSON_LIMIT + 1)
        finally:
            connection.close()
    except (OSError, http.client.HTTPException) as exc:
        raise SmokeError("authenticated native runtime identity request failed") from exc
    if status != 200 or len(body) > JSON_LIMIT:
        raise SmokeError(f"authenticated native runtime identity returned HTTP {status} or an oversized body")
    try:
        value = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SmokeError("authenticated native runtime identity returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("state") != "active"
        or value.get("instance_id") != marker["instance_id"]
    ):
        raise SmokeError("authenticated native runtime identity disagrees with process readiness")
    if _process_start_token(pid) != recorded_token:
        raise SmokeError("native process identity changed during authenticated inspection")
    return {"status": "authenticated", "instance_id": value["instance_id"], "schema_version": 1}


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
            "Allowed/denied origin requests and cross-guest socket access remain stage-B work.",
        ],
    }


def _require_substrate(substrate: dict[str, Any]) -> None:
    """Require the selected Linux/macOS bridge before reporting a smoke pass."""
    if substrate.get("status") != "discovered":
        reason = substrate.get("reason") or "the required host substrate was not discovered"
        raise SmokeError(f"required host substrate unavailable: {reason}")


def _smoke_logs_dir(config_dir: Path) -> Path:
    """Return a private log directory inside the marked disposable instance."""
    selected = config_dir / "logs"
    if selected.is_symlink():
        raise SmokeError(f"disposable smoke logs directory must not be a symlink: {selected}")
    logs_dir = selected.resolve()
    try:
        logs_dir.relative_to(config_dir)
    except ValueError as exc:
        raise SmokeError(f"disposable smoke logs directory escapes config dir: {logs_dir}") from exc
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SmokeError(f"disposable smoke logs directory is not writable: {logs_dir}") from exc
    if not logs_dir.is_dir():
        raise SmokeError(f"disposable smoke logs path is not a directory: {logs_dir}")
    return logs_dir


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
        _require_substrate(substrate)
        native_path = _absolute_path(args.rust_config, cwd)
        native = _native_config(native_path, cwd)
        report["native"] = {key: value for key, value in native.items() if key != "raw"}
        report["runtime"] = _runtime_observation(
            config_dir,
            native,
            candidate_path,
            config_path=native_path,
            working_directory=cwd,
            require_running=require_running,
            require_authenticated_identity=args.mode == "attached",
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
    report["status"] = "discovered" if not require_running else "attached_ready"
    return report, 0


def _native_smoke(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    """Prove the installed host package, traffic effects and owned stop."""
    config_dir = _config_dir(args.config_dir)
    _require_disposable(config_dir)
    if Path(args.rust_config).expanduser().resolve() != config_dir / "config.toml":
        raise SmokeError("native smoke must observe the installed config.toml")
    cwd = Path(args.working_directory).expanduser().resolve()
    candidate_path, cli = _installed_rust_binary(args.cli or "safeyolo")
    supplied, candidate = _rust_identity(args.rust_bin or candidate_path)
    if supplied.resolve() != candidate_path.resolve():
        raise SmokeError("package smoke must use the native binary installed beside its CLI")
    if not args.install_commit or cli["source_revision"] != args.install_commit:
        raise SmokeError("installed native source revision does not match --install-commit")
    report = _base_report(cli, candidate, _substrate_identity(config_dir))
    report["source_revision"] = args.install_commit
    report["limitations"] = ["No guest was booted. Guest isolation and hardware virtualization remain unproved."]
    report["instance"] = {"config_dir": str(config_dir), "mode": "smoke"}
    env = os.environ.copy()
    env.pop("SAFEYOLO_RUST_PROXY", None)
    env.update(SAFEYOLO_CONFIG_DIR=str(config_dir), SAFEYOLO_LOGS_DIR=str(_smoke_logs_dir(config_dir)))
    cli_path = cli["path"]
    listeners = []
    runtime = None
    started = False
    servers = []
    threads = []
    report["status"] = "infrastructure_failure"

    class OriginHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback
            self.server.requests.append({"host": self.headers.get("Host"), "path": self.path})
            payload = b"installed-origin-ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    try:
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", args.http_port), OriginHandler)
        origin.requests = []
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        servers.append(origin)
        threads.append(thread)
        thread.start()
        endpoints = [f"{host}:{origin.server_port}" for host in ("127.0.0.1", "localhost")]
        # Both policy authorities must reach the same known-live fixture.
        for host in ("127.0.0.1", "localhost"):
            connection = http.client.HTTPConnection(host, origin.server_port, timeout=5)
            try:
                connection.request("GET", "/origin-ready")
                response = connection.getresponse()
                if response.status != 200 or response.read() != b"installed-origin-ok\n":
                    raise SmokeError("HTTP fixture authority did not reach the owned origin")
            finally:
                connection.close()
        origin.requests.clear()
        import tomlkit
        policy = config_dir / "policy.toml"
        document = tomlkit.parse(policy.read_text())
        for decision, endpoint in (("allow", endpoints[0]), ("deny", endpoints[1])):
            document["hosts"][endpoint] = {"egress": decision}
        policy.write_text(tomlkit.dumps(document))
        started = True  # A failed start can still have spawned an owned process.
        result = _run([cli_path, "--root", str(config_dir), "start"], env=env, cwd=cwd, timeout=45)
        if result.returncode:
            raise SmokeError(f"installed native start failed (exit {result.returncode}): "
                             f"{result.stdout.strip()} {result.stderr.strip()}")
        native_path = config_dir / "config.toml"
        native = _native_config(native_path, cwd)
        runtime = _runtime_observation(config_dir, native, candidate_path,
                                       config_path=native_path, working_directory=cwd,
                                       require_running=True, require_authenticated_identity=True)
        report["runtime"] = runtime
        listeners = [{"agent_id": row["agent_id"], "path": row["socket_path"]} for row in native["listeners"]]
        selected = next((row for row in listeners if row["agent_id"] == args.agent), None)
        if selected is None:
            raise SmokeError("package smoke agent has no registered installed UDS listener")
        report["health"] = _probe_agent_health(selected, config_dir)
        outcomes = []
        for endpoint, expected in zip(endpoints, (200, 403), strict=True):
            target = f"http://{endpoint}/installed-package"
            status = _proxy_status(selected["path"], target)
            if status != expected:
                raise AssertionError(f"installed host origin returned HTTP {status}, expected {expected}")
            outcomes.append(status)
        if origin.requests != [{"host": endpoints[0], "path": "/installed-package"}]:
            raise AssertionError("installed allow/deny response disagrees with owned origin delivery")
        report["origin"] = {"bind": list(origin.server_address), "authorities": endpoints,
                            "allowed_status": outcomes[0], "allowed_deliveries": len(origin.requests),
                            "denied_status": outcomes[1], "denied_deliveries": sum(
                                row["host"] == endpoints[1] for row in origin.requests)}
        report["status"] = "host_package_passed"
    except AssertionError as exc:
        report.update(status="assertion_failure", error=str(exc))
    except (SmokeError, OSError, http.client.HTTPException, OverflowError) as exc:
        report["error"] = str(exc)
    finally:
        cleanup_errors = []
        if started:
            if __package__:
                from .installed_sections import owned_processes, surviving_processes
            else:
                from installed_sections import owned_processes, surviving_processes
            try:
                processes = owned_processes(config_dir)
            except (OSError, ValueError, KeyError) as exc:
                cleanup_errors.append(f"owned process inspection failed: {exc}")
                processes = []
            try:
                result = _run([cli_path, "stop"], env=env, cwd=cwd, timeout=45)
                if result.returncode:
                    cleanup_errors.append(f"installed stop exited {result.returncode}")
            except SmokeError as exc:
                cleanup_errors.append(str(exc))
            for name in ("proxy-rust.json", "proxy-readiness.json", "proxy.pid"):
                if (config_dir / "data" / name).exists():
                    cleanup_errors.append(f"installed stop left {name}")
            cleanup_errors.extend(surviving_processes(processes))
            for listener in listeners:
                path = Path(listener["path"])
                if path.exists() or _socket_accepting(path):
                    cleanup_errors.append("installed agent UDS remains after stop")
        for server, thread in zip(servers, threads, strict=True):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                cleanup_errors.append("owned origin did not stop")
        report["cleanup"] = {"status": "stopped" if not cleanup_errors else "failed", "errors": cleanup_errors}
        if cleanup_errors:
            report["status"] = "cleanup_failure"
    return report, {"host_package_passed": 0, "assertion_failure": 1}.get(report["status"], 2)


def main(argv: list[str] | None = None) -> int:
    """Run the selected discovery or disposable lifecycle smoke."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("discover", "attached", "smoke"), default="discover")
    parser.add_argument("--cli", help="installed safeyolo executable (defaults to SAFEYOLO_CLI/PATH)")
    parser.add_argument("--rust-bin", help="supplied safeyolo-proxy executable")
    parser.add_argument("--rust-config", required=True,
                        help="installed native config.toml")
    parser.add_argument("--config-dir", help="SafeYolo config directory (required and disposable for --mode smoke)")
    parser.add_argument("--working-directory", default=os.getcwd(), help="working directory used for relative native paths")
    parser.add_argument("--agent", help="agent name for the UDS health probe")
    parser.add_argument("--install-commit", help="exact source revision in installed package-info")
    parser.add_argument("--http-port", type=int, default=0,
                        help="current package smoke's loopback HTTP fixture port (default: ephemeral)")
    parser.add_argument("--output", type=Path, required=True, help="JSON evidence output outside the checkout")
    args = parser.parse_args(argv)
    try:
        if args.mode == "smoke":
            report, code = _native_smoke(args)
        else:
            report, code = _discover(args, require_running=args.mode == "attached")
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
